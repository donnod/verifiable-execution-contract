#include <sched.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include "sgx_urts.h"
#include "sgx_vec_u.h"

#include "tsx-cpuid.h"

int main_thread_cpuid = 3;
int shadow_thread_cpuid = -1;
pthread_t shadow_thread;

int sgxvec = -1, got;

pthread_mutex_t sgv_vec_wait_for_ecall = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t sgv_vec_wait_for_complete = PTHREAD_MUTEX_INITIALIZER;
int sgv_vec_terminate_shadow = 0;


typedef struct sgx_cat_cmd {
    int mode;
    int cpuid;
} sgx_cat_cmd;

typedef struct shadow_thread_param {
	sgx_enclave_id_t global_eid;
    sgx_status_t (*shadow_init)(sgx_enclave_id_t eid, uint32_t* retval, int* has_rtm);
    sgx_status_t (*attack_init)(sgx_enclave_id_t eid, uint32_t* retval, int* delta);
} shadow_thread_param;

shadow_thread_param shadow_param;

void *shadow_thread_function(void *param)
{
    int has_rtm = cpu_has_rtm();

    printf("shadow created\n");
    while (1) {

        pthread_mutex_lock(&sgv_vec_wait_for_ecall);

        if (sgv_vec_terminate_shadow) break;

        if (sgxvec >= 0)
        {
            sgx_cat_cmd buf;
            buf.mode = DISABLE_APIC_CMD;
            buf.cpuid = shadow_thread_cpuid;
            got = write(sgxvec, &buf, sizeof(buf));
        }

        uint32_t enclave_ret;
        shadow_param.shadow_init(shadow_param.global_eid, &enclave_ret, &has_rtm);
        if (enclave_ret != 0) printf("shadow init failed\n");

        if (sgxvec >= 0)
        {
            sgx_cat_cmd buf;
            buf.mode = ENABLE_APIC_CMD;
            buf.cpuid = shadow_thread_cpuid;
            got = write(sgxvec, &buf, sizeof(buf));
        }

        pthread_mutex_unlock(&sgv_vec_wait_for_complete);
    }

    pthread_mutex_unlock(&sgv_vec_wait_for_complete);
}

void *attack_thread_function(void *param)
{
    printf("attaker created\n");
    int delta = 10000000;
    uint32_t enclave_ret;
    shadow_param.attack_init(shadow_param.global_eid, &enclave_ret, &delta);
}

void sgx_vec_u_shadow_init(sgx_enclave_id_t global_eid, sgx_status_t (*shadow_init)(sgx_enclave_id_t eid, uint32_t* retval, int* has_rtm), sgx_status_t (*attack_init)(sgx_enclave_id_t eid, uint32_t* retval, int* delta))
{
	// auto determine shadow thread cpuid
    // if (shadow_thread_cpuid == -1) {

    pthread_mutex_lock(&sgv_vec_wait_for_ecall);
    pthread_mutex_lock(&sgv_vec_wait_for_complete);
    sgv_vec_terminate_shadow = 0;

    int a, b, c, d;
    __cpuid_count(0xB, 1, a, b, c, d);
    shadow_thread_cpuid = (main_thread_cpuid + b / 2) % b;
    printf("Main thread runs on core %d, shadow thread runs on core %d\n", main_thread_cpuid, shadow_thread_cpuid);
    // }

    sgxvec = open("/proc/sgxvec", O_WRONLY);
    // assert(sgxvec >= 0);
    if (sgxvec < 0) {
        printf("failed to open sgxvec, cannot disable local timer\n");
    }

    // shadow_thread_param shadow_param = {global_eid, shadow_init};
    shadow_param.global_eid = global_eid;
    shadow_param.shadow_init = shadow_init;
    shadow_param.attack_init = attack_init;

    cpu_set_t cpus;
    pthread_attr_t attr;
    pthread_attr_init(&attr);

    //pin shadowthread
    CPU_ZERO(&cpus);
    CPU_SET(shadow_thread_cpuid, &cpus);
    pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus);
    pthread_create(&shadow_thread, &attr, shadow_thread_function, NULL);
    pthread_setname_np(shadow_thread, "shadowthread");

    if (attack_init) {
        //pin attackthread
        pthread_t attack_thread;
        int attack_thread_cpuid  = main_thread_cpuid - 1;

        CPU_ZERO(&cpus);
        CPU_SET(attack_thread_cpuid, &cpus);
        pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus);
        pthread_create(&attack_thread, &attr, attack_thread_function, NULL);
        pthread_setname_np(attack_thread, "attackthread");
    }

	//pin main
    CPU_ZERO(&cpus);
    CPU_SET(main_thread_cpuid, &cpus);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpus);
}

void sgx_vec_u_shadow_exit()
{
    sgv_vec_terminate_shadow = 1;

    pthread_mutex_unlock(&sgv_vec_wait_for_ecall);
    pthread_mutex_lock(&sgv_vec_wait_for_complete);

    pthread_join(shadow_thread, NULL);
}

void sgx_vec_u_ifew_enter()
{
    pthread_mutex_unlock(&sgv_vec_wait_for_ecall);

	if (sgxvec >= 0)
	{
		sgx_cat_cmd buf;
	    buf.mode = DISABLE_APIC_CMD;
	    buf.cpuid = main_thread_cpuid;
	    got = write(sgxvec, &buf, sizeof(buf));
	}
}

void sgx_vec_u_ifew_exit()
{
	if (sgxvec >= 0)
	{
		sgx_cat_cmd buf;
	    buf.mode = ENABLE_APIC_CMD;
	    buf.cpuid = main_thread_cpuid;
	    got = write(sgxvec, &buf, sizeof(buf));
	}
    pthread_mutex_lock(&sgv_vec_wait_for_complete);
}
