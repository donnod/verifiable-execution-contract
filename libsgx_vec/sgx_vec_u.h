#ifndef SGX_VEC_T_H_
#define SGX_VEC_T_H_

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DISABLE_APIC_CMD 0
#define ENABLE_APIC_CMD 1

#define USE_RDTSCP
static inline uint64_t rdtsc() {
  uint64_t a = 0, d = 0;
#if defined(USE_RDTSCP) && defined(__x86_64__)
  asm volatile("rdtscp" : "=a"(a), "=d"(d) :: "rcx");
#elif defined(USE_RDTSCP) && defined(__i386__)
  asm volatile("rdtscp" : "=A"(a), :: "ecx");
#elif defined(__x86_64__)
  asm volatile("rdtsc" : "=a"(a), "=d"(d));
#elif defined(__i386__)
  asm volatile("rdtsc" : "=A"(a));
#endif
  a = (d << 32) | a;
  return a;
}

void sgx_vec_u_shadow_init(sgx_enclave_id_t global_eid, sgx_status_t (*sgx_vec_t_shadow_init)(sgx_enclave_id_t eid, uint32_t* retval, int* has_rtm), sgx_status_t (*attack_init)(sgx_enclave_id_t eid, uint32_t* retval, int* delta));
void sgx_vec_u_shadow_exit();

void sgx_vec_u_ifew_enter();
void sgx_vec_u_ifew_exit();
void ocall_print_for_debug(const char *str);

#ifdef __cplusplus
}
#endif

#endif
