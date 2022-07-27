#include "sgx_vec_t.h"
#include "rtm.h"

sgx_spinlock_t wait_for_cmd = 1, wait_for_complete = 1;

ssa_gpr_t *main_ssa = NULL, *shadow_ssa = NULL;
void ctFunc();
void ctFunc2();

char counter[0x50] = {'\0'};
uint64_t result1 = 0;
uint64_t result2 = 0;

uint64_t sgx_vec_cmd = 0;


typedef struct sgx_vec_llc_ma {
    uint64_t sa;
    uint64_t ea;
} sgx_vec_llc_ma;

#define SGX_VEC_LLC_MA_MAX_COUNT 20
#define SGX_VEC_LLC_MA_MAX_RANGE 0x10000
sgx_vec_llc_ma llc_mas[SGX_VEC_LLC_MA_MAX_COUNT];
int llc_mas_size = 0;
sgx_spinlock_t llc_mas_mutex = 0;

uint64_t sgx_vec_tsx_count = 0;
uint64_t sgx_vec_tsx_conflict = 0;
uint64_t sgx_vec_tsx_unknown = 0;
uint64_t sgx_vec_tsx_other = 0;
uint64_t sgx_vec_tsx_clflush = 0;

uint64_t sgx_vec_tr_counter = 0;

uint32_t sgx_vec_t_attack_init(int *delta)
{
	uint64_t seed = 0, m = 1 << 31, a = 1103515245, c = 12345;

	while (1) {
		int cnt = 0;
		while (cnt++ < *delta) ;
		uint64_t cur_sa = 0, cur_ea = 0;
		sgx_spin_lock(&llc_mas_mutex);
		if (llc_mas_size) {
			cur_sa = llc_mas[0].sa;
			cur_ea = llc_mas[0].ea;
		}
		sgx_vec_tsx_clflush ++;
		sgx_spin_unlock(&llc_mas_mutex);
		if (cur_sa) {
			seed = (a * seed + c) % m;
			uint64_t rand_addr = (cur_ea > cur_sa ? seed % (cur_ea - cur_sa) + cur_sa : cur_sa);
			__asm__(
                "clflush (%0)\n\t"
                :
                : "r" (rand_addr)
                :
                );
		}
	}
}

uint32_t sgx_vec_t_shadow_init(int *has_rtm)
{
    thread_data_t *thread_data = get_thread_data();
    shadow_ssa = (ssa_gpr_t *)(thread_data->first_ssa_gpr);
    if (shadow_ssa == NULL) return -1;
    while (1) {
        sgx_spin_lock(&wait_for_cmd);

        if (sgx_vec_cmd == SGX_VEC_CMD_EXIT) {
        	break;
        } else if (sgx_vec_cmd == SGX_VEC_CMD_IFEW) {
        	shadow_ssa->REG(ip) = 0;
        } else if (sgx_vec_cmd == SGX_VEC_CMD_HT) {
		    ctFunc();
        } else if (sgx_vec_cmd == SGX_VEC_CMD_LLC) {

    		int eax;
    		int i = -1;
    		uint64_t cur_sa = 0, cur_ea = 0;
		    while (sgx_vec_cmd == SGX_VEC_CMD_LLC) {
	            if (!*has_rtm || llc_mas_size == 0) {
	            	__asm __volatile("pause");
	            	continue;
	            }

	            cur_sa += SGX_VEC_LLC_MA_MAX_RANGE;
	            if (cur_sa >= cur_ea) {
					sgx_spin_lock(&llc_mas_mutex);
					i++;
					if (i == llc_mas_size) i = 0;
					cur_sa = llc_mas[i].sa;
					cur_ea = llc_mas[i].ea;
					sgx_spin_unlock(&llc_mas_mutex);
	            }

	            sgx_vec_tsx_count ++;
	            if ((eax = _xbegin()) == _XBEGIN_STARTED) {
	                __asm__(
	                    "mov $0, %%rdi\n\t"

	                    "loop_j:\n\t"
	                    "mov %0, %%rsi\n\t"

	                    "loop_i:\n\t"
	                    "mov (%%rsi), %%dl\n\t"

	                    "add $64, %%rsi\n\t"
	                    "cmp %1, %%rsi\n\t"
	                    "jb loop_i\n\t"

	                    "inc %%rdi\n\t"
	                    "cmp $1000, %%rdi\n\t"
	                    "jb loop_j\n\t"

	                    :
	                    : "r" (cur_sa), "r" (cur_sa + SGX_VEC_LLC_MA_MAX_RANGE < cur_ea ? cur_sa + SGX_VEC_LLC_MA_MAX_RANGE : cur_ea)
	                    :
	                    );
	                _xend();
	            } else {
	                if (eax & _XABORT_CONFLICT) {
	                    sgx_vec_tsx_conflict ++;
	                } else if (eax == 0) {
	                	sgx_vec_tsx_unknown ++;
	                } else {
	                	sgx_vec_tsx_other ++;
	                }
	            }
		    }
        } else if (sgx_vec_cmd == SGX_VEC_CMD_TR) {

		    while (sgx_vec_cmd == SGX_VEC_CMD_TR) {
	                __asm__(
	                    "mov $0, %%rdi\n\t"

	                    "mov (%0), %%rsi\n\t"

	                    "loop_tr:\n\t"
	                    "inc %%rsi\n\t"
	                    "mov %%rsi, (%0)\n\t"

	                    "inc %%rdi\n\t"
	                    "cmp $10000, %%rdi\n\t"
	                    "jb loop_tr\n\t"

	                    :
	                    : "r" (&sgx_vec_tr_counter)
	                    :
	                    );

		    }
        }

        sgx_spin_unlock(&wait_for_complete);
    }
    shadow_ssa = NULL;
    sgx_spin_unlock(&wait_for_complete);
    return 0;
}

uint32_t sgx_vec_t_shadow_exit()
{
    sgx_vec_cmd = SGX_VEC_CMD_EXIT;
    sgx_spin_unlock(&wait_for_cmd);
    sgx_spin_lock(&wait_for_complete);
    return 0;
}

void sgx_vec_t_ifew_enter()
{
    thread_data_t *thread_data = get_thread_data();
    main_ssa = (ssa_gpr_t *)(thread_data->first_ssa_gpr);
    main_ssa->REG(ip) = 0;

    sgx_vec_cmd = SGX_VEC_CMD_IFEW;

    sgx_spin_unlock(&wait_for_cmd);
    sgx_spin_lock(&wait_for_complete);
}

int sgx_vec_t_ifew_test()
{
    thread_data_t *thread_data = get_thread_data();
    main_ssa = (ssa_gpr_t *)(thread_data->first_ssa_gpr);

	return main_ssa->REG(ip) == 0 && (!shadow_ssa || shadow_ssa->REG(ip) == 0);
}

int sgx_vec_t_ht()
{
    sgx_vec_cmd = SGX_VEC_CMD_HT;

    int re_try_count = SGX_VEC_HT_MAX_RETRY;
    while (re_try_count--) {
        sgx_spin_unlock(&wait_for_cmd);
        ctFunc2();
        sgx_spin_lock(&wait_for_complete);
        // check co-location
        if (
            (
		    ((result1>>0) & 0xff) >= 0xe1 ||
		    ((result1>>8) & 0xff) >= 0xe1 ||
		    ((result1>>16) & 0xff) >= 0xe1 ||
		    ((result1>>24) & 0xff) >= 0xe1 ||
		    ((result1>>32) & 0xff) >= 0xe1 ||
		    ((result1>>40) & 0xff) >= 0xe1 ||
		    ((result1>>48) & 0xff) >= 0xe1 ||
		    ((result1>>56) & 0xff) >= 0xe1
		    ) && (
		    ((result2>>0) & 0xff) >= 0xf2 ||
		    ((result2>>8) & 0xff) >= 0xf2 ||
		    ((result2>>16) & 0xff) >= 0xf2 ||
		    ((result2>>24) & 0xff) >= 0xf2 ||
		    ((result2>>32) & 0xff) >= 0xf2 ||
		    ((result2>>40) & 0xff) >= 0xf2 ||
		    ((result2>>48) & 0xff) >= 0xf2 ||
		    ((result2>>56) & 0xff) >= 0xf2
		    )
	     ) {
	     	return true;
	     }
    }
    return false;
}

int sgx_vec_t_llc_set(uint64_t start_addr, uint64_t end_addr)
{
	int ret = 0;
	if (start_addr > end_addr) return -1;

	sgx_spin_lock(&llc_mas_mutex);
    llc_mas_size = 1;

	if (llc_mas[0].sa == start_addr) {
		ret = -3;
	} else {
		llc_mas[0].sa = start_addr;
		llc_mas[0].ea = end_addr;
	}
	sgx_spin_unlock(&llc_mas_mutex);
	return ret;
}

void sgx_vec_t_llc_clear()
{
	sgx_spin_lock(&llc_mas_mutex);
	llc_mas_size = 0;
	sgx_vec_tsx_clflush = 0;
	sgx_spin_unlock(&llc_mas_mutex);
	sgx_vec_tsx_count = 0;
	sgx_vec_tsx_conflict = 0;
	sgx_vec_tsx_unknown = 0;
	sgx_vec_tsx_other = 0;
}

void sgx_vec_t_llc_start()
{
    sgx_vec_cmd = SGX_VEC_CMD_LLC;

    sgx_spin_unlock(&wait_for_cmd);
}

void sgx_vec_t_llc_stop()
{
    sgx_vec_cmd = 0;

    sgx_spin_lock(&wait_for_complete);
}

void sgx_vec_t_tr_start()
{
    sgx_vec_cmd = SGX_VEC_CMD_TR;

    sgx_spin_unlock(&wait_for_cmd);

    uint64_t tmp = sgx_vec_tr_counter;
    while (tmp == sgx_vec_tr_counter) __asm__("pause\n\t");
}

void sgx_vec_t_tr_stop()
{
    sgx_vec_cmd = 0;

    sgx_spin_lock(&wait_for_complete);
}

void ctFunc()
{
	__asm__ __volatile__(
		"movl $1, %%edx\n\t"  // initialize to zero, count of co-location test
		"xor %%rcx, %%rcx\n\t" // count the number of data races
		"mfence\n\t"
		".L1o21:\n\t"

		//sync_code{
		"movb $0, -0x1a(%1)\n\t" //unlock 1a

		"mfence\n\t"
		".L1_dr_sync:\n\t"
		"movl %%edx, -0x8(%1)\n\t"    // write to one address to tell the other thread it's ready
		"cmpl %%edx, -0x10(%1)\n\t"    // test whether the other thread has written to this address
		"je .L1xx21\n\t"               // if equal, then the other thread is also ready, then goto: co-location test
		"jmp .L1_dr_sync\n\t"
		//sync_code}
		".L1xx21:\n\t"

		"mfence\n\t"

		"movl %%edx, -0x8(%1)\n\t"
		"movq $0, -0x10(%1)\n\t"
		"movq $59, %%rsi\n\t"         // each co-location test has $ race tests

		"movq $1, %%rbx\n\t"   // to shift according to %%rsi

		"mfence\n\t"

		".L122:\n\t"


		"movq (%1), %%rax\n\t"

		//"movq $0, (%1)\n\t"  // store, a different value

		"movq $0, %%r10\n\t"
		"movq $0, %%r11\n\t"

		"cmpq $70, %%rax\n\t"
		"cmovg %%rbx, %%r10\n\t"

		"subq %%rax, %%r9\n\t"
		"cmpq $1, %%r9\n\t"
		"cmova %%r11, %%r10\n\t"

		"addq %%r10, %%rcx\n\t"

		"shlq $8, %%rbx\n\t"
		"movq %%rax, %%r9\n\t"


		"movq %%rsi, (%1)\n\t"  // store



		"movq (%1), %%rax\n\t"
		"lfence\n\t"
		"movq (%1), %%rax\n\t"
		"lfence\n\t"
		"movq (%1), %%rax\n\t"
		"lfence\n\t"
		"movq (%1), %%rax\n\t"
		"lfence\n\t"
		"movq (%1), %%rax\n\t"
		"lfence\n\t"


		"dec %%rsi\n\t"
		"cmp $50, %%rsi\n\t"
		"jne .L122\n\t"


		"mfence\n\t"
	    //sync_code{
	    "movb $1, %%r10b\n\t"

	    ".L1lock:\n\t"//lock 1b
	    "lock xchg %%r10b, -0x1b(%1)\n\t"
	    "cmpb $1, %%r10b\n\t"
	    "je .L1lock\n\t"
	    //sync_code}

		"inc %%edx\n\t"
		"cmpl $256, %%edx\n\t"
		"jne .L1o21\n\t"
		"movl %%edx, -0x8(%1)\n\t"

		"mfence\n\t"

		"movq %%rcx, %0\n\t"
		: "=m" (result1)
		: "r" (&counter[0x40])//, "r" (&measure[0])
		: "memory", "rax", "rbx", "rcx", "rdx", "rsi", "r9", "r10", "r11"
	);
}

void ctFunc2()
{
	__asm__ __volatile__(
		"movl $1, %%edx\n\t"
		"xor %%rcx, %%rcx\n\t"

		"mfence\n\t"

		".Lo21:\n\t"
	    //sync_code{
	    "movb $1, %%r10b\n\t"

	    "mfence\n\t"

	    ".L2lock:\n\t"//lock 1a
	    "lock xchg %%r10b, -0x1a(%1)\n\t"
	    "cmpb $1, %%r10b\n\t"
	    "je .L2lock\n\t"

	    ".L2_dr_sync:\n\t"
		"movl %%edx, -0x10(%1)\n\t"
		"cmpl %%edx, -0x8(%1)\n\t"
		"je .Loxx21\n\t"

		"jmp .L2_dr_sync\n\t"
		//sync_code}
		".Loxx21:\n\t"

		"mfence\n\t"

		"movl %%edx, -0x10(%1)\n\t"
		"movq $0, -0x8(%1)\n\t"
		"movq $109, %%rsi\n\t"

		"movq $1, %%rbx\n\t"   // to shift according to %%rsi

		"mfence\n\t"

		".L222:\n\t"

		"movq (%1), %%rax\n\t"


		"movq %%rsi, (%1)\n\t" // store

		"movq $0, %%r10\n\t"
		"movq $0, %%r11\n\t"

		"cmpq $70, %%rax\n\t"
		"cmovl %%rbx, %%r10\n\t"

		"subq %%rax, %%r9\n\t"
		"cmpq $1, %%r9\n\t"
		"cmova %%r11, %%r10\n\t"

		"addq %%r10, %%rcx\n\t"

		"shlq $8, %%rbx\n\t"
		"movq %%rax, %%r9\n\t"


		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"


		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"

		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t" // 10

		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"  // 20

		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"  // 30

		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"  // 40

		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t" // 50

		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t" // 60

		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"  // 70

		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"  // 80


		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t" // 90

		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t"
		"movq (%1), %%rax\n\t" // 100

		"dec %%rsi\n\t"
		"cmp $100, %%rsi\n\t"
		"jne .L222\n\t"

		"mfence\n\t"
		//sync_code{
		"movb $0, -0x1b(%1)\n\t" //unlock 1b
		//sync_code}
		"inc %%edx\n\t"
		"cmpl $256, %%edx\n\t"
		"jne .Lo21\n\t"
		"movl %%edx, -0x10(%1)\n\t"

		"mfence\n\t"

		"movq %%rcx, %0\n\t"
		: "=m" (result2)
		: "r" (&counter[0x40])
		: "memory", "rax", "rbx", "rcx", "rdx", "rsi", "r9", "r10", "r11"
	);
}
