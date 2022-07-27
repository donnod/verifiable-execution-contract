#ifndef SGX_VEC_T_H_
#define SGX_VEC_T_H_

#include "stdio.h"

#include "common/inc/internal/thread_data.h"
#include "common/inc/internal/arch.h"

#include <sgx_spinlock.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SGX_VEC_CMD_HT      1
#define SGX_VEC_CMD_LLC     2
#define SGX_VEC_CMD_IFEW    3
#define SGX_VEC_CMD_TR      4
#define SGX_VEC_CMD_EXIT    99

#define SGX_VEC_HT_MAX_RETRY 22

uint32_t sgx_vec_t_attack_init(int *delta);
uint32_t sgx_vec_t_shadow_init(int *has_rtm);
uint32_t sgx_vec_t_shadow_exit();
void sgx_vec_t_ifew_enter();
int sgx_vec_t_ifew_test();
int sgx_vec_t_ht();

int sgx_vec_t_llc_set(uint64_t start_addr, uint64_t end_addr);
void sgx_vec_t_llc_clear();
void sgx_vec_t_llc_start();
void sgx_vec_t_llc_stop();
void sgx_vec_t_tr_start();
void sgx_vec_t_tr_stop();

#define SGX_VEC_ENTER              \
    sgx_vec_t_ifew_enter();       \
    if (!sgx_vec_t_ht()) printf("!!! co-location test failed.\n"); \
    sgx_vec_t_llc_start();

#define SGX_VEC_EXIT                         \
    sgx_vec_t_llc_stop();                    \
    if (!sgx_vec_t_ifew_test()) printf("!!! ifew violated\n");

#define SGX_VEC_TSX_SET_SA           \
start_addr: sgx_vec_t_llc_set((uint64_t)&&start_addr, (uint64_t)&&end_addr);

#define SGX_VEC_TSX_SET_EA           \
end_addr: asm("nop");

#define SGX_VEC_FREE            \
    sgx_vec_t_shadow_exit();    \
    sgx_vec_t_llc_clear();

#ifdef __cplusplus
}
#endif

#endif
