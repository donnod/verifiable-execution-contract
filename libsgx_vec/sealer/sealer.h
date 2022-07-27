#ifndef SGX_VEC_SEALER_H
#define SGX_VEC_SEALER_H

#include "sgx_tcrypto.h"
#include "sgx_quote.h"
#include "sgx_tseal.h"

typedef struct VecSealer {
    uint8_t *p_src_data;
    uint32_t src_data_size;
    uint8_t p_sealed_blob[0];
} VecSealer;


sgx_status_t sgx_vec_sealer_init(uint8_t *p_src_data, uint32_t src_data_size, VecSealer **p_vec_sealer);

sgx_status_t sgx_vec_sealer_free(VecSealer **p_vec_sealer);

sgx_status_t sgx_vec_sealer_conceal(VecSealer *p_vec_sealer);

sgx_status_t sgx_vec_sealer_recover(VecSealer *p_vec_sealer);

#endif