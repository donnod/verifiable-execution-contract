#include "sealer.h"

#include "sgx_tseal.h"
#include "string.h"

#define BREAK_ON_SGX_ERROR(ret) \
  if (SGX_SUCCESS != (ret)) {     \
    break;                       \
  }

sgx_status_t sgx_vec_sealer_init(uint8_t *p_src_data, uint32_t src_data_size, VecSealer **p_vec_sealer)
{
    sgx_status_t ret = SGX_SUCCESS;
    VecSealer *tmp_sealer = NULL;
    
    do
    {
        if (*p_vec_sealer) {
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }

        uint32_t sealed_blob_size = sgx_calc_sealed_data_size(0, src_data_size);

        tmp_sealer = (VecSealer*)malloc(sizeof(VecSealer) + sealed_blob_size);
        if (!tmp_sealer) {
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }

        tmp_sealer->p_src_data = p_src_data;
        tmp_sealer->src_data_size = src_data_size;

        *p_vec_sealer = tmp_sealer;
        
    } while (0);
    if (ret != SGX_SUCCESS && tmp_sealer) {
        free(tmp_sealer);
    }
    return ret;
}


sgx_status_t sgx_vec_sealer_free(VecSealer **p_vec_sealer)
{
    sgx_status_t ret = SGX_SUCCESS;
    do
    {
        free(*p_vec_sealer);
        *p_vec_sealer = NULL;
    } while (0);
    return ret;
}


sgx_status_t sgx_vec_sealer_conceal(VecSealer *p_vec_sealer)
{
    sgx_status_t ret = SGX_SUCCESS;
    
    do
    {
        if (!p_vec_sealer) {
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        uint32_t sealed_blob_size = sgx_calc_sealed_data_size(0, p_vec_sealer->src_data_size);

        ret = sgx_seal_data(0, NULL, p_vec_sealer->src_data_size, p_vec_sealer->p_src_data,
                sealed_blob_size, (sgx_sealed_data_t*)p_vec_sealer->p_sealed_blob);
        BREAK_ON_SGX_ERROR(ret)
        memset(p_vec_sealer->p_src_data, 0, p_vec_sealer->src_data_size);
    } while (0);

    return ret;
}

sgx_status_t sgx_vec_sealer_recover(VecSealer *p_vec_sealer)
{

    sgx_status_t ret = SGX_SUCCESS;
    do
    {
        ret = sgx_unseal_data((sgx_sealed_data_t*)p_vec_sealer->p_sealed_blob, 
            NULL, 0, p_vec_sealer->p_src_data, &p_vec_sealer->src_data_size);
        BREAK_ON_SGX_ERROR(ret)
    } while (0);
    return ret;
}