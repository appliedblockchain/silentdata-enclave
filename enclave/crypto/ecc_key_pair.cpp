#include "ecc_key_pair.hpp"
#include <ipp/ippcp.h>

#include "enclave/common/enclave_exception.hpp"

namespace silentdata
{
namespace enclave
{

ECCKeyPair::ECCKeyPair()
{
    sgx_ecc_state_handle_t handle;

    auto ret = sgx_ecc256_open_context(&handle);
    if (ret != SGX_SUCCESS)
        THROW_EXCEPTION(sgx_error_status(ret), sgx_error_message("sgx_ecc256_open_context", ret));

    ret = sgx_ecc256_create_key_pair(&private_key, &public_key, handle);
    if (ret != SGX_SUCCESS)
    {
        sgx_ecc256_close_context(handle);
        THROW_EXCEPTION(sgx_error_status(ret),
                        sgx_error_message("sgx_ecc256_create_key_pair", ret));
    }

    ret = sgx_ecc256_close_context(handle);
    if (ret != SGX_SUCCESS)
        THROW_EXCEPTION(sgx_error_status(ret), sgx_error_message("sgx_ecc256_close_context", ret));
}

} // namespace enclave
} // namespace silentdata
