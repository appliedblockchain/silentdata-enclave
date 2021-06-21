#ifndef SILENTDATA_ENCLAVE_RSA_PARAMS_H
#define SILENTDATA_ENCLAVE_RSA_PARAMS_H

#include "sgx_tcrypto.h"

#include "enclave/common/enclave_exception.hpp"
#include "enclave/common/sgx_error_message.hpp"

namespace silentdata
{
namespace enclave
{

class RSAParams
{
public:
    // modulus
    unsigned char n[SGX_RSA3072_KEY_SIZE]{};
    // public exponent, we set this to 65537
    unsigned char e[SGX_RSA3072_PUB_EXP_SIZE] = {0x01, 0x00, 0x01, 0x00};
    // private exponent
    unsigned char d[SGX_RSA3072_PRI_EXP_SIZE]{};
    // prime factor
    unsigned char p[SGX_RSA3072_KEY_SIZE / 2]{};
    // prime factor
    unsigned char q[SGX_RSA3072_KEY_SIZE / 2]{};
    // d mod (p-1)
    unsigned char dmp1[SGX_RSA3072_KEY_SIZE / 2]{};
    // d mod (q-1)
    unsigned char dmq1[SGX_RSA3072_KEY_SIZE / 2]{};
    // q^-1 mod p
    unsigned char iqmp[SGX_RSA3072_KEY_SIZE / 2]{};
    RSAParams()
    {
        sgx_status_t result = sgx_create_rsa_key_pair(
            SGX_RSA3072_KEY_SIZE, SGX_RSA3072_PUB_EXP_SIZE, n, d, e, p, q, dmp1, dmq1, iqmp);
        if (result != SGX_SUCCESS)
            THROW_EXCEPTION(kKeyCreationError,
                            sgx_error_message("sgx_create_rsa_key_pair", result));
    }
};

} // namespace enclave
} // namespace silentdata

#endif
