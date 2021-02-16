#ifndef SILENTDATA_ENCLAVE_ECC_KEY_PAIR_H
#define SILENTDATA_ENCLAVE_ECC_KEY_PAIR_H

#include <sgx_tcrypto.h>

#include "enclave/common/sgx_error_message.hpp"

namespace silentdata
{
namespace enclave
{

class ECCKeyPair
{
public:
    sgx_ec256_private_t private_key;
    sgx_ec256_public_t public_key;
    ECCKeyPair();
};

} // namespace enclave
} // namespace silentdata

#endif
