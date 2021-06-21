/*
 * Common proof request/response types
 */

#ifndef SILENTDATA_ENCLAVE_RESULT_TYPES_H
#define SILENTDATA_ENCLAVE_RESULT_TYPES_H

#include <array>
#include <string>
#include <vector>

#include "enclave/core_status_codes.h"
#include "enclave/crypto/enclave_crypto.hpp"
#include "enclave/plaid/plaid_client.hpp"
#include "enclave/proofs/proof_data.hpp"
#include "enclave/proofs/request_types.hpp"

namespace silentdata
{
namespace enclave
{

class BalanceProofResult
{
public:
    CoreStatusCode status;
    std::string timestamp;
    std::string account_holder_name;
    std::string institution_name;
    std::array<uint8_t, 65> wallet_signature;
    std::string certificate_chain;
    sgx_rsa3072_signature_t signature;

    void sign(const BalanceProofRequest &request, const RSAParams &signature_rsa_params);
};

class IncomeProofResult
{
public:
    CoreStatusCode status;
    std::string timestamp;
    std::string account_holder_name;
    std::string institution_name;
    std::array<uint8_t, 65> wallet_signature;
    std::string certificate_chain;
    sgx_rsa3072_signature_t signature;

    void sign(const IncomeProofRequest &request, const RSAParams &signature_rsa_params);
};

class OwnershipProofResult
{
public:
    CoreStatusCode status;
    std::string timestamp;
    std::string account_holder_name;
    std::string institution_name;
    std::string certificate_chain;
    AuthSupport supported_bank_info;
    sgx_rsa3072_signature_t signature;

    void sign(const OwnershipProofRequest &request, const RSAParams &signature_rsa_params);
};

} // namespace enclave
} // namespace silentdata

#endif
