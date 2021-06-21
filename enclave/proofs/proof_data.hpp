/*
 * Functions for serialising proof data to be signed
 */

#ifndef SILENTDATA_ENCLAVE_PROOF_DATA_H
#define SILENTDATA_ENCLAVE_PROOF_DATA_H

#include <string>
#include <vector>

#include "enclave/common/enclave_exception.hpp"
#include "enclave/common/enclave_logger.hpp"
#include "enclave/core_status_codes.h"

namespace silentdata
{
namespace enclave
{

const std::string proof_data_version = "v0001";

enum ProofType
{
    kMinimumBalanceProof = 1,
    kConsistentIncomeProof = 2,
    kAccountOwnershipProof = 3,
    kStableIncomeProof = 4
};

// Create a padded structure of the attestation data
std::vector<uint8_t> serialize_proof_data(ProofType type,
                                          uint8_t *nonce,
                                          const std::string &http_timestamp,
                                          const std::string &account_holder_name,
                                          const std::string &institution_name,
                                          const std::string &currency_code,
                                          uint32_t comparison_value,
                                          int32_t unix_timestamp,
                                          const std::string &certificate_chain);

// Create a padded structure of the attestation data for contracts
std::vector<uint8_t> serialize_contract_proof_data(ProofType type,
                                                   uint8_t *nonce,
                                                   uint8_t *wallet_signature,
                                                   const std::string &http_timestamp,
                                                   const std::string &currency_code,
                                                   uint32_t comparison_value,
                                                   int32_t unix_timestamp,
                                                   const std::string &certificate_chain);

std::vector<uint8_t> serialize_account_ownership_proof_data(uint8_t *nonce,
                                                            const std::string &http_timestamp,
                                                            const std::string &account_holder_name,
                                                            const std::string &institution_name,
                                                            AuthSupport supported_bank_info,
                                                            uint32_t account_number,
                                                            uint32_t sort_code,
                                                            const std::string &iban,
                                                            int32_t unix_timestamp,
                                                            const std::string &certificate_chain);

} // namespace enclave
} // namespace silentdata

#endif
