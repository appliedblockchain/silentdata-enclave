/*
 * Functions for serialising Plaid request data to be signed
 */

#ifndef SILENTDATA_ENCLAVE_PLAID_ATTESTATION_H
#define SILENTDATA_ENCLAVE_PLAID_ATTESTATION_H

#include <string>
#include <vector>

#include "enclave/common/enclave_exception.hpp"
#include "enclave/common/enclave_logger.hpp"
#include "enclave/core_status_codes.h"
#include "enclave/plaid/plaid_comparison_functions.hpp"

namespace silentdata
{
namespace enclave
{

enum attestation_type
{
    kMinimumBalanceAttestation = 1,
    kConsistentIncomeAttestation = 2,
    kAccountOwnershipAttestation = 3,
    kStableIncomeAttestation = 4
};

// Create a padded structure of the attestation data
std::vector<uint8_t> create_plaid_attestation_data(attestation_type type,
                                                   uint8_t *nonce,
                                                   const std::string &http_timestamp,
                                                   const std::string &account_holder_name,
                                                   const std::string &institution_name,
                                                   int32_t comparison_value,
                                                   int32_t unix_timestamp,
                                                   const std::string &certificate_chain);

std::vector<uint8_t>
create_plaid_account_ownership_attestation_data(uint8_t *nonce,
                                                const std::string &http_timestamp,
                                                const std::string &account_holder_name,
                                                const std::string &institution_name,
                                                auth_support supported_bank_info,
                                                int32_t account_number,
                                                int32_t sort_code,
                                                const std::string &iban,
                                                int32_t unix_timestamp,
                                                const std::string &certificate_chain);

} // namespace enclave
} // namespace silentdata

#endif
