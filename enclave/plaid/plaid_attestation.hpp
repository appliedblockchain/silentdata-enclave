/*
 * Functions for serialising Plaid request data to be signed
 */

#ifndef SILENTDATA_ENCLAVE_PLAID_ATTESTATION_H
#define SILENTDATA_ENCLAVE_PLAID_ATTESTATION_H

#include <string>
#include <vector>

#include "enclave/common/enclave_exception.hpp"
#include "enclave/core_status_codes.h"

namespace silentdata
{
namespace enclave
{

const uint16_t kMinimumBalanceAttestation = 1;
const uint16_t kConsistentIncomeAttestation = 2;

// Create a padded structure of the attestation data
std::vector<uint8_t> create_plaid_attestation_data(uint16_t attestation_type,
                                                   uint8_t *nonce,
                                                   const std::string &http_timestamp,
                                                   const std::string &account_holder_name,
                                                   const std::string &institution_name,
                                                   int32_t comparison_value,
                                                   int32_t unix_timestamp,
                                                   const std::string &certificate_chain);

} // namespace enclave
} // namespace silentdata

#endif
