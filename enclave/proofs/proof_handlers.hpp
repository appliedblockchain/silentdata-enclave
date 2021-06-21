/*
 * Functions for processing proofs
 */

#ifndef SILENTDATA_ENCLAVE_PROOF_HANDLERS_H
#define SILENTDATA_ENCLAVE_PROOF_HANDLERS_H

#include <string>
#include <vector>

#include "enclave/common/enclave_exception.hpp"
#include "enclave/common/enclave_logger.hpp"
#include "enclave/core_status_codes.h"
#include "enclave/crypto/rsa_params.hpp"
#include "enclave/plaid/plaid_client.hpp"
#include "enclave/proofs/comparison_functions.hpp"
#include "enclave/proofs/request_types.hpp"
#include "enclave/proofs/result_types.hpp"

namespace silentdata
{
namespace enclave
{

BalanceProofResult process_balance_proof(const BalanceProofRequest &request,
                                         const RSAParams &signature_rsa_params);

IncomeProofResult process_income_proof(const IncomeProofRequest &request,
                                       const RSAParams &signature_rsa_params);

OwnershipProofResult process_ownership_proof(const OwnershipProofRequest &request,
                                             const RSAParams &signature_rsa_params);

} // namespace enclave
} // namespace silentdata

#endif
