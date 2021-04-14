/*
 * Functions for comparing outputs of Plaid calls to attestation inputs
 */

#ifndef SILENTDATA_ENCLAVE_PLAID_COMPARISON_FUNCTIONS_H
#define SILENTDATA_ENCLAVE_PLAID_COMPARISON_FUNCTIONS_H

#include "enclave/common/enclave_exception.hpp"
#include "enclave/common/enclave_logger.hpp"
#include "enclave/core_status_codes.h"
#include "enclave/plaid/plaid_requests.hpp"

namespace silentdata
{
namespace enclave
{

struct PlaidAccountMatchResult
{
    std::string matched_account_id;
    auth_support supported_bank_info;

    PlaidAccountMatchResult() {}
    PlaidAccountMatchResult(const std::string &id, auth_support info)
        : matched_account_id(id), supported_bank_info(info)
    {
    }
};

// Check income is above a given amount each month between two dates
bool plaid_check_income(const std::vector<PlaidTransaction> &transactions,
                        const struct tm &start_date,
                        const struct tm &end_date,
                        int32_t consistent_income);

// Check stable income (same date, same name) is above a given amount each month between two dates
bool plaid_check_stable_income(const std::vector<PlaidTransaction> &transactions,
                               const struct tm &start_date,
                               const struct tm &end_date,
                               int32_t consistent_income);

// Check a linked account matches either account number + sort code / IBAN / all three
PlaidAccountMatchResult plaid_match_account(const std::vector<PlaidAccount> &account_details,
                                            uint32_t account_number,
                                            uint32_t sort_code,
                                            const std::string &iban);

} // namespace enclave
} // namespace silentdata

#endif
