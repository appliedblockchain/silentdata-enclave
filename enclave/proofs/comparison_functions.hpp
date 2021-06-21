/*
 * Functions for comparing outputs of Plaid calls to attestation inputs
 */

#ifndef SILENTDATA_ENCLAVE_COMPARISON_FUNCTIONS_H
#define SILENTDATA_ENCLAVE_COMPARISON_FUNCTIONS_H

#include <time.h>

#include "enclave/common/date_time.hpp"
#include "enclave/common/enclave_exception.hpp"
#include "enclave/common/enclave_logger.hpp"
#include "enclave/common/types.hpp"
#include "enclave/core_status_codes.h"

namespace silentdata
{
namespace enclave
{

struct AccountMatchResult
{
    std::string matched_account_id;
    AuthSupport supported_bank_info;

    AccountMatchResult() {}
    AccountMatchResult(const std::string &id, AuthSupport info)
        : matched_account_id(id), supported_bank_info(info)
    {
    }
};

// Check if balance is above a given amount
bool check_minimum_balance(const BankBalance &balance,
                           const std::string &currency_code,
                           uint32_t minimum_balance);

// Check income is above a given amount each month between two dates
bool check_consistent_income(const std::vector<BankTransaction> &transactions,
                             const struct tm &start_date,
                             const struct tm &end_date,
                             const std::string &currency_code,
                             uint32_t consistent_income);

// Check stable income (same date, same name) is above a given amount each month between two dates
bool check_stable_income(const std::vector<BankTransaction> &transactions,
                         const struct tm &start_date,
                         const struct tm &end_date,
                         const std::string &currency_code,
                         uint32_t consistent_income);

// Check a linked account matches either account number + sort code / IBAN / all three
AccountMatchResult match_account(const std::vector<AccountDetails> &account_details,
                                 uint32_t account_number,
                                 uint32_t sort_code,
                                 const std::string &iban);

} // namespace enclave
} // namespace silentdata

#endif
