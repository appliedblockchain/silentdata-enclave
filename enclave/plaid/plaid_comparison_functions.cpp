#include "enclave/plaid/plaid_comparison_functions.hpp"

namespace silentdata
{
namespace enclave
{

bool plaid_check_income(const std::vector<PlaidTransaction> &transactions,
                        const struct tm &start_date,
                        const struct tm &end_date,
                        int32_t consistent_income)
{
    std::map<int, double> income;
    // Initialise in case there are no transactions in a month
    for (int month = start_date.tm_mon; month < end_date.tm_mon; month++)
        income[month] = 0;

    for (const auto &transaction : transactions)
    {
        // Ignore outgoing (negative) transactions for now
        if (transaction.amount < 0)
            continue;
        int month = transaction.date.tm_mon;
        income[month] += transaction.amount;
    }

    // Do the attestation
    for (const auto &kv : income)
    {
        if (kv.first == end_date.tm_mon)
            continue;
        if (kv.second < static_cast<double>(consistent_income))
            return false;
    }

    return true;
}

PlaidAccountMatchResult plaid_match_account(const std::vector<PlaidAccount> &account_details,
                                            uint32_t account_number,
                                            uint32_t sort_code,
                                            const std::string &iban)
{
    auth_support supported_bank_info;
    for (const auto &account : account_details)
    {
        // Check which numbers are supported by this institution
        supported_bank_info = kAuthBACSAndIBANSupported;
        if (account.iban == "")
            supported_bank_info = kAuthIBANNotSupported;
        if (account.account_number == 0 || account.sort_code == 0)
            supported_bank_info = kAuthBACSNotSupported;
        if ((account.account_number == 0 || account.sort_code == 0) && account.iban == "")
        {
            ERROR_LOG("Bank does not provide BACS or IBAN number, impossible to match");
            THROW_ERROR_CODE(kAccountOwnershipBACSAndIBANNotSupported);
        }
        // Match just account number and sort code if IBAN not provided
        if (iban == "" && account_number != 0 && sort_code != 0)
        {
            if (account.account_number == 0 || account.sort_code == 0)
            {
                ERROR_LOG("Account number/sort code match requested, but bank does not provide "
                          "this information");
                THROW_ERROR_CODE(kAccountOwnershipBACSNotSupported);
            }
            DEBUG_LOG("IBAN is not provided, trying to match account number and sort code");
            if (account_number == account.account_number && sort_code == account.sort_code)
            {
                DEBUG_LOG("Account has the required number and sort code");
                return PlaidAccountMatchResult(account.account_id, supported_bank_info);
            }
        }
        // Match just IBAN if account number and sort code not provided
        if (account_number == 0 && sort_code == 0 && iban != "")
        {
            if (account.iban == "")
            {
                ERROR_LOG("IBAN match requested, but bank does not provide this information");
                THROW_ERROR_CODE(kAccountOwnershipIBANNotSupported);
            }
            DEBUG_LOG("Account number and sort code not provided, trying to match IBAN");
            if (iban == account.iban)
            {
                DEBUG_LOG("Account has the required IBAN");
                return PlaidAccountMatchResult(account.account_id, supported_bank_info);
            }
        }
        // Match all three
        if (account_number != 0 && sort_code != 0 && iban != "")
        {
            if (account.account_number == 0 || account.sort_code == 0)
            {
                WARNING_LOG("Account number/sort code match requested, but bank does not provide "
                            "this information");
                // Allow IBAN matching if it's provided
                if (iban == account.iban)
                {
                    DEBUG_LOG("Account has a matching IBAN");
                    return PlaidAccountMatchResult(account.account_id, supported_bank_info);
                }
            }
            else if (account.iban == "")
            {
                WARNING_LOG("IBAN match requested, but bank does not provide this information");
                // Allow BACS matching if it's provided
                if (account_number == account.account_number && sort_code == account.sort_code)
                {
                    DEBUG_LOG("Account has a matching account number and sort code");
                    return PlaidAccountMatchResult(account.account_id, supported_bank_info);
                }
            }
            DEBUG_LOG("Trying to match all three of account number, sort code and IBAN");
            if (account_number == account.account_number && sort_code == account.sort_code &&
                iban == account.iban)
            {
                DEBUG_LOG("Account has the required number, sort code and IBAN");
                return PlaidAccountMatchResult(account.account_id, supported_bank_info);
            }
        }
        DEBUG_LOG("Not a match");
    }

    THROW_ERROR_CODE(kAccountOwnershipNoMatchingAccount);
}

} // namespace enclave
} // namespace silentdata
