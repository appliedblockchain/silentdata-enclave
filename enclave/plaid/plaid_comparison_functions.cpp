#include "enclave/plaid/plaid_comparison_functions.hpp"

namespace
{

using namespace silentdata::enclave;

// Match transactions by same name and day of the month
int find_matching_transaction(const PlaidTransaction &transaction,
                              const std::vector<PlaidTransaction> &other_transactions,
                              int tolerance)
{
    int matched_index = -1;
    for (size_t i = 0; i < other_transactions.size(); i++)
    {
        PlaidTransaction other_transaction = other_transactions[i];
        // Must be from the same source
        if (other_transaction.name != transaction.name)
            continue;
        // Must be on the same day if the day <= 28
        int day = transaction.date.tm_mday;
        int next_day = other_transaction.date.tm_mday;
        if (next_day <= 28 && day <= 28 && std::abs(next_day - day) > tolerance)
            continue;
        // Must be in the range 28 - 31 if day >= 28
        if (next_day >= 28 && day < (28 - tolerance))
            continue;
        if (day >= 28 && next_day < (28 - tolerance))
            continue;
        matched_index = static_cast<int>(i);
    }
    return matched_index;
}

// Check monthly income against a total over a range of months, index of income should be the number
// of months from the first checked month
bool check_income(const std::map<int, double> &income, int32_t consistent_income, int num_months)
{
    // Do the attestation
    int months_checked = 0;
    for (const auto &kv : income)
    {
        DEBUG_LOG("Comparing month %i", kv.first);
        if (kv.first == num_months)
        {
            DEBUG_LOG("Skip current month");
            continue;
        }
        if (kv.second < static_cast<double>(consistent_income))
        {
            DEBUG_LOG("Monthly income < %f", static_cast<double>(consistent_income));
            return false;
        }
        DEBUG_LOG("Monthly income >= %f", static_cast<double>(consistent_income));
        months_checked++;
    }
    DEBUG_LOG("Number of months checked = %i", months_checked);
    if (months_checked != num_months)
        return false;

    return true;
}
} // namespace

namespace silentdata
{
namespace enclave
{

bool plaid_check_income(const std::vector<PlaidTransaction> &transactions,
                        const struct tm &start_date,
                        const struct tm &end_date,
                        int32_t consistent_income)
{
    int num_months = tm_month_difference(start_date, end_date);
    DEBUG_LOG("Start date = %i-%i-%i", start_date.tm_year, start_date.tm_mon, start_date.tm_mday);
    DEBUG_LOG("End date = %i-%i-%i", end_date.tm_year, end_date.tm_mon, end_date.tm_mday);
    DEBUG_LOG("Month range = %i", num_months);

    std::map<int, double> income;
    // Initialise in case there are no transactions in a month
    for (int i = 0; i < num_months; i++)
        income[i] = 0;

    for (const auto &transaction : transactions)
    {
        // Ignore outgoing (negative) transactions for now
        if (transaction.amount < 0)
            continue;
        int index = tm_month_difference(start_date, transaction.date);
        // Ignore anything outside of the date range we're considering
        if (income.find(index) == income.end())
            continue;
        income[index] += transaction.amount;
    }

    return check_income(income, consistent_income, num_months);
}

bool plaid_check_stable_income(const std::vector<PlaidTransaction> &transactions,
                               const struct tm &start_date,
                               const struct tm &end_date,
                               int32_t consistent_income)
{
    int num_months = tm_month_difference(start_date, end_date);
    DEBUG_LOG("Start date = %i-%i-%i", start_date.tm_year, start_date.tm_mon, start_date.tm_mday);
    DEBUG_LOG("End date = %i-%i-%i", end_date.tm_year, end_date.tm_mon, end_date.tm_mday);
    DEBUG_LOG("Month range = %i", num_months);

    // Create map of incoming transactions by month
    std::map<int, std::vector<PlaidTransaction>> month_transactions_map;
    for (const auto &transaction : transactions)
    {
        // Ignore outgoing (negative) transactions for now
        if (transaction.amount < 0)
            continue;
        int index = tm_month_difference(start_date, transaction.date);
        month_transactions_map[index].push_back(transaction);
    }

    std::map<int, double> income;
    // Initialise in case there are no transactions in a month
    for (int i = 0; i < num_months; i++)
        income[i] = 0;

    if (month_transactions_map.find(0) == month_transactions_map.end())
        return false;

    // For each transaction in the first month, check there is a corresponding transaction in all
    // subsequent months before adding to the total income
    std::vector<PlaidTransaction> first_month_transactions = month_transactions_map[0];
    for (const auto &transaction : first_month_transactions)
    {
        std::vector<PlaidTransaction> stable_transactions = {transaction};
        bool is_stable = true;
        // Check there is a transaction from the same entity at around the same time each month
        for (const auto &kv : month_transactions_map)
        {
            if (kv.first == 0)
                continue;
            std::vector<PlaidTransaction> other_transactions = kv.second;
            int matched_index = find_matching_transaction(transaction, other_transactions, 3);
            if (matched_index < 0 || matched_index >= static_cast<int>(other_transactions.size()))
            {
                DEBUG_LOG("No match found for transaction");
                is_stable = false;
                break;
            }
            stable_transactions.push_back(other_transactions[matched_index]);
        }
        // Add any stable transactions to the total
        if (is_stable)
        {
            for (const auto &stable_transaction : stable_transactions)
            {
                int index = tm_month_difference(start_date, stable_transaction.date);
                income[index] += stable_transaction.amount;
            }
        }
    }

    return check_income(income, consistent_income, num_months);
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
