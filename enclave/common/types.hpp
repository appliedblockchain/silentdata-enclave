/*
 * Common data types
 */

#ifndef SILENTDATA_ENCLAVE_TYPES_H
#define SILENTDATA_ENCLAVE_TYPES_H

#include <string>
#include <vector>

namespace silentdata
{
namespace enclave
{

struct BankBalance
{
    BankBalance(const std::string &cc, double a, double c)
        : currency_code(cc), available(a), current(c)
    {
    }
    BankBalance() {}
    std::string currency_code;
    double available;
    double current;
};

struct BankTransaction
{
    BankTransaction(const std::string &cc, double a, struct tm d, const std::string &n)
        : currency_code(cc), amount(a), date(d), name(n)
    {
    }
    std::string currency_code;
    double amount;
    struct tm date;
    std::string name;
};

struct AccountDetails
{
    AccountDetails(uint32_t a, uint32_t s, const std::string &i, const std::string &id)
        : account_number(a), sort_code(s), iban(i), account_id(id)
    {
    }
    uint32_t account_number;
    uint32_t sort_code;
    std::string iban;
    std::string account_id;
};

} // namespace enclave
} // namespace silentdata

#endif
