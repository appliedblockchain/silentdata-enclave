/*
 * Helper functions for date and time manipulations
 */

#ifndef SILENTDATA_ENCLAVE_DATE_TIME_H
#define SILENTDATA_ENCLAVE_DATE_TIME_H

#include <map>
#include <numeric>
#include <stdexcept>
#include <string>
#include <time.h>
#include <vector>

#include "enclave/common/enclave_exception.hpp"
#include "enclave/common/types.hpp"

namespace silentdata
{
namespace enclave
{

// Convert HTTP Date header to a struct tm
struct tm http_date_to_tm(const std::string &date_string);

// Subtract a given number of months from a struct tm date containing year, month and day
struct tm subtract_tm_months(const struct tm &date, int months);

// Convert a struct tm to a string of format "YYYY-MM-DD"
std::string tm_to_string(const struct tm &date);

// Calculate the time in seconds from Jan 01 1970 (UTC)
int tm_to_timestamp(const struct tm &date);

// Calculate the difference between two struct tm's in days
int tm_day_difference(const struct tm &date1, const struct tm &date2);

// Convert date string from Plaid data to struct tm
struct tm plaid_date_to_tm(const std::string &date_str);

// Calculate the difference between two struct tm's in floor(months)
int tm_month_difference(const struct tm &date1, const struct tm &date2);

// Find the first date in a list of transactions
struct tm get_earliest_date(const std::vector<BankTransaction> &transactions);

} // namespace enclave
} // namespace silentdata

#endif
