#include "enclave/common/date_time.hpp"

namespace
{

bool check_tm_limits(const struct tm &date)
{
    if (date.tm_mon < 0 || date.tm_mon > 11)
        return false;
    if (date.tm_mday < 1 || date.tm_mday > 31)
        return false;
    if (date.tm_hour < 0 || date.tm_hour > 23)
        return false;
    if (date.tm_min < 0 || date.tm_min > 59)
        return false;
    if (date.tm_sec < 0 || date.tm_sec > 59)
        return false;
    return true;
}

std::vector<int> days_in_month = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

} // namespace

namespace silentdata
{
namespace enclave
{

struct tm http_date_to_tm(const std::string &date_string)
{
    struct tm output_date = {};

    // Tokenise the date string
    std::vector<std::string> date_tokens;
    // HTTP Date header has the format "Wed, 21 Oct 2015 07:28:00 GMT"
    size_t pos = date_string.find(" ");
    size_t init_pos = 0;
    while (pos != std::string::npos)
    {
        date_tokens.push_back(date_string.substr(init_pos, pos - init_pos));
        init_pos = pos + 1;
        pos = date_string.find(" ", init_pos);
    }
    if (date_tokens.size() != 5)
        THROW_EXCEPTION(kHTTPResponseParseError, "Incorrect number of tokens in HTTP Date header");

    // tm_year defined as years since 1900
    size_t int_size;
    try
    {
        output_date.tm_year = std::stoi(date_tokens[3], &int_size) - 1900;
    }
    catch (...)
    {
        THROW_EXCEPTION(kHTTPResponseParseError, "Could not convert year string to an integer");
    }
    if (int_size != date_tokens[3].size())
        THROW_EXCEPTION(kHTTPResponseParseError,
                        "Could not convert entire year string to an integer");

    // tm_mon defined as months since January
    std::map<std::string, int> month_number = {{"Jan", 0},
                                               {"Feb", 1},
                                               {"Mar", 2},
                                               {"Apr", 3},
                                               {"May", 4},
                                               {"Jun", 5},
                                               {"Jul", 6},
                                               {"Aug", 7},
                                               {"Sep", 8},
                                               {"Oct", 9},
                                               {"Nov", 10},
                                               {"Dec", 11}};
    if (month_number.find(date_tokens[2]) == month_number.end())
    {
        THROW_EXCEPTION(kHTTPResponseParseError, "Unexpected month string");
    }
    output_date.tm_mon = month_number[date_tokens[2]];

    // tm_mday defined as days of the month
    try
    {
        output_date.tm_mday = std::stoi(date_tokens[1], &int_size);
    }
    catch (...)
    {
        THROW_EXCEPTION(kHTTPResponseParseError, "Could not convert day string to an integer");
    }
    if (int_size != date_tokens[1].size())
        THROW_EXCEPTION(kHTTPResponseParseError,
                        "Could not convert entire date string to an integer");

    if (!check_tm_limits(output_date))
        THROW_EXCEPTION(kHTTPResponseParseError,
                        "Invalid struct tm date outside of limits mon(0-11), mday(1-31)");
    return output_date;
}

struct tm subtract_tm_months(const struct tm &date, int months)
{
    if (!check_tm_limits(date))
        THROW_EXCEPTION(kDateTimeError,
                        "Invalid struct tm date outside of limits mon(0-11), mday(1-31)");

    struct tm output_date = {};
    // If the number of months is greater than a year, subtract years
    int year = date.tm_year;
    while (months > 12)
    {
        months -= 12;
        year -= 1;
    }
    // If the remaining number of months is greater than the current month subtract
    // a year
    if (date.tm_mon < months)
        year -= 1;
    output_date.tm_year = year;
    // Subtract number of months using modular arithmatic (months are 0-11)
    // Extra +12)%12 to handle negative numbers
    output_date.tm_mon = ((date.tm_mon - months) % 12 + 12) % 12;
    // If the current day is greater than the number of days in the new month, correct for this
    output_date.tm_mday = std::min(date.tm_mday, days_in_month[output_date.tm_mon]);
    return output_date;
}

std::string tm_to_string(const struct tm &date)
{
    if (!check_tm_limits(date))
        THROW_EXCEPTION(kDateTimeError,
                        "Invalid struct tm date outside of limits mon(0-11), mday(1-31)");

    std::string day_str = std::to_string(date.tm_mday);
    if (date.tm_mday < 10)
        day_str = "0" + day_str;
    std::string month_str = std::to_string(date.tm_mon + 1);
    if ((date.tm_mon + 1) < 10)
        month_str = "0" + month_str;
    std::string output = std::to_string(date.tm_year + 1900) + "-" + month_str + "-" + day_str;
    return output;
}

int tm_to_timestamp(const struct tm &date)
{
    // Some input checking
    if (date.tm_year < 70)
        THROW_EXCEPTION(kDateTimeError, "Cannot convert dates before 1970 to timestamps");
    if (date.tm_year >= 138 && (date.tm_mon >= 1 || date.tm_mday > 19))
        THROW_EXCEPTION(kDateTimeError, "Cannot convert dates after 2038 to int32 timestamps");
    if (!check_tm_limits(date))
        THROW_EXCEPTION(kDateTimeError,
                        "Invalid struct tm date outside of limits mon(0-11), mday(1-31)");

    int tm_year = date.tm_year + 1900;
    int days = 0;
    for (int year = 1970; year < tm_year; year++)
    {
        if (((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0))
            days += 366;
        else
            days += 365;
    }
    // Calculate the number of days from Jan 01 to the current day,
    // correcting for leap years
    days += std::accumulate(days_in_month.begin(), days_in_month.begin() + date.tm_mon, 0);
    if (date.tm_mon > 1 && (((tm_year % 4 == 0) && (tm_year % 100 != 0)) || (tm_year % 400 == 0)))
        days += 1;
    days += date.tm_mday - 1;
    // Calculate the number of seconds since Jan 01 1970
    int timestamp = days * 60 * 60 * 24;
    timestamp += date.tm_hour * 60 * 60;
    timestamp += date.tm_min * 60;
    timestamp += date.tm_sec;
    return timestamp;
}

int tm_day_difference(const struct tm &date1, const struct tm &date2)
{
    int timestamp1 = tm_to_timestamp(date1);
    int timestamp2 = tm_to_timestamp(date2);
    int difference_sec = std::abs(timestamp1 - timestamp2);
    int difference_day = difference_sec / (60 * 60 * 24);
    return difference_day;
}

struct tm plaid_date_to_tm(const std::string &date_str)
{
    struct tm date = {};
    try
    {
        // tm_year is year since 1900
        date.tm_year = std::stoi(date_str.substr(0, 4)) - 1900;
        // tm_mon is month since January
        date.tm_mon = std::stoi(date_str.substr(5, 2)) - 1;
        date.tm_mday = std::stoi(date_str.substr(8, 2));
    }
    catch (...)
    {
        THROW_EXCEPTION(kJSONParseError, "Could not convert date to integer");
    }
    return date;
}

int tm_month_difference(const struct tm &date1, const struct tm &date2)
{
    return (date2.tm_year - date1.tm_year) * 12 + date2.tm_mon - date1.tm_mon;
}

struct tm get_earliest_date(const std::vector<BankTransaction> &transactions)
{
    if (transactions.size() < 1)
        THROW_EXCEPTION(kJSONParseError, "No transactions available");
    struct tm first_date = transactions[0].date;
    for (const auto &transaction : transactions)
    {
        struct tm date = transaction.date;
        if (date.tm_year < first_date.tm_year)
        {
            first_date = date;
        }
        else if (date.tm_year == first_date.tm_year)
        {
            if (date.tm_mon < first_date.tm_mon)
            {
                first_date = date;
            }
            else if (date.tm_mon == first_date.tm_mon && date.tm_mday < first_date.tm_mday)
            {
                first_date = date;
            }
        }
    }
    return first_date;
}

} // namespace enclave
} // namespace silentdata
