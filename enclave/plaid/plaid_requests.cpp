#include "enclave/plaid/plaid_requests.hpp"

using json::JSON;

namespace
{

using namespace silentdata::enclave;

std::vector<PlaidTransaction> plaid_get_transactions(HTTPSClient &client,
                                                     const std::vector<char *> &headers,
                                                     const char *body,
                                                     ClientOptions opt,
                                                     core_status_code &error_code,
                                                     int &total)
{
    error_code = kSuccess;

    DEBUG_LOG("Sending /transactions/get POST request to Plaid");
    std::vector<PlaidTransaction> transactions;
    HTTPSResponse response = client.post("/transactions/get", headers, body, opt);
    // An invalid response could be due to the output length not being long enough
    if (!response.is_valid())
    {
        opt.output_length = 2 * opt.output_length;
        response = client.post("/transactions/get", headers, body, opt);
    }
    if (!response.is_valid())
        THROW_ERROR_CODE(kHTTPResponseParseError);
    if (response.get_status_code() != 200)
    {
        error_code = parse_plaid_error(response);
        WARNING_LOG("Error code %i returned by Plaid", error_code);
        if (error_code != kPlaidProductNotReady)
        {
            THROW_ERROR_CODE(error_code);
        }
        return transactions;
    }
    JSON data = JSON::Load(response.get_body());

    // It's possible for there to be no transactions in the first 30 days (as we ignore the current
    // month), check if this is the case and return an empty vector if so
    bool is_int = false;
    total = static_cast<int>(data["total_transactions"].ToInt(is_int));
    if (!is_int)
    {
        THROW_EXCEPTION(kJSONParseError, "Could not convert total transactions to integer");
    }
    if (total == 0)
    {
        WARNING_LOG("No transactions in first 30 days");
        return transactions;
    }

    int n_transactions = data["transactions"].length();
    // Get the transactions of all associated accounts
    for (int i = 0; i < n_transactions; i++)
    {
        std::string date_str = data["transactions"][i]["date"].ToString();
        struct tm date = plaid_date_to_tm(date_str);

        bool is_float = false;
        double amount = data["transactions"][i]["amount"].ToFloat(is_float);
        if (!is_float)
            amount = static_cast<double>(data["transactions"][i]["amount"].ToInt());
        std::string name = data["transactions"][i]["name"].ToString();
        // Negative transactions mean money coming in to the account
        PlaidTransaction transaction(-amount, date, name);
        transactions.push_back(transaction);
    }
    return transactions;
}

struct tm get_earliest_date(const std::vector<PlaidTransaction> &transactions)
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

} // namespace

namespace silentdata
{
namespace enclave
{

PlaidLink plaid_create_link_token(HTTPSClient &client,
                                  const PlaidConfiguration &config,
                                  const char *client_user_id,
                                  const char *redirect_uri)
{
    ClientOptions opt = client.get_client_options();

    // Set the HTTPS headers and request body for obtaining a link token from Plaid
    std::string host = config.environment + std::string(".plaid.com");
    std::string host_header = "Host: " + host;
    std::string content_header = "Content-Type: application/json";
    std::vector<char *> headers = {(char *)host_header.c_str(), (char *)content_header.c_str()};

    JSON request = json::Object();
    request["client_id"] = config.client_id;
    request["secret"] = config.secret;
    request["client_name"] = "SILENTDATA";
    request["country_codes"] = json::Array("GB");
    request["language"] = "en";
    JSON user = json::Object();
    user["client_user_id"] = client_user_id;
    request["user"] = user;
    request["products"] = json::Array("identity");
    request["redirect_uri"] = redirect_uri;
    std::string request_body = request.dump();

    // Make the HTTPS request
    DEBUG_LOG("Sending /link/token/create POST request to Plaid");
    HTTPSResponse response = client.post("/link/token/create", headers, request_body.c_str(), opt);
    if (!response.is_valid())
        THROW_ERROR_CODE(kHTTPResponseParseError);
    if (response.get_status_code() != 200)
    {
        core_status_code error_code = parse_plaid_error(response);
        THROW_ERROR_CODE(error_code);
    }

    JSON data = JSON::Load(response.get_body());

    PlaidLink link;
    bool is_string = false;
    link.token = data["link_token"].ToString(is_string);
    if (!is_string)
        THROW_EXCEPTION(kJSONParseError, "Could not parse link token from JSON body");
    link.expiration = data["expiration"].ToString(is_string);
    if (!is_string)
        THROW_EXCEPTION(kJSONParseError, "Could not parse expiration from JSON body");
    link.request_id = data["request_id"].ToString(is_string);
    if (!is_string)
        THROW_EXCEPTION(kJSONParseError, "Could not parse request id from JSON body");
    return link;
}

PlaidAccess
plaid_get_access(HTTPSClient &client, const PlaidConfiguration &config, const char *public_token)
{
    ClientOptions opt = client.get_client_options();

    std::string host = config.environment + std::string(".plaid.com");
    std::string host_header = "Host: " + host;
    std::string content_header = "Content-Type: application/json";
    std::vector<char *> headers = {(char *)host_header.c_str(), (char *)content_header.c_str()};

    JSON request_body = json::Object();
    request_body["client_id"] = config.client_id;
    request_body["secret"] = config.secret;
    request_body["public_token"] = public_token;
    std::string request_body_str = request_body.dump();

    DEBUG_LOG("Sending /item/public_token/exchange POST request to Plaid");
    HTTPSResponse response =
        client.post("/item/public_token/exchange", headers, request_body_str.c_str(), opt);
    if (!response.is_valid())
        THROW_ERROR_CODE(kHTTPResponseParseError);
    if (response.get_status_code() != 200)
    {
        core_status_code error_code = parse_plaid_error(response);
        THROW_ERROR_CODE(error_code);
    }

    JSON data = JSON::Load(response.get_body());

    PlaidAccess access;
    bool is_string = false;
    access.token = data["access_token"].ToString(is_string);
    if (!is_string)
        THROW_EXCEPTION(kJSONParseError, "Could not parse access token from JSON body");

    // Parse the response to get the timestamp
    access.timestamp = response.get_timestamp();

    // Check that a certificate chain was obtained
    access.certificate_chain = response.get_certificate_chain();
    if (access.certificate_chain.length() == 0)
        THROW_EXCEPTION(kCertificateWriteError,
                        "Could not obtain the certificate chain from the HTTPS client");

    return access;
}

access_token_status plaid_destroy_access(HTTPSClient &client, const PlaidConfiguration &config)
{
    ClientOptions opt = client.get_client_options();
    opt.output_length = 4000;
    opt.close_session = true;

    std::string host = config.environment + std::string(".plaid.com");
    std::string host_header = "Host: " + host;
    std::string content_header = "Content-Type: application/json";
    std::vector<char *> headers = {(char *)host_header.c_str(), (char *)content_header.c_str()};

    JSON request_body = json::Object();
    request_body["client_id"] = config.client_id;
    request_body["secret"] = config.secret;
    request_body["access_token"] = config.access_token;
    std::string request_body_str = request_body.dump();

    DEBUG_LOG("Sending /item/remove POST request to Plaid");
    HTTPSResponse response = client.post("/item/remove", headers, request_body_str.c_str(), opt);
    if (!response.is_valid() || response.get_status_code() != 200)
        return kAccessTokenNotDestroyed;

    JSON data = JSON::Load(response.get_body());
    bool is_bool = false;
    bool is_removed = data["removed"].ToBool(is_bool);
    if (is_bool && is_removed)
        return kAccessTokenDestroyed;

    return kAccessTokenNotDestroyed;
}

double plaid_get_total_balance(HTTPSClient &client, const PlaidConfiguration &config)
{
    ClientOptions opt = client.get_client_options();
    opt.output_length = 6000;

    std::string host = config.environment + std::string(".plaid.com");
    std::string host_header = "Host: " + host;
    std::string content_header = "Content-Type: application/json";
    std::vector<char *> headers = {(char *)host_header.c_str(), (char *)content_header.c_str()};

    JSON request_body = json::Object();
    request_body["client_id"] = config.client_id;
    request_body["secret"] = config.secret;
    request_body["access_token"] = config.access_token;
    std::string request_body_str = request_body.dump();

    DEBUG_LOG("Sending /accounts/balance/get POST request to Plaid");
    HTTPSResponse response =
        client.post("/accounts/balance/get", headers, request_body_str.c_str(), opt);
    // An invalid response could be due to the output length not being long enough
    if (!response.is_valid())
    {
        opt.output_length = 2 * opt.output_length;
        response = client.post("/accounts/balance/get", headers, request_body_str.c_str(), opt);
    }
    if (!response.is_valid())
        THROW_ERROR_CODE(kHTTPResponseParseError);
    if (response.get_status_code() != 200)
    {
        core_status_code error_code = parse_plaid_error(response);
        THROW_ERROR_CODE(error_code);
    }

    // Sum up all of the available balances
    JSON data = JSON::Load(response.get_body());
    int n_accounts = data["accounts"].length();
    if (n_accounts <= 0)
        THROW_EXCEPTION(kJSONParseError, "Could not find any bank accounts");
    double balance = 0;
    for (int i = 0; i < n_accounts; i++)
    {
        bool is_float = false;
        double available_balance = data["accounts"][i]["balances"]["available"].ToFloat(is_float);
        if (!is_float)
            available_balance =
                static_cast<double>(data["accounts"][i]["balances"]["available"].ToInt());
        balance += available_balance;
    }

    return balance;
}

std::vector<PlaidTransaction> plaid_get_all_transactions(HTTPSClient &client,
                                                         const PlaidConfiguration &config,
                                                         struct tm start_date,
                                                         struct tm end_date)
{
    // Shift dates to first days of the month and convert the dates to strings
    start_date.tm_mday = 1;
    std::string start_date_str = tm_to_string(start_date);
    int end_date_day = end_date.tm_mday;
    end_date.tm_mday = 1;
    std::string end_date_str = tm_to_string(end_date);
    end_date.tm_mday = end_date_day;

    ClientOptions opt = client.get_client_options();
    opt.output_length = 200000;
    // Close the client after each connection because we might be waiting a while and that can
    // cause the peer to close the connection
    opt.close_session = true;

    std::string host = config.environment + std::string(".plaid.com");
    std::string host_header = "Host: " + host;
    std::string content_header = "Content-Type: application/json";
    std::vector<char *> headers = {(char *)host_header.c_str(), (char *)content_header.c_str()};

    JSON request_body = json::Object();
    request_body["client_id"] = config.client_id;
    JSON options = json::Object();
    int count = 50; // Number of transactions to get in one go
    int offset = 0;
    options["count"] = count;
    options["offset"] = offset;
    request_body["options"] = options;
    request_body["secret"] = config.secret;
    request_body["access_token"] = config.access_token;
    request_body["start_date"] = start_date_str;
    request_body["end_date"] = end_date_str;
    std::string request_body_str = request_body.dump();

    core_status_code error_code = kSuccess;
    int total_transactions = 0;
    DEBUG_LOG("Getting the first page of transactions");
    std::vector<PlaidTransaction> transactions = plaid_get_transactions(
        client, headers, request_body_str.c_str(), opt, error_code, total_transactions);
    // If the product isn't ready keep trying until it is
    while (error_code == kPlaidProductNotReady)
    {
        DEBUG_LOG("Product not ready, waiting 5 seconds and trying again");
        // Sleep for 5 seconds
        mbedtls_net_usleep(5000000);
        transactions = plaid_get_transactions(
            client, headers, request_body_str.c_str(), opt, error_code, total_transactions);
    }

    // Now we're able to get transactions, but if all transactions aren't ready we'll only get the
    // first 30 days and plaid won't tell us about the rest
    // Two possible situations:
    // 1. We have all historical transactions and can continue
    // 2. We only have the first 30 days and need to wait until the historical transactions are
    // ready
    int days_fetched;
    try
    {
        struct tm first_date = get_earliest_date(transactions);
        days_fetched = tm_day_difference(first_date, end_date);
    }
    catch (...)
    {
        WARNING_LOG(
            "Failed to calculate the difference in days between the first and last transaction");
        // An error here means that no transactions have been fetched
        days_fetched = 0;
    }
    DEBUG_LOG("Number of days fetched = %i", days_fetched);

    // Get the earliest available transaction (only if there are any transactions and we don't
    // already have three months worth)
    if (total_transactions > 0 && days_fetched <= 30)
    {
        DEBUG_LOG("Getting the first available transaction");
        request_body["options"]["count"] = 1;
        request_body["options"]["offset"] = total_transactions - 1;
        request_body_str = request_body.dump();
        int temp_total;
        std::vector<PlaidTransaction> first_transaction = plaid_get_transactions(
            client, headers, request_body_str.c_str(), opt, error_code, temp_total);
        if (first_transaction.size() != 1)
            THROW_EXCEPTION(kJSONParseError, "Couldn't retrieve the first available transaction");
        days_fetched = tm_day_difference(first_transaction[0].date, end_date);
    }

    // If it looks like we've only got the first 30 days, wait 30 seconds and then request again
    // Check if the number of transactions has increased to signal that the historical data
    // has been fetched, try this up to a maximum of 10 times
    int prev_total_transactions = total_transactions;
    int times_waited = 0;
    // Reset the request body count and offset
    request_body["options"]["count"] = count;
    request_body["options"]["offset"] = offset;
    request_body_str = request_body.dump();
    while (total_transactions == prev_total_transactions && times_waited < 10 && days_fetched <= 30)
    {
        DEBUG_LOG("Historical transactions not available, waiting 30 seconds and trying again");
        mbedtls_net_usleep(30000000);
        transactions = plaid_get_transactions(
            client, headers, request_body_str.c_str(), opt, error_code, total_transactions);
        times_waited++;
    }

    // If there are more transactions than "count", page through the transaction data until all
    // the transactions have been saved
    opt.close_session = false;
    while (transactions.size() < static_cast<size_t>(total_transactions))
    {
        DEBUG_LOG("Not all transactions obtained, getting next page");
        DEBUG_LOG("Transactions fetched = %i, total = %i", transactions.size(), total_transactions);
        int current_offset = static_cast<int>(request_body["options"]["offset"].ToInt());
        request_body["options"]["offset"] = current_offset + count;
        request_body_str = request_body.dump();
        std::vector<PlaidTransaction> next_transactions = plaid_get_transactions(
            client, headers, request_body_str.c_str(), opt, error_code, total_transactions);
        transactions.insert(transactions.end(), next_transactions.begin(), next_transactions.end());
    }

    return transactions;
}

std::string plaid_get_account_holder_name(HTTPSClient &client,
                                          const PlaidConfiguration &config,
                                          const std::string &account_id)
{
    ClientOptions opt = client.get_client_options();
    opt.output_length = 22000;

    std::string host = config.environment + std::string(".plaid.com");
    std::string host_header = "Host: " + host;
    std::string content_header = "Content-Type: application/json";
    std::vector<char *> headers = {(char *)host_header.c_str(), (char *)content_header.c_str()};

    JSON request_body = json::Object();
    request_body["client_id"] = config.client_id;
    request_body["secret"] = config.secret;
    request_body["access_token"] = config.access_token;
    // If we're matching a specific account
    if (account_id != "")
    {
        JSON options = json::Object();
        options["account_ids"] = json::Array(account_id);
        request_body["options"] = options;
    }
    std::string request_body_str = request_body.dump();

    DEBUG_LOG("Sending /identity/get POST request to Plaid");
    HTTPSResponse response = client.post("/identity/get", headers, request_body_str.c_str(), opt);
    // An invalid response could be due to the output length not being long enough
    if (!response.is_valid())
    {
        opt.output_length = 2 * opt.output_length;
        response = client.post("/identity/get", headers, request_body_str.c_str(), opt);
    }
    if (!response.is_valid())
        THROW_ERROR_CODE(kHTTPResponseParseError);
    if (response.get_status_code() != 200)
    {
        core_status_code error_code = parse_plaid_error(response);
        THROW_ERROR_CODE(error_code);
    }

    JSON data = JSON::Load(response.get_body());
    std::vector<std::string> names;
    int n_accounts = data["accounts"].length();
    for (int i = 0; i < n_accounts; i++)
    {
        int n_owners = data["accounts"][i]["owners"].length();
        for (int j = 0; j < n_owners; j++)
        {
            int n_names = data["accounts"][i]["owners"][j]["names"].length();
            for (int k = 0; k < n_names; k++)
            {
                bool is_string = false;
                std::string name = data["accounts"][i]["owners"][j]["names"][k].ToString(is_string);
                if (is_string)
                    names.push_back(name);
            }
        }
    }
    if (names.size() == 0)
        THROW_EXCEPTION(kJSONParseError,
                        "Could not obtain the account holder name from the JSON body");

    // Use the name that appears the most
    std::map<std::string, int> name_occurrence;
    for (const auto &name : names)
        name_occurrence[name]++;
    std::string account_holder_name_str = names[0];
    for (const auto &kv : name_occurrence)
        if (kv.second > name_occurrence[account_holder_name_str])
            account_holder_name_str = kv.first;

    return account_holder_name_str;
}

std::string plaid_get_institution_name(HTTPSClient &client, const PlaidConfiguration &config)
{
    ClientOptions opt = client.get_client_options();
    opt.output_length = 6000;

    std::string host = config.environment + std::string(".plaid.com");
    std::string host_header = "Host: " + host;
    std::string content_header = "Content-Type: application/json";
    std::vector<char *> headers = {(char *)host_header.c_str(), (char *)content_header.c_str()};

    JSON request_body = json::Object();
    request_body["client_id"] = config.client_id;
    request_body["secret"] = config.secret;
    request_body["access_token"] = config.access_token;
    std::string request_body_str = request_body.dump();

    DEBUG_LOG("Sending /item/get POST request to Plaid");
    HTTPSResponse response = client.post("/item/get", headers, request_body_str.c_str(), opt);
    if (!response.is_valid())
        THROW_EXCEPTION(kHTTPResponseParseError, "Could not parse HTTP response");
    if (response.get_status_code() != 200)
    {
        core_status_code error_code = parse_plaid_error(response);
        THROW_ERROR_CODE(error_code);
    }

    // Parse the response to get the balances of all associated accounts
    JSON data = JSON::Load(response.get_body());
    bool is_string = false;
    std::string institution_id = data["item"]["institution_id"].ToString(is_string);
    if (!is_string)
        THROW_EXCEPTION(kJSONParseError, "Could not parse institution id from JSON body");

    JSON name_request_body = json::Object();
    name_request_body["client_id"] = config.client_id;
    name_request_body["secret"] = config.secret;
    name_request_body["institution_id"] = institution_id;
    name_request_body["country_codes"] = "[]";
    std::string name_request_body_str = name_request_body.dump();

    DEBUG_LOG("Sending /institutions/get_by_id POST request to Plaid");
    HTTPSResponse name_response =
        client.post("/institutions/get_by_id", headers, name_request_body_str.c_str(), opt);
    if (!name_response.is_valid())
        THROW_EXCEPTION(kHTTPResponseParseError, "Could not parse HTTP response");
    if (name_response.get_status_code() != 200)
    {
        core_status_code error_code = parse_plaid_error(response);
        THROW_ERROR_CODE(error_code);
    }

    // Parse the response to get the balances of all associated accounts
    JSON name_data = JSON::Load(name_response.get_body());
    std::string institution_name = name_data["institution"]["name"].ToString(is_string);
    if (!is_string)
        THROW_EXCEPTION(kJSONParseError, "Could not parse institution name from JSON body");

    return institution_name;
}

std::vector<PlaidAccount> plaid_get_account_details(HTTPSClient &client,
                                                    const PlaidConfiguration &config)
{
    ClientOptions opt = client.get_client_options();
    opt.output_length = 6000;
    int max_tokens = 500;

    std::string host = config.environment + std::string(".plaid.com");
    std::string host_header = "Host: " + host;
    std::string content_header = "Content-Type: application/json";
    std::vector<char *> headers = {(char *)host_header.c_str(), (char *)content_header.c_str()};

    JSON request_body = json::Object();
    request_body["client_id"] = config.client_id;
    request_body["secret"] = config.secret;
    request_body["access_token"] = config.access_token;
    std::string request_body_str = request_body.dump();

    DEBUG_LOG("Sending /auth/get POST request to Plaid");
    HTTPSResponse response = client.post("/auth/get", headers, request_body_str.c_str(), opt);
    // An invalid response could be due to the output length not being long enough
    if (!response.is_valid())
    {
        opt.output_length = 2 * opt.output_length;
        max_tokens = 2 * max_tokens;
        response = client.post("/auth/get", headers, request_body_str.c_str(), opt);
    }
    if (!response.is_valid())
        THROW_ERROR_CODE(kHTTPResponseParseError);
    if (response.get_status_code() != 200)
    {
        core_status_code error_code = parse_plaid_error(response);
        THROW_ERROR_CODE(error_code);
    }

    // Parse the response to get the account details of all associated accounts
    JSON data = JSON::Load(response.get_body());
    int n_bacs = data["numbers"]["bacs"].length();
    int n_international = data["numbers"]["international"].length();

    // Create objects containing account details
    std::vector<std::string> account_numbers;
    std::vector<std::string> sort_codes;
    std::vector<std::string> bacs_ids;
    for (int i = 0; i < n_bacs; i++)
    {
        account_numbers.push_back(data["numbers"]["bacs"][i]["account"].ToString());
        sort_codes.push_back(data["numbers"]["bacs"][i]["sort_code"].ToString());
        bacs_ids.push_back(data["numbers"]["bacs"][i]["account_id"].ToString());
    }
    if (n_bacs == 0)
    {
        WARNING_LOG("No BACS bank number information present");
    }
    std::vector<std::string> ibans;
    std::vector<std::string> international_ids;
    for (int i = 0; i < n_international; i++)
    {
        ibans.push_back(data["numbers"]["international"][i]["iban"].ToString());
        international_ids.push_back(data["numbers"]["international"][i]["account_id"].ToString());
    }
    if (n_international == 0)
    {
        WARNING_LOG("No international bank number information present");
    }
    std::vector<PlaidAccount> account_details;
    for (size_t i = 0; i < account_numbers.size(); i++)
    {
        uint32_t account_number = 0;
        if (account_numbers[i] != "null")
            account_number = static_cast<uint32_t>(std::stoul(account_numbers[i], nullptr, 10));
        else
            WARNING_LOG("Account number is null");
        uint32_t sort_code = 0;
        if (sort_codes[i] != "null")
            sort_code = static_cast<uint32_t>(std::stoul(sort_codes[i], nullptr, 10));
        else
            WARNING_LOG("Sort code is null");
        std::string iban = "";
        // Extra check as bacs and international numbers come in separate lists, and the order of
        // the list items is not guaranteed
        std::string bacs_id = bacs_ids[i];
        for (size_t j = 0; j < ibans.size(); j++)
        {
            if (bacs_id == international_ids[j])
            {
                if (ibans[j] != "null")
                    iban = ibans[j];
                else
                    WARNING_LOG("IBAN is null");
            }
        }
        account_details.push_back(PlaidAccount(account_number, sort_code, iban, bacs_id));
    }
    // If only international numbers are present
    if (account_numbers.size() == 0 && ibans.size() != 0)
    {
        for (size_t i = 0; i < ibans.size(); i++)
        {
            uint32_t account_number = 0;
            uint32_t sort_code = 0;
            std::string iban = "";
            if (ibans[i] != "null")
                iban = ibans[i];
            else
                WARNING_LOG("IBAN is null");
            std::string international_id = international_ids[i];
            account_details.push_back(
                PlaidAccount(account_number, sort_code, iban, international_id));
        }
    }

    return account_details;
}

} // namespace enclave
} // namespace silentdata
