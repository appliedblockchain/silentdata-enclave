#include "enclave/plaid/plaid_requests.hpp"

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
    int max_tokens = 12000;

    DEBUG_LOG("Sending /transactions/get POST request to Plaid");
    std::vector<PlaidTransaction> transactions;
    HTTPSResponse response = client.post("/transactions/get", headers, body, opt);
    // An invalid response could be due to the output length not being long enough
    if (!response.is_valid())
    {
        opt.output_length = 2 * opt.output_length;
        max_tokens = 2 * max_tokens;
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
    std::map<std::string, jsmntype_t> keys = {{"total_transactions", JSMN_PRIMITIVE},
                                              {"transactions->amount", JSMN_PRIMITIVE},
                                              {"transactions->date", JSMN_STRING}};
    JSONParser parser(response.get_body(), max_tokens);
    JSONData data = parser.get_data_from_keys(keys);

    // It's possible for there to be no transactions in the first 30 days (as we ignore the current
    // month), check if this is the case and return an empty vector if so
    try
    {
        total = std::stoi(data.get("total_transactions"));
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        THROW_EXCEPTION(e.get_code(), "Could not parse JSON body of transaction response");
    }
    catch (...)
    {
        THROW_EXCEPTION(kJSONParseError, "Could not convert total transactions to integer");
    }
    if (total == 0)
    {
        WARNING_LOG("No transactions in first 30 days");
        return transactions;
    }

    if (!parser.is_valid())
        THROW_EXCEPTION(kJSONParseError, "Could not parse JSON body of transaction response");
    std::vector<std::string> amounts = data.get_all("transactions->amount");
    std::vector<std::string> dates = data.get_all("transactions->date");
    // Get the transactions of all associated accounts
    for (size_t i = 0; i < amounts.size(); i++)
    {
        struct tm date = {};
        try
        {
            // tm_year is year since 1900
            date.tm_year = std::stoi(dates[i].substr(0, 4)) - 1900;
            // tm_mon is month since January
            date.tm_mon = std::stoi(dates[i].substr(5, 2)) - 1;
            date.tm_mday = std::stoi(dates[i].substr(8, 2));
        }
        catch (...)
        {
            THROW_EXCEPTION(kJSONParseError, "Could not convert date to integer");
        }
        // Shouldn't have any null values, throw error
        if (amounts[i].size() <= 0)
            THROW_EXCEPTION(kJSONParseError, "No amount found in transaction");
        // JSMN_PRIMITIVE can only be a number, boolean (true/false) or null
        if (amounts[i].c_str()[0] == 'n' || amounts[i].c_str()[0] == 't' ||
            amounts[i].c_str()[0] == 'f')
            THROW_EXCEPTION(kJSONParseError, "Null value in transaction amount");
        double amount;
        try
        {
            amount = -std::stof(amounts[i]);
        }
        catch (...)
        {
            THROW_EXCEPTION(kJSONParseError, "Could not convert amount to float");
        }
        PlaidTransaction transaction(amount, date);
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

    json::JSON request = json::Object();
    request["client_id"] = config.client_id;
    request["secret"] = config.secret;
    request["client_name"] = "SILENTDATA";
    request["country_codes"] = json::Array("GB");
    request["language"] = "en";
    json::JSON user = json::Object();
    user["client_user_id"] = client_user_id;
    request["user"] = user;
    request["products"] = json::Array("transactions");
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

    // Obtain key value pairs from the response
    int max_tokens = 7;
    std::map<std::string, jsmntype_t> keys = {
        {"link_token", JSMN_STRING}, {"expiration", JSMN_STRING}, {"request_id", JSMN_STRING}};
    JSONParser parser(response.get_body(), max_tokens);
    JSONData data = parser.get_data_from_keys(keys);
    if (!parser.is_valid())
        THROW_EXCEPTION(kJSONParseError, "Could not parse JSON body");

    PlaidLink link;
    link.token = data.get("link_token");
    link.expiration = data.get("expiration");
    link.request_id = data.get("request_id");
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

    json::JSON request_body = json::Object();
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

    int max_tokens = 7;
    std::map<std::string, jsmntype_t> keys = {{"access_token", JSMN_STRING}};
    JSONParser parser(response.get_body(), max_tokens);
    JSONData data = parser.get_data_from_keys(keys);
    if (!parser.is_valid())
        THROW_EXCEPTION(kJSONParseError, "Could not parse JSON body");

    PlaidAccess access;
    access.token = data.get("access_token");

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

    json::JSON request_body = json::Object();
    request_body["client_id"] = config.client_id;
    request_body["secret"] = config.secret;
    request_body["access_token"] = config.access_token;
    std::string request_body_str = request_body.dump();

    DEBUG_LOG("Sending /item/remove POST request to Plaid");
    HTTPSResponse response = client.post("/item/remove", headers, request_body_str.c_str(), opt);
    if (!response.is_valid() || response.get_status_code() != 200)
        return kAccessTokenNotDestroyed;

    int max_tokens = 10;
    std::map<std::string, jsmntype_t> keys = {{"removed", JSMN_PRIMITIVE}};
    JSONParser parser(response.get_body(), max_tokens);
    JSONData data = parser.get_data_from_keys(keys);
    if (!parser.is_valid())
        return kAccessTokenNotDestroyed;
    if (data.get("removed")[0] != 't')
        return kAccessTokenNotDestroyed;

    return kAccessTokenDestroyed;
}

float plaid_get_total_balance(HTTPSClient &client, const PlaidConfiguration &config)
{
    ClientOptions opt = client.get_client_options();
    opt.output_length = 6000;
    int max_tokens = 500;

    std::string host = config.environment + std::string(".plaid.com");
    std::string host_header = "Host: " + host;
    std::string content_header = "Content-Type: application/json";
    std::vector<char *> headers = {(char *)host_header.c_str(), (char *)content_header.c_str()};

    json::JSON request_body = json::Object();
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
        max_tokens = 2 * max_tokens;
        response = client.post("/accounts/balance/get", headers, request_body_str.c_str(), opt);
    }
    if (!response.is_valid())
        THROW_ERROR_CODE(kHTTPResponseParseError);
    if (response.get_status_code() != 200)
    {
        core_status_code error_code = parse_plaid_error(response);
        THROW_ERROR_CODE(error_code);
    }

    // Parse the response to get the balances of all associated accounts
    std::map<std::string, jsmntype_t> keys = {{"accounts->balances->available", JSMN_PRIMITIVE}};
    JSONParser parser(response.get_body(), max_tokens);
    JSONData data = parser.get_data_from_keys(keys);
    if (!parser.is_valid())
        THROW_EXCEPTION(kJSONParseError, "Could not parse JSON body");

    // Sum up all of the available balances
    std::vector<std::string> available_balances = data.get_all("accounts->balances->available");
    float balance = 0;
    for (const auto &value : available_balances)
    {
        // Check for null values
        if (value.size() <= 0)
            continue;
        // JSMN_PRIMITIVE can only be a number, boolean (true/false) or null
        if (value.c_str()[0] == 'n' || value.c_str()[0] == 't' || value.c_str()[0] == 'f')
            continue;
        balance += std::stof(value);
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

    json::JSON request_body = json::Object();
    request_body["client_id"] = config.client_id;
    json::JSON options = json::Object();
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
    if (total_transactions > 0 && days_fetched < 30)
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
    while (total_transactions == prev_total_transactions && times_waited < 10 && days_fetched < 30)
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
        int current_offset = static_cast<int>(request_body["options"]["offset"].ToInt());
        request_body["options"]["offset"] = current_offset + count;
        request_body_str = request_body.dump();
        std::vector<PlaidTransaction> next_transactions = plaid_get_transactions(
            client, headers, request_body_str.c_str(), opt, error_code, total_transactions);
        transactions.insert(transactions.end(), next_transactions.begin(), next_transactions.end());
    }

    return transactions;
}

std::string plaid_get_account_holder_name(HTTPSClient &client, const PlaidConfiguration &config)
{
    ClientOptions opt = client.get_client_options();
    opt.output_length = 22000;
    int max_tokens = 2000;

    std::string host = config.environment + std::string(".plaid.com");
    std::string host_header = "Host: " + host;
    std::string content_header = "Content-Type: application/json";
    std::vector<char *> headers = {(char *)host_header.c_str(), (char *)content_header.c_str()};

    json::JSON request_body = json::Object();
    request_body["client_id"] = config.client_id;
    request_body["secret"] = config.secret;
    request_body["access_token"] = config.access_token;
    std::string request_body_str = request_body.dump();

    DEBUG_LOG("Sending /identity/get POST request to Plaid");
    HTTPSResponse response = client.post("/identity/get", headers, request_body_str.c_str(), opt);
    // An invalid response could be due to the output length not being long enough
    if (!response.is_valid())
    {
        opt.output_length = 2 * opt.output_length;
        max_tokens = 2 * max_tokens;
        response = client.post("/identity/get", headers, request_body_str.c_str(), opt);
    }
    if (!response.is_valid())
        THROW_ERROR_CODE(kHTTPResponseParseError);
    if (response.get_status_code() != 200)
    {
        core_status_code error_code = parse_plaid_error(response);
        THROW_ERROR_CODE(error_code);
    }

    std::map<std::string, jsmntype_t> keys = {{"accounts->owners->names", JSMN_ARRAY}};
    JSONParser parser(response.get_body(), max_tokens);
    JSONData data = parser.get_data_from_keys(keys);
    if (!parser.is_valid())
        THROW_EXCEPTION(kJSONParseError, "Could not parse JSON body");

    std::vector<std::string> names = data.get_all("accounts->owners->names");
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

    json::JSON request_body = json::Object();
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
    int max_tokens = 500;
    std::map<std::string, jsmntype_t> keys = {{"item->institution_id", JSMN_STRING}};
    JSONParser parser(response.get_body(), max_tokens);
    JSONData data = parser.get_data_from_keys(keys);
    if (!parser.is_valid())
        THROW_EXCEPTION(kJSONParseError, "Could not parse JSON body");

    std::string institution_id = data.get("item->institution_id");

    json::JSON name_request_body = json::Object();
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
    std::map<std::string, jsmntype_t> name_keys = {{"institution->name", JSMN_STRING}};
    JSONParser name_parser(name_response.get_body(), max_tokens);
    JSONData name_data = name_parser.get_data_from_keys(name_keys);
    if (!name_parser.is_valid())
        THROW_EXCEPTION(kJSONParseError, "Could not parse JSON body");

    std::string institution_name = name_data.get("institution->name");

    return institution_name;
}

} // namespace enclave
} // namespace silentdata
