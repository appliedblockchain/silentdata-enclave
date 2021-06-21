#include "enclave/plaid/plaid_client.hpp"

using json::JSON;

namespace silentdata
{
namespace enclave
{

PlaidClient::PlaidClient(const std::string &environment,
                         const std::string &client_id,
                         const std::string &secret,
                         uint32_t timestamp)
    : host_(environment + ".plaid.com"), client_id_(client_id), secret_(secret)
{
    ClientOptions opt;
    opt.server_port = "443";
    opt.timestamp = timestamp;
    std::vector<std::string> certificates;
    if (environment == "sandbox" || environment == "development")
    {
        certificates.push_back(plaid_dev_certificate);
    }
    else
    {
        certificates.push_back(plaid_certificate);
    }
    set_server(host_);
    set_options(opt);
    set_certificates(certificates);
}

PlaidClient::PlaidClient(const PlaidConfig &config)
    : PlaidClient(config.environment, config.client_id, config.secret, config.timestamp)
{
}

PlaidClient::~PlaidClient()
{
    // Destroy access token if it exists
    if (access_token_.size() != 0)
    {
        destroy_access();
    }
}

std::vector<std::string> PlaidClient::default_headers()
{
    std::string host_header = "Host: " + host_;
    std::string content_header = "Content-Type: application/json";
    std::vector<std::string> headers = {host_header, content_header};
    return headers;
}

JSON PlaidClient::default_request_body()
{
    JSON request = json::Object();
    request["client_id"] = client_id_;
    request["secret"] = secret_;
    if (access_token_.length() != 0)
        request["access_token"] = access_token_;
    return request;
}

HTTPSResponse PlaidClient::post(const std::string &endpoint, bool retry)
{
    return post(endpoint, default_request_body(), retry);
}

HTTPSResponse PlaidClient::post(const std::string &endpoint, const JSON &body, bool retry)
{
    HTTPSResponse response = HTTPSClient::post(endpoint, default_headers(), body.dump());
    if (!response.is_valid() && retry)
    {
        set_output_length(2 * get_output_length());
        response = HTTPSClient::post(endpoint, default_headers(), body.dump());
    }
    if (!response.is_valid())
        THROW_ERROR_CODE(kHTTPResponseParseError);
    if (response.get_status_code() != 200)
        THROW_ERROR_CODE(parse_plaid_error(response));
    return response;
}

PlaidLink PlaidClient::create_link_token(const std::string &client_user_id,
                                         const std::string &redirect_uri,
                                         const std::string &country)
{
    JSON request = default_request_body();
    request["client_name"] = "SILENTDATA";
    request["country_codes"] = json::Array(country);
    request["language"] = "en";
    JSON user = json::Object();
    user["client_user_id"] = client_user_id;
    request["user"] = user;
    request["products"] = json::Array("identity");
    request["redirect_uri"] = redirect_uri;

    // Make the HTTPS request
    DEBUG_LOG("Sending /link/token/create POST request to Plaid");
    HTTPSResponse response = post("/link/token/create", request);

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

void PlaidClient::get_access(const std::string &public_token)
{
    JSON request = default_request_body();
    request["public_token"] = public_token;

    DEBUG_LOG("Sending /item/public_token/exchange POST request to Plaid");
    HTTPSResponse response = post("/item/public_token/exchange", request);

    JSON data = JSON::Load(response.get_body());

    bool is_string = false;
    access_token_ = data["access_token"].ToString(is_string);
    if (!is_string)
        THROW_EXCEPTION(kJSONParseError, "Could not parse access token from JSON body");

    // Parse the response to get the timestamp
    last_timestamp_ = response.get_timestamp();

    // Check that a certificate chain was obtained
    last_certificate_chain_ = response.get_certificate_chain();
    if (last_certificate_chain_.length() == 0)
        THROW_EXCEPTION(kCertificateWriteError,
                        "Could not obtain the certificate chain from the HTTPS client");
}

void PlaidClient::destroy_access()
{
    set_output_length(4000);
    set_close_session(true);

    DEBUG_LOG("Sending /item/remove POST request to Plaid");
    HTTPSResponse response = post("/item/remove");

    JSON data = JSON::Load(response.get_body());
    bool is_bool = false;
    bool is_removed = data["removed"].ToBool(is_bool);
    if (!(is_bool && is_removed))
        THROW_ERROR_CODE(kPlaidTokenDestructionError);

    access_token_.clear();
}

BankBalance PlaidClient::get_total_balance(const std::string &currency_code)
{
    set_output_length(6000);

    DEBUG_LOG("Sending /accounts/balance/get POST request to Plaid");
    HTTPSResponse response = post("/accounts/balance/get", true);

    // Sum up all of the available balances
    JSON data = JSON::Load(response.get_body());
    int n_accounts = data["accounts"].length();
    if (n_accounts <= 0)
        THROW_EXCEPTION(kJSONParseError, "Could not find any bank accounts");
    std::string code;
    double available = 0;
    double current = 0;
    for (int i = 0; i < n_accounts; i++)
    {
        code = data["accounts"][i]["balances"]["iso_currency_code"].ToString();
        if (code != currency_code)
        {
            WARNING_LOG("Currency code for this account doesn't match input, skipping...");
            continue;
        }
        bool is_float = false;
        double available_balance = data["accounts"][i]["balances"]["available"].ToFloat(is_float);
        if (!is_float)
            available_balance =
                static_cast<double>(data["accounts"][i]["balances"]["available"].ToInt());
        available += available_balance;
        is_float = false;
        double current_balance = data["accounts"][i]["balances"]["current"].ToFloat(is_float);
        if (!is_float)
            current_balance =
                static_cast<double>(data["accounts"][i]["balances"]["current"].ToInt());
        current += current_balance;
    }

    return BankBalance(currency_code, available, current);
}

std::vector<BankTransaction>
PlaidClient::get_transactions(const JSON &body, CoreStatusCode &error_code, int &total)
{
    error_code = kSuccess;

    DEBUG_LOG("Sending /transactions/get POST request to Plaid");
    std::vector<BankTransaction> transactions;
    HTTPSResponse response = HTTPSClient::post("/transactions/get", default_headers(), body.dump());
    // An invalid response could be due to the output length not being long enough
    if (!response.is_valid())
    {
        set_output_length(2 * get_output_length());
        response = post("/transactions/get", body);
    }
    if (!response.is_valid())
        THROW_ERROR_CODE(kHTTPResponseParseError);
    if (response.get_status_code() != 200)
    {
        error_code = parse_plaid_error(response);
        WARNING_LOG("Error code %i returned by Plaid", error_code);
        if (error_code != kPlaidProductNotReady)
            THROW_ERROR_CODE(error_code);
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
        std::string currency_code = data["transactions"][i]["iso_currency_code"].ToString();
        std::string date_str = data["transactions"][i]["date"].ToString();
        struct tm date = plaid_date_to_tm(date_str);

        bool is_float = false;
        double amount = data["transactions"][i]["amount"].ToFloat(is_float);
        if (!is_float)
            amount = static_cast<double>(data["transactions"][i]["amount"].ToInt());
        std::string name = data["transactions"][i]["name"].ToString();
        // Negative transactions mean money coming in to the account
        transactions.push_back(BankTransaction(currency_code, -amount, date, name));
    }
    return transactions;
}

std::vector<BankTransaction> PlaidClient::get_all_transactions(struct tm start_date,
                                                               struct tm end_date)
{
    // Shift dates to first days of the month and convert the dates to strings
    start_date.tm_mday = 1;
    std::string start_date_str = tm_to_string(start_date);
    int end_date_day = end_date.tm_mday;
    end_date.tm_mday = 1;
    std::string end_date_str = tm_to_string(end_date);
    end_date.tm_mday = end_date_day;

    set_output_length(200000);
    // Close the client after each connection because we might be waiting a while and that can
    // cause the peer to close the connection
    set_close_session(true);

    JSON request = default_request_body();
    JSON options = json::Object();
    int count = 50; // Number of transactions to get in one go
    int offset = 0;
    options["count"] = count;
    options["offset"] = offset;
    request["options"] = options;
    request["start_date"] = start_date_str;
    request["end_date"] = end_date_str;

    CoreStatusCode error_code = kSuccess;
    int total_transactions = 0;
    DEBUG_LOG("Getting the first page of transactions");
    std::vector<BankTransaction> transactions =
        get_transactions(request, error_code, total_transactions);
    // If the product isn't ready keep trying until it is
    while (error_code == kPlaidProductNotReady)
    {
        DEBUG_LOG("Product not ready, waiting 5 seconds and trying again");
        // Sleep for 5 seconds
        mbedtls_net_usleep(5000000);
        transactions = get_transactions(request, error_code, total_transactions);
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
        request["options"]["count"] = 1;
        request["options"]["offset"] = total_transactions - 1;
        int temp_total;
        std::vector<BankTransaction> first_transaction =
            get_transactions(request, error_code, temp_total);
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
    request["options"]["count"] = count;
    request["options"]["offset"] = offset;
    while (total_transactions == prev_total_transactions && times_waited < 10 && days_fetched <= 30)
    {
        DEBUG_LOG("Historical transactions not available, waiting 30 seconds and trying again");
        mbedtls_net_usleep(30000000);
        transactions = get_transactions(request, error_code, total_transactions);
        times_waited++;
    }

    // If there are more transactions than "count", page through the transaction data until all
    // the transactions have been saved
    set_close_session(false);
    while (transactions.size() < static_cast<size_t>(total_transactions))
    {
        DEBUG_LOG("Not all transactions obtained, getting next page");
        int current_offset = static_cast<int>(request["options"]["offset"].ToInt());
        request["options"]["offset"] = current_offset + count;
        std::vector<BankTransaction> next_transactions =
            get_transactions(request, error_code, total_transactions);
        transactions.insert(transactions.end(), next_transactions.begin(), next_transactions.end());
    }

    return transactions;
}

std::string PlaidClient::get_account_holder_name(const std::string &account_id)
{
    set_output_length(22000);

    JSON request = default_request_body();
    // If we're matching a specific account
    if (account_id != "")
    {
        JSON options = json::Object();
        options["account_ids"] = json::Array(account_id);
        request["options"] = options;
    }

    DEBUG_LOG("Sending /identity/get POST request to Plaid");
    HTTPSResponse response = post("/identity/get", request, true);

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

std::string PlaidClient::get_institution_name()
{
    set_output_length(6000);

    DEBUG_LOG("Sending /item/get POST request to Plaid");
    HTTPSResponse response = post("/item/get");

    JSON data = JSON::Load(response.get_body());
    bool is_string = false;
    std::string institution_id = data["item"]["institution_id"].ToString(is_string);
    if (!is_string)
        THROW_EXCEPTION(kJSONParseError, "Could not parse institution id from JSON body");

    JSON request = json::Object();
    request["client_id"] = client_id_;
    request["secret"] = secret_;
    request["institution_id"] = institution_id;
    request["country_codes"] = "[]";

    DEBUG_LOG("Sending /institutions/get_by_id POST request to Plaid");
    HTTPSResponse name_response = post("/institutions/get_by_id", request);

    // Parse the response to get the balances of all associated accounts
    JSON name_data = JSON::Load(name_response.get_body());
    std::string institution_name = name_data["institution"]["name"].ToString(is_string);
    if (!is_string)
        THROW_EXCEPTION(kJSONParseError, "Could not parse institution name from JSON body");

    return institution_name;
}

std::vector<AccountDetails> PlaidClient::get_account_details()
{
    set_output_length(6000);

    DEBUG_LOG("Sending /auth/get POST request to Plaid");
    HTTPSResponse response = post("/auth/get", true);

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

    std::vector<AccountDetails> account_details;
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
        account_details.push_back(AccountDetails(account_number, sort_code, iban, bacs_id));
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
                AccountDetails(account_number, sort_code, iban, international_id));
        }
    }

    return account_details;
}

} // namespace enclave
} // namespace silentdata
