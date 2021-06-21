/*
 * Calls to plaid API
 */

#ifndef SILENTDATA_ENCLAVE_PLAID_CLIENT_H
#define SILENTDATA_ENCLAVE_PLAID_CLIENT_H

#include <map>
#include <string>
#include <time.h>
#include <vector>

#include "enclave/client/client_opt.h"
#include "enclave/client/https_client.hpp"
#include "enclave/client/https_response.hpp"
#include "enclave/common/date_time.hpp"
#include "enclave/common/enclave_exception.hpp"
#include "enclave/common/enclave_logger.hpp"
#include "enclave/common/json.hpp"
#include "enclave/common/types.hpp"
#include "enclave/core_status_codes.h"
#include "enclave/plaid/plaid_certificate.h"
#include "enclave/plaid/plaid_errors.hpp"

namespace silentdata
{
namespace enclave
{

struct PlaidConfig
{
    PlaidConfig() {}
    PlaidConfig(const std::string &e, const std::string &c, const std::string &s, uint32_t t)
        : environment(e), client_id(c), secret(s), timestamp(t)
    {
    }
    std::string environment;
    std::string client_id;
    std::string secret;
    uint32_t timestamp;
};

struct PlaidLink
{
    std::string token;
    std::string expiration;
    std::string request_id;
};

class PlaidClient : public HTTPSClient
{
private:
    std::string host_;
    std::string client_id_;
    std::string secret_;
    std::string access_token_;
    std::string last_timestamp_;
    std::string last_certificate_chain_;

    std::vector<BankTransaction>
    get_transactions(const json::JSON &body, CoreStatusCode &error_code, int &total);

    std::vector<std::string> default_headers();
    json::JSON default_request_body();

    HTTPSResponse post(const std::string &endpoint, bool retry = false);
    HTTPSResponse post(const std::string &endpoint, const json::JSON &body, bool retry = false);

public:
    PlaidClient(const std::string &environment,
                const std::string &client_id,
                const std::string &secret,
                uint32_t timestamp);
    PlaidClient(const PlaidConfig &config);
    ~PlaidClient();

    // Send a request to the Plaid API to create a link token for a user
    PlaidLink create_link_token(const std::string &client_user_id,
                                const std::string &redirect_uri,
                                const std::string &country);

    // Send a request to the Plaid API to obtain an access token from a link token
    void get_access(const std::string &public_token);

    // Send a request to the Plaid API to destroy a given access token
    void destroy_access();

    // Send a request to the Plaid API to return the total bank balance for all connected accounts
    BankBalance get_total_balance(const std::string &currency_code);

    // Send a request to the Plaid API to return all transactions as amount-date pairs in a given
    // time period
    std::vector<BankTransaction> get_all_transactions(struct tm start_date, struct tm end_date);

    // Send a request to the Plaid API to get the most common account holder name
    std::string get_account_holder_name(const std::string &account_id = "");

    // Get the institution ID from the balance data and obtain the name from the ID
    std::string get_institution_name();

    // Get account information for all associated accounts
    std::vector<AccountDetails> get_account_details();

    std::string get_timestamp() const { return last_timestamp_; }
    std::string get_certificate_chain() const { return last_certificate_chain_; }
    void set_host(const std::string &host) { host_ = host; }
};

} // namespace enclave
} // namespace silentdata

#endif
