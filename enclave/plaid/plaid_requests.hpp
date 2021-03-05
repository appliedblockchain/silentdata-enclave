/*
 * Calls to plaid API
 */

#ifndef SILENTDATA_ENCLAVE_PLAID_REQUESTS_H
#define SILENTDATA_ENCLAVE_PLAID_REQUESTS_H

#include <map>
#include <string>
#include <time.h>
#include <vector>

#include "enclave/client/client_opt.h"
#include "enclave/client/https_client.hpp"
#include "enclave/client/https_response.hpp"
#include "enclave/common/enclave_exception.hpp"
#include "enclave/common/enclave_logger.hpp"
#include "enclave/core_status_codes.h"
#include "enclave/json/json.hpp"
#include "enclave/json/json_data.hpp"
#include "enclave/json/json_parser.hpp"
#include "enclave/plaid/plaid_errors.hpp"

namespace silentdata
{
namespace enclave
{

struct PlaidLink
{
    std::string token;
    std::string expiration;
    std::string request_id;
};

struct PlaidConfiguration
{
    std::string environment;
    std::string client_id;
    std::string secret;
    std::string access_token;
};

struct PlaidAccess
{
    std::string token;
    std::string timestamp;
    std::string certificate_chain;
};

struct PlaidTransaction
{
    PlaidTransaction(double a, struct tm d) : amount(a), date(d) {}
    double amount;
    struct tm date;
};

struct PlaidAccount
{
    PlaidAccount(uint32_t a, uint32_t s, const std::string &i, const std::string &id)
        : account_number(a), sort_code(s), iban(i), account_id(id)
    {
    }
    uint32_t account_number;
    uint32_t sort_code;
    std::string iban;
    std::string account_id;
};

// Send a request to the Plaid API to create a link token for a user
PlaidLink plaid_create_link_token(HTTPSClient &client,
                                  const PlaidConfiguration &config,
                                  const char *client_user_id,
                                  const char *redirect_uri);

// Send a request to the Plaid API to obtain an access token from a link token
PlaidAccess
plaid_get_access(HTTPSClient &client, const PlaidConfiguration &config, const char *public_token);

// Send a request to the Plaid API to destroy a given access token
access_token_status plaid_destroy_access(HTTPSClient &client, const PlaidConfiguration &config);

// Send a request to the Plaid API to return the total bank balance for all connected accounts
float plaid_get_total_balance(HTTPSClient &client, const PlaidConfiguration &config);

// Send a request to the Plaid API to return all transactions as amount-date pairs in a given time
// period
std::vector<PlaidTransaction> plaid_get_all_transactions(HTTPSClient &client,
                                                         const PlaidConfiguration &config,
                                                         struct tm start_date,
                                                         struct tm end_date);

// Send a request to the Plaid API to get the most common account holder name
std::string plaid_get_account_holder_name(HTTPSClient &client,
                                          const PlaidConfiguration &config,
                                          const std::string &account_id = "");

// Get the institution ID from the balance data and obtain the name from the ID
std::string plaid_get_institution_name(HTTPSClient &client, const PlaidConfiguration &config);

// Get account information for all associated accounts
std::vector<PlaidAccount> plaid_get_account_details(HTTPSClient &client,
                                                    const PlaidConfiguration &config);

} // namespace enclave
} // namespace silentdata

#endif
