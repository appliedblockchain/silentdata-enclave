#include "enclave/plaid/plaid_errors.hpp"

namespace silentdata
{
namespace enclave
{

core_status_code parse_plaid_error(HTTPSResponse response)
{
    // Just in case a valid response was passed to the function
    if (response.get_status_code() == 200)
        return kSuccess;

    // Try to parse the error response
    // Details of Plaid error codes: https://plaid.com/docs/errors/
    try
    {
        ERROR_LOG("Plaid Error:\n%s", response.get_body().c_str());
        json::JSON error_data = json::JSON::Load(response.get_body());
        std::string error_type = error_data["error_type"].ToString();
        std::string error_code = error_data["error_code"].ToString();
        if (error_type == "API_ERROR")
            return kPlaidApiError;
        if (error_type == "INSTITUTION_ERROR")
        {
            if (error_code == "INSTITUTION_NO_LONGER_SUPPORTED")
                return kPlaidInstitutionNotSupported;
            return kPlaidInstitutionError;
        }
        if (error_type == "INVALID_INPUT")
            return kPlaidInvalidInput;
        if (error_type == "INVALID_REQUEST")
            return kPlaidInvalidRequest;
        if (error_type == "INVALID_RESULT")
            return kPlaidInvalidResult;
        if (error_type == "ITEM_ERROR")
        {
            if (error_code == "PRODUCT_NOT_READY" || error_code == "ITEM_PRODUCT_NOT_READY")
                return kPlaidProductNotReady;
            return kPlaidItemError;
        }
        if (error_type == "OAUTH_ERROR")
            return kPlaidOAuthError;
        if (error_type == "RATE_LIMIT_EXCEEDED")
            return kPlaidRateLimitExceeded;
        return kPlaidOtherError;
    }
    // If that fails just set the error by the HTTP status code
    catch (...)
    {
        int status_code = response.get_status_code();
        if (status_code >= 400 && status_code <= 499)
        {
            if (status_code == 400)
                return kHTTPStatus400;
            if (status_code == 401)
                return kHTTPStatus401;
            if (status_code == 403)
                return kHTTPStatus403;
            if (status_code == 404)
                return kHTTPStatus404;
            if (status_code == 405)
                return kHTTPStatus405;
            if (status_code == 408)
                return kHTTPStatus408;
            return kHTTPStatus4xx;
        }
        if (status_code >= 500 && status_code <= 599)
        {
            if (status_code == 500)
                return kHTTPStatus500;
            if (status_code == 503)
                return kHTTPStatus503;
            return kHTTPStatus5xx;
        }
    }
    return kHTTPStatusNot200;
}

} // namespace enclave
} // namespace silentdata
