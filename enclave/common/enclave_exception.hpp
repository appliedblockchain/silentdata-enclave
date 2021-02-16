#ifndef SILENTDATA_ENCLAVE_ENCLAVE_EXCEPTION_H
#define SILENTDATA_ENCLAVE_ENCLAVE_EXCEPTION_H

#include <map>
#include <stdexcept>
#include <string>

#include "enclave/core_status_codes.h"

namespace silentdata
{
namespace enclave
{

struct core_status_info
{
    std::string name;
    std::string message;
};

const std::map<core_status_code, core_status_info> core_status_map = {
    {kSuccess, {"Success", "Success!"}},
    {kInvalidInput, {"InvalidInput", "The input to the enclave is not valid"}},
    {kInvalidNonce, {"InvalidNonce", "The plaintext nonce does not match the decrypted input"}},
    {kCertificateWriteError,
     {"CertificateWriteError", "Unable to write the server certificate chain to the output"}},
    {kDateTimeError, {"DateTimeError", "Error in a a date_time function"}},
    {kSGXError, {"SGXError", "Unknown/uncategorised SGX error"}},
    {kSGXBusy, {"SGXBusy", "The enclave is busy, try again later"}},
    {kSGXOutOfMemory, {"SGXOutOfMemory", "The enclave is out of memory"}},
    {kSGXInvalidParameter,
     {"SGXInvalidParameter", "Parameter provided to an SGX function is invalid"}},
    {kSGXEnclaveCrashed, {"SGXEnclaveCrashed", "The enclave has crashed"}},
    {kSGXStackOverrun, {"SGXStackOverrun", "A stack overrun has occured withing the enclave"}},
    {kSGXNDebugEnclave,
     {"SGXNDebugEnclave",
      "Enclave signed as a product enclave cannot be created as a debuggable enclave"}},
    {kSGXEnclaveError, {"SGXEnclaveError", "There is an issue with the enclave"}},
    {kSGXEnclaveInvalid, {"SGXEnclaveInvalid", "A component of the enclave is invalid"}},
    {kSGXCryptoError, {"SGXCryptoError", "Error in an SGX cryptographic component"}},
    {kSGXServiceError, {"SGXServiceError", "Error in an architectural enclave (AE) service"}},
    {kSGXMCError, {"SGXMCError", "Error in SGX monotonic counter"}},
    {kSGXPlatformError,
     {"SGXPlatformError", "There is an issue with the platform hosting the enclave"}},
    {kSGXPCLError, {"SGXPCLError", "There is an issue with the protected code loader"}},
    {kSGXFileError, {"SGXFileError", "There is an issue with file sealing"}},
    {kSGXAttestationError,
     {"SGXAttestationError", "There is an issue with the SGX attestation generation"}},
    {kSGXEnclaveFileAccess, {"SGXEnclaveFileAccess", "The enclave file cannot be opened"}},
    {kJSONParseError, {"JSONParseError", "Could not parse JSON"}},
    {kJSONIteratorError,
     {"JSONIteratorError", "JSON iterators passed to a function do not match expected symantics"}},
    {kJSONOutOfRangeError,
     {"JSONOutOfRangeError", "Expected range exceeded when acessing JSON values by index"}},
    {kJSONKeyError, {"JSONKeyError", "The given key was not found in the JSON object"}},
    {kJSONMultipleValuesError,
     {"JSONMultipleValuesError",
      "Multiple values are associated with this JSON key, should use get_all rather than get"}},
    {kJSONTypeError, {"JSONTypeError", "The JSON value type is not what is expected"}},
    {kHTTPRequestError, {"HTTPRequestError", "Sending a HTTP request failed"}},
    {kHTTPResponseParseError, {"HTTPResponseParseError", "Error parsing HTTP response"}},
    {kHTTPStatusNot200, {"HTTPStatusCodeNot200", "HTTP response status code not 200"}},
    {kHTTPStatus400, {"HTTPStatus400", "HTTP response status code 400: Bad request"}},
    {kHTTPStatus401, {"HTTPStatus401", "HTTP response status code 401: Unauthorized"}},
    {kHTTPStatus403, {"HTTPStatus403", "HTTP response status code 403: Forbidden"}},
    {kHTTPStatus404, {"HTTPStatus404", "HTTP response status code 404: Not found"}},
    {kHTTPStatus405, {"HTTPStatus405", "HTTP response status code 405: Method not allowed"}},
    {kHTTPStatus408, {"HTTPStatus408", "HTTP response status code 408: Request timeout"}},
    {kHTTPStatus4xx, {"HTTPStatus4xx", "HTTP response status code 4xx"}},
    {kHTTPStatus500, {"HTTPStatus500", "HTTP response status code 500: Internal server error"}},
    {kHTTPStatus503, {"HTTPStatus503", "HTTP response status code 503: Service unavailable"}},
    {kHTTPStatus5xx, {"HTTPStatus5xx", "HTTP response status code 5xx"}},
    {kKeyCreationError, {"KeyCreationError", "Error occured in enclave key generation"}},
    {kEncryptionError, {"EncryptionError", "Error occured while encrypting data"}},
    {kDecryptionError, {"DecryptionError", "Error occured while decrypting data"}},
    {kSigningError, {"SigningError", "Error occured while signing data"}},
    {kSigningDataFieldTooLong,
     {"SigningDataFieldTooLong", "One of the data field to be signed is longer than expected"}},
    {kECDHError, {"ECDHError", "Error in the ECDH process"}},
    {kPlaidTokenDestructionError,
     {"PlaidTokenDestructionError", "Plaid access token destruction failed"}},
    {kPlaidApiError, {"PlaidApiError", "Plaid planned maintenance or internal server error"}},
    {kPlaidInstitutionError,
     {"PlaidInstitutionError", "Plaid error with requested financial institution"}},
    {kPlaidInstitutionNotSupported,
     {"PlaidInstitutionNotSupported", "Financial institution not supported by Plaid"}},
    {kPlaidInvalidInput,
     {"PlaidInvalidInput", "One or more values provided to Plaid is incorrect"}},
    {kPlaidInvalidRequest,
     {"PlaidInvalidRequest", "Plaid request is malformed and cannot be processed"}},
    {kPlaidInvalidResult, {"PlaidInvalidResult", "Plaid response is unusable"}},
    {kPlaidItemError, {"PlaidItemError", "Plaid item is invalid or not supported"}},
    {kPlaidOAuthError, {"PlaidOAuthError", "Error in Plaid OAuth authentication"}},
    {kPlaidRateLimitExceeded,
     {"PlaidRateLimitExceeded",
      "Excessive number of Plaid requests have been made in a short period of time"}},
    {kPlaidProductNotReady,
     {"PlaidProductNotReady", "Plaid product is not ready yet, try again later"}},
    {kPlaidOtherError, {"PlaidOtherError", "A Plaid error occured"}},
    {kClientConfigurationError,
     {"ClientConfigurationError", "Configuration of the HTTPSClient failed"}},
    {kClientCertificateParseError,
     {"ClientCertificateParseError", "Pinned certificates could not be parsed"}},
    {kClientConnectionError,
     {"ClientConnectionError", "Initial connection between client and server failed"}},
    {kClientHandshakeError,
     {"ClientHandshakeError",
      "TLS handshake with the server failed (most likely invalid certificate)"}},
    {kClientExpiredCertificate, {"ClientExpiredCertificate", "Server certificate is expired"}},
    {kClientReconnectionError,
     {"ClientReconnectionError", "Client failed to reconnect to the server"}},
    {kClientWriteError, {"ClientWriteError", "Client error writing HTTP request"}},
    {kClientReadError, {"ClientReadError", "Client error reading HTTP response"}},
    {kUnknownError, {"UnknownError", "An unknown error occured"}},
    {kMinimumBalanceInvalidInput,
     {"MinimumBalanceInvalidInput",
      "The input minimum balance does not match the decrypted input"}},
    {kMinimumBalanceRequirementsNotMet,
     {"MinimumBalanceRequirementsNotMet",
      "The account balance is less than the minimum value requested"}},
    {kConsistentIncomeInvalidInput,
     {"ConsistentIncomeInvalidInput",
      "The input consistent income does not match the decrypted input"}},
    {kConsistentIncomeRequirementsNotMet,
     {"ConsistentIncomeRequirementsNotMet",
      "The monthly income was below the minimum value requested for one or more of the previous "
      "three months"}},
    {kJSONRPCParseError, {"JSONRPCParseError", "Invalid JSON was recieved by the server"}},
    {kJSONRPCInvalidRequest,
     {"JSONRPCInvalidRequest", "The JSON send is not a valid request object"}},
    {kJSONRPCMethodNotFound,
     {"JSONRPCMethodNotFound", "The method does not exist or is not available"}},
    {kJSONRPCInvalidParams, {"JSONRPCInvalidParams", "Invalid method parameters"}},
    {kJSONRPCInternalError, {"JSONRPCInternalError", "Internal JSON-RPC error"}}};

inline std::string core_status_message(core_status_code status)
{
    std::string message = "(MissingErrorCode-" + std::to_string(static_cast<int>(status)) + ")";
    if (core_status_map.find(status) != core_status_map.end())
    {
        message = "(" + core_status_map.at(status).name + "-" +
                  std::to_string(static_cast<int>(status)) + ") " +
                  core_status_map.at(status).message;
    }
    return message;
}

inline std::string core_status_name(core_status_code status)
{
    std::string name = "MissingErrorCode";
    if (core_status_map.find(status) != core_status_map.end())
    {
        name = core_status_map.at(status).name;
    }
    return name;
}

class EnclaveException : public std::runtime_error
{
    std::string message_;
    core_status_code code_;

public:
    EnclaveException(core_status_code code,
                     const std::string &info,
                     const char *file,
                     const char *func,
                     int line)
        : std::runtime_error(info), code_(code)
    {
        const char *file_name = strrchr(file, '/');
        if (file_name == nullptr)
            file_name = file;
        else
            file_name = file_name + 1;
        message_ = std::string(file_name) + ":" + std::string(func) + ":" + std::to_string(line) +
                   ": " + "(" + core_status_name(code) + "-" +
                   std::to_string(static_cast<int>(code)) + ") " + std::string(info);
    }

    EnclaveException(core_status_code code, const char *file, const char *func, int line)
        : std::runtime_error(""), code_(code)
    {
        const char *file_name = strrchr(file, '/');
        if (file_name == nullptr)
            file_name = file;
        else
            file_name = file_name + 1;
        message_ = std::string(file_name) + ":" + std::string(func) + ":" + std::to_string(line) +
                   ": " + core_status_message(code);
    }

    const char *what() const throw() { return message_.c_str(); }

    core_status_code get_code() const { return code_; }
    void set_code(core_status_code code) { code_ = code; }
};
#define THROW_EXCEPTION(code, arg) throw EnclaveException(code, arg, __FILE__, __func__, __LINE__);
#define THROW_ERROR_CODE(code) throw EnclaveException(code, __FILE__, __func__, __LINE__);

} // namespace enclave
} // namespace silentdata

#endif
