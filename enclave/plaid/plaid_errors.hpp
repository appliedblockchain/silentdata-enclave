/*
 * Functions for serialising Plaid request data to be signed
 */

#ifndef SILENTDATA_ENCLAVE_PLAID_ERRORS_H
#define SILENTDATA_ENCLAVE_PLAID_ERRORS_H

#include "enclave/client/https_response.hpp"
#include "enclave/common/enclave_exception.hpp"
#include "enclave/common/enclave_logger.hpp"
#include "enclave/core_status_codes.h"
#include "enclave/json/json_data.hpp"
#include "enclave/json/json_parser.hpp"

namespace silentdata
{
namespace enclave
{

// Obtain the plaid error from the response and convert it to the corresponding core status code
core_status_code parse_plaid_error(HTTPSResponse response);

} // namespace enclave
} // namespace silentdata

#endif
