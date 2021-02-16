#include "enclave/common/enclave_logger.hpp"

const char *log_level_strings[] = {
    "NONE",  // 0
    " CRIT", // 1
    "ERROR", // 2
    " WARN", // 3
    " INFO", // 4
    "DEBUG"  // 5
};

void EXCEPTION_LOG(const std::runtime_error &e)
{
    if (LOG_SHOULD_I(kEnclaveLogLevelError))
    {
        mbedtls_compat_sgx_printf("[ERROR] %s\n", e.what());
    }
}
