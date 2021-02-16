# Common library
set(E_COMMON_SRCS date_time.cpp
                  enclave_logger.cpp
                  sgx_error_message.cpp)

add_trusted_library(enclave_common_t
                    SRCS ${E_COMMON_SRCS}
                    EDL ${EDL_FILE}
                    EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

install(TARGETS enclave_common_t
    DESTINATION lib
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
