# Plaid library
set(E_PLAID_SRCS plaid_client.cpp
                 plaid_errors.cpp)

add_trusted_library(enclave_plaid_t
                    SRCS ${E_PLAID_SRCS}
                    EDL ${EDL_FILE}
                    EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

install(TARGETS enclave_plaid_t
    DESTINATION lib
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
