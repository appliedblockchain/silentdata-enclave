# Client library
set(E_CLIENT_SRCS https_client.cpp
                  https_response.cpp)

add_trusted_library(enclave_client_t
                    SRCS ${E_CLIENT_SRCS}
                    EDL ${EDL_FILE}
                    EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

install(TARGETS enclave_client_t
    DESTINATION lib
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
