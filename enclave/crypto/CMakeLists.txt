# Crypto library
set(E_CRYPTO_SRCS ecc_key_pair.cpp
                  enclave_crypto.cpp)

add_trusted_library(enclave_crypto_t
                    SRCS ${E_CRYPTO_SRCS}
                    EDL ${EDL_FILE}
                    EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

install(TARGETS enclave_crypto_t
    DESTINATION lib
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
