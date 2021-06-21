########## MAIN ENCLAVE ##########

add_subdirectory(common)
add_subdirectory(crypto)
add_subdirectory(client)
add_subdirectory(plaid)
add_subdirectory(proofs)

set(E_SRCS enclave.cpp)

set(ENCLAVE_TRUSTED_LIBS enclave_common_t
                         enclave_crypto_t
                         enclave_client_t
                         enclave_plaid_t
                         enclave_proofs_t)

set(ENCLAVE_LIB_PATHS ${MBEDTLS_LIB_PATH})

set(ENCLAVE_LIBS mbedtls_SGX_t)

add_enclave_library(enclave
                    SRCS ${E_SRCS}
                    TRUSTED_LIBS ${ENCLAVE_TRUSTED_LIBS}
                    EDL ${EDL_FILE}
                    EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
                    LDSCRIPT ${LDS}
                    LIB_PATHS ${ENCLAVE_LIB_PATHS}
                    LIBS ${ENCLAVE_LIBS})

if(SGX_HW AND SGX_MODE STREQUAL "Release")
message(STATUS "DisableDebug = 1")
enclave_sign(enclave
             KEY enclave_private_test.pem
             CONFIG enclave.config.xml
             OUTPUT enclave.signed.so)
else()
message(STATUS "DisableDebug = 0")
enclave_sign(enclave
             KEY enclave_private_test.pem
             CONFIG enclave_debug.config.xml
             OUTPUT enclave.signed.so)
endif()

install(TARGETS enclave
    DESTINATION enclave
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

# In release mode the hash of the enclave code needs to be signed before producing the signed
# enclave object
if(SGX_HW AND SGX_MODE STREQUAL "Release")
    install(FILES "$<TARGET_FILE_DIR:enclave>/enclave_hash.hex"
        DESTINATION enclave
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
else()
    install(FILES "$<TARGET_FILE_DIR:enclave>/enclave.signed.so"
        DESTINATION enclave
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

    install(FILES "$<TARGET_FILE_DIR:enclave>/enclave.signed.so"
        DESTINATION ../
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endif()
