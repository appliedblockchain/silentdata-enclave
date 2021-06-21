# Proof library
set(E_PROOFS_SRCS proof_data.cpp
                  request_types.cpp
                  result_types.cpp
                  comparison_functions.cpp
                  proof_handlers.cpp)

add_trusted_library(enclave_proofs_t
                    SRCS ${E_PROOFS_SRCS}
                    EDL ${EDL_FILE}
                    EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

install(TARGETS enclave_proofs_t
    DESTINATION lib
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
