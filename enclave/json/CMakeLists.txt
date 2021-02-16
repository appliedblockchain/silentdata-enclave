# JSON library
set(E_JSON_SRCS json_data.cpp
                json_parser.cpp
                jsmn.cpp)

add_trusted_library(enclave_json_t
                    SRCS ${E_JSON_SRCS}
                    EDL ${EDL_FILE}
                    EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

install(TARGETS enclave_json_t
    DESTINATION lib
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
