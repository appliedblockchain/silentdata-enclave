cmake_minimum_required(VERSION 3.0)
project(silentdata-core C CXX)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_INSTALL_PREFIX ${PROJECT_BINARY_DIR}/install)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
find_package(SGX REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(MBED_DIR Default CACHE STRING "Path to mbedtls-compat-sgx lib and include")
if(MBED_DIR STREQUAL "Default")
    message(STATUS "MBED_DIR not set, using default of ${PROJECT_SOURCE_DIR}/../mbedtls-compat-sgx/build/mbedtls_SGX-2.24.0")
    set(MBED_DIR ${PROJECT_SOURCE_DIR}/../mbedtls-compat-sgx/build/mbedtls_SGX-2.24.0)
else()
    message(STATUS "MBED_DIR set to ${MBED_DIR}")
endif()
set(MBEDTLS_LIB_PATH ${MBED_DIR}/lib)
set(MBEDTLS_INCLUDE_DIR ${MBED_DIR}/include)

include_directories(${SGX_INCLUDE_DIR}
                    ${PROJECT_SOURCE_DIR}
                    ${PROJECT_SOURCE_DIR}/enclave
                    ${PROJECT_BINARY_DIR}
                    ${PROJECT_BINARY_DIR}/enclave
                    ${MBEDTLS_INCLUDE_DIR})

set(EDL_SEARCH_PATHS ${PROJECT_SOURCE_DIR}/enclave
                     ${MBEDTLS_LIB_PATH})

set(EDL_FILE ${PROJECT_SOURCE_DIR}/enclave/enclave.edl)

set(LDS enclave.lds)

########## MAIN ENCLAVE ##########

add_subdirectory(enclave)
