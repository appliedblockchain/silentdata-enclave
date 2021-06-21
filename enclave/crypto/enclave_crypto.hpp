/*
 * Functions related to encryption, decryption and signing inside the enclave
 */

#ifndef SILENTDATA_ENCLAVE_ENCLAVE_CRYPTO_H
#define SILENTDATA_ENCLAVE_ENCLAVE_CRYPTO_H

#include <array>
#include <string>
#include <vector>

#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "enclave/common/enclave_exception.hpp"
#include "enclave/common/enclave_logger.hpp"
#include "enclave/common/sgx_error_message.hpp"
#include "enclave/crypto/ecc_key_pair.hpp"
#include "enclave/crypto/rsa_params.hpp"

namespace silentdata
{
namespace enclave
{

// Encrypt data using AES-GCM
void aes_encrypt(const sgx_aes_gcm_128bit_key_t &key,
                 const uint8_t *input,
                 const uint32_t input_len,
                 const uint8_t *aad,
                 uint32_t aad_len,
                 uint8_t *output);

// Decrypt data using AES-GCM and or check additional authenticated data
sgx_status_t aes_decrypt(const sgx_aes_gcm_128bit_key_t &sym_key,
                         const uint8_t *input,
                         uint32_t ciphertext_len,
                         const uint8_t *aad,
                         uint32_t aad_len,
                         uint8_t *output);

// Create an RSA signature
void rsa_sign(const RSAParams &signature_rsa_params,
              std::vector<uint8_t> data,
              sgx_rsa3072_signature_t &signature);

// Perform an elliptic-curve Diffie-Hellman key exchange and derive a key usable for AES encryption
void ecdh(const sgx_ec256_private_t *local_private_key,
          const uint8_t *peer_public_key_bytes,
          sgx_aes_gcm_128bit_key_t &shared_secret);

} // namespace enclave
} // namespace silentdata

#endif
