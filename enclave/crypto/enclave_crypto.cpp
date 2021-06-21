#include "enclave/crypto/enclave_crypto.hpp"

namespace silentdata
{
namespace enclave
{

void aes_encrypt(const sgx_aes_gcm_128bit_key_t &key,
                 const uint8_t *input,
                 const uint32_t input_len,
                 const uint8_t *aad,
                 uint32_t aad_len,
                 uint8_t *output)
{
    // Set the initialisation vector
    std::array<uint8_t, 12> iv{};
    sgx_status_t ret;
    if ((ret = sgx_read_rand(iv.data(), 12)) != SGX_SUCCESS)
    {
        THROW_EXCEPTION(sgx_error_status(ret), sgx_error_message("sgx_read_rand", ret).c_str());
    }

    sgx_aes_gcm_128bit_tag_t mac;
    // Encrypt the information with the symmetric key
    ret = sgx_rijndael128GCM_encrypt(&key,
                                     input,
                                     input_len,
                                     output + 12 + 16,
                                     const_cast<const uint8_t *>(iv.data()),
                                     12,
                                     aad,
                                     aad_len,
                                     &mac);
    if (ret != SGX_SUCCESS)
    {
        THROW_EXCEPTION(sgx_error_status(ret),
                        sgx_error_message("sgx_rijndael128GCM_encrypt", ret).c_str());
    }

    // Put the MAC and IV at the start of the output
    std::copy(std::begin(mac), std::end(mac), output);
    std::copy(iv.begin(), iv.end(), output + 16);

    return;
}

sgx_status_t aes_decrypt(const sgx_aes_gcm_128bit_key_t &key,
                         const uint8_t *input,
                         uint32_t ciphertext_len,
                         const uint8_t *aad,
                         uint32_t aad_len,
                         uint8_t *output)
{
    return sgx_rijndael128GCM_decrypt(&key,
                                      input == nullptr ? nullptr : input + 16 + 12,
                                      ciphertext_len,
                                      output,
                                      input + 16,
                                      12,
                                      aad,
                                      aad_len,
                                      reinterpret_cast<const sgx_aes_gcm_128bit_tag_t *>(input));
}

void rsa_sign(const RSAParams &rsa_params,
              std::vector<uint8_t> data,
              sgx_rsa3072_signature_t &signature)
{
    DEBUG_LOG("Signing with enclaves private key");
    sgx_rsa3072_key_t private_key;
    memcpy(private_key.mod, rsa_params.n, sizeof(rsa_params.n));
    memcpy(private_key.e, rsa_params.e, sizeof(rsa_params.e));
    memcpy(private_key.d, rsa_params.d, sizeof(rsa_params.d));

    sgx_status_t ret =
        sgx_rsa3072_sign(data.data(), static_cast<uint32_t>(data.size()), &private_key, &signature);
    if (ret != SGX_SUCCESS)
        THROW_EXCEPTION(sgx_error_status(ret), sgx_error_message("sgx_rsa3072_sign", ret));

    DEBUG_HEX_LOG("Signature:", &signature, 384);
}

void ecdh(const sgx_ec256_private_t *local_private_key,
          const uint8_t *peer_public_key_bytes,
          sgx_aes_gcm_128bit_key_t &shared_secret)
{

    sgx_ec256_public_t peer_public_key;
    memcpy(peer_public_key.gx, peer_public_key_bytes, 32);
    memcpy(peer_public_key.gy, peer_public_key_bytes + 32, 32);

    sgx_ecc_state_handle_t handle;
    sgx_status_t ret = sgx_ecc256_open_context(&handle);
    if (ret != SGX_SUCCESS)
        THROW_EXCEPTION(kECDHError, sgx_error_message("sgx_ecc256_open_context", ret));

    sgx_ec256_dh_shared_t shared_secret_full{};

    // This will generate a little-endian x coordinate of a point on the elliptic curve (256 bit)
    ret = sgx_ecc256_compute_shared_dhkey(
        local_private_key, &peer_public_key, &shared_secret_full, handle);
    if (ret != SGX_SUCCESS)
    {
        sgx_ecc256_close_context(handle);
        THROW_EXCEPTION(kECDHError, sgx_error_message("sgx_ecc256_compute_shared_dhkey", ret));
    }

    ret = sgx_ecc256_close_context(handle);
    if (ret != SGX_SUCCESS)
        THROW_EXCEPTION(kECDHError, sgx_error_message("sgx_ecc256_close_context", ret));

    // "Key derivation": Take the first 16 bits of the big-endian representation
    // to replicate what the JS code does
    for (size_t i = 0; i < 16; i++)
    {
        shared_secret[i] = shared_secret_full.s[31 - i];
    }
}

} // namespace enclave
} // namespace silentdata
