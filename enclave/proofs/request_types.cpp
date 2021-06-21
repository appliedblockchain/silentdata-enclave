#include "enclave/proofs/request_types.hpp"

namespace silentdata
{
namespace enclave
{

PlaidRequest::PlaidRequest(const char *client_id,
                           const char *secret,
                           const char *plaid_environment,
                           uint8_t *client_public_key_bytes,
                           int32_t client_timestamp,
                           uint8_t *encrypted_input,
                           const sgx_ec256_private_t *local_private_key)
{
    // Validate function argument pointers
    if (client_id == nullptr || secret == nullptr || plaid_environment == nullptr ||
        encrypted_input == nullptr)
        THROW_EXCEPTION(kInvalidInput, "One or more of the function argument pointers is NULL");
    plaid_config_ = PlaidConfig(plaid_environment, client_id, secret, client_timestamp);
    client_public_key_bytes_ = client_public_key_bytes;
    encrypted_input_ = encrypted_input;
    ecdh(local_private_key, client_public_key_bytes_, symmetric_key_);
}

PlaidLinkRequest::PlaidLinkRequest(const char *client_id,
                                   const char *secret,
                                   const char *client_user_id,
                                   const char *country,
                                   const char *redirect_uri,
                                   const char *plaid_environment,
                                   uint8_t *client_public_key_bytes,
                                   int32_t client_timestamp,
                                   uint8_t *encrypted_input,
                                   const sgx_ec256_private_t *local_private_key)
    : PlaidRequest(client_id,
                   secret,
                   plaid_environment,
                   client_public_key_bytes,
                   client_timestamp,
                   encrypted_input,
                   local_private_key)
{
    if (redirect_uri == nullptr || client_user_id == nullptr || country == nullptr)
        THROW_EXCEPTION(kInvalidInput, "One or more of the function argument pointers is NULL");
    redirect_uri_ = redirect_uri;
    client_user_id_ = client_user_id;
    country_ = country;
}

std::vector<uint8_t> PlaidLinkRequest::get_decrypted_input() const
{
    sgx_status_t ret;
    std::array<uint8_t, 1> temp_out{};
    uint32_t timestamp = get_client_timestamp();
    if ((ret = aes_decrypt(symmetric_key_,
                           encrypted_input_,
                           1,
                           reinterpret_cast<uint8_t *>(&timestamp),
                           4,
                           temp_out.data())) != SGX_SUCCESS)
    {
        ERROR_LOG("Decryption failed: %s", sgx_error_message("aes_decrypt", ret).c_str());
        THROW_ERROR_CODE(kDecryptionError);
    }
    std::vector<uint8_t> output(temp_out.begin(), temp_out.end());
    return output;
}

ProofRequest::ProofRequest(const char *client_id,
                           const char *secret,
                           const char *plaid_environment,
                           uint8_t *client_public_key_bytes,
                           uint8_t *nonce,
                           int32_t client_timestamp,
                           uint8_t *encrypted_input,
                           const sgx_ec256_private_t *local_private_key)
    : PlaidRequest(client_id,
                   secret,
                   plaid_environment,
                   client_public_key_bytes,
                   client_timestamp,
                   encrypted_input,
                   local_private_key)
{
    if (nonce == nullptr)
        THROW_EXCEPTION(kInvalidInput, "One or more of the function argument pointers is NULL");
    nonce_ = nonce;
}

std::vector<uint8_t> ProofRequest::get_decrypted_input_aad(std::vector<uint8_t> aad,
                                                           bool is_contract) const
{
    sgx_status_t ret;
    if (is_contract)
    {
        std::array<uint8_t, 121> decrypted_data{};
        ret = aes_decrypt(symmetric_key_,
                          encrypted_input_,
                          121,
                          aad.data(),
                          static_cast<uint32_t>(aad.size()),
                          decrypted_data.data());
        if (ret == SGX_SUCCESS)
        {
            std::vector<uint8_t> output(decrypted_data.begin(), decrypted_data.end());
            return output;
        }
    }
    else
    {
        std::array<uint8_t, 56> decrypted_data{};
        ret = aes_decrypt(symmetric_key_,
                          encrypted_input_,
                          56,
                          aad.data(),
                          static_cast<uint32_t>(aad.size()),
                          decrypted_data.data());
        if (ret == SGX_SUCCESS)
        {
            std::vector<uint8_t> output(decrypted_data.begin(), decrypted_data.end());
            return output;
        }
    }
    ERROR_LOG("Decryption failed: %s", sgx_error_message("aes_decrypt", ret).c_str());
    THROW_EXCEPTION(sgx_error_status(ret), "Decryption failed");
}

BalanceProofRequest::BalanceProofRequest(const char *client_id,
                                         const char *secret,
                                         const char *plaid_environment,
                                         uint8_t *client_public_key_bytes,
                                         uint8_t *nonce,
                                         const char *currency_code,
                                         uint32_t minimum_balance,
                                         bool contract,
                                         int32_t client_timestamp,
                                         uint8_t *encrypted_input,
                                         const sgx_ec256_private_t *local_private_key)
    : ProofRequest(client_id,
                   secret,
                   plaid_environment,
                   client_public_key_bytes,
                   nonce,
                   client_timestamp,
                   encrypted_input,
                   local_private_key),
      minimum_balance_(minimum_balance), contract_(contract)
{
    // Validate function argument pointers
    if (currency_code == nullptr)
        THROW_EXCEPTION(kInvalidInput, "One or more of the function argument pointers is NULL");
    currency_code_ = currency_code;
}

std::vector<uint8_t> BalanceProofRequest::get_decrypted_input() const
{
    // Construct additional authenticated data
    uint32_t timestamp = get_client_timestamp();
    std::array<uint8_t, 16 + 4 + 4> aad{};
    std::memcpy(aad.data(), nonce_, 16);
    std::memcpy(aad.data() + 16, &minimum_balance_, 4);
    std::memcpy(aad.data() + 16 + 4, &timestamp, 4);
    std::vector<uint8_t> aad_vec(aad.begin(), aad.end());
    return get_decrypted_input_aad(aad_vec, contract_);
}

IncomeProofRequest::IncomeProofRequest(const char *client_id,
                                       const char *secret,
                                       const char *plaid_environment,
                                       uint8_t *client_public_key_bytes,
                                       uint8_t *nonce,
                                       const char *currency_code,
                                       uint32_t consistent_income,
                                       bool stable,
                                       bool contract,
                                       int32_t client_timestamp,
                                       uint8_t *encrypted_input,
                                       const sgx_ec256_private_t *local_private_key)
    : ProofRequest(client_id,
                   secret,
                   plaid_environment,
                   client_public_key_bytes,
                   nonce,
                   client_timestamp,
                   encrypted_input,
                   local_private_key),
      consistent_income_(consistent_income), stable_(stable), contract_(contract)
{
    // Validate function argument pointers
    if (currency_code == nullptr)
        THROW_EXCEPTION(kInvalidInput, "One or more of the function argument pointers is NULL");
    currency_code_ = currency_code;
}

std::vector<uint8_t> IncomeProofRequest::get_decrypted_input() const
{
    // Construct additional authenticated data
    uint32_t timestamp = get_client_timestamp();
    std::array<uint8_t, 16 + 4 + 4> aad{};
    std::memcpy(aad.data(), nonce_, 16);
    std::memcpy(aad.data() + 16, &consistent_income_, 4);
    std::memcpy(aad.data() + 16 + 4, &timestamp, 4);
    std::vector<uint8_t> aad_vec(aad.begin(), aad.end());
    return get_decrypted_input_aad(aad_vec, contract_);
}

OwnershipProofRequest::OwnershipProofRequest(const char *client_id,
                                             const char *secret,
                                             const char *plaid_environment,
                                             uint8_t *client_public_key_bytes,
                                             uint8_t *nonce,
                                             uint32_t account_number,
                                             uint32_t sort_code,
                                             const char *iban,
                                             int32_t client_timestamp,
                                             uint8_t *encrypted_input,
                                             const sgx_ec256_private_t *local_private_key)
    : ProofRequest(client_id,
                   secret,
                   plaid_environment,
                   client_public_key_bytes,
                   nonce,
                   client_timestamp,
                   encrypted_input,
                   local_private_key),
      account_number_(account_number), sort_code_(sort_code), iban_(iban)
{
}

std::vector<uint8_t> OwnershipProofRequest::get_decrypted_input() const
{
    // Construct additional authenticated data
    uint32_t timestamp = get_client_timestamp();
    std::array<uint8_t, 16 + 4 + 4 + 35 + 4> aad{};
    std::memcpy(aad.data(), nonce_, 16);
    std::memcpy(aad.data() + 16, &account_number_, 4);
    std::memcpy(aad.data() + 16 + 4, &sort_code_, 4);
    std::memcpy(aad.data() + 16 + 4 + 4, iban_.data(), iban_.size());
    std::memcpy(aad.data() + 16 + 4 + 4 + 35, &timestamp, 4);
    std::vector<uint8_t> aad_vec(aad.begin(), aad.end());
    return get_decrypted_input_aad(aad_vec, false);
}

} // namespace enclave
} // namespace silentdata
