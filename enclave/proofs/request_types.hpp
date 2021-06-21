/*
 * Common proof request/response types
 */

#ifndef SILENTDATA_ENCLAVE_REQUEST_TYPES_H
#define SILENTDATA_ENCLAVE_REQUEST_TYPES_H

#include <array>
#include <string>
#include <vector>

#include "enclave/core_status_codes.h"
#include "enclave/crypto/enclave_crypto.hpp"
#include "enclave/plaid/plaid_client.hpp"
#include "enclave/proofs/proof_data.hpp"

namespace silentdata
{
namespace enclave
{

class PlaidRequest
{
public:
    PlaidRequest(const char *client_id,
                 const char *secret,
                 const char *plaid_environment,
                 uint8_t *client_public_key_bytes,
                 int32_t client_timestamp,
                 uint8_t *encrypted_input,
                 const sgx_ec256_private_t *local_private_key);
    virtual ~PlaidRequest() {}

    PlaidConfig get_plaid_config() const { return plaid_config_; }
    int32_t get_client_timestamp() const { return plaid_config_.timestamp; }
    sgx_aes_gcm_128bit_key_t *get_symmetric_key() { return &symmetric_key_; }
    virtual std::vector<uint8_t> get_decrypted_input() const = 0;

private:
    PlaidConfig plaid_config_;

protected:
    uint8_t *client_public_key_bytes_;
    uint8_t *encrypted_input_;
    sgx_aes_gcm_128bit_key_t symmetric_key_;
};

class PlaidLinkRequest : public PlaidRequest
{
public:
    PlaidLinkRequest(const char *client_id,
                     const char *secret,
                     const char *client_user_id,
                     const char *country,
                     const char *redirect_uri,
                     const char *plaid_environment,
                     uint8_t *client_public_key_bytes,
                     int32_t client_timestamp,
                     uint8_t *encrypted_input,
                     const sgx_ec256_private_t *local_private_key);
    ~PlaidLinkRequest() {}

    std::string get_redirect_uri() const { return redirect_uri_; }
    std::string get_client_user_id() const { return client_user_id_; }
    std::string get_country() const { return country_; }
    std::vector<uint8_t> get_decrypted_input() const;

private:
    std::string redirect_uri_;
    std::string client_user_id_;
    std::string country_;
};

class ProofRequest : public PlaidRequest
{
public:
    ProofRequest(const char *client_id,
                 const char *secret,
                 const char *plaid_environment,
                 uint8_t *client_public_key_bytes,
                 uint8_t *nonce,
                 int32_t client_timestamp,
                 uint8_t *encrypted_input,
                 const sgx_ec256_private_t *local_private_key);
    virtual ~ProofRequest() {}

    uint8_t *get_nonce() const { return nonce_; }

protected:
    uint8_t *nonce_;

    std::vector<uint8_t> get_decrypted_input_aad(std::vector<uint8_t> aad, bool is_contract) const;
};

class BalanceProofRequest : public ProofRequest
{
public:
    BalanceProofRequest(const char *client_id,
                        const char *secret,
                        const char *plaid_environment,
                        uint8_t *client_public_key_bytes,
                        uint8_t *nonce,
                        const char *currency_code,
                        uint32_t minimum_balance,
                        bool contract,
                        int32_t client_timestamp,
                        uint8_t *encrypted_input,
                        const sgx_ec256_private_t *local_private_key);
    ~BalanceProofRequest() {}

    std::string get_currency_code() const { return currency_code_; }
    uint32_t get_minimum_balance() const { return minimum_balance_; }
    bool is_contract() const { return contract_; }
    std::vector<uint8_t> get_decrypted_input() const;

private:
    std::string currency_code_;
    int32_t minimum_balance_;
    bool contract_;
};

class IncomeProofRequest : public ProofRequest
{
public:
    IncomeProofRequest(const char *client_id,
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
                       const sgx_ec256_private_t *local_private_key);
    ~IncomeProofRequest() {}

    std::string get_currency_code() const { return currency_code_; }
    uint32_t get_consistent_income() const { return consistent_income_; }
    bool is_stable() const { return stable_; }
    bool is_contract() const { return contract_; }
    std::vector<uint8_t> get_decrypted_input() const;

private:
    std::string currency_code_;
    uint32_t consistent_income_;
    bool stable_;
    bool contract_;
};

class OwnershipProofRequest : public ProofRequest
{
public:
    OwnershipProofRequest(const char *client_id,
                          const char *secret,
                          const char *plaid_environment,
                          uint8_t *client_public_key_bytes,
                          uint8_t *nonce,
                          uint32_t account_number,
                          uint32_t sort_code,
                          const char *iban,
                          int32_t client_timestamp,
                          uint8_t *encrypted_input,
                          const sgx_ec256_private_t *local_private_key);
    ~OwnershipProofRequest() {}

    uint32_t get_account_number() const { return account_number_; }
    uint32_t get_sort_code() const { return sort_code_; }
    std::string get_iban() const { return iban_; }
    std::vector<uint8_t> get_decrypted_input() const;

private:
    uint32_t account_number_;
    uint32_t sort_code_;
    std::string iban_;
};

} // namespace enclave
} // namespace silentdata

#endif
