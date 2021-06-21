#include <array>
#include <cmath>
#include <cstring>
#include <map>
#include <string>

#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_utils.h"

#include "enclave/common/date_time.hpp"
#include "enclave/common/enclave_exception.hpp"
#include "enclave/common/enclave_logger.hpp"
#include "enclave/common/sgx_error_message.hpp"
#include "enclave/common/types.hpp"
#include "enclave/core_status_codes.h"
#include "enclave/crypto/ecc_key_pair.hpp"
#include "enclave/crypto/enclave_crypto.hpp"
#include "enclave/crypto/rsa_params.hpp"
#include "enclave/plaid/plaid_client.hpp"
#include "enclave/proofs/proof_data.hpp"
#include "enclave/proofs/proof_handlers.hpp"
#include "enclave/proofs/request_types.hpp"
#include "enclave/proofs/result_types.hpp"
#include "enclave_t.h"

using namespace silentdata::enclave;

static const RSAParams sig_rsa_params;
static const ECCKeyPair enc_key_pair;

//
//  Enclave ECalls
//

// Return the enclave's public keys
// Output: - sig_modulus = public key used for signatures
//         - enc_public_key = public key used for encryption
CoreStatusCode get_keys(uint8_t *sig_modulus, uint8_t *enc_public_key)
{
    DEBUG_LOG("Validating function argument pointers");
    // Validate function argument pointers
    if (sig_modulus == nullptr || enc_public_key == nullptr)
        return kInvalidInput;

    // Copy the public keys
    DEBUG_HEX_LOG("Signing public key modulus:", sig_rsa_params.n, sizeof(sig_rsa_params.n));
    memcpy(sig_modulus, sig_rsa_params.n, sizeof(sig_rsa_params.n));
    DEBUG_HEX_LOG("Encryption public key gx:", enc_key_pair.public_key.gx, 32);
    memcpy(enc_public_key, enc_key_pair.public_key.gx, 32);
    DEBUG_HEX_LOG("Encryption public key gy:", enc_key_pair.public_key.gy, 32);
    memcpy(enc_public_key + 32, enc_key_pair.public_key.gy, 32);
    return kSuccess;
}

// Return the report required for verifying the enclave
// Input: - p_qe_target = Struct containing information about the target (quoting) enclave, used to
//                        generate a local proof report which can then be verified by the
//                        target and converted to a quote
// Output: - p_report = Struct containing the report information for the enclave
CoreStatusCode get_report(sgx_target_info_t *p_qe_target, sgx_report_t *p_report)
{
    // Validate function argument pointers
    if (p_qe_target == nullptr || p_report == nullptr)
        return kInvalidInput;

    sgx_status_t ret;
    sgx_report_data_t report_data = {{0}};

    // Create the hash of the concatenation of the public keys
    DEBUG_LOG("Creating hash of public keys");
    std::array<uint8_t, 384 + 32 + 32> msg{};
    auto msg_void_ptr = msg.begin();
    memcpy(msg_void_ptr, sig_rsa_params.n, 384);
    memcpy(msg_void_ptr + 384, enc_key_pair.public_key.gx, 32);
    memcpy(msg_void_ptr + 384 + 32, enc_key_pair.public_key.gy, 32);
    sgx_sha256_hash_t hash;
    ret = sgx_sha256_msg(msg.data(), msg.size(), &hash);
    if (ret != SGX_SUCCESS)
    {
        ERROR_LOG("Failed to create hash of public keys: %s",
                  sgx_error_message("sgx_sha256_msg", ret).c_str());
        return sgx_error_status(ret);
    }

    // The hash will be (the first half of) the report data
    memcpy(&report_data, hash, sizeof(hash));

    DEBUG_LOG("Creating report");
    ret = sgx_create_report(p_qe_target, &report_data, p_report);
    if (ret != SGX_SUCCESS)
    {
        ERROR_LOG("Failed to create report: %s",
                  sgx_error_message("sgx_create_report", ret).c_str());
        return sgx_error_status(ret);
    }

    return kSuccess;
}

// Obtain a link token from the Plaid API with the SILENTDATA client ID and
// secret
// Input:  - client_id = Private identifier for team on Plaid
//         - secret = Private key for Plaid environment
//         - client_user_id = Identifier for particular user
//         - redirect_uri
//         - plaid_environment (sandbox, development, production)
//         - client_public_key_bytes = Client's ECDH public key
//         - client_timestamp = Current timestamp sent by the client
//         - encrypted_input = Cryptographic data to verify timestamp parameter
// Output: - enc_data = Link token data encrypted with the symmetric key derived via ECDH
CoreStatusCode plaid_get_link_token(const char *client_id,
                                    const char *secret,
                                    const char *client_user_id,
                                    const char *country,
                                    const char *redirect_uri,
                                    const char *plaid_environment,
                                    uint8_t *client_public_key_bytes,
                                    int32_t client_timestamp,
                                    uint8_t *encrypted_input,
                                    uint8_t *encrypted_output)
{
    PlaidLinkRequest request(client_id,
                             secret,
                             client_user_id,
                             country,
                             redirect_uri,
                             plaid_environment,
                             client_public_key_bytes,
                             client_timestamp,
                             encrypted_input,
                             &enc_key_pair.private_key);

    // Checks that the key is ok
    try
    {
        request.get_decrypted_input();
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }

    // Configure the Plaid options
    PlaidClient plaid(request.get_plaid_config());

    PlaidLink plaid_link;
    try
    {
        plaid_link = plaid.create_link_token(
            request.get_client_user_id(), request.get_redirect_uri(), request.get_country());
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }

    std::array<uint8_t, 304> link{};
    std::copy(plaid_link.token.begin(), plaid_link.token.end(), link.data());
    std::copy(plaid_link.expiration.begin(), plaid_link.expiration.end(), link.data() + 100);
    std::copy(plaid_link.request_id.begin(), plaid_link.request_id.end(), link.data() + 200);
    memcpy(link.begin() + 300, &client_timestamp, 4);

    try
    {
        aes_encrypt(
            *(request.get_symmetric_key()), link.data(), link.size(), nullptr, 0, encrypted_output);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return kEncryptionError;
    }

    return kSuccess;
}

// Exchange a public token for an access token and obtain the users total bank
// balance from the Plaid API and compare it against a given value
// Input:  - client_id = Private identifier for team on Plaid
//         - secret = Private key for Plaid environment
//         - plaid_environment (sandbox, development, production)
//         - client_public_key_bytes = Client's ECDH public key
//         - nonce = SILENTDATA proof request ID
//         - minimum_balance = The value to check the balance against
//         - client_timestamp = Current timestamp sent by the client
//         - encrypted_input = public token, encrypted
// Output: - proof = A struct containing result
//         - certificate_chain = The certificate chain for Plaid
//         - signature = proof + certificate chain signed with private key
CoreStatusCode plaid_minimum_balance_proof(const char *client_id,
                                           const char *secret,
                                           const char *plaid_environment,
                                           uint8_t *client_public_key_bytes,
                                           uint8_t *nonce,
                                           const char *currency_code,
                                           uint32_t minimum_balance,
                                           int32_t client_timestamp,
                                           uint8_t *encrypted_input,
                                           MinimumBalanceProofData *proof_data,
                                           char *certificate_chain,
                                           uint8_t *signature)
{
    // Validate function argument output pointers
    if (proof_data == nullptr || certificate_chain == nullptr || signature == nullptr)
    {
        ERROR_LOG("One or more of the function argument pointers is NULL");
        return kInvalidInput;
    }

    // Initialise padded struct
    std::memset(proof_data, 0, sizeof(MinimumBalanceProofData));

    BalanceProofRequest request(client_id,
                                secret,
                                plaid_environment,
                                client_public_key_bytes,
                                nonce,
                                currency_code,
                                minimum_balance,
                                false,
                                client_timestamp,
                                encrypted_input,
                                &enc_key_pair.private_key);
    BalanceProofResult result;
    try
    {
        result = process_balance_proof(request, sig_rsa_params);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    catch (...)
    {
        return kUnknownError;
    }
    if (result.status != kSuccess)
        return result.status;

    // Write proof data to the output pointers
    std::copy(proof_data_version.begin(), proof_data_version.end(), proof_data->version);
    memcpy(proof_data->nonce, nonce, 16);
    std::copy(result.timestamp.begin(), result.timestamp.end(), proof_data->timestamp);
    std::copy(result.account_holder_name.begin(),
              result.account_holder_name.end(),
              proof_data->account_holder_name);
    std::copy(result.institution_name.begin(),
              result.institution_name.end(),
              proof_data->institution_name);
    proof_data->minimum_balance = minimum_balance;
    std::copy(result.certificate_chain.begin(), result.certificate_chain.end(), certificate_chain);
    memcpy(signature, result.signature, 384);

    return kSuccess;
}

CoreStatusCode plaid_minimum_balance_contract_proof(const char *client_id,
                                                    const char *secret,
                                                    const char *plaid_environment,
                                                    uint8_t *client_public_key_bytes,
                                                    uint8_t *nonce,
                                                    const char *currency_code,
                                                    uint32_t minimum_balance,
                                                    int32_t client_timestamp,
                                                    uint8_t *encrypted_input,
                                                    MinimumBalanceContractProofData *proof_data,
                                                    char *certificate_chain,
                                                    uint8_t *signature)
{
    // Validate function argument output pointers
    if (proof_data == nullptr || certificate_chain == nullptr || signature == nullptr)
    {
        ERROR_LOG("One or more of the function argument pointers is NULL");
        return kInvalidInput;
    }

    // Initialise padded struct
    std::memset(proof_data, 0, sizeof(MinimumBalanceContractProofData));

    BalanceProofRequest request(client_id,
                                secret,
                                plaid_environment,
                                client_public_key_bytes,
                                nonce,
                                currency_code,
                                minimum_balance,
                                true,
                                client_timestamp,
                                encrypted_input,
                                &enc_key_pair.private_key);
    BalanceProofResult result;
    try
    {
        result = process_balance_proof(request, sig_rsa_params);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    catch (...)
    {
        return kUnknownError;
    }
    if (result.status != kSuccess)
        return result.status;

    // Write proof data to the output pointers
    std::copy(proof_data_version.begin(), proof_data_version.end(), proof_data->version);
    memcpy(proof_data->nonce, nonce, 16);
    std::copy(result.timestamp.begin(), result.timestamp.end(), proof_data->timestamp);
    std::copy(result.wallet_signature.begin(),
              result.wallet_signature.end(),
              proof_data->wallet_signature);
    proof_data->minimum_balance = minimum_balance;
    std::copy(result.certificate_chain.begin(), result.certificate_chain.end(), certificate_chain);
    memcpy(signature, result.signature, 384);

    return kSuccess;
}

// Exchange a public token for an access token and obtain the users transaction data for the last 3
// months and compare the incoming total for each month against a given value
// Input:  - client_id = Private identifier for team on Plaid
//         - secret = Private key for Plaid environment
//         - plaid_environment (sandbox, development, production)
//         - client_public_key_bytes = Client's ECDH public key
//         - nonce = SILENTDATA proof request ID
//         - consistent_income = The value to check the income against
//         - client_timestamp = Current timestamp sent by the client
//         - encrypted_input = public token, encrypted
// Output: - proof = A struct containing result
//         - certificate_chain = The certificate chain for Plaid
//         - signature = proof + certificate chain signed with private key
CoreStatusCode plaid_income_proof(const IncomeProofRequest &request,
                                  ConsistentIncomeProofData *proof_data,
                                  char *certificate_chain,
                                  uint8_t *signature)
{
    // Validate function argument output pointers
    if (proof_data == nullptr || certificate_chain == nullptr || signature == nullptr)
    {
        ERROR_LOG("One or more of the function argument pointers is NULL");
        return kInvalidInput;
    }

    // Initialise padded struct
    std::memset(proof_data, 0, sizeof(ConsistentIncomeProofData));

    IncomeProofResult result;
    try
    {
        result = process_income_proof(request, sig_rsa_params);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    catch (...)
    {
        return kUnknownError;
    }
    if (result.status != kSuccess)
        return result.status;

    // Write proof data to the output pointers
    std::copy(proof_data_version.begin(), proof_data_version.end(), proof_data->version);
    memcpy(proof_data->nonce, request.get_nonce(), 16);
    std::copy(result.timestamp.begin(), result.timestamp.end(), proof_data->timestamp);
    std::copy(result.account_holder_name.begin(),
              result.account_holder_name.end(),
              proof_data->account_holder_name);
    std::copy(result.institution_name.begin(),
              result.institution_name.end(),
              proof_data->institution_name);
    proof_data->consistent_income = request.get_consistent_income();
    std::copy(result.certificate_chain.begin(), result.certificate_chain.end(), certificate_chain);
    memcpy(signature, result.signature, 384);

    return kSuccess;
}

CoreStatusCode plaid_consistent_income_proof(const char *client_id,
                                             const char *secret,
                                             const char *plaid_environment,
                                             uint8_t *client_public_key_bytes,
                                             uint8_t *nonce,
                                             const char *currency_code,
                                             uint32_t consistent_income,
                                             int32_t client_timestamp,
                                             uint8_t *encrypted_input,
                                             ConsistentIncomeProofData *proof_data,
                                             char *certificate_chain,
                                             uint8_t *signature)
{
    IncomeProofRequest request(client_id,
                               secret,
                               plaid_environment,
                               client_public_key_bytes,
                               nonce,
                               currency_code,
                               consistent_income,
                               false,
                               false,
                               client_timestamp,
                               encrypted_input,
                               &enc_key_pair.private_key);
    return plaid_income_proof(request, proof_data, certificate_chain, signature);
}

CoreStatusCode plaid_stable_income_proof(const char *client_id,
                                         const char *secret,
                                         const char *plaid_environment,
                                         uint8_t *client_public_key_bytes,
                                         uint8_t *nonce,
                                         const char *currency_code,
                                         uint32_t consistent_income,
                                         int32_t client_timestamp,
                                         uint8_t *encrypted_input,
                                         ConsistentIncomeProofData *proof_data,
                                         char *certificate_chain,
                                         uint8_t *signature)
{
    IncomeProofRequest request(client_id,
                               secret,
                               plaid_environment,
                               client_public_key_bytes,
                               nonce,
                               currency_code,
                               consistent_income,
                               true,
                               false,
                               client_timestamp,
                               encrypted_input,
                               &enc_key_pair.private_key);
    return plaid_income_proof(request, proof_data, certificate_chain, signature);
}

CoreStatusCode plaid_income_contract_proof(const IncomeProofRequest &request,
                                           ConsistentIncomeContractProofData *proof_data,
                                           char *certificate_chain,
                                           uint8_t *signature)
{
    // Validate function argument pointers
    if (proof_data == nullptr || certificate_chain == nullptr || signature == nullptr)
    {
        ERROR_LOG("One or more of the function argument pointers is NULL");
        return kInvalidInput;
    }

    // Initialise padded struct
    std::memset(proof_data, 0, sizeof(ConsistentIncomeContractProofData));

    IncomeProofResult result;
    try
    {
        result = process_income_proof(request, sig_rsa_params);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    catch (...)
    {
        return kUnknownError;
    }
    if (result.status != kSuccess)
        return result.status;

    // Write proof data to the output pointers
    std::copy(proof_data_version.begin(), proof_data_version.end(), proof_data->version);
    memcpy(proof_data->nonce, request.get_nonce(), 16);
    std::copy(result.timestamp.begin(), result.timestamp.end(), proof_data->timestamp);
    std::copy(result.wallet_signature.begin(),
              result.wallet_signature.end(),
              proof_data->wallet_signature);
    proof_data->consistent_income = request.get_consistent_income();
    std::copy(result.certificate_chain.begin(), result.certificate_chain.end(), certificate_chain);
    memcpy(signature, result.signature, 384);

    return kSuccess;
}

CoreStatusCode plaid_consistent_income_contract_proof(const char *client_id,
                                                      const char *secret,
                                                      const char *plaid_environment,
                                                      uint8_t *client_public_key_bytes,
                                                      uint8_t *nonce,
                                                      const char *currency_code,
                                                      uint32_t consistent_income,
                                                      int32_t client_timestamp,
                                                      uint8_t *encrypted_input,
                                                      ConsistentIncomeContractProofData *proof_data,
                                                      char *certificate_chain,
                                                      uint8_t *signature)
{
    IncomeProofRequest request(client_id,
                               secret,
                               plaid_environment,
                               client_public_key_bytes,
                               nonce,
                               currency_code,
                               consistent_income,
                               false,
                               true,
                               client_timestamp,
                               encrypted_input,
                               &enc_key_pair.private_key);
    return plaid_income_contract_proof(request, proof_data, certificate_chain, signature);
}

CoreStatusCode plaid_stable_income_contract_proof(const char *client_id,
                                                  const char *secret,
                                                  const char *plaid_environment,
                                                  uint8_t *client_public_key_bytes,
                                                  uint8_t *nonce,
                                                  const char *currency_code,
                                                  uint32_t consistent_income,
                                                  int32_t client_timestamp,
                                                  uint8_t *encrypted_input,
                                                  ConsistentIncomeContractProofData *proof_data,
                                                  char *certificate_chain,
                                                  uint8_t *signature)
{
    IncomeProofRequest request(client_id,
                               secret,
                               plaid_environment,
                               client_public_key_bytes,
                               nonce,
                               currency_code,
                               consistent_income,
                               true,
                               true,
                               client_timestamp,
                               encrypted_input,
                               &enc_key_pair.private_key);
    return plaid_income_contract_proof(request, proof_data, certificate_chain, signature);
}

// Exchange a public token for an access token and obtain the users account holder name from the
// Plaid API
// Input:  - client_id = Private identifier for team on Plaid
//         - secret = Private key for Plaid environment
//         - plaid_environment (sandbox, development, production)
//         - client_public_key_bytes = Client's ECDH public key
//         - nonce = SILENTDATA proof request ID
//         - client_timestamp = Current timestamp sent by the client
//         - encrypted_input = public token, encrypted
// Output: - proof = A struct containing result
//         - certificate_chain = The certificate chain for Plaid
//         - signature = proof + certificate chain signed with private key
CoreStatusCode plaid_account_ownership_proof(const char *client_id,
                                             const char *secret,
                                             const char *plaid_environment,
                                             uint8_t *client_public_key_bytes,
                                             uint8_t *nonce,
                                             uint32_t account_number,
                                             uint32_t sort_code,
                                             const char *iban,
                                             int32_t client_timestamp,
                                             uint8_t *encrypted_input,
                                             AccountOwnershipProofData *proof_data,
                                             char *certificate_chain,
                                             uint8_t *signature)
{
    // Validate function argument output pointers
    if (proof_data == nullptr || certificate_chain == nullptr || signature == nullptr)
    {
        ERROR_LOG("One or more of the function argument pointers is NULL");
        return kInvalidInput;
    }

    // Initialise padded struct
    std::memset(proof_data, 0, sizeof(AccountOwnershipProofData));

    OwnershipProofRequest request(client_id,
                                  secret,
                                  plaid_environment,
                                  client_public_key_bytes,
                                  nonce,
                                  account_number,
                                  sort_code,
                                  iban,
                                  client_timestamp,
                                  encrypted_input,
                                  &enc_key_pair.private_key);
    OwnershipProofResult result;
    try
    {
        result = process_ownership_proof(request, sig_rsa_params);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    catch (...)
    {
        return kUnknownError;
    }
    if (result.status != kSuccess)
        return result.status;

    // Write proof data to the output pointers
    std::copy(proof_data_version.begin(), proof_data_version.end(), proof_data->version);
    memcpy(proof_data->nonce, nonce, 16);
    std::copy(result.timestamp.begin(), result.timestamp.end(), proof_data->timestamp);
    std::copy(result.account_holder_name.begin(),
              result.account_holder_name.end(),
              proof_data->account_holder_name);
    std::copy(result.institution_name.begin(),
              result.institution_name.end(),
              proof_data->institution_name);
    proof_data->account_number = account_number;
    proof_data->sort_code = sort_code;
    std::string iban_str = iban;
    std::copy(iban_str.begin(), iban_str.end(), proof_data->iban);
    proof_data->supported_bank_info = result.supported_bank_info;
    std::copy(result.certificate_chain.begin(), result.certificate_chain.end(), certificate_chain);
    memcpy(signature, result.signature, 384);

    return kSuccess;
}
