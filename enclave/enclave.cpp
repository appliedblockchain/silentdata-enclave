#include <array>
#include <cmath>
#include <cstring>
#include <map>
#include <string>

#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_utils.h"

#include "enclave/client/client_opt.h"
#include "enclave/client/https_client.hpp"
#include "enclave/client/plaid_certificate.h"
#include "enclave/common/date_time.hpp"
#include "enclave/common/enclave_exception.hpp"
#include "enclave/common/enclave_logger.hpp"
#include "enclave/common/sgx_error_message.hpp"
#include "enclave/core_status_codes.h"
#include "enclave/crypto/ecc_key_pair.hpp"
#include "enclave/crypto/enclave_crypto.hpp"
#include "enclave/crypto/rsa_params.hpp"
#include "enclave/plaid/plaid_attestation.hpp"
#include "enclave/plaid/plaid_comparison_functions.hpp"
#include "enclave/plaid/plaid_requests.hpp"
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
core_status_code get_keys(uint8_t *sig_modulus, uint8_t *enc_public_key)
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
//                        generate a local attestation report which can then be verified by the
//                        target and converted to a quote
// Output: - p_report = Struct containing the report information for the enclave
core_status_code get_report(sgx_target_info_t *p_qe_target, sgx_report_t *p_report)
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
core_status_code plaid_get_link_token(const char *client_id,
                                      const char *secret,
                                      const char *client_user_id,
                                      const char *redirect_uri,
                                      const char *plaid_environment,
                                      uint8_t *client_public_key_bytes,
                                      int32_t client_timestamp,
                                      uint8_t *encrypted_input,
                                      uint8_t *enc_data)
{
    // Validate function argument pointers
    if (client_id == nullptr || secret == nullptr || client_user_id == nullptr ||
        redirect_uri == nullptr || plaid_environment == nullptr || encrypted_input == nullptr ||
        enc_data == nullptr)
    {
        ERROR_LOG("One or more of the function argument pointers is NULL");
        return kInvalidInput;
    }

    sgx_aes_gcm_128bit_key_t sym_key;
    try
    {
        ecdh(&enc_key_pair.private_key, client_public_key_bytes, sym_key);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    catch (...)
    {
        ERROR_LOG("ECDH failed");
        return kECDHError;
    }

    sgx_status_t ret;
    std::array<uint8_t, 1> temp_out;
    if ((ret = aes_decrypt(sym_key,
                           encrypted_input,
                           1,
                           reinterpret_cast<uint8_t *>(&client_timestamp),
                           4,
                           temp_out.data())) != SGX_SUCCESS)
    {
        ERROR_LOG("Decryption failed: %s", sgx_error_message("aes_decrypt", ret).c_str());
        return kDecryptionError;
    }

    // Configure the Plaid options
    PlaidConfiguration plaid_config;
    plaid_config.client_id = client_id;
    plaid_config.secret = secret;
    plaid_config.environment = plaid_environment;

    // Configure the HTTPS client options
    ClientOptions opt;
    opt.debug_level = 1;
    opt.server_port = "443";
    opt.close_session = true;
    opt.timestamp = client_timestamp;
    std::string host = plaid_environment + std::string(".plaid.com");
    std::vector<std::string> certificates{plaid_certificate};
    HTTPSClient client(host.c_str(), opt, certificates);

    PlaidLink plaid_link;
    try
    {
        plaid_link = plaid_create_link_token(client, plaid_config, client_user_id, redirect_uri);
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
        aes_encrypt(sym_key, link.data(), link.size(), nullptr, 0, enc_data);
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
//         - nonce = SILENTDATA attestation request ID
//         - minimum_balance = The value to check the balance against
//         - client_timestamp = Current timestamp sent by the client
//         - encrypted_input = public token, encrypted
// Output: - attestation = A struct containing result
//         - certificate_chain = The certificate chain for Plaid
//         - signature = attestation + certificate chain signed with private key
//         - access_status = Whether the access token has been destroyed correctly
core_status_code
plaid_minimum_balance_attestation(const char *client_id,
                                  const char *secret,
                                  const char *plaid_environment,
                                  uint8_t *client_public_key_bytes,
                                  uint8_t *nonce,
                                  int32_t minimum_balance,
                                  int32_t client_timestamp,
                                  uint8_t *encrypted_input,
                                  plaid_minimum_balance_attestation_data *attestation,
                                  char *certificate_chain,
                                  uint8_t *signature,
                                  access_token_status *access_status)
{
    // Validate function argument pointers
    if (client_id == nullptr || secret == nullptr || plaid_environment == nullptr ||
        nonce == nullptr || encrypted_input == nullptr || attestation == nullptr ||
        certificate_chain == nullptr || signature == nullptr || access_status == nullptr)
    {
        ERROR_LOG("One or more of the function argument pointers is NULL");
        return kInvalidInput;
    }

    // Initialise padded struct
    std::memset(attestation, 0, sizeof(plaid_minimum_balance_attestation_data));
    *access_status = kAccessTokenNotCreated;

    sgx_aes_gcm_128bit_key_t sym_key;
    try
    {
        ecdh(&enc_key_pair.private_key, client_public_key_bytes, sym_key);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    catch (...)
    {
        ERROR_LOG("ECDH failed");
        return kECDHError;
    }

    // Construct additional authenticated data
    std::array<uint8_t, 16 + 4 + 4> aad{};
    std::memcpy(aad.data(), nonce, 16);
    std::memcpy(aad.data() + 16, &minimum_balance, 4);
    std::memcpy(aad.data() + 16 + 4, &client_timestamp, 4);

    // Decrypt public token
    std::array<uint8_t, 56> public_token{};
    sgx_status_t ret;
    if ((ret = aes_decrypt(
             sym_key, encrypted_input, 56, aad.data(), aad.size(), public_token.data())) !=
        SGX_SUCCESS)
    {
        ERROR_LOG("Decryption failed: %s", sgx_error_message("aes_decrypt", ret).c_str());
        return sgx_error_status(ret);
    }

    // Configure the Plaid options
    PlaidConfiguration plaid_config;
    plaid_config.client_id = client_id;
    plaid_config.secret = secret;
    plaid_config.environment = plaid_environment;

    // Configure the HTTPS client
    ClientOptions opt;
    opt.debug_level = 1;
    opt.server_port = "443";
    opt.timestamp = client_timestamp;
    std::string host = plaid_environment + std::string(".plaid.com");
    std::vector<std::string> certificates{plaid_certificate};
    HTTPSClient client(host.c_str(), opt, certificates);

    //
    //  Access token request
    //
    PlaidAccess access;
    try
    {
        access =
            plaid_get_access(client, plaid_config, reinterpret_cast<char *>(public_token.data()));
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    *access_status = kAccessTokenCreated;
    plaid_config.access_token = access.token;

    //
    //  Account balance request
    //
    float balance;
    try
    {
        balance = plaid_get_total_balance(client, plaid_config);
    }
    catch (const EnclaveException &e)
    {
        *access_status = plaid_destroy_access(client, plaid_config);
        EXCEPTION_LOG(e);
        return e.get_code();
    }

    // Do the attestation
    if (balance < (float)minimum_balance)
    {
        *access_status = plaid_destroy_access(client, plaid_config);
        WARNING_LOG("Minimum account balance requirements not met");
        return kMinimumBalanceRequirementsNotMet;
    }

    //
    //  Account holder name and institution name requests
    //
    std::string account_holder_name;
    std::string institution_name;
    try
    {
        account_holder_name = plaid_get_account_holder_name(client, plaid_config);
        institution_name = plaid_get_institution_name(client, plaid_config);
    }
    catch (const EnclaveException &e)
    {
        *access_status = plaid_destroy_access(client, plaid_config);
        EXCEPTION_LOG(e);
        return e.get_code();
    }

    //
    // Access (and public) token destruction request
    //
    *access_status = plaid_destroy_access(client, plaid_config);
    if (*access_status == kAccessTokenNotDestroyed)
    {
        ERROR_LOG("Failed to destroy the Plaid access token");
        return kPlaidTokenDestructionError;
    }

    //
    // Attestation data and signature verification
    //
    memcpy(attestation->nonce, nonce, 16);
    std::copy(access.timestamp.begin(), access.timestamp.end(), attestation->timestamp);
    std::copy(
        account_holder_name.begin(), account_holder_name.end(), attestation->account_holder_name);
    std::copy(institution_name.begin(), institution_name.end(), attestation->institution_name);
    attestation->minimum_balance = minimum_balance;
    std::copy(access.certificate_chain.begin(), access.certificate_chain.end(), certificate_chain);

    sgx_rsa3072_signature_t sig;
    try
    {
        std::vector<uint8_t> attestation_data =
            create_plaid_attestation_data(kMinimumBalanceAttestation,
                                          nonce,
                                          access.timestamp,
                                          account_holder_name,
                                          institution_name,
                                          minimum_balance,
                                          client_timestamp,
                                          access.certificate_chain);
        rsa_sign(sig_rsa_params, attestation_data, sig);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    memcpy(signature, sig, 384);
    return kSuccess;
}

// Exchange a public token for an access token and obtain the users transaction data for the last 3
// months and compare the incoming total for each month against a given value
// Input:  - client_id = Private identifier for team on Plaid
//         - secret = Private key for Plaid environment
//         - plaid_environment (sandbox, development, production)
//         - client_public_key_bytes = Client's ECDH public key
//         - nonce = SILENTDATA attestation request ID
//         - consistent_income = The value to check the income against
//         - client_timestamp = Current timestamp sent by the client
//         - encrypted_input = public token, encrypted
// Output: - attestation = A struct containing result
//         - certificate_chain = The certificate chain for Plaid
//         - signature = attestation + certificate chain signed with private key
//         - access_status = Whether the access token has been destroyed correctly
core_status_code
plaid_consistent_income_attestation(const char *client_id,
                                    const char *secret,
                                    const char *plaid_environment,
                                    uint8_t *client_public_key_bytes,
                                    uint8_t *nonce,
                                    int32_t consistent_income,
                                    int32_t client_timestamp,
                                    uint8_t *encrypted_input,
                                    plaid_consistent_income_attestation_data *attestation,
                                    char *certificate_chain,
                                    uint8_t *signature,
                                    access_token_status *access_status)
{
    // Validate function argument pointers
    if (client_id == nullptr || secret == nullptr || plaid_environment == nullptr ||
        nonce == nullptr || encrypted_input == nullptr || attestation == nullptr ||
        certificate_chain == nullptr || signature == nullptr || access_status == nullptr)
    {
        ERROR_LOG("One or more of the function argument pointers is NULL");
        return kInvalidInput;
    }

    // Initialise padded struct
    std::memset(attestation, 0, sizeof(plaid_consistent_income_attestation_data));
    *access_status = kAccessTokenNotCreated;

    sgx_aes_gcm_128bit_key_t sym_key;
    try
    {
        ecdh(&enc_key_pair.private_key, client_public_key_bytes, sym_key);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    catch (...)
    {
        ERROR_LOG("ECDH failed");
        return kECDHError;
    }

    // Construct additional authenticated data
    std::array<uint8_t, 16 + 4 + 4> aad{};
    std::memcpy(aad.data(), nonce, 16);
    std::memcpy(aad.data() + 16, &consistent_income, 4);
    std::memcpy(aad.data() + 16 + 4, &client_timestamp, 4);

    // Decrypt public token
    std::array<uint8_t, 56> public_token{};
    sgx_status_t ret;
    if ((ret = aes_decrypt(
             sym_key, encrypted_input, 56, aad.data(), aad.size(), public_token.data())) !=
        SGX_SUCCESS)
    {
        ERROR_LOG("Decryption failed: %s", sgx_error_message("aes_decrypt", ret).c_str());
        return sgx_error_status(ret);
    }

    // Configure the Plaid options
    PlaidConfiguration plaid_config;
    plaid_config.client_id = client_id;
    plaid_config.secret = secret;
    plaid_config.environment = plaid_environment;

    // Configure the HTTPS client
    ClientOptions opt;
    opt.debug_level = 1;
    opt.server_port = "443";
    opt.timestamp = client_timestamp;
    std::string host = plaid_environment + std::string(".plaid.com");
    std::vector<std::string> certificates{plaid_certificate};
    HTTPSClient client(host.c_str(), opt, certificates);

    //
    //  Access token request
    //
    PlaidAccess access;
    try
    {
        access =
            plaid_get_access(client, plaid_config, reinterpret_cast<char *>(public_token.data()));
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    *access_status = kAccessTokenCreated;
    plaid_config.access_token = access.token;

    //
    //  Account income request
    //
    // Get a date range spanning the previous 3 full months
    struct tm start_date = {};
    struct tm end_date = {};
    try
    {
        end_date = http_date_to_tm(access.timestamp);
        start_date = subtract_tm_months(end_date, 3);
    }
    catch (const EnclaveException &e)
    {
        *access_status = plaid_destroy_access(client, plaid_config);
        EXCEPTION_LOG(e);
        return e.get_code();
    }

    std::vector<PlaidTransaction> transactions;
    try
    {
        transactions = plaid_get_all_transactions(client, plaid_config, start_date, end_date);
    }
    catch (const EnclaveException &e)
    {
        *access_status = plaid_destroy_access(client, plaid_config);
        EXCEPTION_LOG(e);
        return e.get_code();
    }

    if (!plaid_check_income(transactions, start_date, end_date, consistent_income))
    {
        *access_status = plaid_destroy_access(client, plaid_config);
        WARNING_LOG("Consistent income requirements were not met");
        return kConsistentIncomeRequirementsNotMet;
    }

    //
    //  Account holder name and institution name requests
    //
    std::string account_holder_name;
    std::string institution_name;
    try
    {
        account_holder_name = plaid_get_account_holder_name(client, plaid_config);
        institution_name = plaid_get_institution_name(client, plaid_config);
    }
    catch (const EnclaveException &e)
    {
        *access_status = plaid_destroy_access(client, plaid_config);
        EXCEPTION_LOG(e);
        return e.get_code();
    }

    //
    // Access (and public) token destruction request
    //
    *access_status = plaid_destroy_access(client, plaid_config);
    if (*access_status == kAccessTokenNotDestroyed)
    {
        ERROR_LOG("Failed to destroy the Plaid access token");
        return kPlaidTokenDestructionError;
    }

    //
    // Attestation data and signature verification
    //
    memcpy(attestation->nonce, nonce, 16);
    std::copy(access.timestamp.begin(), access.timestamp.end(), attestation->timestamp);
    std::copy(
        account_holder_name.begin(), account_holder_name.end(), attestation->account_holder_name);
    std::copy(institution_name.begin(), institution_name.end(), attestation->institution_name);
    attestation->consistent_income = consistent_income;
    std::copy(access.certificate_chain.begin(), access.certificate_chain.end(), certificate_chain);

    sgx_rsa3072_signature_t sig;
    try
    {
        std::vector<uint8_t> attestation_data =
            create_plaid_attestation_data(kConsistentIncomeAttestation,
                                          nonce,
                                          access.timestamp,
                                          account_holder_name,
                                          institution_name,
                                          consistent_income,
                                          client_timestamp,
                                          access.certificate_chain);
        rsa_sign(sig_rsa_params, attestation_data, sig);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    memcpy(signature, sig, 384);

    return kSuccess;
}

// Exchange a public token for an access token and obtain the users account holder name from the
// Plaid API
// Input:  - client_id = Private identifier for team on Plaid
//         - secret = Private key for Plaid environment
//         - plaid_environment (sandbox, development, production)
//         - client_public_key_bytes = Client's ECDH public key
//         - nonce = SILENTDATA attestation request ID
//         - client_timestamp = Current timestamp sent by the client
//         - encrypted_input = public token, encrypted
// Output: - attestation = A struct containing result
//         - certificate_chain = The certificate chain for Plaid
//         - signature = attestation + certificate chain signed with private key
//         - access_status = Whether the access token has been destroyed correctly
core_status_code
plaid_account_ownership_attestation(const char *client_id,
                                    const char *secret,
                                    const char *plaid_environment,
                                    uint8_t *client_public_key_bytes,
                                    uint8_t *nonce,
                                    uint32_t account_number,
                                    uint32_t sort_code,
                                    const char *iban,
                                    int32_t client_timestamp,
                                    uint8_t *encrypted_input,
                                    plaid_account_ownership_attestation_data *attestation,
                                    char *certificate_chain,
                                    uint8_t *signature,
                                    access_token_status *access_status)
{
    // Validate function argument pointers
    if (client_id == nullptr || secret == nullptr || plaid_environment == nullptr ||
        nonce == nullptr || iban == nullptr || encrypted_input == nullptr ||
        attestation == nullptr || certificate_chain == nullptr || signature == nullptr ||
        access_status == nullptr)
    {
        ERROR_LOG("One or more of the function argument pointers is NULL");
        return kInvalidInput;
    }

    // Initialise padded struct
    std::memset(attestation, 0, sizeof(plaid_account_ownership_attestation_data));
    *access_status = kAccessTokenNotCreated;

    sgx_aes_gcm_128bit_key_t sym_key;
    try
    {
        ecdh(&enc_key_pair.private_key, client_public_key_bytes, sym_key);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    catch (...)
    {
        ERROR_LOG("ECDH failed");
        return kECDHError;
    }

    // Construct additional authenticated data
    std::string iban_str = iban;
    std::array<uint8_t, 16 + 4 + 4 + 35 + 4> aad{};
    std::memcpy(aad.data(), nonce, 16);
    std::memcpy(aad.data() + 16, &account_number, 4);
    std::memcpy(aad.data() + 16 + 4, &sort_code, 4);
    std::memcpy(aad.data() + 16 + 4 + 4, iban_str.data(), iban_str.size());
    std::memcpy(aad.data() + 16 + 4 + 4 + 35, &client_timestamp, 4);

    // Decrypt public token
    std::array<uint8_t, 56> public_token{};
    sgx_status_t ret;
    if ((ret = aes_decrypt(
             sym_key, encrypted_input, 56, aad.data(), aad.size(), public_token.data())) !=
        SGX_SUCCESS)
    {
        ERROR_LOG("Decryption failed: %s", sgx_error_message("aes_decrypt", ret).c_str());
        return sgx_error_status(ret);
    }

    // Configure the Plaid options
    PlaidConfiguration plaid_config;
    plaid_config.client_id = client_id;
    plaid_config.secret = secret;
    plaid_config.environment = plaid_environment;

    // Configure the HTTPS client
    ClientOptions opt;
    opt.debug_level = 1;
    opt.server_port = "443";
    opt.timestamp = client_timestamp;
    std::string host = plaid_environment + std::string(".plaid.com");
    std::vector<std::string> certificates{plaid_certificate};
    HTTPSClient client(host.c_str(), opt, certificates);

    //
    //  Access token request
    //
    PlaidAccess access;
    try
    {
        access =
            plaid_get_access(client, plaid_config, reinterpret_cast<char *>(public_token.data()));
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    *access_status = kAccessTokenCreated;
    plaid_config.access_token = access.token;

    //
    //  Account balance request
    //
    std::vector<PlaidAccount> account_details;
    try
    {
        account_details = plaid_get_account_details(client, plaid_config);
    }
    catch (const EnclaveException &e)
    {
        *access_status = plaid_destroy_access(client, plaid_config);
        EXCEPTION_LOG(e);
        return e.get_code();
    }

    PlaidAccountMatchResult account_match_result;
    try
    {
        account_match_result =
            plaid_match_account(account_details, account_number, sort_code, iban_str);
    }
    catch (const EnclaveException &e)
    {
        *access_status = plaid_destroy_access(client, plaid_config);
        EXCEPTION_LOG(e);
        return e.get_code();
    }

    //
    //  Account holder name and institution name requests
    //
    std::string account_holder_name;
    std::string institution_name;
    try
    {
        account_holder_name = plaid_get_account_holder_name(
            client, plaid_config, account_match_result.matched_account_id);
        institution_name = plaid_get_institution_name(client, plaid_config);
    }
    catch (const EnclaveException &e)
    {
        *access_status = plaid_destroy_access(client, plaid_config);
        EXCEPTION_LOG(e);
        return e.get_code();
    }

    //
    // Access (and public) token destruction request
    //
    *access_status = plaid_destroy_access(client, plaid_config);
    if (*access_status == kAccessTokenNotDestroyed)
    {
        ERROR_LOG("Failed to destroy the Plaid access token");
        return kPlaidTokenDestructionError;
    }

    //
    // Attestation data and signature verification
    //
    memcpy(attestation->nonce, nonce, 16);
    std::copy(access.timestamp.begin(), access.timestamp.end(), attestation->timestamp);
    std::copy(
        account_holder_name.begin(), account_holder_name.end(), attestation->account_holder_name);
    std::copy(institution_name.begin(), institution_name.end(), attestation->institution_name);
    std::copy(access.certificate_chain.begin(), access.certificate_chain.end(), certificate_chain);
    attestation->account_number = account_number;
    attestation->sort_code = sort_code;
    std::copy(iban_str.begin(), iban_str.end(), attestation->iban);
    attestation->supported_bank_info = account_match_result.supported_bank_info;

    sgx_rsa3072_signature_t sig;
    try
    {
        std::vector<uint8_t> attestation_data = create_plaid_account_ownership_attestation_data(
            nonce,
            access.timestamp,
            account_holder_name,
            institution_name,
            account_match_result.supported_bank_info,
            account_number,
            sort_code,
            iban,
            client_timestamp,
            access.certificate_chain);
        rsa_sign(sig_rsa_params, attestation_data, sig);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    memcpy(signature, sig, 384);
    return kSuccess;
}
