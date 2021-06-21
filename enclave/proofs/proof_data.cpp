#include "enclave/proofs/proof_data.hpp"

namespace silentdata
{
namespace enclave
{

std::vector<uint8_t> serialize_proof_data(ProofType type,
                                          uint8_t *nonce,
                                          const std::string &http_timestamp,
                                          const std::string &account_holder_name,
                                          const std::string &institution_name,
                                          const std::string &currency_code,
                                          uint32_t comparison_value,
                                          int32_t unix_timestamp,
                                          const std::string &certificate_chain)
{
    if (type == kMinimumBalanceProof)
        DEBUG_LOG("Serializing minimum balance proof data.");
    else if (type == kConsistentIncomeProof)
        DEBUG_LOG("Serializing consistent income proof data.");
    else if (type == kStableIncomeProof)
        DEBUG_LOG("Serializing stable income proof data.");
    else
        THROW_EXCEPTION(kSigningError, "Invalid proof type");

    std::vector<uint8_t> proof_data(356 + certificate_chain.length(), 0);
    auto cursor = proof_data.begin();

    std::copy(proof_data_version.begin(), proof_data_version.end(), cursor);
    std::advance(cursor, 6);

    uint16_t type_uint = static_cast<uint16_t>(type);
    std::memcpy(&*cursor, &type_uint, 2);
    std::advance(cursor, 2);

    std::copy(nonce, nonce + 16, cursor);
    std::advance(cursor, 16);

    if (http_timestamp.length() > 63)
        THROW_EXCEPTION(kSigningDataFieldTooLong, "HTTP timestamp longer than 63 chars");
    std::copy(http_timestamp.begin(), http_timestamp.end(), cursor);
    std::advance(cursor, 64);

    if (account_holder_name.length() > 127)
        THROW_EXCEPTION(kSigningDataFieldTooLong, "Account holder name longer than 127 chars");
    std::copy(account_holder_name.begin(), account_holder_name.end(), cursor);
    std::advance(cursor, 128);

    if (institution_name.length() > 127)
        THROW_EXCEPTION(kSigningDataFieldTooLong, "Institution name longer than 127 chars");
    std::copy(institution_name.begin(), institution_name.end(), cursor);
    std::advance(cursor, 128);

    if (currency_code.length() > 3)
        THROW_EXCEPTION(kSigningDataFieldTooLong, "Currency code longer than 3 chars");
    std::copy(currency_code.begin(), currency_code.end(), cursor);
    std::advance(cursor, 4);

    std::memcpy(&*cursor, &comparison_value, 4);
    std::advance(cursor, 4);

    std::memcpy(&*cursor, &unix_timestamp, 4);
    std::advance(cursor, 4);

    std::copy(certificate_chain.begin(), certificate_chain.end(), cursor);

    DEBUG_HEX_LOG("Proof data", proof_data.data(), (int)proof_data.size());

    return proof_data;
}

// Create a padded structure of the proof data for contracts
std::vector<uint8_t> serialize_contract_proof_data(ProofType type,
                                                   uint8_t *nonce,
                                                   uint8_t *wallet_signature,
                                                   const std::string &http_timestamp,
                                                   const std::string &currency_code,
                                                   uint32_t comparison_value,
                                                   int32_t unix_timestamp,
                                                   const std::string &certificate_chain)
{
    if (type == kMinimumBalanceProof)
        DEBUG_LOG("Serializing minimum balance proof data.");
    else if (type == kConsistentIncomeProof)
        DEBUG_LOG("Serializing consistent income proof data.");
    else if (type == kStableIncomeProof)
        DEBUG_LOG("Serializing stable income proof data.");
    else
        THROW_EXCEPTION(kSigningError, "Invalid proof type");

    std::vector<uint8_t> proof_data(165 + certificate_chain.length(), 0);
    auto cursor = proof_data.begin();

    std::copy(proof_data_version.begin(), proof_data_version.end(), cursor);
    std::advance(cursor, 6);

    uint16_t type_uint = static_cast<uint16_t>(type);
    std::memcpy(&*cursor, &type_uint, 2);
    std::advance(cursor, 2);

    std::copy(nonce, nonce + 16, cursor);
    std::advance(cursor, 16);

    std::copy(wallet_signature, wallet_signature + 65, cursor);
    std::advance(cursor, 65);

    if (http_timestamp.length() > 63)
        THROW_EXCEPTION(kSigningDataFieldTooLong, "HTTP timestamp longer than 63 chars");
    std::copy(http_timestamp.begin(), http_timestamp.end(), cursor);
    std::advance(cursor, 64);

    if (currency_code.length() > 3)
        THROW_EXCEPTION(kSigningDataFieldTooLong, "Currency code longer than 3 chars");
    std::copy(currency_code.begin(), currency_code.end(), cursor);
    std::advance(cursor, 4);

    std::memcpy(&*cursor, &comparison_value, 4);
    std::advance(cursor, 4);

    std::memcpy(&*cursor, &unix_timestamp, 4);
    std::advance(cursor, 4);

    std::copy(certificate_chain.begin(), certificate_chain.end(), cursor);

    DEBUG_HEX_LOG("Proof data", proof_data.data(), (int)proof_data.size());

    return proof_data;
}

std::vector<uint8_t> serialize_account_ownership_proof_data(uint8_t *nonce,
                                                            const std::string &http_timestamp,
                                                            const std::string &account_holder_name,
                                                            const std::string &institution_name,
                                                            AuthSupport supported_bank_info,
                                                            uint32_t account_number,
                                                            uint32_t sort_code,
                                                            const std::string &iban,
                                                            int32_t unix_timestamp,
                                                            const std::string &certificate_chain)
{
    DEBUG_LOG("Serializing account ownership proof data.");
    std::vector<uint8_t> proof_data(393 + certificate_chain.length(), 0);
    auto cursor = proof_data.begin();

    std::copy(proof_data_version.begin(), proof_data_version.end(), cursor);
    std::advance(cursor, 6);

    uint16_t type_uint = static_cast<uint16_t>(kAccountOwnershipProof);
    std::memcpy(&*cursor, &type_uint, 2);
    std::advance(cursor, 2);

    std::copy(nonce, nonce + 16, cursor);
    std::advance(cursor, 16);

    if (http_timestamp.length() > 63)
        THROW_EXCEPTION(kSigningDataFieldTooLong, "HTTP timestamp longer than 63 chars");
    std::copy(http_timestamp.begin(), http_timestamp.end(), cursor);
    std::advance(cursor, 64);

    if (account_holder_name.length() > 127)
        THROW_EXCEPTION(kSigningDataFieldTooLong, "Account holder name longer than 127 chars");
    std::copy(account_holder_name.begin(), account_holder_name.end(), cursor);
    std::advance(cursor, 128);

    if (institution_name.length() > 127)
        THROW_EXCEPTION(kSigningDataFieldTooLong, "Institution name longer than 127 chars");
    std::copy(institution_name.begin(), institution_name.end(), cursor);
    std::advance(cursor, 128);

    uint16_t support_uint = static_cast<uint16_t>(supported_bank_info);
    std::memcpy(&*cursor, &support_uint, 2);
    std::advance(cursor, 2);

    std::memcpy(&*cursor, &account_number, 4);
    std::advance(cursor, 4);

    std::memcpy(&*cursor, &sort_code, 4);
    std::advance(cursor, 4);

    if (iban.length() > 34)
        THROW_EXCEPTION(kSigningDataFieldTooLong, "IBAN longer than 34 chars");
    std::copy(iban.begin(), iban.end(), cursor);
    std::advance(cursor, 35);

    std::memcpy(&*cursor, &unix_timestamp, 4);
    std::advance(cursor, 4);

    std::copy(certificate_chain.begin(), certificate_chain.end(), cursor);

    DEBUG_HEX_LOG("Proof data", proof_data.data(), (int)proof_data.size());

    return proof_data;
}
} // namespace enclave
} // namespace silentdata
