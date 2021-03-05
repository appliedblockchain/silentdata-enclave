#include "enclave/plaid/plaid_attestation.hpp"

namespace silentdata
{
namespace enclave
{

std::vector<uint8_t> create_plaid_attestation_data(attestation_type type,
                                                   uint8_t *nonce,
                                                   const std::string &http_timestamp,
                                                   const std::string &account_holder_name,
                                                   const std::string &institution_name,
                                                   int32_t comparison_value,
                                                   int32_t unix_timestamp,
                                                   const std::string &certificate_chain)
{
    if (type == kMinimumBalanceAttestation)
        DEBUG_LOG("Serializing minimum balance attestation data.");
    else if (type == kConsistentIncomeAttestation)
        DEBUG_LOG("Serializing consistent income attestation data.");
    else
        THROW_EXCEPTION(kSigningError, "Invalid attestation type");

    std::vector<uint8_t> attestation_data(346 + certificate_chain.length(), 0);
    auto cursor = attestation_data.begin();

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

    std::memcpy(&*cursor, &comparison_value, 4);
    std::advance(cursor, 4);

    std::memcpy(&*cursor, &unix_timestamp, 4);
    std::advance(cursor, 4);

    std::copy(certificate_chain.begin(), certificate_chain.end(), cursor);

    DEBUG_HEX_LOG("Attestation data", attestation_data.data(), (int)attestation_data.size());

    return attestation_data;
}

std::vector<uint8_t>
create_plaid_account_ownership_attestation_data(uint8_t *nonce,
                                                const std::string &http_timestamp,
                                                const std::string &account_holder_name,
                                                const std::string &institution_name,
                                                auth_support supported_bank_info,
                                                int32_t account_number,
                                                int32_t sort_code,
                                                const std::string &iban,
                                                int32_t unix_timestamp,
                                                const std::string &certificate_chain)
{
    DEBUG_LOG("Serializing account ownership attestation data.");
    std::vector<uint8_t> attestation_data(387 + certificate_chain.length(), 0);
    auto cursor = attestation_data.begin();

    uint16_t type_uint = static_cast<uint16_t>(kAccountOwnershipAttestation);
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

    DEBUG_HEX_LOG("Attestation data", attestation_data.data(), (int)attestation_data.size());

    return attestation_data;
}
} // namespace enclave
} // namespace silentdata
