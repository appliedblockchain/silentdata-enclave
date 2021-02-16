#include "enclave/plaid/plaid_attestation.hpp"

namespace silentdata
{
namespace enclave
{

std::vector<uint8_t> create_plaid_attestation_data(uint16_t attestation_type,
                                                   uint8_t *nonce,
                                                   const std::string &http_timestamp,
                                                   const std::string &account_holder_name,
                                                   const std::string &institution_name,
                                                   int32_t comparison_value,
                                                   int32_t unix_timestamp,
                                                   const std::string &certificate_chain)
{
    std::vector<uint8_t> attestation_data(346 + certificate_chain.length(), 0);
    auto cursor = attestation_data.begin();

    std::memcpy(&*cursor, &attestation_type, 2);
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

    return attestation_data;
}

} // namespace enclave
} // namespace silentdata
