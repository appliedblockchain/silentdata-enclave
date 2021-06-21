#include "enclave/proofs/proof_handlers.hpp"

namespace silentdata
{
namespace enclave
{

BalanceProofResult process_balance_proof(const BalanceProofRequest &request,
                                         const RSAParams &signature_rsa_params)
{
    BalanceProofResult result;
    result.status = kUnknownError;

    // Decrypt public token (and wallet signature if this is a contract proof)
    std::array<uint8_t, 56> public_token{};
    std::array<uint8_t, 65> wallet_signature{};
    std::vector<uint8_t> decrypted_data = request.get_decrypted_input();
    std::memcpy(public_token.data(), decrypted_data.data(), 56);
    if (request.is_contract())
        std::memcpy(wallet_signature.data(), decrypted_data.data() + 56, 65);

    // Configure the Plaid options
    PlaidClient plaid(request.get_plaid_config());

    //  Access token request
    plaid.get_access(reinterpret_cast<char *>(public_token.data()));

    //  Account balance request
    BankBalance balance = plaid.get_total_balance(request.get_currency_code());

    // Do the proof check
    if (!check_minimum_balance(balance, request.get_currency_code(), request.get_minimum_balance()))
    {
        result.status = kMinimumBalanceRequirementsNotMet;
        return result;
    }

    // Account holder name and institution name requests
    std::string account_holder_name = plaid.get_account_holder_name();
    std::string institution_name = plaid.get_institution_name();

    // Access (and public) token destruction request
    plaid.destroy_access();

    // Proof data and signature verification
    result.timestamp = plaid.get_timestamp();
    result.account_holder_name = account_holder_name;
    result.institution_name = institution_name;
    result.wallet_signature = wallet_signature;
    result.certificate_chain = plaid.get_certificate_chain();
    result.sign(request, signature_rsa_params);
    result.status = kSuccess;

    return result;
}

IncomeProofResult process_income_proof(const IncomeProofRequest &request,
                                       const RSAParams &signature_rsa_params)
{
    IncomeProofResult result;
    result.status = kUnknownError;

    // Decrypt public token (and wallet signature if this is a contract proof)
    std::array<uint8_t, 56> public_token{};
    std::array<uint8_t, 65> wallet_signature{};
    std::vector<uint8_t> decrypted_data = request.get_decrypted_input();
    std::memcpy(public_token.data(), decrypted_data.data(), 56);
    if (request.is_contract())
        std::memcpy(wallet_signature.data(), decrypted_data.data() + 56, 65);

    // Configure the Plaid options
    PlaidClient plaid(request.get_plaid_config());

    //  Access token request
    plaid.get_access(reinterpret_cast<char *>(public_token.data()));

    //  Account income request
    // Get a date range spanning the previous 3 full months
    struct tm start_date = {};
    struct tm end_date = {};
    end_date = http_date_to_tm(plaid.get_timestamp());
    start_date = subtract_tm_months(end_date, 3);
    std::vector<BankTransaction> transactions = plaid.get_all_transactions(start_date, end_date);

    // Do the proof check
    if ((request.is_stable() && !check_stable_income(transactions,
                                                     start_date,
                                                     end_date,
                                                     request.get_currency_code(),
                                                     request.get_consistent_income())) ||
        (!request.is_stable() && !check_consistent_income(transactions,
                                                          start_date,
                                                          end_date,
                                                          request.get_currency_code(),
                                                          request.get_consistent_income())))
    {
        WARNING_LOG("Consistent stable income requirements were not met");
        result.status = kConsistentIncomeRequirementsNotMet;
        return result;
    }

    // Account holder name and institution name requests
    std::string account_holder_name = plaid.get_account_holder_name();
    std::string institution_name = plaid.get_institution_name();

    // Access (and public) token destruction request
    plaid.destroy_access();

    result.timestamp = plaid.get_timestamp();
    result.account_holder_name = account_holder_name;
    result.institution_name = institution_name;
    result.wallet_signature = wallet_signature;
    result.certificate_chain = plaid.get_certificate_chain();
    result.sign(request, signature_rsa_params);
    result.status = kSuccess;

    return result;
}

OwnershipProofResult process_ownership_proof(const OwnershipProofRequest &request,
                                             const RSAParams &signature_rsa_params)
{
    OwnershipProofResult result;
    result.status = kUnknownError;

    // Decrypt public token
    std::vector<uint8_t> public_token = request.get_decrypted_input();

    // Configure the Plaid options
    PlaidClient plaid(request.get_plaid_config());

    //  Access token request
    plaid.get_access(reinterpret_cast<char *>(public_token.data()));

    //  Account details request
    std::vector<AccountDetails> account_details = plaid.get_account_details();

    // Do the ownership proof check
    AccountMatchResult account_match_result = match_account(
        account_details, request.get_account_number(), request.get_sort_code(), request.get_iban());

    //  Account holder name and institution name requests
    std::string account_holder_name =
        plaid.get_account_holder_name(account_match_result.matched_account_id);
    std::string institution_name = plaid.get_institution_name();

    // Access (and public) token destruction request
    plaid.destroy_access();

    result.timestamp = plaid.get_timestamp();
    result.account_holder_name = account_holder_name;
    result.institution_name = institution_name;
    result.certificate_chain = plaid.get_certificate_chain();
    result.supported_bank_info = account_match_result.supported_bank_info;
    result.sign(request, signature_rsa_params);
    result.status = kSuccess;

    return result;
}

} // namespace enclave
} // namespace silentdata
