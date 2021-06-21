#include "enclave/proofs/result_types.hpp"

namespace silentdata
{
namespace enclave
{

void BalanceProofResult::sign(const BalanceProofRequest &request,
                              const RSAParams &signature_rsa_params)
{
    std::vector<uint8_t> binary_proof_data;
    if (request.is_contract())
    {
        binary_proof_data = serialize_contract_proof_data(kMinimumBalanceProof,
                                                          request.get_nonce(),
                                                          wallet_signature.data(),
                                                          timestamp,
                                                          request.get_currency_code(),
                                                          request.get_minimum_balance(),
                                                          request.get_client_timestamp(),
                                                          certificate_chain);
    }
    else
    {
        binary_proof_data = serialize_proof_data(kMinimumBalanceProof,
                                                 request.get_nonce(),
                                                 timestamp,
                                                 account_holder_name,
                                                 institution_name,
                                                 request.get_currency_code(),
                                                 request.get_minimum_balance(),
                                                 request.get_client_timestamp(),
                                                 certificate_chain);
    }
    rsa_sign(signature_rsa_params, binary_proof_data, signature);
}

void IncomeProofResult::sign(const IncomeProofRequest &request,
                             const RSAParams &signature_rsa_params)
{
    std::vector<uint8_t> binary_proof_data;
    ProofType type = kConsistentIncomeProof;
    if (request.is_stable())
        type = kStableIncomeProof;
    if (request.is_contract())
    {
        binary_proof_data = serialize_contract_proof_data(type,
                                                          request.get_nonce(),
                                                          wallet_signature.data(),
                                                          timestamp,
                                                          request.get_currency_code(),
                                                          request.get_consistent_income(),
                                                          request.get_client_timestamp(),
                                                          certificate_chain);
    }
    else
    {
        binary_proof_data = serialize_proof_data(type,
                                                 request.get_nonce(),
                                                 timestamp,
                                                 account_holder_name,
                                                 institution_name,
                                                 request.get_currency_code(),
                                                 request.get_consistent_income(),
                                                 request.get_client_timestamp(),
                                                 certificate_chain);
    }
    rsa_sign(signature_rsa_params, binary_proof_data, signature);
}

void OwnershipProofResult::sign(const OwnershipProofRequest &request,
                                const RSAParams &signature_rsa_params)
{
    std::vector<uint8_t> binary_proof_data =
        serialize_account_ownership_proof_data(request.get_nonce(),
                                               timestamp,
                                               account_holder_name,
                                               institution_name,
                                               supported_bank_info,
                                               request.get_account_number(),
                                               request.get_sort_code(),
                                               request.get_iban(),
                                               request.get_client_timestamp(),
                                               certificate_chain);
    rsa_sign(signature_rsa_params, binary_proof_data, signature);
}

} // namespace enclave
} // namespace silentdata
