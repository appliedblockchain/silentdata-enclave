/*
 * Functions to help with HTTP response and JSON parsing
 */

#ifndef SILENTDATA_ENCLAVE_JSON_DATA_H
#define SILENTDATA_ENCLAVE_JSON_DATA_H

#include <algorithm>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "enclave/common/enclave_exception.hpp"

namespace silentdata
{
namespace enclave
{

// Simple JSON data structure for flattening a nested object, assumes everything is a string for
// simplicity
class JSONData
{
public:
    JSONData() {}

    size_t size() const { return data_.size(); }
    void clear() { data_.clear(); }

    // Add a single value or array to a key in the data
    void push_value_to_key(const std::string &key, const std::string &value);
    void push_array_to_key(const std::string &key, const std::vector<std::string> &array);
    // Get a single value if we expect just one to be associated with key
    std::string get(const std::string &key) const;
    // Return all values associated with a key
    std::vector<std::string> get_all(const std::string &key) const;

private:
    // Container for all data in flattened JSON
    // - First level vector allows for multiple values associated to one key (e.g. someone with
    //   more than one bank account)
    // - Second level vector allows for final value to be an array (e.g. more than one account
    //   holder name associated to a bank account)
    std::map<std::string, std::vector<std::vector<std::string>>> data_;
};

} // namespace enclave
} // namespace silentdata

#endif
