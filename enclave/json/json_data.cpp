#include "enclave/json/json_data.hpp"

namespace silentdata
{
namespace enclave
{

// Get a single value if we expect just one to be associated with key
std::string JSONData::get(const std::string &key) const
{
    if (data_.find(key) == data_.end())
        THROW_EXCEPTION(kJSONKeyError, "Cannot find key in JSONData");
    if (data_.at(key).size() != 1)
        THROW_EXCEPTION(kJSONMultipleValuesError, "More than one entry for key");
    if (data_.at(key)[0].size() != 1)
        THROW_EXCEPTION(kJSONMultipleValuesError, "Value for key is an array");
    return data_.at(key)[0][0];
}

// Return all values associated with a key
std::vector<std::string> JSONData::get_all(const std::string &key) const
{
    if (data_.find(key) == data_.end())
        THROW_EXCEPTION(kJSONKeyError, "Cannot find key in JSONData");
    std::vector<std::string> values;
    for (size_t i = 0; i < data_.at(key).size(); i++)
        values.insert(values.end(), data_.at(key)[i].begin(), data_.at(key)[i].end());
    return values;
}

void JSONData::push_value_to_key(const std::string &key, const std::string &value)
{
    std::vector<std::string> value_vector = {value};
    data_[key].push_back(value_vector);
}

void JSONData::push_array_to_key(const std::string &key, const std::vector<std::string> &array)
{
    data_[key].push_back(array);
}

} // namespace enclave
} // namespace silentdata
