#include "enclave/json/json_parser.hpp"

namespace silentdata
{
namespace enclave
{

void JSONParser::parse_text(std::string raw_text, int max_tokens)
{
    raw_text_ = raw_text;
    max_tokens_ = max_tokens;
    valid_ = true;
    data_.clear();
    tokens_.clear();
    parse();
}

JSONData JSONParser::get_data_from_keys(const std::map<std::string, jsmntype_t> &keys)
{
    data_.clear();
    // Check if the initial parsing was OK
    if (!valid_)
        return data_;

    // Get all values associated with each key
    for (const auto &key_type : keys)
    {
        std::string key_str = key_type.first;
        std::vector<std::string> key_chain = key_string_to_vector(key_str);
        if (key_chain.size() == 0)
            continue;

        // Keep track of all the regions of the raw text to look in
        std::vector<int> start_iterators{0};
        std::vector<int> end_iterators{static_cast<int>(raw_text_.size())};
        // Loop through the levels of the nested keys
        for (size_t i = 0; i < key_chain.size(); i++)
        {
            std::vector<int> all_value_indices;
            std::vector<int> next_start_iterators;
            std::vector<int> next_end_iterators;
            // Loop through the regions the values are allowed to be in and get all values
            // associated with this key level
            for (size_t j = 0; j < start_iterators.size(); j++)
            {
                std::vector<int> value_indices =
                    find_values_from_key(key_chain[i], start_iterators[j], end_iterators[j]);
                // Store the allowed regions for the next key level
                for (const auto &value_index : value_indices)
                {
                    jsmntok_t &value_token = tokens_[value_index];
                    all_value_indices.push_back(value_index);
                    next_start_iterators.push_back(value_token.start);
                    next_end_iterators.push_back(value_token.end);
                }
            }
            start_iterators = next_start_iterators;
            end_iterators = next_end_iterators;
            // If it's the last key in the chain write the values to the data object
            if (i == key_chain.size() - 1)
            {
                for (const auto &value_index : all_value_indices)
                {
                    // Check the value type is as expected
                    jsmntok_t &value_token = tokens_[value_index];
                    if (value_token.type != key_type.second || value_token.type == JSMN_OBJECT)
                        continue;
                    fill_data(value_index, key_str);
                }
            }
        }
    }
    // Check that all keys have been found
    if (data_.size() != keys.size())
        valid_ = false;
    return data_;
}

void JSONParser::parse()
{
    jsmn_parser parser;
    jsmntok_t tokens[max_tokens_];
    jsmn_init(&parser);
    n_tokens_ = jsmn_parse(&parser, raw_text_.data(), raw_text_.size(), tokens, max_tokens_);
    for (int i = 0; i < n_tokens_; i++)
        tokens_.push_back(tokens[i]);

    jsmntok_t &first_token = tokens[0];
    valid_ &= first_token.type == JSMN_OBJECT;
    valid_ &= first_token.start == 0;
    valid_ &= (first_token.end >= 0 && ((size_t)first_token.end == raw_text_.size() ||
                                        (size_t)first_token.end == raw_text_.size() - 1));
}

std::vector<std::string> JSONParser::key_string_to_vector(std::string key_str)
{
    std::vector<std::string> key_chain;
    std::string delimiter = "->";
    size_t pos = 0;
    while ((pos = key_str.find(delimiter)) != std::string::npos)
    {
        key_chain.push_back(key_str.substr(0, pos));
        key_str.erase(0, pos + delimiter.length());
    }
    key_chain.push_back(key_str);
    return key_chain;
}

std::vector<int> JSONParser::find_values_from_key(std::string key, int start_it, int end_it)
{
    int token_index = 1;
    std::vector<int> value_indices;
    // Loop over all of the tokens in the parsed JSON
    while (token_index < n_tokens_)
    {
        // Get a token assuming it's a key
        jsmntok_t &key_token = tokens_[token_index];
        token_index++;
        // They key should always be a string
        if (key_token.type != JSMN_STRING)
            continue;
        // Both the key and value should be contained in the given range
        if (key_token.start < start_it || key_token.end > end_it)
            continue;
        // Check if it exists in the list of keys to save
        std::string key_str =
            std::string(raw_text_.begin() + key_token.start, raw_text_.begin() + key_token.end);
        // If this is the key we're looking for, record the value index
        if (key_str == key)
        {
            jsmntok_t &value_token = tokens_[token_index];
            if (value_token.start < start_it || value_token.end > end_it)
            {
                token_index++;
                continue;
            }
            value_indices.push_back(token_index);
            // Don't check for the key inside the value of the key
            token_index = skip_value(token_index);
        }
        // If this isn't the correct key and the value is an object or an array, don't check inside
        else if (token_index < n_tokens_)
        {
            jsmntok_t &value_token = tokens_[token_index];
            if (value_token.type == JSMN_ARRAY || value_token.type == JSMN_OBJECT)
            {
                token_index = skip_value(token_index);
            }
            else
            {
                token_index++;
            }
        }
    }
    return value_indices;
}

int JSONParser::skip_value(int current_index)
{
    jsmntok_t &token = tokens_[current_index];
    int current = token.start;
    int end = token.end;
    do
    {
        current_index++;
        if (current_index >= n_tokens_)
            break;
        jsmntok_t &next_token = tokens_[current_index];
        current = next_token.end;
    } while (current < end);
    return current_index;
}

void JSONParser::fill_data(int value_index, std::string key_str)
{
    int token_index = value_index;
    jsmntok_t &value_token = tokens_[token_index];
    token_index++;
    // If it's an array push all values onto a vector
    if (value_token.type == JSMN_ARRAY)
    {
        std::vector<std::string> array_vector;
        for (int i = 0; i < value_token.size; i++)
        {
            jsmntok_t &array_token = tokens_[token_index];
            token_index++;
            std::string array_value = std::string(raw_text_.begin() + array_token.start,
                                                  raw_text_.begin() + array_token.end);
            array_vector.push_back(array_value);
        }
        data_.push_array_to_key(key_str, array_vector);
    }
    // Otherwise just push back the value string to a vector of size 1
    else
    {
        std::string value =
            std::string(raw_text_.begin() + value_token.start, raw_text_.begin() + value_token.end);
        data_.push_value_to_key(key_str, value);
    }
}

} // namespace enclave
} // namespace silentdata
