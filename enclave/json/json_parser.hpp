/*
 * Class to help with JSON parsing
 * mostly acts as a wrapper around jsmn header
 */

#ifndef SILENTDATA_ENCLAVE_JSON_PARSER_H
#define SILENTDATA_ENCLAVE_JSON_PARSER_H

#include <algorithm>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "enclave/json/jsmn.h"
#include "enclave/json/json_data.hpp"

namespace silentdata
{
namespace enclave
{

// Simple JSON parser for retrieving data with a set of known keys
class JSONParser
{
public:
    JSONParser() : valid_(false) {}
    // Constructor parses the input text to obtain jsmn tokens
    JSONParser(std::string raw_text, int max_tokens)
        : raw_text_(raw_text), max_tokens_(max_tokens), valid_(true)
    {
        parse();
    }

    // Clear the data and parse a new text input
    void parse_text(std::string raw_text, int max_tokens);
    // Obtain a JSONData object from a list of keys with associated value types
    JSONData get_data_from_keys(const std::map<std::string, jsmntype_t> &keys);
    bool is_valid() const { return valid_; }

protected:
    // Uses jsmn to parse and tokenise the input string
    void parse();
    // Convert a string of nested keys separated by "->" into a vector
    std::vector<std::string> key_string_to_vector(std::string key_str);
    // Obtain all value indices associated with a key within a range given by the start/end
    // iterator positions of the initial text
    std::vector<int> find_values_from_key(std::string key, int start_it, int end_it);
    // Fill a JSONData object with a key value(s) pair
    void fill_data(int value_index, std::string key_str);
    // Get the next token index outside of the current value
    int skip_value(int current_index);

private:
    JSONData data_;
    std::vector<jsmntok_t> tokens_;
    std::string raw_text_;
    int max_tokens_;
    int n_tokens_;
    bool valid_;
};

} // namespace enclave
} // namespace silentdata

#endif
