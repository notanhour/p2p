#pragma once

#include <climits>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace codec {

inline std::string base64_encode(const std::vector<unsigned char>& data) {
    if (data.empty()) return {};
    if (data.size() > (static_cast<std::size_t>(INT_MAX) / 4) * 3)
        throw std::length_error("Base64 input is too large");
    std::string encoded(4 * ((data.size() + 2) / 3) + 1, '\0');
    const int length = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(encoded.data()), data.data(),
                                     static_cast<int>(data.size()));
    if (length < 0) throw std::runtime_error("Base64 encoding failed");
    encoded.resize(length);
    return encoded;
}

inline std::vector<unsigned char> base64_decode(const std::string& encoded) {
    if (encoded.empty()) return {};
    if (encoded.size() > INT_MAX || encoded.size() % 4 != 0)
        throw std::invalid_argument("Invalid Base64 length");
    const auto first_padding = encoded.find('=');
    const std::size_t data_length = first_padding == std::string::npos ? encoded.size() : first_padding;
    const std::size_t padding = encoded.size() - data_length;
    if (padding > 2) throw std::invalid_argument("Invalid Base64 padding");
    for (std::size_t i = 0; i < encoded.size(); ++i) {
        const char ch = encoded[i];
        const bool valid = i < data_length
            ? ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
               (ch >= '0' && ch <= '9') || ch == '+' || ch == '/')
            : ch == '=';
        if (!valid) throw std::invalid_argument("Invalid Base64 character");
    }
    std::vector<unsigned char> decoded(3 * (encoded.size() / 4));
    const int length = EVP_DecodeBlock(decoded.data(), reinterpret_cast<const unsigned char*>(encoded.data()),
                                     static_cast<int>(encoded.size()));
    if (length < 0 || static_cast<std::size_t>(length) < padding)
        throw std::invalid_argument("Invalid Base64 data");
    decoded.resize(static_cast<std::size_t>(length) - padding);
    if (base64_encode(decoded) != encoded) throw std::invalid_argument("Noncanonical Base64 data");
    return decoded;
}

}
