#pragma once

#include <string>
#include <vector>
#include <stdexcept>

namespace wallet {

class HexUtils {
public:
    // Convert a hexadecimal string to a byte vector
    static std::vector<uint8_t> decode(const std::string& hex) {
        if (hex.length() % 2 != 0) {
            throw std::invalid_argument("Invalid hex string length");
        }

        std::vector<uint8_t> bytes;
        bytes.reserve(hex.length() / 2);

        for (size_t i = 0; i < hex.length(); i += 2) {
            bytes.push_back(static_cast<uint8_t>(
                std::stoi(hex.substr(i, 2), nullptr, 16)
            ));
        }

        return bytes;
    }

    // Convert a byte vector to a hexadecimal string
    static std::string encode(const std::vector<uint8_t>& data) {
        std::string result;
        result.reserve(data.size() * 2);
        
        static const char hex_chars[] = "0123456789abcdef";
        for (uint8_t byte : data) {
            result.push_back(hex_chars[byte >> 4]);
            result.push_back(hex_chars[byte & 0x0F]);
        }
        
        return result;
    }
};

} // namespace wallet 