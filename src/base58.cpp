#include "base58.hpp"
#include "error.hpp"
#include <array>

namespace wallet {

// Decodes a Base58-encoded string into bytes.
//
// The decoding process:
// 1. Converts each Base58 character to its corresponding value
// 2. Builds the result by multiplying existing value by 58 and adding new digits
// 3. Handles leading '1' characters (which represent leading zeros)
// 4. Removes the 4-byte checksum from the end
//
// Args:
//   base58_string: The Base58-encoded string to decode
// Returns:
//   The decoded bytes as a vector of uint8_t
// Throws:
//   BalanceError if the input is invalid or too short
std::vector<uint8_t> Base58::decode(const std::string& base58_string) {
    static const std::string BASE58_CHARS = 
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    
    std::vector<uint8_t> result{0};
    for (char c : base58_string) {
        // Convert character to Base58 value
        auto digit = BASE58_CHARS.find(c);
        if (digit == std::string::npos) {
            throw BalanceError(BalanceError::ErrorType::Base58DecodeError);
        }
        
        // Multiply existing result by 58 and add new digit
        size_t carry = digit;
        for (auto it = result.rbegin(); it != result.rend(); ++it) {
            carry += static_cast<size_t>(*it) * 58;
            *it = static_cast<uint8_t>(carry & 0xff);
            carry >>= 8;
        }
        
        // Add any remaining carry as new digits
        while (carry > 0) {
            result.insert(result.begin(), static_cast<uint8_t>(carry & 0xff));
            carry >>= 8;
        }
    }

    // Handle leading '1' characters (0x00 bytes in output)
    for (char c : base58_string) {
        if (c != '1') break;
        result.insert(result.begin(), 0);
    }

    // Remove 4-byte checksum from end
    if (result.size() < 4) {
        throw BalanceError(BalanceError::ErrorType::Base58DecodeError);
    }
    result.resize(result.size() - 4);
    return result;
}

} // namespace wallet 