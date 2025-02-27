#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace wallet {

// Base58 is a utility class for Base58 encoding and decoding.
//
// Base58 is a binary-to-text encoding scheme primarily used in Bitcoin addresses
// and other cryptocurrency systems. It uses a 58-character alphabet consisting of
// easily distinguishable characters (excluding 0, O, I, l) to represent data.
class Base58 {
public:
    // Decodes a Base58-encoded string into bytes
    static std::vector<uint8_t> decode(const std::string& encoded);

private:
    // Private constructor to prevent instantiation
    Base58() = delete;
};

} // namespace wallet 