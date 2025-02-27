#pragma once

#include <array>
#include <vector>
#include <span>
#include <cstdint>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

namespace wallet {

// HashUtils is a utility class for various cryptographic hash functions
// used in Bitcoin and other cryptocurrencies
class HashUtils {
public:
    // Computes the SHA256 hash of input data
    // Returns a 32-byte SHA256 hash of the input data
    static std::array<uint8_t, SHA256_DIGEST_LENGTH> sha256(std::span<const uint8_t> data);
    
    // Computes double SHA256 hash (SHA256(SHA256(data)))
    // Returns a 32-byte double SHA256 hash of the input data
    static std::array<uint8_t, SHA256_DIGEST_LENGTH> double_sha256(std::span<const uint8_t> data);
    
    // Computes RIPEMD160 hash of input data
    // Returns a 20-byte RIPEMD160 hash of the input data
    static std::array<uint8_t, RIPEMD160_DIGEST_LENGTH> ripemd160(std::span<const uint8_t> data);
    
    // Computes HASH160 (RIPEMD160(SHA256(data)))
    // Returns a 20-byte HASH160 result
    static std::array<uint8_t, RIPEMD160_DIGEST_LENGTH> hash160(std::span<const uint8_t> data);

private:
    // Private constructor to prevent instantiation
    HashUtils() = delete;
};

} // namespace wallet 