#include "hash_utils.h"

namespace wallet {

// Computes the SHA256 hash of input data
// SHA256 is a cryptographic hash function that produces a fixed-size 32-byte output
// regardless of the input size. It's widely used in Bitcoin for various purposes
// including transaction IDs, block hashes, and address generation.
std::array<uint8_t, SHA256_DIGEST_LENGTH> HashUtils::sha256(std::span<const uint8_t> data) {
    std::array<uint8_t, SHA256_DIGEST_LENGTH> hash;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.data(), data.size());
    SHA256_Final(hash.data(), &sha256);
    return hash;
}

// Computes double SHA256 hash (SHA256(SHA256(data)))
// Double SHA256 is commonly used in Bitcoin for transaction and block hashing
// to provide additional security and prevent length-extension attacks.
std::array<uint8_t, SHA256_DIGEST_LENGTH> HashUtils::double_sha256(std::span<const uint8_t> data) {
    auto first_hash = sha256(data);
    return sha256(std::span<const uint8_t>(first_hash.data(), first_hash.size()));
}

// Computes RIPEMD160 hash of input data
// RIPEMD160 is a 160-bit cryptographic hash function used in Bitcoin
// address generation to shorten public keys.
std::array<uint8_t, RIPEMD160_DIGEST_LENGTH> HashUtils::ripemd160(std::span<const uint8_t> data) {
    std::array<uint8_t, RIPEMD160_DIGEST_LENGTH> hash;
    RIPEMD160_CTX ripemd160;
    RIPEMD160_Init(&ripemd160);
    RIPEMD160_Update(&ripemd160, data.data(), data.size());
    RIPEMD160_Final(hash.data(), &ripemd160);
    return hash;
}

// Computes HASH160 (RIPEMD160(SHA256(data)))
// HASH160 is commonly used in Bitcoin for address generation
// to create a shorter, more manageable hash of a public key.
std::array<uint8_t, RIPEMD160_DIGEST_LENGTH> HashUtils::hash160(std::span<const uint8_t> data) {
    auto sha256_result = sha256(data);
    return ripemd160(std::span<const uint8_t>(sha256_result.data(), sha256_result.size()));
}

} // namespace wallet 