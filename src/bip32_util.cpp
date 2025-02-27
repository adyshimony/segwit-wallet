#include "bip32_util.hpp"
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/hmac.h>
#include <memory>
#include <sstream>
#include <algorithm>

namespace wallet {

// Derives a public key from a private key using elliptic curve multiplication
// This implements the secp256k1 curve operation: public_key = private_key * G
// where G is the generator point of the curve.
//
// The process:
// 1. Create an EC_KEY context for the secp256k1 curve
// 2. Convert the private key bytes to a BIGNUM
// 3. Set the private key in the EC_KEY context
// 4. Perform the elliptic curve multiplication (private_key * G)
// 5. Serialize the resulting point in compressed format (33 bytes)
//
// Compressed public key format:
// - First byte: 0x02 if y-coordinate is even, 0x03 if y-coordinate is odd
// - Remaining 32 bytes: x-coordinate
std::vector<uint8_t> Bip32Util::derive_public_key_from_private(std::span<const uint8_t> key) {
    // Create OpenSSL key context with RAII cleanup
    auto ec_key = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>(
        EC_KEY_new_by_curve_name(NID_secp256k1),
        EC_KEY_free
    );
    
    if (!ec_key) {
        throw wallet::BalanceError(wallet::BalanceError::ErrorType::DerivationError);
    }

    // Convert private key bytes to OpenSSL BIGNUM
    // BIGNUM is OpenSSL's arbitrary-precision integer type needed for cryptographic operations
    BIGNUM* priv_key = BN_bin2bn(key.data(), key.size(), nullptr);
    if (!priv_key) {
        throw wallet::BalanceError(wallet::BalanceError::ErrorType::DerivationError);
    }

    // Set private key in context
    if (!EC_KEY_set_private_key(ec_key.get(), priv_key)) {
        BN_free(priv_key);
        throw wallet::BalanceError(wallet::BalanceError::ErrorType::DerivationError);
    }

    // Get curve group and create point for public key
    // The group contains the curve parameters (a, b, p, G, n, h)
    const EC_GROUP* group = EC_KEY_get0_group(ec_key.get());
    EC_POINT* pub_key = EC_POINT_new(group);
    
    // Calculate public key point: pub = priv * G
    // This is the core elliptic curve operation: scalar multiplication of the generator point
    if (!EC_POINT_mul(group, pub_key, priv_key, nullptr, nullptr, nullptr)) {
        EC_POINT_free(pub_key);
        BN_free(priv_key);
        throw wallet::BalanceError(wallet::BalanceError::ErrorType::DerivationError);
    }

    // Serialize public key to compressed format
    // Compressed format reduces the key size from 65 to 33 bytes
    std::vector<uint8_t> result(33); // Size for compressed key
    size_t size = EC_POINT_point2oct(
        group, pub_key, POINT_CONVERSION_COMPRESSED,
        result.data(), result.size(), nullptr
    );

    // Cleanup OpenSSL objects
    EC_POINT_free(pub_key);
    BN_free(priv_key);

    if (size != 33) {
        throw wallet::BalanceError(wallet::BalanceError::ErrorType::DerivationError);
    }

    return result;
}

// Derives a child private key from a parent private key according to BIP32
// This implements the key derivation algorithm defined in BIP32 (Hierarchical Deterministic Wallets)
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
//
// The derivation process:
// 1. Create a seed data from parent key and child index
// 2. Calculate HMAC-SHA512 of the seed data using the parent chain code as key
// 3. Split the HMAC result into two 32-byte parts: left and right
// 4. The left part is added to the parent private key (mod n) to get the child private key
// 5. The right part becomes the child chain code
//
// There are two types of derivation:
// - Normal derivation (child_num < 0x80000000): uses parent public key in the seed
// - Hardened derivation (child_num >= 0x80000000): uses parent private key in the seed
//
// Hardened derivation provides better security but doesn't allow deriving child public keys
// directly from parent public keys (requires the parent private key).
ExKey Bip32Util::derive_priv_child(const ExKey& parent, uint32_t child_num) {
    std::vector<uint8_t> data;
    data.reserve(37); // Maximum size needed

    if (child_num >= 0x80000000) {
        // Hardened derivation: data = 0x00 || parent private key
        // The 0x00 prefix ensures the data is distinct from the public key format
        data.push_back(0x00);
        data.insert(data.end(), parent.key.begin(), parent.key.end());
    } else {
        // Normal derivation: data = parent public key
        // This allows for public derivation (deriving child public keys from parent public key)
        auto pubkey = derive_public_key_from_private(parent.key);
        data.insert(data.end(), pubkey.begin(), pubkey.end());
    }

    // Add child number in big-endian format
    // The child number identifies which child key to derive
    auto child_num_be = std::array<uint8_t, 4>{
        static_cast<uint8_t>((child_num >> 24) & 0xff),
        static_cast<uint8_t>((child_num >> 16) & 0xff),
        static_cast<uint8_t>((child_num >> 8) & 0xff),
        static_cast<uint8_t>(child_num & 0xff)
    };
    data.insert(data.end(), child_num_be.begin(), child_num_be.end());

    // Calculate HMAC-SHA512
    // This produces 64 bytes of deterministic output based on the input data
    std::array<uint8_t, 64> hmac_result;
    unsigned int hmac_len;
    if (!HMAC(EVP_sha512(), parent.chaincode.data(), parent.chaincode.size(),
              data.data(), data.size(), hmac_result.data(), &hmac_len) ||
        hmac_len != 64) {
        throw wallet::BalanceError(wallet::BalanceError::ErrorType::DerivationError);
    }

    // Prepare child key structure
    // Copy parent data and update with child-specific information
    ExKey child = parent;
    child.depth[0] += 1;
    std::copy(child_num_be.begin(), child_num_be.end(), child.child_number.begin());
    std::copy_n(hmac_result.begin() + 32, 32, child.chaincode.begin());

    // Add private keys (mod n)
    // This is a critical step: child_key = (parent_key + hmac_left) mod n
    // where n is the order of the secp256k1 curve
    BIGNUM* n = BN_new();
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group || !n || !EC_GROUP_get_order(group, n, nullptr)) {
        BN_free(n);
        EC_GROUP_free(group);
        throw wallet::BalanceError(wallet::BalanceError::ErrorType::DerivationError);
    }

    // Perform modular addition of private keys
    // This ensures the result is a valid private key (less than the curve order)
    BIGNUM* parent_key = BN_bin2bn(parent.key.data(), parent.key.size(), nullptr);
    BIGNUM* child_key = BN_bin2bn(hmac_result.data(), 32, nullptr);
    BN_CTX* ctx = BN_CTX_new();

    if (!parent_key || !child_key || !ctx ||
        !BN_mod_add(child_key, parent_key, child_key, n, ctx)) {
        BN_free(n);
        BN_free(parent_key);
        BN_free(child_key);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        throw wallet::BalanceError(wallet::BalanceError::ErrorType::DerivationError);
    }

    // Convert result back to bytes
    BN_bn2bin(child_key, child.key.data());

    // Cleanup
    BN_free(n);
    BN_free(parent_key);
    BN_free(child_key);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);

    return child;
}

// Derives a child key at a specific derivation path from a parent key
// This implements the path-based derivation defined in BIP32, allowing for
// a sequence of child key derivations specified by a path string.
//
// The derivation path format:
// - "m" represents the master key
// - "/" separates path components
// - Numbers represent child indices
// - Numbers with ' or h suffix represent hardened derivation (index + 0x80000000)
//
// Examples:
// - "m/0/1" derives the 2nd child of the 1st child of the master key
// - "m/44'/0'/0'" derives the hardened path used for BIP44 Bitcoin accounts
//
// The function iteratively applies derive_priv_child for each component in the path.
ExKey Bip32Util::get_child_key_at_path(const ExKey& key, const std::string& derivation_path) {
    std::string path = derivation_path;
    if (path.starts_with("m/")) {
        path = path.substr(2);
    }

    ExKey current_key = key;
    std::istringstream path_stream(path);
    std::string index_str;

    while (std::getline(path_stream, index_str, '/')) {
        bool hardened = index_str.ends_with('\'') || index_str.ends_with('h');
        if (hardened) {
            index_str.pop_back();
        }

        uint32_t index;
        try {
            index = std::stoul(index_str);
            if (hardened) {
                index += 0x80000000;
            }
        } catch (...) {
            throw wallet::BalanceError(wallet::BalanceError::ErrorType::DerivationError);
        }

        current_key = derive_priv_child(current_key, index);
    }

    return current_key;
}

// Derives multiple child keys from a parent key using sequential indices
// This is useful for generating a series of addresses from a single account key.
//
// The function:
// 1. Takes a parent key (typically an account-level key)
// 2. Derives num_keys sequential child keys starting from index 0
// 3. Returns a vector of the derived child keys
//
// This is commonly used in wallet implementations to generate multiple addresses
// for a user without requiring additional user input.
std::vector<ExKey> Bip32Util::get_keys_at_child_key_path(const ExKey& child_key, uint32_t num_keys) {
    std::vector<ExKey> keys;
    keys.reserve(num_keys);

    for (uint32_t i = 0; i < num_keys; ++i) {
        keys.push_back(derive_priv_child(child_key, i));
    }

    return keys;
}

} // namespace wallet 