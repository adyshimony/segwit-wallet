#pragma once

#include <vector>
#include <span>
#include <cstdint>
#include <array>
#include <string>
#include "error.hpp"

namespace wallet {

// Extended key structure used in BIP32 hierarchical deterministic wallets
struct ExKey {
    std::array<uint8_t, 4> version;      // Version bytes indicating key type (mainnet/testnet, private/public)
    std::array<uint8_t, 1> depth;        // Depth in the derivation path (0 for master keys)
    std::array<uint8_t, 4> finger_print; // First 4 bytes of the parent key's identifier
    std::array<uint8_t, 4> child_number; // Index of the key in relation to its parent
    std::array<uint8_t, 32> chaincode;   // Extra entropy used in child key derivation
    std::array<uint8_t, 32> key;         // The actual key data (private or public)
};

// Utility class for BIP32 hierarchical deterministic wallet operations
class Bip32Util {
public:
    // Derives a public key from a private key using elliptic curve multiplication
    static std::vector<uint8_t> derive_public_key_from_private(std::span<const uint8_t> key);

    // Derives a child private key from a parent private key using BIP32 derivation
    static ExKey derive_priv_child(const ExKey& parent, uint32_t child_num);

    // Derives a key at a specific BIP32 derivation path from a parent key
    static ExKey get_child_key_at_path(const ExKey& key, const std::string& derivation_path);

    // Generates multiple sequential child keys from a parent key
    static std::vector<ExKey> get_keys_at_child_key_path(const ExKey& child_key, uint32_t num_keys);
};

} // namespace wallet 