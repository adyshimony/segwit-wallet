#pragma once

#include <vector>
#include <cstdint>
#include <nlohmann/json.hpp>

namespace wallet {

struct Outpoint {
    std::vector<uint8_t> txid_vec;  // Transaction ID as bytes in little-endian
    uint32_t index;                 // Output index in transaction
};

struct Utxo {
    Outpoint outpoint;
    uint64_t amount;               // Amount in satoshis
    std::vector<uint8_t> script_pubkey; // Locking script
    size_t child_code;            // Index of corresponding key pair
};

// JSON serialization for Outpoint
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Outpoint, txid_vec, index)

// JSON serialization for Utxo
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Utxo, outpoint, amount, script_pubkey, child_code)

} // namespace wallet 