#pragma once

#include "utxo.hpp"  
#include <vector>
#include <span>
#include <cstdint>
#include <optional>

namespace wallet {

// Forward declaration
struct Utxo;

class Segwit {
public:
    // Get the P2WPKH witness program from a public key
    static std::vector<uint8_t> get_p2wpkh_program(std::span<const uint8_t> pubkey);
    
    // Get the P2WSH witness program from a script with optional version
    static std::vector<uint8_t> get_p2wsh_program(const std::vector<uint8_t>& script, std::optional<uint32_t> version = std::nullopt);
    
    // Create a witness script from a list of public keys
    static std::vector<uint8_t> create_witness_script(const std::vector<std::vector<uint8_t>>& keys);
    
    // Get the P2WPKH script code from a UTXO
    static std::vector<uint8_t> get_p2wpkh_scriptcode(const Utxo& utxo);

    // Create an input from a transaction outpoint
    static std::vector<uint8_t> input_from_utxo(const Outpoint& outpoint);
};

} // namespace wallet 