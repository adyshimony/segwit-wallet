/**
 * @file balance.hpp
 * @brief Bitcoin wallet functionality for managing keys and UTXOs
 * 
 * This header defines the core wallet functionality including:
 * - BIP32 key derivation
 * - UTXO (Unspent Transaction Output) management
 * - Wallet state persistence
 * - Bitcoin RPC communication
 * 
 * Bitcoin Protocol Concepts:
 * 
 * 1. Extended Keys (BIP32):
 *    - Hierarchical Deterministic wallet structure
 *    - Parent keys can derive sequences of child keys
 *    - Enables backup/restore from single seed
 * 
 * 2. UTXOs:
 *    - Bitcoin's way of tracking spendable amounts
 *    - Each UTXO represents an unspent output from a previous transaction
 *    - Contains amount and spending conditions (script)
 * 
 * 3. SegWit (Segregated Witness):
 *    - Modern Bitcoin address format
 *    - Separates signature data from transaction data
 *    - Improves scalability and fixes transaction malleability
 * 
 * Key C++ Features:
 * 
 * 1. Modern C++ Types:
 *    - std::span: Safe array view (C++20)
 *    - std::array: Fixed-size arrays
 *    - std::optional: Nullable value wrapper
 * 
 * 2. Memory Safety:
 *    - RAII principles throughout
 *    - Smart pointers for resource management
 *    - Value semantics where appropriate
 * 
 * 3. Error Handling:
 *    - Custom exception class with error types
 *    - Strong exception guarantees
 *    - Clear error categorization
 */

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <numeric>
#include <nlohmann/json.hpp>
#include "error.hpp"
#include "bip32_util.hpp"
#include "utxo.hpp"
#include "secure_memory.hpp"

// For C++20 span support
#if __has_include(<span>)
    #include <span>
#else
    #include <experimental/span>
    namespace std {
        using std::experimental::span;
    }
#endif

namespace wallet {

class WalletState {
public:
    // Add constructor that takes wallet name and extended private key
    WalletState(const std::string& wallet_name, const std::string& extended_private_key);

    // Get wallet name
    const std::string& get_wallet_name() const { return wallet_name; }

    // Choose a UTXO with sufficient value
    std::optional<Utxo> choose_utxo(uint64_t min_satoshis) const;

    // Calculate total wallet balance
    uint64_t balance() const;

    // Get default change script
    std::optional<std::vector<uint8_t>> get_change_script() const;

    // Get private key by index
    std::optional<std::span<const uint8_t>> get_private_key(size_t index) const;

    // Get all public keys
    std::span<const std::vector<uint8_t>> get_public_keys() const;

    // Get keys for multisig (first two public keys)
    std::optional<std::vector<std::vector<uint8_t>>> get_multisig_keys() const;

    // Lookup UTXO by transaction ID
    std::optional<Utxo> get_utxo(const std::array<uint8_t, 32>& txid) const;

    // Persistence methods
    void save_to_file(const std::string& path) const;
    bool load_from_file(const std::string& path);

    // Friend declaration for recovery function
    bool recover_wallet_state();

private:
    std::string wallet_name;  // Human-readable identifier for the wallet
    
    // Secure container for the BIP32 master key with memory protection
    std::unique_ptr<SecureMemory> extended_private_key;  
    
    std::unordered_map<std::string, Utxo> utxo_map; // Maps transaction IDs to unspent transaction outputs
    std::vector<std::vector<uint8_t>> witness_programs; // SegWit output scripts for receiving payments
    std::vector<std::vector<uint8_t>> public_keys; // Derived public keys used for address generation
    std::vector<std::vector<uint8_t>> private_keys; // Derived private keys for signing transactions

    // Friend declaration for JSON serialization
    friend void to_json(nlohmann::json& j, const WalletState& w);
    friend void from_json(const nlohmann::json& j, WalletState& w);
};

// Update the recovery function signature

} // namespace wallet 