/**
 * @file wallet.cpp
 * @brief Implementation of Bitcoin wallet functionality
 * 
 * This file implements the core wallet operations including:
 * 1. Key Management:
 *    - Base58 encoding/decoding for Bitcoin keys
 *    - BIP32 hierarchical key derivation
 *    - Public key generation from private keys
 * 
 * 2. UTXO Management:
 *    - UTXO tracking and selection
 *    - Balance calculation
 *    - Blockchain scanning for wallet UTXOs
 * 
 * 3. Bitcoin Protocol Features:
 *    - SegWit address generation (P2WPKH)
 *    - Bitcoin Core RPC communication
 *    - Transaction output parsing
 * 
 * Key C++ Implementation Features:
 * 
 * 1. Cryptographic Operations:
 *    - OpenSSL library integration
 *    - Secure key operations
 *    - Hash functions (SHA256, RIPEMD160)
 * 
 * 2. Memory Management:
 *    - RAII with smart pointers
 *    - Exception-safe resource handling
 *    - Secure memory practices for keys
 * 
 * 3. Modern C++ Features:
 *    - std::span for safe array views
 *    - std::optional for nullable returns
 *    - JSON serialization for persistence
 */

#include "wallet_state.hpp"
#include "error.hpp"
#include "base58.hpp"
#include "key_deserializer.hpp"
#include "bip32_util.hpp"
#include "bitcoin_cli.hpp"
#include "hex_utils.hpp"
#include "segwit.hpp"
#include "consts.hpp"
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <nlohmann/json.hpp>
#include <cstdio>
#include <array>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <memory>
#include <stdexcept>
#include <iostream>


using json = nlohmann::json;

namespace wallet {

// Define a constant for the maximum block height to scan
// This limits the initial blockchain scan to a reasonable range
// For a full wallet, this would be set to the current chain height
// or use a timestamp-based approach to scan from wallet creation date
constexpr uint32_t MAX_BLOCK_SCAN_HEIGHT = 300;

// WalletState implementation

// Constructor for WalletState that initializes a wallet with a name and extended private key
// The extended private key is typically a BIP32 master key in Base58Check encoding
// This is the entry point for wallet initialization
WalletState::WalletState(const std::string& wallet_name, const std::string& extended_private_key)
    : wallet_name(wallet_name),
      extended_private_key(extended_private_key) {
    std::cout << "Initialized wallet state for wallet: " << wallet_name << std::endl;
}

// Selects a UTXO that has at least min_satoshis value
// Returns the first UTXO found that meets the criteria, or nullopt if none exists
// This is a simple UTXO selection algorithm; more sophisticated ones might consider:
// - Coin age
// - Minimizing change
// - Privacy considerations (avoiding address reuse)
std::optional<Utxo> WalletState::choose_utxo(uint64_t min_satoshis) const {
    auto it = std::find_if(utxo_map.begin(), utxo_map.end(),
        [min_satoshis](const auto& pair) {
            return pair.second.amount >= min_satoshis;
        });
    
    if (it != utxo_map.end()) {
        return it->second;
    }
    return std::nullopt;
}


// Calculates the total balance of the wallet by summing all UTXOs
// Returns the balance in satoshis (1 BTC = 100,000,000 satoshis)
// This is a simple accumulation of unspent outputs
uint64_t WalletState::balance() const {
    return std::accumulate(utxo_map.begin(), utxo_map.end(), 0ULL,
        [](uint64_t sum, const auto& pair) {
            return sum + pair.second.amount;
        });
}


// Returns the first witness program to use as a change address
// In Bitcoin, change from a transaction is typically sent back to the sender
// This implementation uses the first available witness program (P2WPKH script)
std::optional<std::vector<uint8_t>> WalletState::get_change_script() const {
    if (!witness_programs.empty()) {
        return witness_programs[0];
    }
    return std::nullopt;
}


// Retrieves a private key at the specified index
// Private keys are sensitive data used to sign transactions
// Returns a span to avoid copying the key data
std::optional<std::span<const uint8_t>> WalletState::get_private_key(size_t index) const {
    if (index < private_keys.size()) {
        return std::span<const uint8_t>(private_keys[index]);
    }
    return std::nullopt;
}


// Returns all public keys in the wallet
// Public keys are used to derive addresses and verify signatures
// In Bitcoin, public keys can be shared without compromising security
std::span<const std::vector<uint8_t>> WalletState::get_public_keys() const {
    return std::span<const std::vector<uint8_t>>(public_keys);
}


// Returns the first two public keys for multisig address creation
// Multisig addresses require multiple signatures to spend funds
// Common patterns include 2-of-2 or 2-of-3 multisig setups
std::optional<std::vector<std::vector<uint8_t>>> WalletState::get_multisig_keys() const {
    if (public_keys.size() >= 2) {
        return std::vector<std::vector<uint8_t>>{
            public_keys[0],
            public_keys[1]
        };
    }
    return std::nullopt;
}


// Retrieves a specific UTXO by its transaction ID
// In Bitcoin, UTXOs are identified by a transaction ID (txid) and output index
// Returns the UTXO if found, or nullopt if not in the wallet
std::optional<Utxo> WalletState::get_utxo(const std::array<uint8_t, 32>& txid) const {
    std::string txid_str;
    for (auto byte : txid) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", byte);
        txid_str += hex;
    }

    auto it = std::find_if(utxo_map.begin(), utxo_map.end(),
        [&txid_str](const auto& pair) {
            return pair.first.starts_with(txid_str);
        });

    if (it != utxo_map.end()) {
        return it->second;
    }
    return std::nullopt;
}

// Serializes and saves the wallet state to a JSON file
// This includes UTXOs, witness programs, and key data
// Persistence allows wallet recovery without rescanning the blockchain
void WalletState::save_to_file(const std::string& path) const {
    json j = {
        {"utxo_map", utxo_map},
        {"witness_programs", witness_programs},
        {"public_keys", public_keys},
        {"private_keys", private_keys}
    };

    std::ofstream file(path);
    if (!file) {
        throw std::runtime_error("Failed to open file for writing");
    }
    file << j.dump(4);
}

// Loads wallet state from a JSON file
// This restores the wallet's UTXOs and keys from persistent storage
// Returns true if loading was successful
bool WalletState::load_from_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Failed to open file for reading");
    }

    json j;
    file >> j;

    this->utxo_map = j["utxo_map"].get<std::unordered_map<std::string, Utxo>>();
    this->witness_programs = j["witness_programs"].get<std::vector<std::vector<uint8_t>>>();
    this->public_keys = j["public_keys"].get<std::vector<std::vector<uint8_t>>>();
    this->private_keys = j["private_keys"].get<std::vector<std::vector<uint8_t>>>();

    return true;
}

// Recovers wallet state by deriving keys and scanning the blockchain
// This implements BIP84 (Native SegWit) derivation path for Signet
// The process involves:
// 1. Deriving keys from the master key
// 2. Generating addresses from public keys
// 3. Scanning the blockchain for UTXOs belonging to those addresses
bool WalletState::recover_wallet_state() {
    // Decode the Base58Check-encoded extended private key
    auto decoded = wallet::Base58::decode(extended_private_key);
    auto master = wallet::KeyDeserializer::deserialize(decoded);

    // Get account key at BIP84 path for signet: m/84'/1'/0'
    // BIP84 defines the derivation path for Native SegWit (bech32) addresses
    // The path components are:
    // - 84': Purpose (BIP84 for Native SegWit)
    // - 1': Coin type (1 for testnet/signet, 0 would be for mainnet)
    // - 0': Account number
    auto account = Bip32Util::get_child_key_at_path(master, "m/84'/1'/0'");
    
    // Derive external chain key: m/84'/1'/0'/0
    // In HD wallets, 0 is used for the external chain (receiving addresses)
    // 1 would be used for internal chain (change addresses)
    auto chain = Bip32Util::derive_priv_child(account, 0);
    
    // Generate first N keys for addresses
    // This creates a large number of keys to scan for UTXOs
    // In practice, wallets typically use a gap limit (e.g., 20) and only
    // generate more keys when existing ones are used
    constexpr uint32_t NUM_KEYS = 2000;
    auto keys = Bip32Util::get_keys_at_child_key_path(chain, NUM_KEYS);

    this->private_keys.reserve(keys.size());
    this->public_keys.reserve(keys.size());
    this->witness_programs.reserve(keys.size());

    // For each private key, derive the public key and witness program
    // The witness program is the script that locks the funds
    // For P2WPKH, it's a version byte (0) followed by a 20-byte hash of the public key
    for (const auto& priv_key : keys) {
        auto pub_key = wallet::Bip32Util::derive_public_key_from_private(priv_key.key);
        auto witness_program = wallet::Segwit::get_p2wpkh_program(pub_key);

        this->private_keys.push_back(std::vector<uint8_t>(priv_key.key.begin(), priv_key.key.end()));
        this->public_keys.push_back(std::move(pub_key));
        this->witness_programs.push_back(std::move(witness_program));
    }

    // Scan blockchain for UTXOs
    // This iterates through blocks to find transactions relevant to our wallet
    // In a production wallet, this would use more efficient methods like:
    // - Bloom filters (BIP37)
    // - Compact block filters (BIP158)
    // - Electrum protocol
    //
    // The scanning process follows these steps:
    // 1. Retrieve each block by height using Bitcoin RPC
    // 2. For each transaction in the block:
    //    a. Check inputs to remove spent UTXOs from our wallet
    //    b. Check outputs to add new UTXOs to our wallet
    // 3. Build a UTXO set that represents our current spendable coins
    //
    // This is a "full scan" approach which is inefficient but reliable.
    // It processes every transaction in every block to find those relevant
    // to our wallet's addresses (witness programs).
    for (uint32_t block_height = 0; block_height <= MAX_BLOCK_SCAN_HEIGHT; ++block_height) {
        // Print debug information about the current block being scanned
        std::cout << "Scanning block " << block_height << " of " << MAX_BLOCK_SCAN_HEIGHT 
                  << " (" << (block_height * 100 / MAX_BLOCK_SCAN_HEIGHT) << "%)" << std::endl;
        
        // Get the block hash for the current height using RPC
        auto block_hash_data = wallet::BitcoinCLI::execute("getblockhash " + std::to_string(block_height));
        std::string block_hash(block_hash_data.begin(), block_hash_data.end());
        
        // Get the full block data with verbosity level 2 (includes transaction details)
        // Verbosity levels in Bitcoin Core RPC:
        // 0: Returns hex-encoded serialized block
        // 1: Returns block object with transaction IDs only
        // 2: Returns block object with full transaction details
        auto block_data = wallet::BitcoinCLI::execute("getblock " + block_hash + " 2");
        
        try {
            json block = json::parse(block_data);
            
            if (!block.contains("tx") || !block["tx"].is_array()) {
                std::cout << "  Block has no transactions, skipping" << std::endl;
                continue;
            }

            // Print transaction count for this block
            std::cout << "  Processing " << block["tx"].size() << " transactions" << std::endl;

            for (const auto& tx : block["tx"]) {
                if (!tx.contains("txid") || !tx["txid"].is_string()) {
                    continue;
                }

                std::string txid = tx["txid"];
                
                // Remove spent UTXOs
                // When a transaction spends a UTXO, we need to remove it from our wallet
                // This prevents double-counting of funds and ensures accurate balance
                if (tx.contains("vin") && tx["vin"].is_array()) {
                    for (const auto& input : tx["vin"]) {
                        if (input.contains("txid") && input.contains("vout")) {
                            std::string prev_txid = input["txid"];
                            uint64_t vout_n = input["vout"];
                            
                            // UTXOs are identified by txid:vout format
                            // This is a standard way to reference specific outputs
                            std::string utxo_key = prev_txid + ":" + std::to_string(vout_n);
                            
                            // Remove this UTXO if it belongs to our wallet
                            if (this->utxo_map.count(utxo_key) > 0) {
                                std::cout << "  Found spent UTXO: " << utxo_key 
                                          << " (" << this->utxo_map[utxo_key].amount << " satoshis)" << std::endl;
                                this->utxo_map.erase(utxo_key);
                            }
                        }
                    }
                }

                // Add new UTXOs
                // We check each transaction output to see if it pays to one of our addresses
                // If it does, we add it to our UTXO set as a spendable coin
                if (tx.contains("vout") && tx["vout"].is_array()) {
                    for (const auto& output : tx["vout"]) {
                        if (!output.contains("scriptPubKey") || 
                            !output["scriptPubKey"].contains("hex") ||
                            !output.contains("n") ||
                            !output.contains("value")) {
                            continue;
                        }

                        // Extract output details
                        std::string script_hex = output["scriptPubKey"]["hex"];
                        uint64_t n = output["n"];
                        double value = output["value"];

                        // Convert hex script to binary for comparison
                        std::vector<uint8_t> script = HexUtils::decode(script_hex);
                        
                        // Check if this output pays to one of our witness programs
                        // For P2WPKH, the script is: 0x0014{20-byte-key-hash}
                        auto it = std::find(this->witness_programs.begin(),
                                          this->witness_programs.end(), script);
                        if (it != this->witness_programs.end()) {
                            // This output belongs to our wallet - create a UTXO entry
                            std::string utxo_key = txid + ":" + std::to_string(n);
                            
                            // Bitcoin internally uses little-endian for txids, but RPC returns big-endian
                            // We need to reverse the bytes for internal representation
                            std::vector<uint8_t> txid_bytes = HexUtils::decode(txid);
                            std::reverse(txid_bytes.begin(), txid_bytes.end());

                            // Create the UTXO structure with all necessary information
                            // - outpoint: references the specific output (txid + index)
                            // - amount: value in satoshis (BTC * 100,000,000)
                            // - script_pubkey: the locking script that controls spending
                            // - child_code: index of the key that can spend this UTXO
                            Utxo utxo{
                                .outpoint = {
                                    .txid_vec = std::move(txid_bytes),
                                    .index = static_cast<uint32_t>(n)
                                },
                                .amount = static_cast<uint64_t>(value * 100000000.0),
                                .script_pubkey = script,
                                .child_code = static_cast<size_t>(it - this->witness_programs.begin())
                            };

                            // Add to our UTXO map
                            this->utxo_map.emplace(utxo_key, std::move(utxo));
                            std::cout << "  Found new UTXO: " << utxo_key 
                                      << " (" << value * 100000000.0 << " satoshis)" << std::endl;
                        }
                    }
                }
            }
        } catch (const json::exception& e) {
            // Handle JSON parsing errors by throwing a domain-specific exception
            // This provides better error context than a generic JSON exception
            throw wallet::BalanceError(wallet::BalanceError::ErrorType::InvalidBlockData,
                "Failed to parse block data: " + std::string(e.what()));
        }
    }

    return true;
}

// JSON serialization for WalletState
// This enables conversion between WalletState objects and JSON
// Used for persistence and potentially for RPC interfaces
void to_json(json& j, const WalletState& w) {
    j = json{
        {"utxo_map", w.utxo_map},
        {"witness_programs", w.witness_programs},
        {"public_keys", w.public_keys},
        {"private_keys", w.private_keys}
    };
}

// JSON deserialization for WalletState
// This enables reconstruction of WalletState objects from JSON
// Used when loading wallet data from storage
void from_json(const json& j, WalletState& w) {
    j.at("utxo_map").get_to(w.utxo_map);
    j.at("witness_programs").get_to(w.witness_programs);
    j.at("public_keys").get_to(w.public_keys);
    j.at("private_keys").get_to(w.private_keys);
}

// JSON serialization for vector<uint8_t>
// Binary data is encoded as hex strings for JSON compatibility
// This is used for keys, scripts, and transaction data
void to_json(json& j, const std::vector<uint8_t>& v) {
    j = HexUtils::encode(v);
}

// JSON deserialization for vector<uint8_t>
// Converts hex strings back to binary data
// This is the inverse of the to_json operation
void from_json(const json& j, std::vector<uint8_t>& v) {
    v = HexUtils::decode(j.get<std::string>());
}

} // namespace wallet 