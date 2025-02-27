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

// WalletState implementation

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


uint64_t WalletState::balance() const {
    return std::accumulate(utxo_map.begin(), utxo_map.end(), 0ULL,
        [](uint64_t sum, const auto& pair) {
            return sum + pair.second.amount;
        });
}


std::optional<std::vector<uint8_t>> WalletState::get_change_script() const {
    if (!witness_programs.empty()) {
        return witness_programs[0];
    }
    return std::nullopt;
}


std::optional<std::span<const uint8_t>> WalletState::get_private_key(size_t index) const {
    if (index < private_keys.size()) {
        return std::span<const uint8_t>(private_keys[index]);
    }
    return std::nullopt;
}


std::span<const std::vector<uint8_t>> WalletState::get_public_keys() const {
    return std::span<const std::vector<uint8_t>>(public_keys);
}


std::optional<std::vector<std::vector<uint8_t>>> WalletState::get_multisig_keys() const {
    if (public_keys.size() >= 2) {
        return std::vector<std::vector<uint8_t>>{
            public_keys[0],
            public_keys[1]
        };
    }
    return std::nullopt;
}


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

WalletState WalletState::load_from_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Failed to open file for reading");
    }

    json j;
    file >> j;

    WalletState state;
    state.utxo_map = j["utxo_map"].get<std::unordered_map<std::string, Utxo>>();
    state.witness_programs = j["witness_programs"].get<std::vector<std::vector<uint8_t>>>();
    state.public_keys = j["public_keys"].get<std::vector<std::vector<uint8_t>>>();
    state.private_keys = j["private_keys"].get<std::vector<std::vector<uint8_t>>>();

    return state;
}

WalletState recover_wallet_state(const std::string& extended_private_key) {
    auto decoded = wallet::Base58::decode(extended_private_key);
    auto master = wallet::KeyDeserializer::deserialize(decoded);

    // Get account key at BIP84 path for signet: m/84'/1'/0'
    auto account = Bip32Util::get_child_key_at_path(master, "m/84'/1'/0'");
    
    // Derive external chain key: m/84'/1'/0'/0
    auto chain = Bip32Util::derive_priv_child(account, 0);
    
    // Generate first N keys for addresses
    constexpr uint32_t NUM_KEYS = 2000;
    auto keys = Bip32Util::get_keys_at_child_key_path(chain, NUM_KEYS);

    WalletState state;
    state.private_keys.reserve(keys.size());
    state.public_keys.reserve(keys.size());
    state.witness_programs.reserve(keys.size());

    for (const auto& priv_key : keys) {
        auto pub_key = wallet::Bip32Util::derive_public_key_from_private(priv_key.key);
        auto witness_program = wallet::Segwit::get_p2wpkh_program(pub_key);

        state.private_keys.push_back(std::vector<uint8_t>(priv_key.key.begin(), priv_key.key.end()));
        state.public_keys.push_back(std::move(pub_key));
        state.witness_programs.push_back(std::move(witness_program));
    }

    // Scan blockchain for UTXOs
    for (uint32_t block_height = 0; block_height <= 300; ++block_height) {
        auto block_hash_data = wallet::BitcoinCLI::execute("getblockhash " + std::to_string(block_height));
        std::string block_hash(block_hash_data.begin(), block_hash_data.end());
        auto block_data = wallet::BitcoinCLI::execute("getblock " + block_hash + " 2");
        
        try {
            json block = json::parse(block_data);
            
            if (!block.contains("tx") || !block["tx"].is_array()) {
                continue;
            }

            for (const auto& tx : block["tx"]) {
                if (!tx.contains("txid") || !tx["txid"].is_string()) {
                    continue;
                }

                std::string txid = tx["txid"];
                
                // Remove spent UTXOs
                if (tx.contains("vin") && tx["vin"].is_array()) {
                    for (const auto& input : tx["vin"]) {
                        if (input.contains("txid") && input.contains("vout")) {
                            std::string prev_txid = input["txid"];
                            uint64_t vout_n = input["vout"];
                            std::string utxo_key = prev_txid + ":" + std::to_string(vout_n);
                            state.utxo_map.erase(utxo_key);
                        }
                    }
                }

                // Add new UTXOs
                if (tx.contains("vout") && tx["vout"].is_array()) {
                    for (const auto& output : tx["vout"]) {
                        if (!output.contains("scriptPubKey") || 
                            !output["scriptPubKey"].contains("hex") ||
                            !output.contains("n") ||
                            !output.contains("value")) {
                            continue;
                        }

                        std::string script_hex = output["scriptPubKey"]["hex"];
                        uint64_t n = output["n"];
                        double value = output["value"];

                        std::vector<uint8_t> script = HexUtils::decode(script_hex);
                        
                        auto it = std::find(state.witness_programs.begin(),
                                          state.witness_programs.end(), script);
                        if (it != state.witness_programs.end()) {
                            std::string utxo_key = txid + ":" + std::to_string(n);
                            std::vector<uint8_t> txid_bytes = HexUtils::decode(txid);
                            std::reverse(txid_bytes.begin(), txid_bytes.end());

                            Utxo utxo{
                                .outpoint = {
                                    .txid_vec = std::move(txid_bytes),
                                    .index = static_cast<uint32_t>(n)
                                },
                                .amount = static_cast<uint64_t>(value * 100000000.0),
                                .script_pubkey = script,
                                .child_code = static_cast<size_t>(it - state.witness_programs.begin())
                            };

                            state.utxo_map.emplace(utxo_key, std::move(utxo));
                        }
                    }
                }
            }
        } catch (const json::exception& e) {
            throw wallet::BalanceError(wallet::BalanceError::ErrorType::InvalidBlockData,
                "Failed to parse block data: " + std::string(e.what()));
        }
    }

    return state;
}

// Add JSON serialization for WalletState
void to_json(json& j, const WalletState& w) {
    j = json{
        {"utxo_map", w.utxo_map},
        {"witness_programs", w.witness_programs},
        {"public_keys", w.public_keys},
        {"private_keys", w.private_keys}
    };
}

void from_json(const json& j, WalletState& w) {
    j.at("utxo_map").get_to(w.utxo_map);
    j.at("witness_programs").get_to(w.witness_programs);
    j.at("public_keys").get_to(w.public_keys);
    j.at("private_keys").get_to(w.private_keys);
}

// Add JSON serialization for vector<uint8_t>
void to_json(json& j, const std::vector<uint8_t>& v) {
    j = HexUtils::encode(v);
}

void from_json(const json& j, std::vector<uint8_t>& v) {
    v = HexUtils::decode(j.get<std::string>());
}

} // namespace wallet 