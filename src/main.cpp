/**
 * @file main.cpp
 * @brief Bitcoin wallet balance checker for signet testnet
 * 
 * This program implements a Bitcoin wallet that:
 * 1. Recovers wallet state from an extended private key (xpriv)
 * 2. Maintains wallet state in a JSON file
 * 3. Displays current balance in BTC
 * 
 * Bitcoin Protocol Elements:
 * - Uses BIP32 Hierarchical Deterministic Wallets
 * - Implements BIP84 Native SegWit (bech32) addresses
 * - Works with Bitcoin's signet test network
 * - Uses derivation path m/84'/1'/0'/0 (Signet, Account 0, External Chain)
 * 
 * Key C++ Features Used:
 * - std::filesystem: Modern file system operations (C++17)
 * - RAII: Resource management through smart pointers and containers
 * - Exception handling: For error management
 * - Fixed-width integers: For precise Bitcoin protocol values
 * - std::fixed/setprecision: For proper Bitcoin amount formatting
 */

#include "bitcoin_cli.hpp"
#include "segwit.hpp"
#include "wallet_state.hpp"
#include "wallet.hpp"
#include "hex_utils.hpp"
#include <iostream>
#include <iomanip>
#include <filesystem>
#include <nlohmann/json.hpp>

int main() {
    try {
        // Wallet state file stores UTXOs, keys, and other wallet data in JSON format
        const std::string wallet_file = "wallet_state.json";
        
        // Debug output to help with path-related issues
        //std::cout << "Current working directory: " << std::filesystem::current_path() << std::endl;
        
        // Check if wallet state exists, if not, perform recovery
        if (!std::filesystem::exists(wallet_file)) {
            std::cout << "Wallet state file not found. Running recovery..." << std::endl;
            try {
                // Recover wallet state from extended private key
                // This process:
                // 1. Derives child keys according to BIP32
                // 2. Generates corresponding public keys
                // 3. Creates SegWit addresses
                // 4. Scans blockchain for UTXOs
                auto wallet_state = wallet::recover_wallet_state(wallet::EXTENDED_PRIVATE_KEY);
                wallet_state.save_to_file(wallet_file);
                std::cout << "Wallet state recovered and saved." << std::endl;
            } catch (const wallet::BalanceError& e) {
                // Special handling for missing bitcoin-cli
                if (e.type() == wallet::BalanceError::ErrorType::MissingCodeCantRun) {
                    std::cerr << "Warning: " << e.what() << std::endl;
                    std::cerr << "Creating empty wallet state." << std::endl;
                    wallet::WalletState empty_state;
                    empty_state.save_to_file(wallet_file);
                } else {
                    throw; // Re-throw other errors
                }
            }
        }

        // Load wallet state and calculate balance
        wallet::WalletState wallet_state = wallet::WalletState::load_from_file(wallet_file);
        
        // Get balance in satoshis (1 BTC = 100,000,000 satoshis)
        auto balance = wallet_state.balance();
        
        // Convert satoshis to BTC with proper decimal formatting
        // Use fixed-point notation with 8 decimal places (Bitcoin standard)
        double balance_btc = static_cast<double>(balance) / 100'000'000.0;

        // Output format: "<wallet_name> <balance>"
        // Example: "wallet_314 0.05000000"
        std::cout << wallet::WALLET_NAME << " " 
                  << std::fixed << std::setprecision(8) << balance_btc 
                  << std::endl;

        // Create wallet instance with the loaded state
        wallet::Wallet wallet(wallet_state);

        // Spend P2WPKH transaction
        auto result1 = wallet.spend_p2wpkh();
        auto txid1 = result1.first;
        auto tx1 = result1.second;
        if (tx1.empty()) {
            std::cerr << "Failed to create P2WPKH transaction" << std::endl;
            return 1;
        }

        std::cout << "***********************************Transactions*************************************************" << std::endl;
        std::cout << "TX1:" << std::endl;
        std::cout << wallet::HexUtils::encode(tx1) << std::endl;

        // Spend P2WSH transaction using the txid from the first transaction
        auto tx2 = wallet.spend_p2wsh(txid1);
        if (tx2.empty()) {
            std::cerr << "Failed to create P2WSH transaction" << std::endl;
            return 1;
        }

        std::cout << "TX2:" << std::endl;
        std::cout << wallet::HexUtils::encode(tx2) << std::endl;        

        // Format transactions for mempool acceptance check
        std::string mempool_check_command = "testmempoolaccept '[\"" + 
            wallet::HexUtils::encode(tx1) + "\", \"" + 
            wallet::HexUtils::encode(tx2) + "\"]'";
        
        std::cout << "\nChecking mempool acceptance..." << std::endl;
        auto result = wallet::BitcoinCLI::execute(mempool_check_command);
        
        // Parse and format the JSON result
        try {
            nlohmann::json mempool_result = nlohmann::json::parse(result);
            std::cout << "Mempool acceptance result:" << std::endl;
            std::cout << std::setw(4) << mempool_result << std::endl;
        } catch (const nlohmann::json::parse_error& e) {
            std::cerr << "Failed to parse mempool result: " << e.what() << std::endl;
        }

    } catch (const std::exception& e) {
        // Central error handling for all exceptions
        std::cerr << "Error: " << e.what() << std::endl;
        return 1; // Return error code
    }

    return 0; // Successful execution
} 