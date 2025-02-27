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

// Constants provided by the administrator for the wallet
// WALLET_NAME: Identifier for this wallet instance
// EXTENDED_PRIVATE_KEY: BIP32 master key in Base58Check encoding (tprv prefix for testnet)
// WALLET_STATE_FILE: Local file to persist wallet data between runs
constexpr const char* WALLET_NAME = "wallet_314";
constexpr const char* EXTENDED_PRIVATE_KEY = "tprv8ZgxMBicQKsPf8BJPyF6ryFmhgviot5aXsbfVh8o3Fa88iz3d7xZqnSKCeWJ25hAkq4S6Tu1RgRwBNdRqPTjgHX64WEqgbiB8xk1XjEmMX5";
constexpr const char* WALLET_STATE_FILE = "wallet_state.json";

int main() {
    try {
        // Create wallet instance with the loaded state
        // The wallet constructor initializes the wallet with the provided name and extended private key
        // This establishes the cryptographic identity of the wallet
        wallet::Wallet wallet(WALLET_NAME, EXTENDED_PRIVATE_KEY);

        // Load existing wallet state from file
        // This restores previously discovered UTXOs and address data
        // If the file doesn't exist, the wallet will perform a blockchain scan
        wallet.load(WALLET_STATE_FILE);

        // Get balance in satoshis (1 BTC = 100,000,000 satoshis)
        // Satoshis are the smallest unit in Bitcoin, similar to cents in dollars
        auto balance = wallet.balance();
        
        // Convert satoshis to BTC with proper decimal formatting
        // Use fixed-point notation with 8 decimal places (Bitcoin standard)
        // This ensures consistent display of Bitcoin amounts
        double balance_btc = static_cast<double>(balance) / 100'000'000.0;

        // Output format: "<wallet_name> <balance>"
        // Example: "wallet_314 0.05000000"
        // This format is designed for easy parsing by other tools
        std::cout << wallet.get_wallet_name() << " " 
                  << std::fixed << std::setprecision(8) << balance_btc 
                  << std::endl;

        // Spend P2WPKH transaction
        // This creates a Pay-to-Witness-Public-Key-Hash transaction
        // P2WPKH is the standard SegWit transaction type for single-signature wallets
        // It returns both the transaction ID and the raw transaction data
        auto p2wpkh_result = wallet.spend_p2wpkh();
        auto p2wpkh_txid = p2wpkh_result.first;
        auto p2wpkh_tx = p2wpkh_result.second;
        if (p2wpkh_tx.empty()) {
            std::cerr << "Failed to create P2WPKH transaction" << std::endl;
            return 1;
        }

        // Display the raw transaction in hexadecimal format
        std::cout << std::endl;
        std::cout << "p2wpkh tx:" << std::endl;
        std::cout << wallet::HexUtils::encode(p2wpkh_tx) << std::endl;

        // Spend P2WSH transaction using the txid from the first transaction
        // Pay-to-Witness-Script-Hash (P2WSH) is used for more complex script conditions
        // In this case, it demonstrates spending from a multi-signature or time-locked script
        auto p2wsh_tx = wallet.spend_p2wsh(p2wpkh_txid);
        if (p2wsh_tx.empty()) {
            std::cerr << "Failed to create P2WSH transaction" << std::endl;
            return 1;
        }

        std::cout << std::endl;
        std::cout << "p2wsh tx:" << std::endl;
        std::cout << wallet::HexUtils::encode(p2wsh_tx) << std::endl;        

        // Format transactions for mempool acceptance check
        // The testmempoolaccept RPC call validates transactions without broadcasting them
        // This is useful to check if transactions would be accepted by the network
        std::string mempool_check_command = "testmempoolaccept '[\"" + 
            wallet::HexUtils::encode(p2wpkh_tx) + "\", \"" + 
            wallet::HexUtils::encode(p2wsh_tx) + "\"]'";
        
        // Execute the mempool acceptance check
        // This communicates with the Bitcoin Core node to validate the transactions
        std::cout << "\nChecking mempool acceptance..." << std::endl;
        auto result = wallet::BitcoinCLI::execute(mempool_check_command);
        
        // Parse and format the JSON result
        // The result contains detailed information about transaction validity
        // Including potential reasons for rejection if the transaction is invalid
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