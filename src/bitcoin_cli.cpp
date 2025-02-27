#include "bitcoin_cli.hpp"
#include <array>
#include <memory>
#include <cstdio>
#include <nlohmann/json.hpp>

namespace wallet {

using json = nlohmann::json;

// Execute a bitcoin-cli command and return the result as a byte vector.
// 
// Args:
//   cmd: The bitcoin-cli command to execute (without the 'bitcoin-cli' prefix)
// Returns:
//   The command output as a vector of bytes
// Throws:
//   wallet::BalanceError if the command fails or returns invalid data
std::vector<uint8_t> BitcoinCLI::execute(const std::string& cmd) {
    std::string full_cmd = "bitcoin-cli -signet " + cmd + " 2>&1";  // Capture stderr too
    
    std::unique_ptr<FILE, decltype(&pclose)> pipe(
        popen(full_cmd.c_str(), "r"),
        pclose
    );

    if (!pipe) {
        throw wallet::BalanceError(wallet::BalanceError::ErrorType::MissingCodeCantRun, 
            "Failed to execute bitcoin-cli. Make sure it is installed and in your PATH.");
    }

    std::string result;
    std::array<char, 128> buffer;
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    int exit_code = pclose(pipe.release());
    if (exit_code != 0) {
        throw wallet::BalanceError(wallet::BalanceError::ErrorType::RPCError, 
            "bitcoin-cli command failed with exit code " + std::to_string(exit_code) + 
            ". Output: " + result);
    }

    if (result.empty()) {
        throw wallet::BalanceError(wallet::BalanceError::ErrorType::RPCError, "Empty response from bitcoin-cli");
    }

    // Remove trailing newline if present
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }

    // For non-JSON responses (like getblockhash), return the raw bytes
    if (result[0] != '{' && result[0] != '[') {
        return std::vector<uint8_t>(result.begin(), result.end());
    }

    // For JSON responses, parse and validate
    try {
        return std::vector<uint8_t>(result.begin(), result.end());
    } catch (const json::exception& e) {
        throw wallet::BalanceError(wallet::BalanceError::ErrorType::RPCError, 
            std::string("Failed to parse JSON response: ") + e.what());
    }
}

} // namespace wallet 