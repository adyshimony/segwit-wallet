/**
 * Bitcoin CLI Interface
 * 
 * This file contains the BitcoinCLI class which provides a wrapper around
 * the bitcoin-cli command line tool. It allows for executing commands and
 * processing their results, with special handling for numeric formatting
 * in JSON responses.
 * 
 * The class handles error conditions and provides appropriate exceptions
 * when commands fail or return invalid data.
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "error.h"
#include "wallet_state.h"

namespace wallet {

/**
 * BitcoinCLI class
 * 
 * Provides an interface to execute bitcoin-cli commands and process their results.
 * Handles command execution, error checking, and formatting of responses.
 * 
 * Features:
 * Executes bitcoin-cli commands on the signet test network
 * Captures and processes command output
 * Formats numeric values in JSON responses with fixed precision
 * Handles errors with appropriate exceptions
 */
class BitcoinCLI {
public:
    /**
     * Execute a bitcoin-cli command and return the result
     * 
     * Parameters:
     * cmd - The bitcoin-cli command to execute (without the 'bitcoin-cli' prefix)
     * 
     * Returns:
     * The command output as a vector of bytes
     * 
     * Throws:
     * wallet::BalanceError if the command fails or returns invalid data
     */
    static std::vector<uint8_t> execute(const std::string& cmd);
};

} // namespace wallet 