#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "error.hpp"
#include "wallet_state.hpp"

namespace wallet {

class BitcoinCLI {
public:
    // Execute a bitcoin-cli command and return the result as a byte vector
    static std::vector<uint8_t> execute(const std::string& cmd);
};

} // namespace wallet 