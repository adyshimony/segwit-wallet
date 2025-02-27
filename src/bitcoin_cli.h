#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "error.h"
#include "wallet_state.h"

namespace wallet {

class BitcoinCLI {
public:
    // Execute a bitcoin-cli command and return the result as a byte vector
    static std::vector<uint8_t> execute(const std::string& cmd);
};

} // namespace wallet 