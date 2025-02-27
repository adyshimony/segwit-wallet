#pragma once

#include <span>
#include <cstdint>
#include "bip32_util.hpp" 

namespace wallet {

class KeyDeserializer {
public:
    // Deserialize bytes into an extended key
    static ExKey deserialize(std::span<const uint8_t> bytes);
};

} // namespace wallet 