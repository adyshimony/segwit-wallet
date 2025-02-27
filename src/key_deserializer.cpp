#include "key_deserializer.hpp"
#include "error.hpp"
#include <algorithm>

namespace wallet {

// Deserialize bytes into an extended key.
// Args: bytes - Byte span containing the serialized key data (must be 78 bytes)
// Returns: The deserialized extended key
// Throws: wallet::BalanceError if the input has invalid format
ExKey KeyDeserializer::deserialize(std::span<const uint8_t> bytes) {
    if (bytes.size() != 78) {
        throw wallet::BalanceError(wallet::BalanceError::ErrorType::InvalidKeyFormat);
    }

    ExKey key;
    // Copy each field with exact size checking
    std::copy_n(bytes.begin(), 4, key.version.begin());
    std::copy_n(bytes.begin() + 4, 1, key.depth.begin());
    std::copy_n(bytes.begin() + 5, 4, key.finger_print.begin());
    std::copy_n(bytes.begin() + 9, 4, key.child_number.begin());
    std::copy_n(bytes.begin() + 13, 32, key.chaincode.begin());
    std::copy_n(bytes.begin() + 46, 32, key.key.begin());
    
    return key;
}

} // namespace wallet 