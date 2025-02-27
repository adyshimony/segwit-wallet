#pragma once

#include <cstdint>

namespace wallet {

    // Bitcoin Script Operation Codes
    constexpr uint8_t OP_0 = 0x00;
    constexpr uint8_t OP_2 = 0x52;
    constexpr uint8_t OP_DUP = 0x76;
    constexpr uint8_t OP_HASH160 = 0xA9;
    constexpr uint8_t OP_EQUALVERIFY = 0x88;
    constexpr uint8_t OP_CHECKSIG = 0xAC;
    constexpr uint8_t OP_CHECKMULTISIG = 0xAE;
    constexpr uint8_t OP_RETURN = 0x6a;

    // Common script-related constants
    constexpr uint8_t COMPRESSED_PUBKEY_SIZE = 0x21; // 33 bytes
    constexpr uint8_t PUBKEY_HASH_SIZE = 0x14; // 20 bytes
    constexpr uint8_t P2WPKH_SCRIPT_SIZE = 0x19; // 25 bytes
    constexpr uint8_t WITNESS_VERSION_0 = 0x00;
    constexpr uint8_t WITNESS_PROGRAM_SIZE = 0x20; // 32 bytes

    // Transaction-related constants
    constexpr uint32_t SEQUENCE_NO_LOCKTIME = 0xFFFFFFFF;
    constexpr uint32_t SIGHASH_ALL = 0x01;
    constexpr uint32_t TX_VERSION = 0x02;
    constexpr uint8_t TX_MARKER = 0x00;
    constexpr uint8_t TX_FLAG = 0x01;

    

} // namespace wallet 