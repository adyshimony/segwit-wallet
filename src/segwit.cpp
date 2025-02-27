#include "segwit.hpp"
#include "utxo.hpp"
#include "consts.hpp"
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <array>
#include "hash_utils.hpp"

namespace wallet {

// Create a Pay-to-Witness-Public-Key-Hash (P2WPKH) program from a public key
// This implements the standard P2WPKH witness program as defined in BIP141
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
//
// The process:
// 1. Compute SHA256 of the public key
// 2. Compute RIPEMD160 of the SHA256 hash (this is the HASH160 algorithm)
// 3. Create witness program: [version byte] [push byte] [20-byte hash]
//
// P2WPKH structure (22 bytes total):
// - 0x00     : Witness version 0
// - 0x14     : Push 20 bytes
// - [20 bytes]: HASH160 of public key
std::vector<uint8_t> Segwit::get_p2wpkh_program(std::span<const uint8_t> pubkey) {
    // Compute HASH160 of the public key (RIPEMD160(SHA256(pubkey)))
    auto hash160_result = HashUtils::hash160(pubkey);
    
    // Create the witness program
    std::vector<uint8_t> program;
    program.reserve(22);
    program.push_back(0x00); // SegWit version 0
    program.push_back(0x14); // 20 bytes push
    program.insert(program.end(), hash160_result.begin(), hash160_result.end());
    
    return program;
}

// Create a Pay-to-Witness-Script-Hash (P2WSH) program from a script
// This implements the standard P2WSH witness program as defined in BIP141
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
//
// The process:
// 1. Compute SHA256 of the witness script (note: single SHA256, not double)
// 2. Create witness program: [version byte] [push byte] [32-byte hash]
//
// P2WSH structure (34 bytes total):
// - 0x00     : Witness version 0
// - 0x20     : Push 32 bytes
// - [32 bytes]: SHA256 hash of the witness script
std::vector<uint8_t> Segwit::get_p2wsh_program(const std::vector<uint8_t>& script, std::optional<uint32_t> version) {
    // Compute SHA256 of the witness script
    auto hash = HashUtils::sha256(script);
    
    // Create the witness program
    std::vector<uint8_t> program;
    program.push_back(version.value_or(0x00)); // SegWit version (default to 0)
    program.push_back(0x20); // 32 bytes push
    program.insert(program.end(), hash.begin(), hash.end());
    
    return program;
}

// Create a 2-of-2 multisignature witness script for use in P2WSH outputs
// This creates a standard Bitcoin multisig script following the pattern:
// OP_n <pubkey1> <pubkey2> ... <pubkey_m> OP_m OP_CHECKMULTISIG
//
// The script requires 2 signatures from the provided public keys to spend
// This is commonly used in 2-of-2 multisig wallets and Lightning Network channels
//
// Multisig script structure:
// - OP_2     : Require 2 signatures (m)
// - 0x21     : Push 33 bytes (compressed public key size)
// - [33 bytes]: First public key
// - 0x21     : Push 33 bytes
// - [33 bytes]: Second public key
// - OP_2     : Total number of keys (n)
// - OP_CHECKMULTISIG: Verify the signatures
std::vector<uint8_t> Segwit::create_witness_script(const std::vector<std::vector<uint8_t>>& keys) {
    std::vector<uint8_t> script;
    script.push_back(OP_2);  // Require 2 signatures
    
    // Add each public key to the script
    for (const auto& key : keys) {
        script.push_back(COMPRESSED_PUBKEY_SIZE);  // Push 33 bytes
        script.insert(script.end(), key.begin(), key.end());
    }
    
    script.push_back(OP_2);  // Total number of keys
    script.push_back(OP_CHECKMULTISIG);  // Verify the signatures
    
    return script;
}

// Given a Utxo object, extract the public key hash from the output script
// and assemble the p2wpkh scriptcode as defined in BIP143
// https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
//
// For P2WPKH, the scriptCode is a standard P2PKH script:
// <script length> OP_DUP OP_HASH160 <pubkey hash> OP_EQUALVERIFY OP_CHECKSIG
//
// P2WPKH scriptcode structure (25 bytes total):
// - 0x19     : Script length (25 bytes)
// - 0x76     : OP_DUP
// - 0xA9     : OP_HASH160
// - 0x14     : Push 20 bytes
// - [20 bytes]: Public key hash (from witness program)
// - 0x88     : OP_EQUALVERIFY
// - 0xAC     : OP_CHECKSIG
std::vector<uint8_t> Segwit::get_p2wpkh_scriptcode(const Utxo& utxo) {
    std::vector<uint8_t> script;
    script.push_back(P2WPKH_SCRIPT_SIZE);  // Script length (25 bytes)
    script.push_back(OP_DUP);              // Duplicate the top stack item
    script.push_back(OP_HASH160);          // Hash the top stack item
    script.push_back(PUBKEY_HASH_SIZE);    // Push 20 bytes
    
    // Extract the public key hash from the witness program
    // The witness program format is: [version byte] [push byte] [20-byte hash]
    // So we skip the first 2 bytes to get the hash
    script.insert(script.end(), utxo.script_pubkey.begin() + 2, utxo.script_pubkey.begin() + 22);
    
    script.push_back(OP_EQUALVERIFY);      // Verify equality and remove from stack
    script.push_back(OP_CHECKSIG);         // Check signature against public key
    
    return script;
}

// Create a transaction input from an outpoint (previous transaction output)
// This serializes the input according to the Bitcoin transaction format
// https://en.bitcoin.it/wiki/Transaction
//
// Transaction input structure:
// - [32 bytes]: Previous transaction ID (little-endian)
// - [4 bytes] : Previous output index (little-endian)
// - [1-9 bytes]: Script length (varint) - 0 for SegWit inputs
// - [0 bytes] : Empty script for SegWit inputs
// - [4 bytes] : Sequence number (typically 0xffffffff for non-RBF transactions)
std::vector<uint8_t> Segwit::input_from_utxo(const Outpoint& outpoint) {
    std::vector<uint8_t> input;
    
    // Previous transaction ID (32 bytes, little-endian)
    input.insert(input.end(), outpoint.txid_vec.begin(), outpoint.txid_vec.end());
    
    // Previous output index (4 bytes, little-endian)
    const auto index_bytes = std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(&outpoint.index),
        reinterpret_cast<const uint8_t*>(&outpoint.index) + sizeof(outpoint.index)
    );
    input.insert(input.end(), index_bytes.begin(), index_bytes.end());
    
    // Empty scriptSig for SegWit inputs (1 byte: 0x00)
    input.push_back(0x00);
    
    // Sequence number (4 bytes, little-endian)
    // SEQUENCE_NO_LOCKTIME (0xffffffff) indicates that this input is not affected by locktime
    const auto sequence_bytes = std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(&SEQUENCE_NO_LOCKTIME),
        reinterpret_cast<const uint8_t*>(&SEQUENCE_NO_LOCKTIME) + sizeof(SEQUENCE_NO_LOCKTIME)
    );
    input.insert(input.end(), sequence_bytes.begin(), sequence_bytes.end());
    
    return input;
}

} // namespace wallet 