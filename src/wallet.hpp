#pragma once
#include <vector>
#include <string>
#include <array>
#include <memory>
#include <cstdint>
#include <stdexcept>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <optional>
#include "wallet_state.hpp"  // Include the WalletState header

namespace wallet {

// Error types
enum class SpendError {
    MissingCodeCantRun,
    SigningFailure
};

// Forward declarations
struct Outpoint;
struct Utxo;

class Wallet {
public:
    // Constructor that takes a WalletState
    Wallet(const WalletState& state) : wallet_state(state) {}
    
    // Creates a transaction spending from P2WPKH to P2WSH multisig with change
    // Returns the transaction ID and complete transaction
    std::pair<std::array<uint8_t, 32>, std::vector<uint8_t>> spend_p2wpkh();
    
    // Creates a transaction spending from P2WSH multisig to OP_RETURN with change
    // Returns the complete transaction
    std::vector<uint8_t> spend_p2wsh(const std::array<uint8_t, 32>& txid);
    
    // Get the wallet state
    const WalletState& get_wallet_state() const { return wallet_state; }
    
private:
    // The wallet state as a member variable
    WalletState wallet_state;
    
    // Serializes a transaction output with script and value
    std::vector<uint8_t> create_output(const std::vector<uint8_t>& script, uint64_t value);

    // Creates a BIP143 signature hash (commitment hash) for transaction signing
    std::vector<uint8_t> get_commitment_hash(const Outpoint& outpoint, 
                                           const std::vector<uint8_t>& scriptcode,
                                           uint64_t value,
                                           const std::vector<const Utxo*>& outputs);

    // Finds the key index for a UTXO from a list of programs
    uint32_t get_key_index(const Utxo& utxo, const std::vector<std::string>& programs);
    
    // Signs a message with a private key using ECDSA with low-S normalization
    std::vector<uint8_t> sign(const std::array<uint8_t, 32>& privkey, const std::vector<uint8_t>& msg);
    
    // Creates a witness for a P2WPKH input with signature and public key
    std::vector<uint8_t> get_p2wpkh_witness(const std::array<uint8_t, 32>& privkey, const std::vector<uint8_t>& msg);
    
    // Creates a witness for a P2WSH multisig input with multiple signatures
    std::vector<uint8_t> get_p2wsh_witness(const std::vector<const std::array<uint8_t, 32>*>& privs, const std::vector<uint8_t>& msg);
    
    // Assembles a complete SegWit transaction with inputs, outputs, and witnesses
    std::vector<uint8_t> assemble_transaction(const std::vector<std::vector<uint8_t>>& inputs,
                                             const std::vector<Utxo>& outputs,
                                             const std::vector<std::vector<uint8_t>>& witnesses);

    // Calculates the transaction ID (txid) for a transaction, excluding witness data
    std::array<uint8_t, 32> get_txid(const std::vector<std::vector<uint8_t>>& inputs, const std::vector<Utxo>& outputs);
    
    // Creates an OP_RETURN script containing a message (up to 75 bytes)
    std::vector<uint8_t> create_op_return_script(const std::vector<uint8_t>& message);

    // Derive a compressed public key from a private key
    std::vector<uint8_t> derive_public_key(const std::array<uint8_t, 32>& privkey);
};

} // namespace wallet