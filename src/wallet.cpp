#include "wallet.hpp"
#include "wallet_state.hpp"
#include "utxo.hpp"
#include "consts.hpp"
#include "segwit.hpp"
#include "hash_utils.hpp"
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <algorithm>
#include <ranges>

namespace wallet {

// Create a serialized transaction output from a script and value
// This follows the Bitcoin transaction output format:
// https://en.bitcoin.it/wiki/Transaction#Output
//
// Transaction output structure:
// - [8 bytes]: Value in satoshis (little-endian)
// - [1-9 bytes]: Script length (varint)
// - [variable]: Script (scriptPubKey)
std::vector<uint8_t> Wallet::create_output(const std::vector<uint8_t>& script, uint64_t value) {
    std::vector<uint8_t> output;
    
    // Value in satoshis (8 bytes, little-endian)
    const auto value_bytes = std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(&value),
        reinterpret_cast<const uint8_t*>(&value) + sizeof(value)
    );
    output.insert(output.end(), value_bytes.begin(), value_bytes.end());
    
    // Script length (1 byte for scripts < 253 bytes)
    output.push_back(static_cast<uint8_t>(script.size()));
    
    // Script (scriptPubKey)
    output.insert(output.end(), script.begin(), script.end());
    
    return output;
}

// Create the transaction digest (hash) for signing according to BIP143
// This implements the improved signature hash algorithm for SegWit transactions
// https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
//
// The commitment hash (also called sighash) is the data that is actually signed when 
// creating a digital signature for a Bitcoin transaction. It commits to specific parts
// of the transaction, ensuring that those parts cannot be modified without invalidating
// the signature. For SegWit transactions, BIP143 introduced a new algorithm that fixes
// the quadratic hashing problem and enables signing the input values directly.
//
// In transaction signing, this commitment hash serves several critical purposes:
// - Prevents transaction malleability by committing to the witness program and values
// - Enables verification that the signer had knowledge of the input values
// - Allows selective commitment to parts of the transaction (via SIGHASH flags)
// - Provides replay protection across different inputs in the same transaction
//
// The commitment structure includes:
// 1. Transaction version (4 bytes)
// 2. Hash of all input outpoints (32 bytes) - double SHA256
// 3. Hash of all input sequence numbers (32 bytes) - double SHA256
// 4. Outpoint being spent (36 bytes)
// 5. Script code of the input (variable)
// 6. Value of the output being spent (8 bytes)
// 7. Sequence number of the input (4 bytes)
// 8. Hash of all outputs (32 bytes) - double SHA256
// 9. Locktime (4 bytes)
// 10. Sighash type (4 bytes)
std::vector<uint8_t> Wallet::get_commitment_hash(
    const Outpoint& outpoint,
    const std::vector<uint8_t>& scriptcode,
    uint64_t value,
    const std::vector<const Utxo*>& outputs) {
    
    std::vector<uint8_t> commitment;
    
    // 1. Transaction version (4 bytes, little-endian)
    commitment.insert(commitment.end(),
        reinterpret_cast<const uint8_t*>(&TX_VERSION),
        reinterpret_cast<const uint8_t*>(&TX_VERSION) + sizeof(TX_VERSION));
    
    // 2. Hash of all input outpoints (32 bytes) - double SHA256
    std::vector<uint8_t> prevouts;
    prevouts.insert(prevouts.end(), outpoint.txid_vec.begin(), outpoint.txid_vec.end());
    prevouts.insert(prevouts.end(), 
        reinterpret_cast<const uint8_t*>(&outpoint.index),
        reinterpret_cast<const uint8_t*>(&outpoint.index) + sizeof(outpoint.index));
        
    auto hash_prevouts = HashUtils::double_sha256(prevouts);
    commitment.insert(commitment.end(), hash_prevouts.begin(), hash_prevouts.end());
    
    // 3. Hash of all input sequence numbers (32 bytes) - double SHA256
    const uint32_t sequence = SEQUENCE_NO_LOCKTIME;
    std::vector<uint8_t> seq_bytes(
        reinterpret_cast<const uint8_t*>(&sequence),
        reinterpret_cast<const uint8_t*>(&sequence) + sizeof(sequence)
    );
    
    auto hash_sequence = HashUtils::double_sha256(seq_bytes);
    commitment.insert(commitment.end(), hash_sequence.begin(), hash_sequence.end());
    
    // 4. Outpoint being spent (36 bytes)
    // - Transaction ID (32 bytes, little-endian)
    // - Output index (4 bytes, little-endian)
    commitment.insert(commitment.end(), outpoint.txid_vec.begin(), outpoint.txid_vec.end());
    commitment.insert(commitment.end(),
        reinterpret_cast<const uint8_t*>(&outpoint.index),
        reinterpret_cast<const uint8_t*>(&outpoint.index) + sizeof(outpoint.index));
    
    // 5. Script code of the input (variable)
    commitment.insert(commitment.end(), scriptcode.begin(), scriptcode.end());
    
    // 6. Value of the output being spent (8 bytes, little-endian)
    commitment.insert(commitment.end(),
        reinterpret_cast<const uint8_t*>(&value),
        reinterpret_cast<const uint8_t*>(&value) + sizeof(value));
    
    // 7. Sequence number of the input (4 bytes, little-endian)
    commitment.insert(commitment.end(),
        reinterpret_cast<const uint8_t*>(&sequence),
        reinterpret_cast<const uint8_t*>(&sequence) + sizeof(sequence));
    
    // 8. Hash of all outputs (32 bytes)
    // Serialize all outputs and compute double SHA256
    std::vector<uint8_t> serialized_outputs;
    for (const auto* output : outputs) {
        auto serialized_output = create_output(output->script_pubkey, output->amount);
        serialized_outputs.insert(serialized_outputs.end(), 
                                 serialized_output.begin(), 
                                 serialized_output.end());
    }
    
    auto hash_outputs = HashUtils::double_sha256(serialized_outputs);
    commitment.insert(commitment.end(), hash_outputs.begin(), hash_outputs.end());
    
    // 9. Locktime (4 bytes, little-endian)
    const uint32_t locktime = 0;
    commitment.insert(commitment.end(),
        reinterpret_cast<const uint8_t*>(&locktime),
        reinterpret_cast<const uint8_t*>(&locktime) + sizeof(locktime));
    
    // 10. Sighash type (4 bytes, little-endian)
    const uint32_t hash_type = SIGHASH_ALL;
    commitment.insert(commitment.end(),
        reinterpret_cast<const uint8_t*>(&hash_type),
        reinterpret_cast<const uint8_t*>(&hash_type) + sizeof(hash_type));
    
    // Final double SHA256 hash
    auto final_hash = HashUtils::double_sha256(commitment);
    
    return std::vector<uint8_t>(final_hash.begin(), final_hash.end());
}

// Sign a message digest with a private key using ECDSA on the secp256k1 curve
// This follows the Bitcoin signature process including low-S value normalization
// https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#low-s-values-in-signatures
//
// Bitcoin uses ECDSA signatures with the secp256k1 curve. For a given message and private key,
// ECDSA produces a signature consisting of two values: r and s. However, for any valid signature (r,s),
// the signature (r,n-s) is also valid (where n is the curve order). To prevent transaction malleability,
// BIP-62 requires that the s value must be in the lower half of the curve order.
//
// The ECDSA math allows for two valid s values for any signature:
// - Original s
// - n - s (where n is the curve order)
// Both produce valid signatures, but this creates a malleability vector where a third party could
// modify a transaction's signature without invalidating it. By enforcing only the lower s-value,
// Bitcoin eliminates this malleability vector, ensuring transaction IDs remain consistent.
//
// We use OpenSSL's BIGNUM for these operations because:
// - The secp256k1 curve order is a 256-bit number (too large for standard C++ types)
// - BIGNUMs allow for arbitrary-precision arithmetic needed for cryptographic operations
// - We need to perform comparisons and arithmetic on these large numbers (like s > n/2 and n - s)
//
// The signature process:
// 1. Initialize the secp256k1 curve and key
// 2. Sign the message digest with ECDSA
// 3. Normalize the S value to be in the lower half of the curve order
// 4. Convert to DER format and append the sighash type
//
// The final signature is encoded in DER format with SIGHASH_ALL appended, which is the standard
// format expected in Bitcoin transaction inputs.
std::vector<uint8_t> Wallet::sign(const std::array<uint8_t, 32>& privkey, const std::vector<uint8_t>& msg) {
    // Initialize EC_KEY with secp256k1
    std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> eckey(
        EC_KEY_new_by_curve_name(NID_secp256k1), EC_KEY_free);
    if (!eckey) {
        throw SpendError::SigningFailure;
    }
    
    // Convert private key to BIGNUM
    // BIGNUM is OpenSSL's arbitrary-precision integer type needed for cryptographic operations
    BIGNUM* bn_priv = BN_bin2bn(privkey.data(), privkey.size(), nullptr);
    if (!bn_priv) {
        throw SpendError::SigningFailure;
    }
    
    // Set private key
    if (!EC_KEY_set_private_key(eckey.get(), bn_priv)) {
        BN_free(bn_priv);
        throw SpendError::SigningFailure;
    }
    
    // Sign the message
    std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(
        ECDSA_do_sign(msg.data(), msg.size(), eckey.get()), ECDSA_SIG_free);
    if (!sig) {
        BN_free(bn_priv);
        throw SpendError::SigningFailure;
    }
    
    // Get R and S from the signature
    // An ECDSA signature consists of two values (r,s) that together prove knowledge of the private key
    const BIGNUM* r;
    const BIGNUM* s;
    ECDSA_SIG_get0(sig.get(), &r, &s);
    
    // Secp256k1 curve order (n)
    // This is the order of the elliptic curve group, a 256-bit prime number
    // n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
    BIGNUM* order = BN_new();
    if (!order || BN_hex2bn(&order, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141") != 64) {
        BN_free(bn_priv);
        BN_free(order);
        throw SpendError::SigningFailure;
    }
    
    // Compute n/2
    // We need half the curve order to determine if s is in the upper or lower half
    BIGNUM* half_order = BN_new();
    if (!half_order || !BN_rshift1(half_order, order)) {
        BN_free(bn_priv);
        BN_free(order);
        BN_free(half_order);
        throw SpendError::SigningFailure;
    }
    
    // If S > n/2, replace S with n - S
    // This is the key step for low-S normalization:
    // - If s is already in the lower half of the curve order, keep it as is
    // - If s is in the upper half, replace it with n - s (the equivalent lower value)
    // This ensures a canonical signature form and prevents transaction malleability
    if (BN_cmp(s, half_order) > 0) {
        BIGNUM* new_s = BN_new();
        if (!new_s || !BN_sub(new_s, order, s)) {
            BN_free(bn_priv);
            BN_free(order);
            BN_free(half_order);
            BN_free(new_s);
            throw SpendError::SigningFailure;
        }
        // Update signature with new S (takes ownership of new_s)
        if (ECDSA_SIG_set0(sig.get(), BN_dup(r), new_s) != 1) {
            BN_free(bn_priv);
            BN_free(order);
            BN_free(half_order);
            BN_free(new_s);
            throw SpendError::SigningFailure;
        }
    }
    
    // Convert to DER format
    // DER (Distinguished Encoding Rules) is the standard format for encoding ECDSA signatures in Bitcoin
    unsigned char* der = nullptr;
    int der_len = i2d_ECDSA_SIG(sig.get(), &der);
    if (der_len <= 0) {
        BN_free(bn_priv);
        BN_free(order);
        BN_free(half_order);
        throw SpendError::SigningFailure;
    }
    
    std::vector<uint8_t> signature(der, der + der_len);
    OPENSSL_free(der);
    BN_free(bn_priv);
    BN_free(order);
    BN_free(half_order);
    
    // Append SIGHASH_ALL
    // This indicates that the signature commits to all inputs and outputs of the transaction
    signature.push_back(SIGHASH_ALL);
    
    return signature;
}
    
    
// Create a witness for a Pay-to-Witness-Public-Key-Hash (P2WPKH) input
// This follows the SegWit transaction format defined in BIP141
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
//
// P2WPKH is the SegWit version of the traditional P2PKH (Pay-to-Public-Key-Hash) script.
// It moves the signature and public key from the scriptSig to the witness data structure,
// which is segregated from the main transaction data (hence "Segregated Witness").
//
// Benefits of P2WPKH over traditional P2PKH:
// - Fixes transaction malleability by moving signatures outside the txid calculation
// - Reduces transaction size (and therefore fees) through witness discount
// - Enables future script upgrades through script versioning
//
// A P2WPKH output contains a witness program in its scriptPubKey:
//   0x00 0x14 {20-byte-key-hash}
// Where the 20-byte-key-hash is the HASH160 of the compressed public key.
//
// A P2WPKH witness consists of exactly two items:
// 1. A signature created with the private key
// 2. The public key that corresponds to the private key
//
// The witness is used to satisfy the spending conditions of a P2WPKH output
// by proving ownership of the private key that corresponds to the public key hash
// in the witness program.
//
// The witness structure:
// - [1 byte]: Number of witness items (0x02 for P2WPKH)
// - [1 byte]: Length of the signature
// - [variable]: Signature (DER-encoded with SIGHASH_ALL appended)
// - [1 byte]: Length of the public key
// - [33 bytes]: Compressed public key
std::vector<uint8_t> Wallet::get_p2wpkh_witness(const std::array<uint8_t, 32>& privkey, const std::vector<uint8_t>& msg) {
    // Sign the message with the private key
    auto signature = sign(privkey, msg);
    
    // Derive the public key using Bip32Util
    auto pub_key_bytes = Bip32Util::derive_public_key_from_private(privkey);
    
    // Construct the witness
    std::vector<uint8_t> witness;
    
    // Number of witness items (2)
    witness.push_back(0x02);
    
    // First item: signature + SIGHASH_ALL
    witness.push_back(static_cast<uint8_t>(signature.size() + 1)); // Length of signature + 1 byte for SIGHASH
    witness.insert(witness.end(), signature.begin(), signature.end());
    witness.push_back(SIGHASH_ALL); // SIGHASH_ALL flag
    
    // Second item: public key
    witness.push_back(static_cast<uint8_t>(pub_key_bytes.size())); // Length of public key
    witness.insert(witness.end(), pub_key_bytes.begin(), pub_key_bytes.end());
    
    return witness;
}  
    

// Create a witness for a Pay-to-Witness-Script-Hash (P2WSH) multisig input
// This follows the SegWit transaction format defined in BIP141 and BIP143
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
// https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
//
// P2WSH is the SegWit version of P2SH (Pay-to-Script-Hash) that allows for complex
// spending conditions. In this implementation, we're creating a multisig witness
// where multiple signatures are required to spend the funds.
//
// For a P2WSH multisig, the witness structure includes:
// 1. An empty byte (0x00) to account for the OP_CHECKMULTISIG bug in Bitcoin
// 2. One or more signatures from the required private keys
// 3. The full witness script (redeem script) that defines the spending conditions
//
// The OP_CHECKMULTISIG bug: Bitcoin's OP_CHECKMULTISIG implementation has a quirk
// where it pops one more item off the stack than it should. To work around this,
// an extra empty value (OP_0) must be placed on the stack before the signatures.
//
// The witness structure for an m-of-n multisig:
// - [1 byte]: Number of witness items (2 + number of signatures)
// - [1 byte]: 0x00 (empty byte for OP_CHECKMULTISIG bug)
// - For each signature:
//   - [1 byte]: Length of the signature
//   - [variable]: Signature (DER-encoded with SIGHASH_ALL appended)
// - [1-2 bytes]: Length of the witness script
// - [variable]: Witness script (the actual multisig script)
std::vector<uint8_t> Wallet::get_p2wsh_witness(
    const std::vector<const std::array<uint8_t, 32>*>& privs,
    const std::vector<uint8_t>& msg) {
    
    // Sign the message with each private key
    std::vector<std::vector<uint8_t>> signatures;
    for (const auto* priv : privs) {
        signatures.push_back(sign(*priv, msg));
    }
    
    // Derive public keys using Bip32Util
    std::vector<std::vector<uint8_t>> pubkeys;
    for (const auto* priv : privs) {
        pubkeys.push_back(Bip32Util::derive_public_key_from_private(*priv));
    }
    
    // Create the witness script (2-of-2 multisig)
    std::vector<uint8_t> witness_script;
    witness_script.push_back(0x52); // OP_2 (2 signatures required)
    
    // Add public keys
    for (const auto& pubkey : pubkeys) {
        witness_script.push_back(static_cast<uint8_t>(pubkey.size())); // Push length
        witness_script.insert(witness_script.end(), pubkey.begin(), pubkey.end());
    }
    
    witness_script.push_back(0x52); // OP_2 (2 total keys)
    witness_script.push_back(0xae); // OP_CHECKMULTISIG
    
    // Construct the witness
    std::vector<uint8_t> witness;
    
    // Number of witness items (4)
    witness.push_back(0x04);
    
    // First item: Empty byte (due to OP_CHECKMULTISIG bug)
    witness.push_back(0x00);
    
    // Second item: First signature + SIGHASH_ALL
    witness.push_back(static_cast<uint8_t>(signatures[0].size() + 1)); // Length of signature + 1 byte for SIGHASH
    witness.insert(witness.end(), signatures[0].begin(), signatures[0].end());
    witness.push_back(SIGHASH_ALL); // SIGHASH_ALL flag
    
    // Third item: Second signature + SIGHASH_ALL
    witness.push_back(static_cast<uint8_t>(signatures[1].size() + 1)); // Length of signature + 1 byte for SIGHASH
    witness.insert(witness.end(), signatures[1].begin(), signatures[1].end());
    witness.push_back(SIGHASH_ALL); // SIGHASH_ALL flag
    
    // Fourth item: Witness script
    witness.push_back(static_cast<uint8_t>(witness_script.size())); // Length of witness script
    witness.insert(witness.end(), witness_script.begin(), witness_script.end());
    
    return witness;
}

// Assemble a complete SegWit transaction from inputs, outputs, and witnesses
// This follows the SegWit transaction format defined in BIP141 and BIP144
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
// https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki
//
// SegWit transaction structure:
// 1. Transaction version (4 bytes)
// 2. Marker (1 byte, 0x00)
// 3. Flag (1 byte, 0x01)
// 4. Input count (varint)
// 5. Inputs (variable)
// 6. Output count (varint)
// 7. Outputs (variable)
// 8. Witness data (variable)
// 9. Locktime (4 bytes)
//
// The marker and flag bytes (0x0001) indicate that this is a SegWit transaction.
// The witness data contains the witness stack for each input, in the same order as the inputs.
std::vector<uint8_t> Wallet::assemble_transaction(
    const std::vector<std::vector<uint8_t>>& inputs,
    const std::vector<Utxo>& outputs,
    const std::vector<std::vector<uint8_t>>& witnesses) {
    
    std::vector<uint8_t> tx;
    
    // Version
    tx.insert(tx.end(),
        reinterpret_cast<const uint8_t*>(&TX_VERSION),
        reinterpret_cast<const uint8_t*>(&TX_VERSION) + sizeof(TX_VERSION));
    
    // Segwit marker and flag
    tx.push_back(TX_MARKER);  // 0x00
    tx.push_back(TX_FLAG);    // 0x01
    
    // Inputs
    tx.push_back(static_cast<uint8_t>(inputs.size()));
    for (const auto& input : inputs) {
        tx.insert(tx.end(), input.begin(), input.end());
    }
    
    // Outputs
    tx.push_back(static_cast<uint8_t>(outputs.size()));
    for (const auto& output : outputs) {
        auto serialized_output = create_output(output.script_pubkey, output.amount);
        tx.insert(tx.end(), serialized_output.begin(), serialized_output.end());
    }
    
    // Witnesses
    for (const auto& witness : witnesses) {
        tx.insert(tx.end(), witness.begin(), witness.end());
    }
    
    // Locktime
    const uint32_t locktime = 0;
    tx.insert(tx.end(),
        reinterpret_cast<const uint8_t*>(&locktime),
        reinterpret_cast<const uint8_t*>(&locktime) + sizeof(locktime));
    
    return tx;
}

// Calculate the transaction ID (txid) for a Bitcoin transaction
// The txid is the double SHA256 hash of the transaction data, excluding witness data
// This follows the Bitcoin transaction format defined in BIP141
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
//
// For SegWit transactions, the txid is calculated from a serialized transaction that:
// - Includes the transaction version
// - Includes all inputs
// - Includes all outputs
// - Includes the locktime
// - Excludes the witness data, marker, and flag
//
// This ensures backward compatibility with non-SegWit nodes and prevents transaction malleability,
// as the txid no longer depends on signature data which can be modified without invalidating the signature.
//
// The txid is returned in little-endian byte order, as is standard in Bitcoin.
std::array<uint8_t, 32> Wallet::get_txid(
    const std::vector<std::vector<uint8_t>>& inputs,
    const std::vector<Utxo>& outputs) {
    
    std::vector<uint8_t> tx;
    
    // Version
    tx.insert(tx.end(),
        reinterpret_cast<const uint8_t*>(&TX_VERSION),
        reinterpret_cast<const uint8_t*>(&TX_VERSION) + sizeof(TX_VERSION));
    
    // Inputs
    tx.push_back(static_cast<uint8_t>(inputs.size()));
    for (const auto& input : inputs) {
        tx.insert(tx.end(), input.begin(), input.end());
    }
    
    // Outputs
    tx.push_back(static_cast<uint8_t>(outputs.size()));
    for (const auto& output : outputs) {
        auto serialized_output = create_output(output.script_pubkey, output.amount);
        tx.insert(tx.end(), serialized_output.begin(), serialized_output.end());
    }
    
    // Locktime
    const uint32_t locktime = 0;
    tx.insert(tx.end(),
        reinterpret_cast<const uint8_t*>(&locktime),
        reinterpret_cast<const uint8_t*>(&locktime) + sizeof(locktime));
    
    // Double SHA256
    auto hash = HashUtils::double_sha256(tx);
    
    // Reverse for little-endian
    std::array<uint8_t, 32> txid;
    std::reverse_copy(hash.begin(), hash.end(), txid.begin());
    
    return txid;
}

// Create an OP_RETURN script with a message
// OP_RETURN outputs allow storing arbitrary data in the blockchain
// https://en.bitcoin.it/wiki/OP_RETURN
//
// OP_RETURN is a Bitcoin script opcode that marks the output as provably unspendable
// and allows a small amount of data to be inserted in the transaction. This is commonly
// used for embedding metadata, timestamps, or messages in the blockchain.
//
// Limitations:
// - Maximum data size is 80 bytes in standard Bitcoin Core nodes (we limit to 75 here)
// - OP_RETURN outputs must have a value of 0 satoshis
// - Only one OP_RETURN output is allowed per transaction in standard policy
//
// OP_RETURN script structure:
// - OP_RETURN (1 byte): 0x6a
// - Data length (1 byte): Length of the message (up to 75 bytes)
// - Data (variable): The message to store
std::vector<uint8_t> Wallet::create_op_return_script(const std::vector<uint8_t>& message) {
    if (message.size() > 75) {
        throw std::runtime_error("OP_RETURN message too long");
    }
    
    std::vector<uint8_t> script;
    script.push_back(OP_RETURN);
    script.push_back(static_cast<uint8_t>(message.size()));
    script.insert(script.end(), message.begin(), message.end());
    
    return script;
}


// Spend a P2WPKH UTXO to create a P2WSH multisig output
// This creates a transaction that:
// 1. Spends from a P2WPKH input (Pay-to-Witness-Public-Key-Hash)
// 2. Creates a P2WSH multisig output (Pay-to-Witness-Script-Hash)
// 3. Returns change to a P2WPKH address
//
// This transaction represents a common pattern in Bitcoin: moving funds from
// a single-signature address to a multisignature address for improved security.
//
// The function:
// - Selects a UTXO from the wallet state
// - Creates the transaction input
// - Creates two outputs: the multisig output and a change output
// - Calculates the commitment hash for signing
// - Creates the witness data for the P2WPKH input
// - Assembles the final transaction
//
// Returns: A pair containing the transaction ID and the complete transaction
std::pair<std::array<uint8_t, 32>, std::vector<uint8_t>> Wallet::spend_p2wpkh() {
    // Choose UTXO
    auto utxo = wallet_state.choose_utxo(1000000).value();
    
    // Create input
    auto input = Segwit::input_from_utxo(utxo.outpoint);
    
    // Get multisig keys and create outputs
    auto multisig_keys = wallet_state.get_multisig_keys().value();
    auto multisig_script = Segwit::create_witness_script(multisig_keys);
    auto multisig_script_pubkey = Segwit::get_p2wsh_program(multisig_script);
    
    
    Utxo multisig_output{
        .outpoint = Outpoint{std::vector<uint8_t>(32, 0), 0},
        .amount = 1000000,
        .script_pubkey = multisig_script_pubkey,
        .child_code = 0
    };

    Utxo change_output{
        .outpoint = Outpoint{std::vector<uint8_t>(32, 0), 0},
        .amount = utxo.amount - 1000000 - 1000,
        .script_pubkey = wallet_state.get_change_script().value(),
        .child_code = 0
    };    
        
    // Get commitment hash and sign
    auto script_code = Segwit::get_p2wpkh_scriptcode(utxo);
    auto commitment_hash = get_commitment_hash(
        utxo.outpoint,
        script_code,
        utxo.amount,
        {&multisig_output, &change_output}
    );
    
    auto privkey = wallet_state.get_private_key(utxo.child_code).value();
    std::array<uint8_t, 32> privkey_array;
    std::copy_n(privkey.begin(), 32, privkey_array.begin());
    
    auto pub_key_bytes = Bip32Util::derive_public_key_from_private(privkey_array);
    auto witness = get_p2wpkh_witness(privkey_array, commitment_hash);
    
    // Get txid and final transaction
    auto txid = get_txid(
        {input},
        {multisig_output, change_output}
    );
    
    auto transaction = assemble_transaction(
        {input},
        {multisig_output, change_output},
        {witness}
    );
    
    return {txid, transaction};
}

// Spend a P2WSH multisig UTXO to create an OP_RETURN output
// This creates a transaction that:
// 1. Spends from a P2WSH multisig input
// 2. Creates an OP_RETURN output with a message
// 3. Returns change to a P2WPKH address
//
// This transaction demonstrates how to spend from a multisig address and
// how to embed data in the blockchain using OP_RETURN.
//
// The function:
// - Creates an input from the provided transaction ID (pointing to a P2WSH output)
// - Creates two outputs: an OP_RETURN output with a message and a change output
// - Calculates the commitment hash for signing
// - Creates the witness data for the P2WSH multisig input (requiring multiple signatures)
// - Assembles the final transaction
//
// Returns: The complete transaction
std::vector<uint8_t> Wallet::spend_p2wsh(const std::array<uint8_t, 32>& txid) {
    std::vector<uint8_t> message{'A', 'd', 'y', 's', ' ', '-', ' ',
                                'I', ' ', 'k', 'n', 'o', 'w', ' ',
                                'k', 'u', 'n', 'g', ' ', 'f', 'u', '!'};
    
    // Create outpoint and input
    Outpoint outpoint{
        .txid_vec = std::vector<uint8_t>(txid.rbegin(), txid.rend()),
        .index = 0
    };
    auto input = Segwit::input_from_utxo(outpoint);
    

    // Create outputs
    Utxo opreturn_output{
        .outpoint = Outpoint{std::vector<uint8_t>(32, 0), 0},
        .amount = 0,
        .script_pubkey = create_op_return_script(message),
        .child_code = 0
    };

    Utxo change_output{
        .outpoint = Outpoint{std::vector<uint8_t>(32, 0), 0},
        .amount = 1000000 - 1000,
        .script_pubkey = wallet_state.get_change_script().value(),
        .child_code = 0
    };
    
    // Create multisig script and get commitment hash
    auto multisig = Segwit::create_witness_script(
        std::vector<std::vector<uint8_t>>(
            wallet_state.get_public_keys().begin(),
            wallet_state.get_public_keys().begin() + 2
        )
    );
    
    std::vector<uint8_t> scriptcode;
    scriptcode.push_back(static_cast<uint8_t>(multisig.size()));
    scriptcode.insert(scriptcode.end(), multisig.begin(), multisig.end());
    
    auto commitment_hash = get_commitment_hash(
        outpoint,
        scriptcode,
        1000000,
        {&opreturn_output, &change_output}
    );
    
    // Sign with both keys
    std::array<uint8_t, 32> privkey1, privkey2;
    std::copy_n(wallet_state.get_private_key(0).value().begin(), 32, privkey1.begin());
    std::copy_n(wallet_state.get_private_key(1).value().begin(), 32, privkey2.begin());
    
    auto pub_key_bytes1 = Bip32Util::derive_public_key_from_private(privkey1);
    auto pub_key_bytes2 = Bip32Util::derive_public_key_from_private(privkey2);
    
    auto witness = get_p2wsh_witness(
        {&privkey1, &privkey2},
        commitment_hash
    );
    
    // Assemble final transaction
    return assemble_transaction(
        {input},
        {opreturn_output, change_output},
        {witness}
    );
}
} // namespace wallet