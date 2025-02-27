# Segwit Wallet 

A simple C++ application to calculate wallet balance and build transactions for learning purposes.

This project demonstrates a basic Bitcoin wallet implementation that works with a custom signet network. It focuses on:

- Working with segregated witness (SegWit) addresses, specifically p2wpkh and p2wsh formats
- Handling Bitcoin private/public key pairs and address generation
- Building and signing Bitcoin transactions
- Interacting with a Bitcoin node via RPC
- Understanding Bitcoin transaction structure and serialization

The wallet is intentionally simplified to focus on core concepts:
- Uses a single descriptor for all addresses
- Works only with SegWit addresses (primarily p2wpkh with one p2wsh multisig)
- Creates transactions with exactly 1 input and 2 outputs
- Uses fixed transaction parameters (version, sequence, locktime)

## Technical Implementation

This wallet is built in C++20 and demonstrates several important Bitcoin concepts:

- **BIP32 Hierarchical Deterministic Wallets**: Derives child keys from a master key using the HD wallet specification
- **BIP84 Native SegWit (bech32)**: Implements the standard for native segregated witness addresses
- **BIP141 SegWit Transaction Format**: Creates transactions with the marker/flag bytes and witness data structure
- **BIP143 Signature Hash Algorithm**: Implements the improved signature hash algorithm for SegWit inputs

### Key Components

- **Key Management**: Handles extended private keys, key derivation, and public key generation
- **UTXO Management**: Tracks unspent transaction outputs and performs coin selection
- **Transaction Building**: Creates and serializes Bitcoin transactions according to the protocol
- **Cryptographic Operations**: Implements ECDSA signatures with secp256k1 and various hash functions
- **Multisignature Support**: Creates and spends from 2-of-2 multisignature addresses

### Wallet State Management

The wallet calculates its state (derived keys and UTXOs) only once and saves it to a `wallet_state.json` file. This approach:

- Avoids redundant blockchain scanning and key derivation on each startup
- Significantly improves performance for subsequent runs
- Allows the wallet to work offline once the initial state is saved

**Note for users without a signet node**: The provided `wallet_state.json` file contains a valid pre-calculated state for the supplied private key. This allows you to experiment with transaction building and signing without needing to run a Bitcoin signet node.

## Build Instructions

### Prerequisites

- C++20 compatible compiler (GCC 10+, Clang 10+, or MSVC 2019+)
- CMake 3.10 or higher
- OpenSSL development libraries
- Bitcoin Core (for RPC functionality)

### Building the Project

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/segwit-wallet.git
   cd segwit-wallet
   ```

2. Create a build directory and run CMake:
   ```
   mkdir build
   cd build
   cmake ..
   ```

3. Build the project:
   ```
   make
   ```

4. Run the wallet:
   ```
   ./wallet
   ```

### Dependencies

- **OpenSSL**: For cryptographic operations (SHA256, RIPEMD160, ECDSA)
- **nlohmann/json**: For wallet state serialization
- **Bitcoin Core**: For RPC communication with the Bitcoin network

This project serves as a practical learning tool for understanding Bitcoin's transaction model, cryptography, and scripting system.

