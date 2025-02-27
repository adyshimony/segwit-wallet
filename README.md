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


### Expected Output
```

Initialized wallet state for wallet: wallet_314
Loading wallet state from file: wallet_state.json
Successfully loaded wallet: wallet_314
Wallet balance: 1782659711 satoshis
wallet_314 17.82659711

p2wpkh tx:
020000000001012f964f42397021f91b20ab513280d2414b7865f1513754bf2780cd39786fcaca8d00000000ffffffff0240420f000000000022002063d1de244bb90c4d46e80da4075fd7dea7b0dfc8173ff725ffd4200f12d65db5bba27b00000000001600142fbbb8a20460e83da09b1a02dc62b0080fcc88a402483045022100f6a7d5dae85e68442756b147e47b16f11601d33fe5a539229b608efd58b39b4c02207b9f7e4462809379a323c54f12d449dfc6b2a30c5280bf56e37c795c1a8569d0012103062b4ace754d8fc40125f6407dc6b5c55ac079e0ec6e6c88022457c9f562340900000000

p2wsh tx:
02000000000101a9a90b601c6146d3a1759e693df6bd2db3e77e15fef303561c44484fdd63cfd10000000000ffffffff020000000000000000186a1641647973202d2049206b6e6f77206b756e6720667521583e0f00000000001600142fbbb8a20460e83da09b1a02dc62b0080fcc88a404004730440220039f431e412ab8da02a8f2d6bdcdc479c1b07a19fe8db2bdfacbd67434a2265302200c6b03de0db1036bd30a49a67fc187db3bff7a759c225ed0781a41d7dd84778701483045022100e55bf5e300434fbc6456af46ba6339937699334e2528c310465f38bb5bc97c2b02206735b9b8e003b02369b7e8be1141a7559aca416226fb504c87cd405c0c8253a10147522102a693f085c8f3cbf9e109a8d9dda9cd6805e2e8c1b82d9abf64f785a337dbe3ff210227b6997a65ef7a576f565bf29e889a71000d5a20260a179ddd2d173d7fd165ce52ae00000000

Checking mempool acceptance...
Mempool acceptance result:
[
    {
        "allowed": true,
        "fees": {
            "base": "0.00001000",
            "effective-feerate": "0.00006535",
            "effective-includes": [
                "4195a1fc84231cd4c0c098d5a83bccfbdcf1bdbcce2a6a7b9bf6e5b912de0dc8"
            ]
        },
        "txid": "d1cf63dd4f48441c5603f3fe157ee7b32dbdf63d699e75a1d346611c600ba9a9",
        "vsize": "153.00000000",
        "wtxid": "4195a1fc84231cd4c0c098d5a83bccfbdcf1bdbcce2a6a7b9bf6e5b912de0dc8"
    },
    {
        "allowed": true,
        "fees": {
            "base": "0.00001000",
            "effective-feerate": "0.00005882",
            "effective-includes": [
                "ba24a31f161de6d9696c1980abe7080af65c0a2d2f64fb8c7e60c60834278986"
            ]
        },
        "txid": "06f949da3dd721de560936ba431c1531ee1403e0955b840724f675a8085e373c",
        "vsize": "170.00000000",
        "wtxid": "ba24a31f161de6d9696c1980abe7080af65c0a2d2f64fb8c7e60c60834278986"
    }
]
```
### Dependencies

- **OpenSSL**: For cryptographic operations (SHA256, RIPEMD160, ECDSA)
- **nlohmann/json**: For wallet state serialization
- **Bitcoin Core**: For RPC communication with the Bitcoin network

This project serves as a practical learning tool for understanding Bitcoin's transaction model, cryptography, and scripting system.

