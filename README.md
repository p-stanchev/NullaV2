# Nulla

<div align="center">

**A minimal, privacy-focused blockchain node implementation in Rust**

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](./LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

</div>

## Overview

Nulla is an experimental blockchain node implementation designed to explore privacy-enhancing network protocols and minimal consensus mechanisms. It features:

- **Proof-of-Work Consensus**: Simple PoW with adjustable difficulty targets
- **UTXO Model**: Bitcoin-style unspent transaction output tracking
- **Privacy Features**: Dandelion++ transaction relay protocol for network-level anonymity
- **P2P Networking**: libp2p-based networking with Noise encryption and Yamux multiplexing
- **Gossip Protocol**: Efficient block and transaction propagation
- **Embedded Database**: Sled-based persistent storage for blocks, headers, and UTXOs

## Architecture

The project is organized as a Rust workspace with four crates:

- **nulla-core**: Core blockchain primitives (transactions, blocks, PoW validation)
- **nulla-db**: Database layer for persistent state (sled-based key-value store)
- **nulla-net**: P2P networking stack (libp2p, gossipsub, Dandelion++)
- **nulla-node**: Main node binary that ties everything together

## Features

### Core Blockchain

- **BLAKE3 Hashing**: Fast cryptographic hashing for block and transaction IDs
- **Merkle Trees**: Binary Merkle tree for transaction commitment
- **Proof-of-Work**: Big-endian hash comparison against difficulty target
- **UTXO Set**: Track spendable outputs and prevent double-spending

### Privacy

- **Dandelion++ Protocol**: Two-phase transaction relay (stem + fluff) to obscure transaction origin
- **Cover Traffic**: Placeholder support for network-level traffic analysis resistance

### Networking

- **Transport Security**: Noise protocol for encrypted connections
- **Multiplexing**: Yamux for efficient connection management
- **Peer Discovery**: Kademlia DHT for finding and connecting to peers
- **Gossip**: Efficient block and transaction propagation
- **Request/Response**: Protocol for syncing blocks and headers

## Quick Start

### Prerequisites

- Rust 1.70 or later
- Cargo (comes with Rust)

### Build

```bash
cargo build --release
```

### Running a Local Network

To test the node, you can run two local peers that connect to each other:

**Terminal 1 - Seed Node:**
```bash
cargo run -p nulla-node -- --listen /ip4/0.0.0.0/tcp/27444
```

**Terminal 2 - Connecting Node:**
```bash
cargo run -p nulla-node -- --peers /ip4/127.0.0.1/tcp/27444 --db ./data2
```

> **Important:** The `--db ./data2` flag is **required** for the second node to avoid database lock conflicts. Each node needs its own separate database directory.

The nodes will connect, exchange peer information, and gossip blocks/transactions.

### Enabling Seed Mode

To create blocks that properly build a chain (with incrementing height):

```bash
cargo run -p nulla-node -- --listen /ip4/0.0.0.0/tcp/27444 --seed
```

The seed node:
- Reads the current best tip from the database
- Creates new blocks every 30 seconds building on top of the previous block
- Increments block height properly (genesis at height 0, then 1, 2, 3...)
- Does NOT perform proof-of-work (uses easy target for testing)
- Broadcasts blocks to all connected peers
- Shows a **progress bar** when syncing blocks from other nodes

### Enabling the Stub Miner

To test raw gossip propagation (broadcasts independent dummy blocks):

```bash
cargo run -p nulla-node -- --listen /ip4/0.0.0.0/tcp/27444 --mine
```

The stub miner broadcasts independent dummy blocks every 30 seconds. Unlike `--seed`, these blocks do NOT build on each other (all at height 0).

### Wallet Operations

#### Token Economics

- **1 NULLA** = 100,000,000 atoms (8 decimal places, like Bitcoin satoshis)
- **Block Reward**: 8 NULLA (800,000,000 atoms) per block

#### Generate a New Wallet

```bash
cargo run -p nulla-node -- --generate-wallet
```

This outputs:
```
=== New Wallet Generated ===
Address: 79bc6374ccc99f1211770ce007e05f6235b98c8b
Seed:    a57ae4a1591694799b7cee1af130dc9486f380a105ca6fe648d850904283f094
```

**Save your seed securely!** You can restore your wallet using `--wallet-seed`.

#### Check Wallet Address

Display the address for a given wallet seed:
```bash
cargo run -p nulla-node -- --wallet-seed a57ae4a1591694799b7cee1af130dc9486f380a105ca6fe648d850904283f094 --get-address
```

Output:
```
=== Wallet Address ===
79bc6374ccc99f1211770ce007e05f6235b98c8b
```

#### Check Wallet Balance

Display the balance and UTXOs for a wallet:
```bash
cargo run -p nulla-node -- --wallet-seed a57ae4a1591694799b7cee1af130dc9486f380a105ca6fe648d850904283f094 --get-balance --db ./data
```

Output:
```
=== Wallet Balance ===
Address: 79bc6374ccc99f1211770ce007e05f6235b98c8b
Balance: 0.00000000 NULLA (0 atoms)
UTXOs:   0

The balance will show coinbase rewards earned by running as a seed node.
```

#### Using a Wallet with a Running Node

Load a wallet when starting the node:
```bash
cargo run -p nulla-node -- --wallet-seed a57ae4a1591694799b7cee1af130dc9486f380a105ca6fe648d850904283f094 --listen /ip4/0.0.0.0/tcp/27444
```

The node will log: `wallet loaded, address: 79bc6374ccc99f1211770ce007e05f6235b98c8b`

### Running on a VPS

To run a public seed node on a VPS that others can connect to:

**On your VPS (seed node):**
```bash
# Build in release mode for better performance
cargo build --release

# Run the node, listening on all interfaces
./target/release/nulla --listen /ip4/0.0.0.0/tcp/27444

# With mining enabled
./target/release/nulla --listen /ip4/0.0.0.0/tcp/27444 --mine
```

**On your local machine (connecting to VPS):**
```bash
# Replace YOUR_VPS_IP with your server's public IP address
cargo run -p nulla-node -- --peers /ip4/YOUR_VPS_IP/tcp/27444
```

> **Note:** You only need `--db ./data2` when running multiple nodes on the **same machine**. Different machines can all use the default `./data` directory.

**Important networking notes:**
- Make sure port `27444` is open in your firewall (or use a different port)
- If using a cloud provider (AWS, DigitalOcean, etc.), configure security groups to allow TCP traffic on port 27444
- The node will log "listening on" and "peer connected" messages when successful
- You can run multiple local nodes connecting to the same VPS seed node

**Automatic Peer Discovery:**
- When you connect to one peer, Kademlia DHT automatically discovers other peers in the network
- Nodes exchange peer information automatically via the Identify protocol
- You only need to specify one seed node with `--peers`, and you'll learn about all other connected nodes
- The node logs "kad: discovered X peers" when it finds new peers through the DHT
- This creates a self-healing mesh network where nodes can find each other automatically

**Example with firewall (Ubuntu/Debian):**
```bash
sudo ufw allow 27444/tcp
sudo ufw reload
```

## Command-Line Options

### Network Configuration

- `--listen <MULTIADDR>`: Multiaddress(es) to listen on (e.g., `/ip4/0.0.0.0/tcp/27444`)
- `--peers <MULTIADDR>`: Multiaddress(es) of peers to connect to on startup
- `--chain-id <ID>`: Chain identifier, max 4 bytes (default: `NULL`)

### Features

- `--gossip`: Enable the gossip networking stack (enabled by default)
- `--no-gossip`: Disable the gossip networking stack (local-only mode)
- `--dandelion`: Enable Dandelion++ transaction privacy (enabled by default)
- `--no-dandelion`: Disable Dandelion++ transaction privacy
- `--cover-traffic`: Enable cover traffic for network-level privacy (experimental)
- `--seed`: Enable seed mode (creates sequential blocks building on chain, no mining)
- `--mine`: Enable stub miner (broadcasts dummy blocks for testing, all at height 0)

### Storage

- `--db <PATH>`: Database directory path (default: `./data`)

### Wallet

- `--generate-wallet`: Generate a new wallet and print address and seed
- `--wallet-seed <HEX>`: Load wallet from 32-byte hex seed
- `--get-address`: Display wallet address (requires `--wallet-seed`)
- `--get-balance`: Display wallet balance and UTXOs (requires `--wallet-seed` and `--db`)

### Placeholders (Not Yet Implemented)

- `--rpc <ADDR>`: RPC server bind address (default: `127.0.0.1:27447`)
- `--miner-address <ADDR>`: Miner payout address for coinbase transactions
- `--socks5 <ADDR>`: SOCKS5 proxy address for network connections

## Development Status

### Implemented ✅

- [x] Core blockchain data structures (blocks, transactions, headers)
- [x] BLAKE3-based hashing and Merkle trees
- [x] Proof-of-work validation
- [x] UTXO database (sled-based storage)
- [x] P2P networking with libp2p (modular: behaviour, gossip, kad modules)
- [x] Gossipsub for block/transaction propagation
- [x] Dandelion++ transaction privacy protocol
- [x] Peer discovery via Kademlia DHT
- [x] Seed node mode (creates sequential blocks, increments height)
- [x] Basic stub miner for testing
- [x] Request/response handlers for block sync
- [x] Cover traffic implementation
- [x] Transaction validation and structure checking
- [x] Mempool management (add, remove, query, clear)
- [x] Chain reorganization support (UTXO rollback, reorg helpers)
- [x] Block sync detection with progress bar UI
- [x] Best tip tracking and automatic updates
- [x] Wallet functionality (Ed25519 keypairs, address generation, transaction signing)
- [x] CLI commands for wallet generation and restoration
- [x] Chain selection based on cumulative work (Nakamoto consensus)
- [x] Token economics (100M atoms per NULLA, 8 NULLA block reward)
- [x] Wallet balance and address commands
- [x] Coinbase transactions (block rewards paid to seed node wallet)
- [x] UTXO validation (inputs exist, not double-spent, value conservation)
- [x] Transaction application to UTXO set (mark spent, create new UTXOs)
- [x] Transaction revert support for chain reorganizations
- [x] Full block gossip protocol (nodes sync complete blocks with transactions)
- [x] Block processing with automatic UTXO set updates
- [x] Ed25519 signature verification infrastructure
- [x] UTXO indexing by address (O(1) balance lookups)
- [x] Working wallet balance checker with UTXO details

### In Progress 🚧
- [ ] Wire up signature verification when processing blocks
- [ ] Wire up UTXO validation when accepting blocks
- [ ] Fork resolution and reorganization (helpers exist, needs wiring)
- [ ] Difficulty adjustment algorithm
- [ ] Full script execution
- [ ] Transaction fees and fee validation

### Planned 📋

- [ ] RPC interface for wallet integration
- [ ] SOCKS5 proxy support for Tor integration
- [ ] Stealth addresses and payment commitments
- [ ] Compact block relay
- [ ] UTXO set snapshots
- [ ] Network message compression

## Project Goals

Nulla is an **educational** and **experimental** project focused on:

1. **Privacy Research**: Exploring network-level privacy techniques (Dandelion++, cover traffic)
2. **Minimal Design**: Keeping the codebase simple and understandable
3. **Modern Rust**: Leveraging async/await and robust type systems
4. **Modular Architecture**: Clean separation between consensus, storage, and networking

**This is not production-ready software.** It's designed for learning, experimentation, and research.

## Technical Details

### Cryptography

- **Hashing**: BLAKE3 for all hash operations (blocks, transactions, Merkle trees)
- **Transport**: Noise protocol (libp2p) for encrypted peer connections
- **Signatures**: Ed25519 and secp256k1 support (via k256 crate)

### Database Schema

The sled-based database uses separate trees for:

- `meta`: Chain tip, best height, and other metadata
- `headers`: Block headers indexed by block ID
- `header_by_height`: Block IDs indexed by height
- `blocks`: Full blocks indexed by block ID
- `utxos`: Unspent outputs indexed by OutPoint
- `mempool`: Pending transactions indexed by txid
- `spent`: Spent outputs indexed by OutPoint

### Network Protocol

All network messages use postcard serialization (compact binary format). The gossipsub topics are namespaced by chain ID:

- `/nulla/{chain_id}/inv_tx`: Transaction inventory
- `/nulla/{chain_id}/inv_block`: Block inventory

Request/response protocol: `/nulla/{chain_id}/reqresp/1`

## Contributing

Contributions are welcome! This project is experimental, so feel free to:

- Open issues for bugs or feature requests
- Submit pull requests with improvements
- Discuss privacy protocol implementations
- Share research and ideas

## License

Licensed under either of:

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

## Acknowledgments

- **libp2p**: Modular P2P networking stack
- **sled**: Embedded database engine
- **BLAKE3**: Fast cryptographic hash function
- **Dandelion++**: Transaction privacy research by Fanti et al.

## Disclaimer

This software is experimental and should not be used in production environments. It has not been audited for security vulnerabilities. Use at your own risk.