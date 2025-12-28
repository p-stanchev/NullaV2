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

### Enabling the Stub Miner

To test gossip propagation, enable the stub miner on one or both nodes:

```bash
cargo run -p nulla-node -- --listen /ip4/0.0.0.0/tcp/27444 --mine
```

The miner broadcasts dummy blocks every 30 seconds for testing purposes.

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
- `--mine`: Enable stub miner (broadcasts dummy blocks for testing)

### Storage

- `--db <PATH>`: Database directory path (default: `./data`)

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
- [x] P2P networking with libp2p
- [x] Gossipsub for block/transaction propagation
- [x] Dandelion++ transaction privacy protocol
- [x] Peer discovery via Kademlia DHT
- [x] Basic stub miner for testing
- [x] Request/response handlers for block sync
- [x] Cover traffic implementation
- [x] Transaction validation and structure checking
- [x] Mempool management (add, remove, query, clear)
- [x] Chain reorganization support (UTXO rollback, reorg helpers)

### In Progress 🚧

- [ ] Full script execution and signature verification
- [ ] Difficulty adjustment algorithm
- [ ] Proper chain selection (most work, not just longest)
- [ ] Complete block synchronization protocol

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