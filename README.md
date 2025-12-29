# Nulla

<div align="center">

**A minimal, privacy-focused blockchain node implementation in Rust**

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](./LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

</div>

## Overview

Nulla is an experimental blockchain node implementation designed to explore privacy-enhancing network protocols and minimal consensus mechanisms. It features:

- **Proof-of-Work Consensus**: Bitcoin-style PoW with dynamic difficulty adjustment
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
- **Dynamic Difficulty Adjustment**: Adjusts every 10 blocks targeting 60-second block times
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
# Secure method (recommended): Use --miner-address to receive rewards without exposing private key
cargo run -p nulla-node -- --listen /ip4/0.0.0.0/tcp/27444 --seed --miner-address 79bc6374ccc99f1211770ce007e05f6235b98c8b

# Alternative (less secure): Use --wallet-seed if you need to sign transactions
# WARNING: This exposes your private key in process lists!
cargo run -p nulla-node -- --listen /ip4/0.0.0.0/tcp/27444 --seed --wallet-seed a57ae4a1591694799b7cee1af130dc9486f380a105ca6fe648d850904283f094
```

**Security Best Practice:** Always use `--miner-address` for mining/seed nodes instead of `--wallet-seed`. The miner address is your public address and safe to expose, while the wallet seed is your private key and should be kept secret.

The seed node:
- Reads the current best tip from the database
- Creates new blocks every 30 seconds building on top of the previous block
- Increments block height properly (genesis at height 0, then 1, 2, 3...)
- Does NOT perform proof-of-work (uses easy target for testing)
- Broadcasts blocks to all connected peers
- Shows a **progress bar** when syncing blocks from other nodes
- Sends block rewards to the specified miner address

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

**Simple Wallet (Single Address):**
```bash
cargo run -p nulla-node -- --generate-wallet
```

This outputs:
```
=== New Wallet Generated ===
Address: 79bc6374ccc99f1211770ce007e05f6235b98c8b
Seed:    a57ae4a1591694799b7cee1af130dc9486f380a105ca6fe648d850904283f094
```

**HD Wallet (Multiple Addresses from One Seed) - RECOMMENDED:**
```bash
cargo run -p nulla-node -- --generate-hd-wallet
```

This outputs:
```
=== New HD Wallet Generated ===
Master Seed: a57ae4a1591694799b7cee1af130dc9486f380a105ca6fe648d850904283f094

First 5 Addresses:
  [0] 79bc6374ccc99f1211770ce007e05f6235b98c8b
  [1] 8a3d5e92f03ab1c7d9e6f7a4b8c2d1e0f9a7b3c6
  [2] 1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c
  [3] 2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d
  [4] 3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e

IMPORTANT: Save your MASTER SEED! This will not be shown again.
```

**Why use HD wallets?**
- **Privacy**: Generate a new address for each transaction
- **Convenience**: One master seed controls unlimited addresses
- **Security**: Share addresses publicly while keeping the master seed private
- **Compatibility**: Uses BIP44 standard (m/44'/0'/0'/0/index)

**Save your seed securely!** You can restore your wallet using `--wallet-seed`.

#### Create Encrypted Wallet File (RECOMMENDED)

For better security and convenience, create an encrypted wallet file instead of managing seeds manually:

```bash
cargo run -p nulla-node -- --create-wallet wallet.dat --wallet-password "your-secure-password"
```

This outputs:
```
=== Encrypted Wallet Created ===
File: wallet.dat

First 5 Addresses:
  [0] 79bc6374ccc99f1211770ce007e05f6235b98c8b
  [1] 8a3d5e92f03ab1c7d9e6f7a4b8c2d1e0f9a7b3c6
  [2] 1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c
  [3] 2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d
  [4] 3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e

IMPORTANT: Remember your password! It cannot be recovered.
IMPORTANT: Back up your wallet file: wallet.dat
```

**Using Your Encrypted Wallet:**

```bash
# Send transactions
cargo run -p nulla-node -- --send --wallet-file wallet.dat --wallet-password "your-secure-password" --to <ADDRESS> --amount 5.0

# Run a node with your wallet (for receiving mining rewards)
cargo run -p nulla-node -- --wallet-file wallet.dat --wallet-password "your-secure-password"

# Check your balance
cargo run -p nulla-node -- --balance 79bc6374ccc99f1211770ce007e05f6235b98c8b
```

**Benefits:**
- ✅ **No more copying/pasting seeds** - just remember your password
- ✅ **HD wallet by default** - unlimited addresses from one file
- ✅ **Encrypted at rest** - seed is protected with BLAKE3-based encryption
- ✅ **Easy backups** - just copy wallet.dat to a safe location
- ✅ **No plaintext exposure** - seed never appears in command history or logs

#### Derive More Addresses from HD Wallet

To generate additional addresses from your HD wallet master seed:
```bash
# Show first 10 addresses
cargo run -p nulla-node -- --wallet-seed a57ae4a1591694799b7cee1af130dc9486f380a105ca6fe648d850904283f094 --derive-address 10
```

Output:
```
=== HD Wallet Addresses ===
Derivation Path: m/44'/0'/0'/0/<index>

  [0] 79bc6374ccc99f1211770ce007e05f6235b98c8b
  [1] 8a3d5e92f03ab1c7d9e6f7a4b8c2d1e0f9a7b3c6
  ...
  [9] 4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f
```

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

#### Check Address Balance

**NEW - Recommended method (works with any address):**
```bash
# Check your own balance (no private key needed!)
cargo run -p nulla-node -- --balance 79bc6374ccc99f1211770ce007e05f6235b98c8b

# Check someone else's balance (blockchain is public!)
cargo run -p nulla-node -- --balance THEIR_ADDRESS_HERE
```

Output:
```
=== Address Balance ===
Address: 79bc6374ccc99f1211770ce007e05f6235b98c8b
Balance: 16.00000000 NULLA (1600000000 atoms)
UTXOs:   2

UTXO Details:
  a1b2c3d4e5f6g7h8 vout:0 = 800000000 atoms
  9f8e7d6c5b4a3210 vout:0 = 800000000 atoms
```

**Old method (DEPRECATED - requires private key):**
```bash
cargo run -p nulla-node -- --wallet-seed a57ae4a1591694799b7cee1af130dc9486f380a105ca6fe648d850904283f094 --get-balance --db ./data
```

**Why use `--balance` instead of `--get-balance`:**
- ✅ No private key needed (read-only operation)
- ✅ Works with any address (check others' balances too)
- ✅ Simpler - just provide the address
- ✅ Safe - can't accidentally expose wallet seed

#### Using a Wallet with a Running Node

**For Mining (Recommended - Secure):**
```bash
# Use --miner-address to receive block rewards WITHOUT exposing your private key
cargo run -p nulla-node -- --seed --miner-address 79bc6374ccc99f1211770ce007e05f6235b98c8b --listen /ip4/0.0.0.0/tcp/27444
```

**For Transaction Signing (Use with Caution):**
```bash
# WARNING: This exposes your private key in process lists!
# Only use --wallet-seed when you need to sign transactions, NOT for mining
cargo run -p nulla-node -- --wallet-seed a57ae4a1591694799b7cee1af130dc9486f380a105ca6fe648d850904283f094 --listen /ip4/0.0.0.0/tcp/27444
```

The node will log:
- With `--miner-address`: `miner address loaded: 79bc6374ccc99f1211770ce007e05f6235b98c8b`
- With `--wallet-seed`: `wallet loaded, address: 79bc6374ccc99f1211770ce007e05f6235b98c8b`

### RPC/API Access

Nulla provides a JSON-RPC 2.0 HTTP API for programmatic interaction with the blockchain node. The RPC server is Bitcoin/Ethereum compatible and enforces localhost-only binding for security.

**Starting the RPC server:**
```bash
# Start node with RPC enabled on localhost:27447
cargo run -p nulla-node -- --rpc 127.0.0.1:27447

# With wallet access (enables wallet RPC methods)
cargo run -p nulla-node -- --rpc 127.0.0.1:27447 --wallet-seed YOUR_SEED_HEX

# Full-featured node with mining, seed mode, and RPC
cargo run -p nulla-node -- --miner-address YOUR_ADDRESS --seed --rpc 127.0.0.1:27447
```

**Security:** The RPC server will only bind to localhost (127.0.0.1 or ::1). Attempts to bind to other addresses will fail with an error.

**Available RPC Methods:**

Chain Query Methods:
- `getbestblockhash` - Returns the hash of the best (tip) block
- `getblockcount` - Returns the current blockchain height
- `getblockhash(height)` - Returns the block hash at a specific height
- `getblockchaininfo` - Returns comprehensive blockchain information
- `getbalance(address)` - Returns the balance for a given address

Transaction Methods:
- `sendrawtransaction(hex)` - Broadcasts a raw transaction to the network

Wallet Methods (require `--wallet-seed`):
- `getnewaddress` - Returns the wallet's address
- `getwalletinfo` - Returns wallet information including balance and transaction count

Network/Admin Methods:
- `uptime` - Returns node uptime in seconds
- `getpeerinfo` - Returns information about connected peers

**Example RPC Calls:**

```bash
# Get the best block hash
curl -X POST http://127.0.0.1:27447 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getbestblockhash","id":1}'

# Get current block height
curl -X POST http://127.0.0.1:27447 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblockcount","id":1}'

# Get blockchain info
curl -X POST http://127.0.0.1:27447 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblockchaininfo","id":1}'

# Get balance for an address
curl -X POST http://127.0.0.1:27447 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getbalance","params":["79bc6374ccc99f1211770ce007e05f6235b98c8b"],"id":1}'

# Get wallet address (requires --wallet-seed)
curl -X POST http://127.0.0.1:27447 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getnewaddress","id":1}'

# Get node uptime
curl -X POST http://127.0.0.1:27447 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"uptime","id":1}'
```

**Response Format:**

All responses follow JSON-RPC 2.0 standard:
```json
{
  "jsonrpc": "2.0",
  "result": "...",
  "id": 1
}
```

Errors return:
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -5,
    "message": "Wallet not loaded. Start node with --wallet flag."
  },
  "id": 1
}
```

### Running on a VPS

To run a public seed node on a VPS that others can connect to:

**On your VPS (seed node):**
```bash
# Build in release mode for better performance
cargo build --release

# Run a basic node (no rewards)
./target/release/nulla --listen /ip4/0.0.0.0/tcp/27444

# Run with seed mode and receive block rewards securely
./target/release/nulla --listen /ip4/0.0.0.0/tcp/27444 --seed --miner-address YOUR_ADDRESS_HERE

# WARNING: Never expose wallet seeds on public VPS!
# NEVER DO THIS: ./target/release/nulla --wallet-seed YOUR_PRIVATE_KEY  # INSECURE!
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

**Automatic Peer Discovery & Connection:**
- When you connect to one peer, nodes **automatically dial each other** without manual configuration
- The Identify protocol exchanges peer addresses automatically on connection
- Discovered peers are **auto-dialed** if they have public IP addresses (private IPs are filtered)
- Kademlia DHT builds a distributed routing table for peer discovery
- You only need to specify one seed node with `--peers`, and your node will automatically connect to the entire network
- Every **30 seconds**, nodes log: `total peers connected: X` for easy monitoring
- This creates a self-healing mesh network where nodes can find each other automatically

**Example with firewall (Ubuntu/Debian):**
```bash
sudo ufw allow 27444/tcp
sudo ufw reload
```

## Security Best Practices

### Mining and Block Rewards

**IMPORTANT:** Nulla provides two ways to receive block rewards, but only one is secure for production use:

✅ **SECURE - Use `--miner-address`:**
```bash
# Generate a wallet once to get your address
cargo run -p nulla-node -- --generate-wallet

# Copy the address (40-char hex) and use it for mining
cargo run -p nulla-node -- --seed --miner-address 79bc6374ccc99f1211770ce007e05f6235b98c8b
```

**Why this is secure:**
- Your **address is public information** - it's safe to expose
- Your **private key stays offline** and secure
- Even if your VPS is compromised, attackers can't steal your private key
- You can later spend your rewards by signing transactions offline

❌ **INSECURE - Avoid `--wallet-seed` for mining:**
```bash
# DON'T DO THIS on production nodes!
cargo run -p nulla-node -- --seed --wallet-seed YOUR_PRIVATE_KEY_HERE
```

**Why this is insecure:**
- Private keys appear in process lists (visible to all users via `ps` command)
- Private keys may be logged to system logs or crash dumps
- If your node is compromised, attackers get your private key immediately
- No way to rotate keys without losing access to past rewards

**Rule of thumb:**
- Use `--miner-address` for receiving rewards (mining/seed nodes)
- Only use `--wallet-seed` for transaction signing on secure, offline machines

### Blockchain Transparency

**Important:** Like Bitcoin and Ethereum, Nulla's blockchain is completely **public and transparent**:

✅ **Anyone can:**
- View all addresses and their balances using `--balance <ADDRESS>`
- See all transactions in blocks
- Track the flow of NULLA between addresses
- Monitor network activity and block production

🔒 **What's private:**
- Your **wallet seed** (private key) - never share this
- The connection between your identity and your address (if you don't tell anyone)

**Privacy tip:** Generate a new address for each transaction using `--generate-wallet` to make tracking harder. The blockchain shows addresses and amounts, but doesn't inherently know which addresses belong to whom.

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

- `--generate-wallet`: Generate a new simple wallet (single address) and print address and seed
- `--generate-hd-wallet`: Generate a new HD wallet (multiple addresses from one master seed)
- `--create-wallet <FILE>`: Create a new encrypted HD wallet file (RECOMMENDED - requires `--wallet-password`)
- `--wallet-file <FILE>`: Load wallet from encrypted file (requires `--wallet-password`)
- `--wallet-password <PASSWORD>`: Password for wallet file encryption/decryption
- `--derive-address <COUNT>`: Derive COUNT addresses from HD wallet master seed (requires `--wallet-seed`)
- `--wallet-seed <HEX>`: Load wallet from 32-byte hex seed (use for transaction signing only, NOT for mining)
- `--miner-address <HEX>`: Miner payout address for block rewards (40-char hex, 20 bytes) - SECURE for mining
- `--get-address`: Display wallet address (requires `--wallet-seed`)
- `--balance <ADDRESS>`: Check balance for any address (40-char hex, 20 bytes) - Works with any address, no private key needed
- `--get-balance`: Display wallet balance (DEPRECATED - requires `--wallet-seed` and `--db`, use `--balance` instead)

### Placeholders (Not Yet Implemented)

- `--rpc <ADDR>`: RPC server bind address (default: `127.0.0.1:27447`)
- `--socks5 <ADDR>`: SOCKS5 proxy address for network connections

## Production Readiness Assessment

### Current Status: ~90% Complete 🚀

**What Works:**
- ✅ Full blockchain sync across multiple nodes
- ✅ Block production and gossip protocol
- ✅ UTXO state management and indexing
- ✅ Wallet generation and balance checking
- ✅ Secure mining with public addresses
- ✅ P2P networking with automatic peer discovery
- ✅ Merkle trees and PoW validation
- ✅ Coinbase transactions and block rewards

**What's Missing (CRITICAL):**
- ❌ Transaction fees and spam prevention
- ❌ Dynamic difficulty adjustment

**Major Security Improvements (JUST COMPLETED!):**
- ✅ **Ed25519 signature verification on all transactions**
- ✅ **UTXO validation prevents double-spending**
- ✅ **Public key verification ensures addresses match**

**Current Status:** Blocks with invalid signatures or missing UTXOs are now **REJECTED**. The chain is significantly more secure!

**Estimated Time to Launch:** 2 critical features remaining, ~3-5 days of focused development.

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
- [x] HD (Hierarchical Deterministic) wallets with BIP44 derivation paths
- [x] CLI commands for wallet generation and restoration
- [x] Multiple address derivation from single master seed
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
- [x] Secure mining with public addresses (--miner-address flag)
- [x] Separation of mining rewards from transaction signing
- [x] Public balance checking (--balance flag works with any address, no private key needed)
- [x] Blockchain transparency (anyone can query any address balance)
- [x] **Ed25519 signature verification on all transaction inputs** 🔐
- [x] **UTXO validation when accepting blocks (prevents double-spending)** 🔐
- [x] **Public key hashing and address verification** 🔐
- [x] Transaction inputs now include public keys for verification
- [x] Blocks with invalid signatures are rejected
- [x] Blocks attempting to spend non-existent UTXOs are rejected
- [x] **Fork resolution and chain reorganization** 🔄
- [x] **Automatic chain switching to highest cumulative work** 🔄
- [x] **UTXO set rollback and reapplication during reorg** 🔄
- [x] **Transaction broadcasting via --send command** 📡
- [x] **Automatic peer mesh formation** 🌐
- [x] **30-second connection heartbeat monitoring** 💓

### Launch Blockers 🚨 (Must Have for Production)
- [x] **Wire up signature verification when processing blocks** ✅ DONE!
- [x] **Wire up UTXO validation when accepting blocks** ✅ DONE!
- [ ] **Transaction fees and fee validation** (prevents spam attacks)
- [ ] **Difficulty adjustment algorithm** (required for real PoW security)

### Nice to Have (Can Launch Without)
- [x] **Fork resolution and reorganization** ✅ DONE!
- [x] **Transaction mempool broadcasting** ✅ DONE! (--send command)
- [x] **HD wallets (hierarchical derivation)** ✅ DONE!
- [x] **Persistent wallet files** ✅ DONE! (encrypted wallet.dat files)
- [x] **Wallet encryption** ✅ DONE! (BLAKE3-based password encryption)
- [ ] Full script execution (simplified P2PKH works for now)

### Future Improvements 💡

**Wallet Management (IMPLEMENTED):**
~~Current approach requires passing `--wallet-seed` or `--miner-address` on every invocation. A better UX would be:~~
✅ **NOW AVAILABLE:** Encrypted wallet files with `--create-wallet` and `--wallet-file`!

```bash
# One-time wallet initialization (creates encrypted wallet.dat)
nulla --init-wallet
# Enter password: ****
# Wallet created: ~/.nulla/wallet.dat
# Address: 79bc6374ccc99f1211770ce007e05f6235b98c8b

# Future launches use wallet automatically
nulla --seed --listen /ip4/0.0.0.0/tcp/27444
# Enter wallet password: ****
# Mining to: 79bc6374ccc99f1211770ce007e05f6235b98c8b
```

Benefits:
- ✅ No private key in command line (more secure)
- ✅ Simpler UX (no copy/paste seeds)
- ✅ Aligns with Bitcoin Core / Ethereum clients
- ✅ Can still use `--miner-address` for flexibility

This is a nice-to-have improvement but NOT required for launch.

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

### Consensus

- **Proof-of-Work**: BLAKE3-based PoW with target-based difficulty
- **Difficulty Adjustment**: Adjusts every 10 blocks to maintain 60-second block times
- **Target Calculation**: Based on actual vs. expected time for previous interval
- **Maximum Adjustment**: 4x per interval to prevent extreme difficulty swings
- **Initial Target**: `0x000033ff...` (relatively easy for bootstrapping)

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