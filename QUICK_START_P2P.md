# Quick Start: P2P Testing

## 3-Node Network in 60 Seconds

### Terminal 1: Miner Node (Creates Blocks)
```bash
# Generate wallet (single command)
cargo run -- --generate-wallet
# Save the ADDRESS and SEED shown

# Start miner node (replace ADDRESS with address from above)
cargo run -- --db ./data-a --listen /ip4/127.0.0.1/tcp/27444 --mine --miner-address ADDRESS
```

### Terminal 2: Seed Node (Relay Only)
```bash
# Start seed node - relays blocks and transactions but doesn't mine
cargo run -- --db ./data-b --listen /ip4/127.0.0.1/tcp/27445 --peers /ip4/127.0.0.1/tcp/27444 --seed
```

### Terminal 3: Regular Node
```bash
cargo run -- --db ./data-c --listen /ip4/127.0.0.1/tcp/27446 --peers /ip4/127.0.0.1/tcp/27444
```

**What's Happening:**
- **Miner node (Terminal 1)**: Creates blocks via proof-of-work mining
- **Seed node (Terminal 2)**: Relays and syncs blocks but doesn't mine
- **Regular node (Terminal 3)**: Syncs blockchain from peers
- All nodes sync blockchain automatically! Blocks appear as the miner finds them.

## Send Your First Transaction

### Terminal 4: Send Transaction
```bash
# Generate receiver wallet (single command)
cargo run -- --generate-wallet
# Save the RECEIVER_ADDRESS shown

# Wait 60 seconds for a few blocks (to get balance from mining)

# Check seed node balance (use seed node address from Terminal 1)
cargo run -- --balance SEED_ADDRESS --db ./data-a

# Send 5 NULLA (replace SEED with wallet seed from Terminal 1, TO_ADDRESS with receiver address)
cargo run -- --send --wallet-seed SEED --to TO_ADDRESS --amount 5.0 --peers /ip4/127.0.0.1/tcp/27444 --db ./data-a
```

**Watch:**
- Transaction broadcasts to all nodes instantly
- Each node validates and relays the transaction
- After 30 seconds, seed node includes transaction in a block
- All nodes sync the new block and update balances

## Verify It Worked

```bash
# Check receiver balance on ALL nodes (should be identical)
cargo run -- --balance RECEIVER_ADDRESS --db ./data-a
cargo run -- --balance RECEIVER_ADDRESS --db ./data-b
cargo run -- --balance RECEIVER_ADDRESS --db ./data-c
```

All three should show: `Balance: 5.0 NULLA`

## Test No Peers Error

```bash
# Try sending without peers
cargo run -- --send --wallet-seed SEED --to RECEIVER --amount 1.0 --db ./data-a
```

You'll see:
```
Error: No peers configured!
Transaction created but NOT broadcasted (no peers online).
```

## Commands Cheat Sheet

```bash
# Generate wallet
cargo run -- --generate-wallet

# Check balance
cargo run -- --balance ADDRESS

# Send transaction
cargo run -- --send --wallet-seed SEED --to ADDRESS --amount NULLA --peers PEER

# Start miner node (creates blocks with proof-of-work)
cargo run -- --db PATH --listen ADDR --mine --miner-address ADDR

# Start seed node (relay/sync only, no mining)
cargo run -- --db PATH --listen ADDR --peers PEER --seed

# Start regular node (basic sync)
cargo run -- --db PATH --listen ADDR --peers PEER
```

## What's Happening Under the Hood?

1. **Gossipsub Protocol**: Transactions and blocks propagate via libp2p gossipsub
2. **Transaction Relay**: Each peer validates and re-broadcasts valid transactions
3. **Blockchain Sync**: Peers automatically share and sync blockchain state
4. **Mempool Management**: Transactions wait in mempool until included in blocks
5. **UTXO Validation**: Double-spending is prevented via UTXO checks
6. **Signature Verification**: Ed25519 signatures prevent transaction forgery

See [TESTING_P2P.md](TESTING_P2P.md) for detailed scenarios and troubleshooting.
