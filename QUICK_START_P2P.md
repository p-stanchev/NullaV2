# Quick Start: P2P Testing

## 3-Node Network in 60 Seconds

### Terminal 1: Miner Node (Creates Blocks)
```bash
# Generate wallet with BIP39 mnemonic
cargo run -- --generate-mnemonic 24
# Save the 24-word MNEMONIC and ADDRESS shown

# Start miner node (replace ADDRESS with address from above)
cargo run -- --db ./data-a --listen /ip4/127.0.0.1/tcp/27444 --mine --miner-address ADDRESS
```

### Terminal 2: Seed Node (Relay Only)
```bash
# Start seed node - relays blocks and transactions but doesn't mine
cargo run -- --db ./data-b --listen /ip4/127.0.0.1/tcp/27445 --peers /ip4/127.0.0.1/tcp/27444
```

### Terminal 3: Regular Node
```bash
cargo run -- --db ./data-c --listen /ip4/127.0.0.1/tcp/27446 --peers /ip4/127.0.0.1/tcp/27444
```

**What's Happening:**
- **Miner node (Terminal 1)**: Creates blocks via proof-of-work mining
- **Seed node (Terminal 2)**: Relays and syncs blocks (no `--seed` flag needed)
- **Regular node (Terminal 3)**: Syncs blockchain from peers
- All nodes sync blockchain automatically! Blocks appear as the miner finds them.

## Send Your First Transaction

### Terminal 4: Send Transaction
```bash
# Generate receiver wallet with BIP39 mnemonic
cargo run -- --generate-mnemonic 24
# Save the RECEIVER_ADDRESS shown

# Wait 60 seconds for a few blocks (to get balance from mining)

# Check miner balance (NO --db needed! Defaults to ./data)
cargo run -- --balance MINER_ADDRESS

# Send 5 NULLA using BIP39 mnemonic (replace with your 24 words)
cargo run -- --send \
  --from-mnemonic "word1 word2 word3 ... word24" \
  --to RECEIVER_ADDRESS \
  --amount 5.0 \
  --peers /ip4/127.0.0.1/tcp/27444
```

**Alternative: Using Environment Variable**
```bash
# Set wallet seed as environment variable
NULLA_WALLET_SEED=<your_seed_hex> cargo run -- --send \
  --to RECEIVER_ADDRESS \
  --amount 5.0 \
  --peers /ip4/127.0.0.1/tcp/27444
```

**Watch:**
- Transaction broadcasts to all nodes instantly
- Each node validates and relays the transaction
- Miner includes transaction in next block (~2 minutes)
- All nodes sync the new block and update balances

## Verify It Worked

```bash
# Check receiver balance on different nodes
# (Each node has its own database, so specify which one to check)
cargo run -- --balance RECEIVER_ADDRESS --db ./data-a  # Miner node
cargo run -- --balance RECEIVER_ADDRESS --db ./data-b  # Seed node
cargo run -- --balance RECEIVER_ADDRESS --db ./data-c  # Regular node

# Or check on default database (./data)
cargo run -- --balance RECEIVER_ADDRESS
```

All should show: `5.0 NULLA`

## Commands Cheat Sheet

```bash
# Generate BIP39 mnemonic wallet (RECOMMENDED)
cargo run -- --generate-mnemonic 24

# Generate simple wallet (single address)
cargo run -- --generate-wallet

# Check balance (NO --db needed, uses default ./data)
cargo run -- --balance ADDRESS

# Check balance on specific database
cargo run -- --balance ADDRESS --db ./data-a

# Send transaction (BIP39 mnemonic)
cargo run -- --send \
  --from-mnemonic "word1 word2 ... word24" \
  --to ADDRESS \
  --amount NULLA \
  --peers PEER

# Send transaction (environment variable)
NULLA_WALLET_SEED=<seed_hex> cargo run -- --send \
  --to ADDRESS \
  --amount NULLA \
  --peers PEER

# Send transaction (encrypted wallet file)
cargo run -- --send \
  --wallet-file wallet.dat \
  --wallet-password "password" \
  --to ADDRESS \
  --amount NULLA \
  --peers PEER

# Start miner node (creates blocks with proof-of-work)
cargo run -- --db PATH --listen ADDR --mine --miner-address ADDR

# Start regular node (relay and sync)
cargo run -- --db PATH --listen ADDR --peers PEER
```

## Security Best Practices

**DO:**
- ✅ Use BIP39 mnemonic phrases for wallet backups
- ✅ Use `--miner-address` for mining (public address, safe)
- ✅ Use environment variables for automation (`NULLA_WALLET_SEED`)
- ✅ Use encrypted wallet files with `--wallet-file`

**DON'T:**
- ❌ Never use `--wallet-seed` in command line (REMOVED for security)
- ❌ Never share your mnemonic phrase or seed hex
- ❌ Never commit seeds to git or store in plain text

**Secure Wallet Loading Options:**

1. **BIP39 Mnemonic** (user-friendly):
   ```bash
   --from-mnemonic "word1 word2 ... word24"
   ```

2. **Environment Variable** (automation):
   ```bash
   NULLA_WALLET_SEED=<seed_hex> nulla ...
   ```

3. **Encrypted Wallet File** (RECOMMENDED):
   ```bash
   --wallet-file wallet.dat --wallet-password "pass"
   ```

4. **Interactive Stdin** (secure manual entry):
   ```bash
   --wallet-seed-stdin
   # Will prompt for seed
   ```

## What's Happening Under the Hood?

1. **Gossipsub Protocol**: Transactions and blocks propagate via libp2p gossipsub
2. **Transaction Relay**: Each peer validates and re-broadcasts valid transactions
3. **Blockchain Sync**: Peers automatically share and sync blockchain state
4. **Mempool Management**: Transactions wait in mempool until included in blocks
5. **UTXO Validation**: Double-spending is prevented via UTXO checks
6. **Signature Verification**: Ed25519 signatures prevent transaction forgery
7. **Fork Resolution**: Nakamoto consensus (longest chain rule) handles competing blocks

## Troubleshooting

**Error: --wallet-seed has been REMOVED**
```
ERROR: --wallet-seed has been REMOVED for security reasons.
```
**Solution:** Use one of the secure alternatives above (BIP39, environment variable, wallet file, or stdin)

**Balance Shows Zero After Mining**
- Wait at least 30 blocks (~60 minutes) for coinbase maturity
- Coinbase rewards require confirmations before they can be spent

**Transaction Not Propagating**
- Ensure you specified `--peers` when sending
- Check that at least one peer is connected
- Verify transaction has sufficient fee (0.0001 NULLA minimum)

**Database Lock Error**
- Each node needs its own `--db` directory when running on same machine
- Use `--db ./data-a`, `--db ./data-b`, etc. for multiple local nodes

See [TESTING_P2P.md](TESTING_P2P.md) for detailed scenarios and troubleshooting.
