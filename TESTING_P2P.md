# Peer-to-Peer Transaction Broadcasting & Blockchain Sync Testing

This guide shows how to test the peer-to-peer transaction broadcasting and blockchain synchronization features in Nulla.

## Features Implemented

1. **Transaction Broadcasting**: When you send a transaction, it's broadcast to all connected peers
2. **Transaction Relay/Gossip**: Peers automatically relay valid transactions to all other peers they know
3. **Blockchain Synchronization**: Peers automatically share and sync blockchain data (blocks and headers)
4. **Error Handling**: Clear error messages when no peers are available
5. **Mempool Management**: Transactions are stored in mempool and included in blocks automatically

## Multi-Peer Network Setup

### Scenario 1: Three-Node Network (Basic Test)

Open three terminal windows for three nodes that will form a network.

#### Terminal 1: Miner Node (Node A)
This node will mine blocks (proof-of-work mining).

```bash
# Generate a wallet for the miner node to receive block rewards
cargo run -- --generate-wallet

# Save the seed and address shown, then start the miner node:
cargo run -- \
  --db ./data-node-a \
  --listen /ip4/127.0.0.1/tcp/27444 \
  --mine \
  --miner-address <ADDRESS_FROM_ABOVE>
```

#### Terminal 2: Regular Node (Node B)
This node will connect to Node A.

```bash
# Start node B and connect to node A
cargo run -- \
  --db ./data-node-b \
  --listen /ip4/127.0.0.1/tcp/27445 \
  --peers /ip4/127.0.0.1/tcp/27444
```

#### Terminal 3: Regular Node (Node C)
This node will also connect to Node A, creating a star topology.

```bash
# Start node C and connect to node A
cargo run -- \
  --db ./data-node-c \
  --listen /ip4/127.0.0.1/tcp/27446 \
  --peers /ip4/127.0.0.1/tcp/27444
```

**What Happens:**
- All three nodes will sync blockchain state automatically
- When Node A creates a block, it broadcasts to Nodes B and C
- Nodes B and C receive the block and relay it to each other
- All nodes converge on the same blockchain state

### Scenario 2: Testing Transaction Broadcasting

Now that you have a 3-node network running, let's test transaction broadcasting.

#### Step 1: Generate Wallets

In a new terminal, generate two wallets (sender and receiver):

```bash
# Generate sender wallet
cargo run -- --generate-wallet
# Save this as SENDER_SEED and SENDER_ADDRESS

# Generate receiver wallet
cargo run -- --generate-wallet
# Save this as RECEIVER_ADDRESS
```

#### Step 2: Wait for Block Rewards

Wait for Node A (the seed node) to create a few blocks (30 seconds each). You should see logs like:
```
seed: broadcasting block height=1 id=... (work: ..., reward: 8 NULLA)
```

After a few blocks, the seed node's address should have some NULLA.

#### Step 3: Check Balance

```bash
# Check the seed node's balance (use the miner address from Terminal 1)
cargo run -- --balance <SEED_NODE_ADDRESS> --db ./data-node-a
```

You should see something like:
```
=== Address Balance ===
Address: 79bc6374ccc99f1211770ce007e05f6235b98c8b
Balance: 24 NULLA (2400000000 atoms)
UTXOs:   3
```

#### Step 4: Send a Transaction

Send some NULLA from the seed node to the receiver:

```bash
cargo run -- \
  --send \
  --wallet-seed <SEED_NODE_WALLET_SEED> \
  --to <RECEIVER_ADDRESS> \
  --amount 5.0 \
  --peers /ip4/127.0.0.1/tcp/27444 \
  --db ./data-node-a
```

**What Happens:**
1. Transaction is created and validated
2. Transaction is added to Node A's mempool
3. Transaction is broadcast to all peers (Nodes B and C)
4. Nodes B and C validate the transaction
5. Nodes B and C add it to their mempool
6. Nodes B and C relay the transaction to each other and back to Node A
7. All nodes have the transaction in their mempool

You should see output like:
```
=== Transaction Created ===
From:   79bc6374ccc99f1211770ce007e05f6235b98c8b
To:     a1b2c3d4e5f6789012345678901234567890abcd
Amount: 5.0 NULLA (500000000 atoms)
Change: 19.0 NULLA (1900000000 atoms)
TxID:   abc123...

Broadcasting transaction to peers...
Connected to 1 peer(s)
Transaction broadcasted successfully!

The transaction will be included in the next block.
```

#### Step 5: Watch Transaction Propagation

In all three terminal windows (Nodes A, B, C), you should see logs like:

**Node A (sender):**
```
received full tx from 12D3KooW...: abc123...
transaction abc123... added to mempool, relaying to peers
```

**Node B:**
```
received full tx from 12D3KooW...: abc123...
transaction abc123... added to mempool, relaying to peers
```

**Node C:**
```
received full tx from 12D3KooW...: abc123...
transaction abc123... added to mempool, relaying to peers
```

#### Step 6: Wait for Block Inclusion

Wait for the next block (30 seconds). The seed node will include the transaction in a block:

```
seed: including 1 transaction(s) from mempool
seed: broadcasting block height=5 id=... (work: ..., reward: 8 NULLA)
```

All nodes will receive this block and:
1. Validate all transactions
2. Apply transactions to their UTXO set
3. Remove transactions from their mempool
4. Update their blockchain state

#### Step 7: Verify Transaction

Check the receiver's balance on any node:

```bash
# Check on Node A
cargo run -- --balance <RECEIVER_ADDRESS> --db ./data-node-a

# Check on Node B (should show same balance due to sync)
cargo run -- --balance <RECEIVER_ADDRESS> --db ./data-node-b

# Check on Node C (should show same balance due to sync)
cargo run -- --balance <RECEIVER_ADDRESS> --db ./data-node-c
```

All three nodes should show:
```
=== Address Balance ===
Address: a1b2c3d4e5f6789012345678901234567890abcd
Balance: 5.0 NULLA (500000000 atoms)
UTXOs:   1
```

### Scenario 3: Testing "No Peers Online" Error

Try sending a transaction without any peers connected:

```bash
cargo run -- \
  --send \
  --wallet-seed <SENDER_SEED> \
  --to <RECEIVER_ADDRESS> \
  --amount 1.0 \
  --db ./data-node-a
  # Note: No --peers argument!
```

You should see:
```
Error: No peers configured!
Transaction created but NOT broadcasted (no peers online).
The transaction is saved in the local mempool.
To broadcast, restart the node with --peers to connect to the network.
```

### Scenario 4: Mixed Network with Seed and Miner Nodes (Advanced)

Create a network with both seed nodes (relay only) and miner nodes (create blocks):

#### Terminal 1: Node A (Miner)
```bash
cargo run -- \
  --db ./data-node-a \
  --listen /ip4/127.0.0.1/tcp/27444 \
  --mine \
  --miner-address <MINER_ADDRESS>
```

#### Terminal 2: Node B (Seed - Relay Only)
```bash
cargo run -- \
  --db ./data-node-b \
  --listen /ip4/127.0.0.1/tcp/27445 \
  --peers /ip4/127.0.0.1/tcp/27444 \
  --seed
```

#### Terminal 3: Node C (Miner)
```bash
# Generate another wallet for this miner
cargo run -- --generate-wallet
# Use the address from above

cargo run -- \
  --db ./data-node-c \
  --listen /ip4/127.0.0.1/tcp/27446 \
  --peers /ip4/127.0.0.1/tcp/27444,/ip4/127.0.0.1/tcp/27445 \
  --mine \
  --miner-address <SECOND_MINER_ADDRESS>
```

#### Terminal 4: Node D (Regular)
```bash
cargo run -- \
  --db ./data-node-d \
  --listen /ip4/127.0.0.1/tcp/27447 \
  --peers /ip4/127.0.0.1/tcp/27444,/ip4/127.0.0.1/tcp/27445,/ip4/127.0.0.1/tcp/27446
```

**Network Topology:**
```
    A (miner)
   /|\
  / | \
 B  C  D
(seed)(miner)(regular)
```

**Test Transaction Propagation:**
Send a transaction and watch it propagate through all nodes. Each node will relay to all connected peers, ensuring full network coverage.

## Expected Behavior Summary

### Transaction Broadcasting
✅ Transaction is broadcast to all connected peers
✅ Each peer validates the transaction (signatures + UTXOs)
✅ Valid transactions are added to mempool
✅ Peers relay transactions to all other connected peers
✅ Invalid transactions are rejected with warning logs

### Blockchain Synchronization
✅ Blocks are broadcast to all connected peers via gossipsub
✅ Peers validate blocks (structure + signatures + UTXOs)
✅ Valid blocks are stored and applied to UTXO set
✅ Chain tip is updated if block extends the best chain
✅ Transactions in blocks are removed from mempool
✅ All peers converge on the same blockchain state

### Error Handling
✅ Clear error when no peers are configured
✅ Transaction saved to local mempool even if broadcast fails
✅ Invalid transactions are rejected with detailed error messages
✅ Signature verification prevents forged transactions
✅ UTXO validation prevents double-spending

## Command Reference

### Check Balance
```bash
cargo run -- --balance <ADDRESS>
```

### Send Transaction
```bash
cargo run -- \
  --send \
  --wallet-seed <SENDER_SEED> \
  --to <RECEIVER_ADDRESS> \
  --amount <NULLA_AMOUNT> \
  --peers <PEER_MULTIADDRS>
```

### Generate Wallet
```bash
cargo run -- --generate-wallet
```

### Start Miner Node (Creates Blocks)
```bash
cargo run -- \
  --db <DB_PATH> \
  --listen <LISTEN_ADDR> \
  --mine \
  --miner-address <MINER_ADDRESS>
```

### Start Seed Node (Relay/Sync Only)
```bash
cargo run -- \
  --db <DB_PATH> \
  --listen <LISTEN_ADDR> \
  --peers <PEER_MULTIADDRS> \
  --seed
```

### Start Regular Node (Basic Sync)
```bash
cargo run -- \
  --db <DB_PATH> \
  --listen <LISTEN_ADDR> \
  --peers <PEER_MULTIADDRS>
```

## Troubleshooting

### "Transaction created but NOT broadcasted"
- **Cause**: No peers are configured or reachable
- **Solution**: Add `--peers` argument with at least one reachable peer

### "UTXO not found"
- **Cause**: Trying to spend outputs that don't exist
- **Solution**: Check balance and ensure you have available UTXOs

### "Signature verification failed"
- **Cause**: Invalid wallet seed or corrupted transaction
- **Solution**: Verify wallet seed is correct (64-char hex)

### "Insufficient balance"
- **Cause**: Not enough NULLA to cover the transaction amount
- **Solution**: Wait for more block rewards or request funds from another wallet

### Nodes not syncing
- **Cause**: Peers not connected or gossipsub not working
- **Solution**: Check that nodes are connected (look for "peer connected" logs)

## Monitoring Tips

Watch the logs in each terminal to observe:
- **Peer connections**: `peer connected <peer_id>`
- **Transaction relay**: `received full tx from <peer>: <txid>`
- **Transaction validation**: `transaction <txid> added to mempool, relaying to peers`
- **Block creation**: `seed: broadcasting block height=X`
- **Block reception**: `full block from <peer> height=X txs=Y`
- **Sync status**: `sync tick: height=X tip=... work=... mempool=Y`

## Performance Notes

- Block interval: 30 seconds (configurable in code)
- Transaction propagation: Near-instant (gossipsub)
- Network topology: Any connected graph works
- Recommended peers: 3-8 for testing, 10-50 for production
