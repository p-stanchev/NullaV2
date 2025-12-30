# Nulla Light Wallet (GUI)

A lightweight web-based wallet for Nulla cryptocurrency using the Electrum protocol for SPV (Simplified Payment Verification).

## Features

✅ **Light Client** - No need to download the full blockchain
✅ **Balance Checking** - View your NULLA balance instantly
✅ **UTXO Management** - See all your unspent outputs
✅ **Transaction Broadcasting** - Send signed transactions
✅ **SPV Verification** - Verify transactions with merkle proofs
✅ **Header-Only Sync** - Download only block headers

## Prerequisites

1. **Nulla Node Running** - You must have a Nulla full node running with RPC enabled
2. **RPC Enabled** - Node must be accessible at `http://127.0.0.1:27447`
3. **Modern Browser** - Chrome, Firefox, Edge, or Safari
4. **Web Server** - Required to serve the wallet (cannot use `file://` protocol due to CORS)

## Important: RPC Bind Address

**CRITICAL**: The RPC server MUST bind to an IP address, not a hostname:

✅ **CORRECT**:
```bash
--rpc 127.0.0.1:27447
```

❌ **WRONG** (will fail):
```bash
--rpc localhost:27447
```

The `jsonrpsee` library requires IP address format. Using `localhost` will cause:
```
WARN Failed to start RPC server: Invalid bind address 'localhost:27447': invalid socket address syntax
```

## Setup Instructions

### 1. Start Your Nulla Node

**IMPORTANT**: Use `127.0.0.1` (not `localhost`) for the RPC bind address:

```bash
cd /path/to/Nulla

# Mining node (Windows - development)
cargo run --release --bin nulla -- --rpc 127.0.0.1:27447 --mine --miner-address YOUR_ADDRESS

# Mining node (Linux/macOS)
./target/release/nulla --rpc 127.0.0.1:27447 --mine --miner-address YOUR_ADDRESS
```

Verify RPC server started successfully in the logs:
```
INFO RPC server started on 127.0.0.1:27447
```

### 2. Start the Wallet Web Server

**REQUIRED**: You MUST serve the wallet through HTTP (not `file://`):

**Windows:**
```cmd
cd c:\Users\stanc\Desktop\Nulla\nulla-wallet-gui
serve.bat
```

**Mac/Linux:**
```bash
cd /path/to/Nulla/nulla-wallet-gui
./serve.sh
```

The script will automatically use:
- Node.js `http-server` (if available), or
- Python `http.server` (if available), or
- PHP built-in server (if available)

### 3. Open the Wallet in Your Browser

Navigate to: **http://localhost:8080**

**CORS Issue**: Due to browser security policies, you may need additional steps. See [CORS_WORKAROUND.md](CORS_WORKAROUND.md) for solutions.

### 4. Load Your Wallet

1. Enter your Nulla address (40-character hex)
2. Click "Load Wallet"
3. View your balance and UTXOs

### 5. Send Transactions

**Important:** This wallet is view-only for security. To send transactions:

1. Build and sign transaction **offline** using the CLI wallet:
   ```bash
   nulla --wallet-seed <YOUR_SEED> --send --to <ADDRESS> --amount 1.0
   ```

2. Copy the transaction hex from the output

3. Paste it into the "Signed Transaction" field in the GUI

4. Click "Broadcast Transaction"

## Available RPC Methods

The wallet uses the following Electrum protocol methods:

### Balance & UTXOs
- `blockchain.scripthash.get_balance` - Get address balance
- `blockchain.scripthash.listunspent` - List UTXOs
- `blockchain.scripthash.get_history` - Get transaction history

### Transactions
- `blockchain.transaction.broadcast` - Broadcast signed transaction
- `blockchain.transaction.get` - Get transaction by ID
- `blockchain.transaction.get_merkle` - Get merkle proof for SPV

### Headers
- `blockchain.headers.subscribe` - Get current tip
- `blockchain.block.headers` - Download header range

## Security Notes

🔒 **Private Keys Never Leave Your Device**
- This wallet never asks for or stores private keys
- All transaction signing must be done offline
- Only signed transactions are broadcast

🔒 **Localhost Only**
- RPC server only accepts connections from 127.0.0.1
- No remote access by default

🔒 **SPV Security**
- Wallet verifies transactions using merkle proofs
- No need to trust the full node blindly

## Architecture

```
┌──────────────────┐
│   Web Browser    │  (Light Wallet GUI)
│  (HTML/JS/CSS)   │
└────────┬─────────┘
         │ JSON-RPC over HTTP
         │ Electrum Protocol
         ▼
┌──────────────────┐
│   Nulla Node     │  (Full Node)
│  RPC Server      │  --prune (optional)
│  127.0.0.1:27447 │
└──────────────────┘
```

## Example Usage

### Check Balance
```javascript
// In browser console
await rpcCall('blockchain.scripthash.get_balance', ['your_address_here'])
// Returns: { confirmed: 800000000, unconfirmed: 0 }
```

### Download Headers
```javascript
await rpcCall('blockchain.block.headers', [0, 100])
// Returns: hex-encoded concatenated headers
```

### Verify Transaction
```javascript
const proof = await rpcCall('blockchain.transaction.get_merkle', [
    'transaction_id',
    block_height
])
// Returns merkle proof for SPV verification
```

## Future Enhancements

- [ ] WebSocket support for real-time updates
- [ ] Integrated transaction signing (with warning)
- [ ] QR code address display
- [ ] Transaction history timeline
- [ ] Multi-address support
- [ ] Electron app for desktop
- [ ] Mobile app (React Native / Flutter)

## Development

This is a simple HTML/JS wallet. To contribute:

1. Edit `index.html` for UI changes
2. Edit `wallet.js` for functionality
3. Test with a local Nulla node
4. Submit pull request

## Troubleshooting

### "Cannot connect to Nulla node"

**Check RPC Server Started**:
```bash
# Look for this in node logs:
INFO RPC server started on 127.0.0.1:27447
```

**Common Causes**:
1. Used `--rpc localhost:27447` instead of `--rpc 127.0.0.1:27447`
   - Error: `WARN Failed to start RPC server: Invalid bind address 'localhost:27447'`
   - Fix: Use IP address format `127.0.0.1` instead of hostname `localhost`

2. Wallet served via `file://` protocol instead of `http://`
   - Browser blocks cross-protocol requests
   - Fix: Use `serve.bat` or `serve.sh` to start web server

3. CORS blocking cross-port requests
   - Browser blocks `localhost:8080` → `localhost:27447`
   - Fix: See [CORS_WORKAROUND.md](CORS_WORKAROUND.md)

**Verify Node is Running**:
```bash
# Windows
netstat -an | findstr 27447

# Linux/macOS
netstat -an | grep 27447
```

Should show: `127.0.0.1:27447`

**Test RPC Directly**:
```bash
curl -X POST http://127.0.0.1:27447 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}'
```

### "Invalid address format"
- Address must be exactly 40 hexadecimal characters
- Generate address: `nulla --generate-wallet`

### "Transaction broadcast failed"
- Verify transaction is properly signed
- Check transaction format is valid hex
- Ensure sufficient balance and valid UTXOs

### Known Issues

**P2P Connection Stability**:
Peer connections may drop after some time. If your node stops receiving new blocks:
1. Restart both mining node and seed node
2. Check logs for "total peers connected" - should be 1 or more
3. If peers = 0, nodes aren't communicating and blocks won't propagate

See [CORS_WORKAROUND.md](CORS_WORKAROUND.md) for complete browser-based CORS solutions.

## License

MIT OR Apache-2.0
