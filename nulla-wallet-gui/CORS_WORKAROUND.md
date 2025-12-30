# CORS Workaround for Nulla Wallet GUI

The wallet GUI cannot connect to the RPC server due to browser CORS (Cross-Origin Resource Sharing) restrictions. Browsers block requests from `http://localhost:8080` to `http://localhost:27447` even though they're both localhost.

## Quick Solution: Use Chrome with CORS Disabled

**Windows:**
```cmd
chrome.exe --disable-web-security --user-data-dir="C:\temp\chrome_dev"
```

**Mac:**
```bash
open -na "Google Chrome" --args --disable-web-security --user-data-dir="/tmp/chrome_dev"
```

**Linux:**
```bash
google-chrome --disable-web-security --user-data-dir="/tmp/chrome_dev"
```

Then navigate to: `http://localhost:8080`

**WARNING:** Only use this for development! Never browse the web with CORS disabled.

## Alternative Solutions:

### Option 1: Browser Extension (Recommended for Regular Use)

Install a CORS extension for your browser:

**Chrome/Edge:**
- "CORS Unblock" extension
- "Allow CORS: Access-Control-Allow-Origin" extension

After installing, enable the extension and refresh the wallet page.

### Option 2: Use Firefox with Relaxed CORS

1. Open Firefox
2. Type `about:config` in the address bar
3. Search for `security.fileuri.strict_origin_policy`
4. Set it to `false`
5. Restart Firefox
6. Navigate to `http://localhost:8080`

### Option 3: Desktop Wallet (Future)

We plan to create an Electron-based desktop wallet that won't have CORS restrictions.

## Complete Setup:

### Terminal 1 - Start Nulla Node:
```bash
cd c:\Users\stanc\Desktop\Nulla
cargo run --release --bin nulla -- --rpc 127.0.0.1:27447 --mine
```

### Terminal 2 - Start Wallet Web Server:
```bash
cd c:\Users\stanc\Desktop\Nulla\nulla-wallet-gui
serve.bat
```

### Browser (with CORS disabled):
Open: **http://localhost:8080**

The wallet should now connect successfully!

## Why This Happens:

Browsers enforce a security policy called CORS (Cross-Origin Resource Sharing). When a web page on one port (`localhost:8080`) tries to make requests to a different port (`localhost:27447`), the browser blocks it unless the server explicitly allows it with CORS headers.

The Nulla RPC server uses `jsonrpsee` version 0.22, which doesn't have built-in CORS support. Upgrading to version 0.24+ would fix this, but it would require rewriting all RPC methods (breaking API changes).

## Security Note:

The Nulla RPC server already binds to `127.0.0.1` (localhost only), which prevents external access. The CORS issue only affects browser-based access. Command-line tools and native applications can connect without issues.

## Known Issues:

### P2P Connection Stability
You may notice that peer connections drop after some time. This is a known issue being investigated. If your node stops receiving new blocks:
1. Restart both the mining node and seed node
2. Check the logs for "total peers connected" - should be 1 or more
3. If peers = 0, the nodes aren't communicating and blocks won't propagate
