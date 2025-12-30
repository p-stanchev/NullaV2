# Fixing "Cannot connect to Nulla node" Error

## The Problem

When you open `index.html` directly in your browser (using `file://` protocol), browsers block HTTP requests to `localhost` for security reasons. This is called **CORS (Cross-Origin Resource Sharing)** restriction.

## The Solution

You need to serve the wallet through a **web server** instead of opening the HTML file directly.

### Quick Fix (Windows):

```batch
cd c:\Users\stanc\Desktop\Nulla\nulla-wallet-gui
serve.bat
```

Then open: **http://localhost:8080**

### Quick Fix (Mac/Linux):

```bash
cd /path/to/Nulla/nulla-wallet-gui
./serve.sh
```

Then open: **http://localhost:8080**

## Manual Methods:

### Option 1: Python (Recommended)

```bash
cd c:\Users\stanc\Desktop\Nulla\nulla-wallet-gui

# Python 3
python -m http.server 8080

# Python 2
python -m SimpleHTTPServer 8080
```

### Option 2: Node.js

```bash
cd c:\Users\stanc\Desktop\Nulla\nulla-wallet-gui

# Using npx (no install needed)
npx http-server -p 8080

# Or install globally first
npm install -g http-server
http-server -p 8080
```

### Option 3: PHP

```bash
cd c:\Users\stanc\Desktop\Nulla\nulla-wallet-gui
php -S localhost:8080
```

### Option 4: VS Code Live Server

1. Open folder in VS Code
2. Install "Live Server" extension
3. Right-click `index.html`
4. Click "Open with Live Server"

## Complete Setup Steps:

### Terminal 1 - Start Nulla Node:

**IMPORTANT:** The node must bind to `127.0.0.1` but you'll access it via `localhost` in the browser.

```bash
cd c:\Users\stanc\Desktop\Nulla
cargo run --release --bin nulla -- --rpc 127.0.0.1:27447 --mine
```

Wait for: `RPC server listening on 127.0.0.1:27447`

**Note:** `127.0.0.1` and `localhost` resolve to the same IP, but the wallet JavaScript uses `localhost` to avoid CORS issues.

### Terminal 2 - Start Wallet Server:

```bash
cd c:\Users\stanc\Desktop\Nulla\nulla-wallet-gui
python -m http.server 8080
```

### Browser:

Open: **http://localhost:8080**

The connection status should now show: ✅ **Connected**

## Verification:

Once both are running, you should see:
- Node terminal: `RPC server listening on 127.0.0.1:27447`
- Wallet browser: Connection status shows "Connected" in green
- Block height showing current blockchain height

## Troubleshooting:

**Still can't connect?**

1. Check node is running:
```bash
netstat -an | findstr 27447
```
Should show: `127.0.0.1:27447`

2. Test RPC directly:
```bash
curl -X POST http://127.0.0.1:27447 -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}'
```

3. Check browser console (F12) for errors

4. Make sure you're accessing `http://localhost:8080` NOT `file://`

## Why This Is Needed:

- **file://** protocol = Browser blocks localhost requests (CORS)
- **http://** protocol = Browser allows localhost requests ✅

The wallet **must** be served through HTTP for security policies to work correctly.
