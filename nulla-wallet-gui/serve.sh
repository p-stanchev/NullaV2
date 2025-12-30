#!/bin/bash

echo "Starting Nulla Wallet GUI Server..."
echo ""
echo "Wallet will be available at: http://localhost:8080"
echo "Make sure your Nulla node is running with: cargo run --bin nulla --rpc 127.0.0.1:27447"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Try Python first
if command -v python3 &> /dev/null; then
    echo "Using Python HTTP server..."
    python3 -m http.server 8080
elif command -v python &> /dev/null; then
    echo "Using Python HTTP server..."
    python -m http.server 8080
# Try Node.js
elif command -v node &> /dev/null; then
    echo "Using Node.js HTTP server..."
    npx http-server -p 8080 --cors
# Try PHP
elif command -v php &> /dev/null; then
    echo "Using PHP built-in server..."
    php -S localhost:8080
else
    echo "ERROR: No web server found!"
    echo "Please install Python, Node.js, or PHP to run the wallet GUI"
    echo ""
    echo "Or manually open: file://$(pwd)/index.html"
fi
