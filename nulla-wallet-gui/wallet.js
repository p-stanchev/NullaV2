// Nulla Light Wallet - Electrum Protocol Client
// Connects to Nulla node via JSON-RPC

const RPC_URL = 'http://localhost:27447';
let currentAddress = null;

// JSON-RPC client
async function rpcCall(method, params = []) {
    try {
        const response = await fetch(RPC_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                jsonrpc: '2.0',
                id: Date.now(),
                method,
                params
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();

        if (data.error) {
            throw new Error(data.error.message || 'RPC error');
        }

        return data.result;
    } catch (error) {
        console.error('RPC call failed:', error);
        throw error;
    }
}

// Check connection and update status
async function checkConnection() {
    try {
        const tip = await rpcCall('blockchain.headers.subscribe');
        document.getElementById('connectionStatus').textContent = 'Connected';
        document.getElementById('connectionStatus').style.color = '#00C851';
        document.getElementById('blockHeight').textContent = tip.height.toLocaleString();
        document.getElementById('syncStatus').textContent = 'Synced';
        document.getElementById('syncStatus').style.color = '#00C851';
        return true;
    } catch (error) {
        console.error('Connection error details:', error);
        document.getElementById('connectionStatus').textContent = 'Failed';
        document.getElementById('connectionStatus').style.color = '#ff4444';
        document.getElementById('syncStatus').textContent = 'No Connection';

        // Show detailed error message
        let errorMsg = 'Cannot connect to Nulla node. ';
        if (error.message.includes('Failed to fetch')) {
            errorMsg += 'CORS or network error. Make sure you\'re accessing via http://localhost:8080 (not file://)';
        } else {
            errorMsg += error.message;
        }
        showError(errorMsg);
        return false;
    }
}

// Load wallet and fetch balance
async function loadWallet() {
    const address = document.getElementById('addressInput').value.trim();

    if (!address) {
        showError('Please enter an address');
        return;
    }

    if (address.length !== 40) {
        showError('Invalid address format (must be 40-character hex)');
        return;
    }

    currentAddress = address;

    // Check connection first
    const connected = await checkConnection();
    if (!connected) return;

    try {
        showMessage('Loading wallet...', 'info');

        // Get balance
        const balanceData = await rpcCall('blockchain.scripthash.get_balance', [address]);
        const balanceAtoms = balanceData.confirmed + balanceData.unconfirmed;
        const balanceNulla = balanceAtoms / 100000000;

        document.getElementById('balanceAmount').textContent = balanceNulla.toFixed(8);
        document.getElementById('balanceSection').style.display = 'block';
        document.getElementById('sendSection').style.display = 'block';

        // Get UTXOs
        const utxos = await rpcCall('blockchain.scripthash.listunspent', [address]);
        displayUTXOs(utxos);

        // Get transaction history
        try {
            const history = await rpcCall('blockchain.scripthash.get_history', [address]);
            console.log('Transaction history:', history);
        } catch (e) {
            console.log('History not available:', e);
        }

        showSuccess('Wallet loaded successfully!');
    } catch (error) {
        showError('Failed to load wallet: ' + error.message);
    }
}

// Display UTXOs
function displayUTXOs(utxos) {
    const utxoList = document.getElementById('utxoList');

    if (!utxos || utxos.length === 0) {
        utxoList.innerHTML = '<p style="text-align: center; color: #999;">No UTXOs found</p>';
        return;
    }

    utxoList.innerHTML = utxos.map(utxo => {
        const valueNulla = utxo.value / 100000000;
        return `
            <div class="utxo-item">
                <strong>TxID:</strong> ${utxo.txid.substring(0, 16)}...${utxo.txid.substring(utxo.txid.length - 16)}<br>
                <strong>Vout:</strong> ${utxo.vout} |
                <strong>Amount:</strong> ${valueNulla.toFixed(8)} NULLA |
                <strong>Height:</strong> ${utxo.height || 'Unconfirmed'}
            </div>
        `;
    }).join('');
}

// Broadcast transaction
async function broadcastTransaction() {
    const txHex = document.getElementById('txHexInput').value.trim();

    if (!txHex) {
        showError('Please enter a signed transaction');
        return;
    }

    try {
        showMessage('Broadcasting transaction...', 'info');

        const txid = await rpcCall('blockchain.transaction.broadcast', [txHex]);

        showSuccess(`Transaction broadcast! TxID: ${txid}`);

        // Refresh wallet after a delay
        setTimeout(() => loadWallet(), 2000);
    } catch (error) {
        showError('Failed to broadcast transaction: ' + error.message);
    }
}

// Get headers for SPV verification
async function downloadHeaders(startHeight, count) {
    try {
        const headersHex = await rpcCall('blockchain.block.headers', [startHeight, count]);
        console.log(`Downloaded ${count} headers starting from ${startHeight}`);
        return headersHex;
    } catch (error) {
        console.error('Failed to download headers:', error);
    }
}

// Get merkle proof for transaction verification
async function getMerkleProof(txid, blockHeight) {
    try {
        const proof = await rpcCall('blockchain.transaction.get_merkle', [txid, blockHeight]);
        console.log('Merkle proof:', proof);
        return proof;
    } catch (error) {
        console.error('Failed to get merkle proof:', error);
    }
}

// UI helper functions
function showError(message) {
    const div = document.getElementById('messageDiv');
    div.innerHTML = `<div class="error">${message}</div>`;
    setTimeout(() => div.innerHTML = '', 5000);
}

function showSuccess(message) {
    const div = document.getElementById('messageDiv');
    div.innerHTML = `<div class="success">${message}</div>`;
    setTimeout(() => div.innerHTML = '', 5000);
}

function showMessage(message, type = 'info') {
    const div = document.getElementById('messageDiv');
    const className = type === 'error' ? 'error' : type === 'success' ? 'success' : 'info-box';
    div.innerHTML = `<div class="${className}"><p>${message}</p></div>`;
}

// Initialize
window.addEventListener('load', () => {
    checkConnection();

    // Auto-refresh connection status every 10 seconds
    setInterval(checkConnection, 10000);
});
