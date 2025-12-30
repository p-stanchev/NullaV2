use jsonrpsee::RpcModule;

use crate::error::RpcError;
use crate::RpcContext;
use nulla_electrum::ElectrumServer;

/// Register Electrum-compatible RPC methods for light wallets.
///
/// These methods provide SPV (Simplified Payment Verification) capabilities
/// allowing lightweight clients to operate without downloading full blockchain.
pub fn register_methods(module: &mut RpcModule<RpcContext>) -> anyhow::Result<()> {
    // Get block headers in range (for header-only sync)
    module.register_async_method("blockchain.headers.subscribe", |_params, ctx| async move {
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        let electrum = ElectrumServer::new(ctx.db.clone(), ctx.chain_id);
        let header = electrum.get_tip_header()
            .map_err(|e| RpcError::Internal(e.to_string()).into_error_object())?;

        Ok::<nulla_electrum::HeaderNotification, jsonrpsee::types::ErrorObjectOwned>(
            nulla_electrum::HeaderNotification {
                height: header.height,
                hex: hex::encode(bincode::serialize(&header).unwrap()),
            }
        )
    })?;

    // Get balance for an address
    module.register_async_method("blockchain.scripthash.get_balance", |params, ctx| async move {
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        let address_hex: String = params.one()?;
        let address = nulla_wallet::Address::from_hex(&address_hex)
            .ok_or_else(|| RpcError::InvalidAddress("Invalid address hex".to_string()).into_error_object())?;

        let electrum = ElectrumServer::new(ctx.db.clone(), ctx.chain_id);
        let balance = electrum.get_balance(address.hash())
            .map_err(|e| RpcError::Internal(e.to_string()).into_error_object())?;

        Ok::<nulla_electrum::AddressBalance, jsonrpsee::types::ErrorObjectOwned>(
            nulla_electrum::AddressBalance {
                confirmed: balance,
                unconfirmed: 0, // TODO: Track unconfirmed balance from mempool
            }
        )
    })?;

    // List unspent outputs for an address
    module.register_async_method("blockchain.scripthash.listunspent", |params, ctx| async move {
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        let address_hex: String = params.one()?;
        let address = nulla_wallet::Address::from_hex(&address_hex)
            .ok_or_else(|| RpcError::InvalidAddress("Invalid address hex".to_string()).into_error_object())?;

        let electrum = ElectrumServer::new(ctx.db.clone(), ctx.chain_id);
        let utxos = electrum.get_utxos(address.hash())
            .map_err(|e| RpcError::Internal(e.to_string()).into_error_object())?;

        let items: Vec<nulla_electrum::UnspentItem> = utxos.into_iter().map(|(outpoint, txout, height)| {
            nulla_electrum::UnspentItem {
                txid: hex::encode(outpoint.txid),
                vout: outpoint.vout,
                value: txout.value_atoms,
                height,
            }
        }).collect();

        Ok::<Vec<nulla_electrum::UnspentItem>, jsonrpsee::types::ErrorObjectOwned>(items)
    })?;

    // Get transaction history for an address
    module.register_async_method("blockchain.scripthash.get_history", |params, ctx| async move {
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        let address_hex: String = params.one()?;
        let address = nulla_wallet::Address::from_hex(&address_hex)
            .ok_or_else(|| RpcError::InvalidAddress("Invalid address hex".to_string()).into_error_object())?;

        let electrum = ElectrumServer::new(ctx.db.clone(), ctx.chain_id);
        let history = electrum.get_history(address.hash())
            .map_err(|e| RpcError::Internal(e.to_string()).into_error_object())?;

        Ok::<Vec<nulla_electrum::HistoryItem>, jsonrpsee::types::ErrorObjectOwned>(history)
    })?;

    // Broadcast a transaction
    module.register_async_method("blockchain.transaction.broadcast", |params, ctx| async move {
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        let tx_hex: String = params.one()?;
        let tx_bytes = hex::decode(&tx_hex)
            .map_err(|_| RpcError::InvalidParameter("Invalid hex".to_string()).into_error_object())?;
        let tx: nulla_core::Tx = bincode::deserialize(&tx_bytes)
            .map_err(|_| RpcError::InvalidParameter("Invalid transaction data".to_string()).into_error_object())?;

        let electrum = ElectrumServer::new(ctx.db.clone(), ctx.chain_id);
        let txid = electrum.broadcast_transaction(tx)
            .map_err(|e| RpcError::Internal(e.to_string()).into_error_object())?;

        Ok::<String, jsonrpsee::types::ErrorObjectOwned>(hex::encode(txid))
    })?;

    // Get transaction by ID
    module.register_async_method("blockchain.transaction.get", |params, ctx| async move {
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        let txid_hex: String = params.one()?;
        let txid_bytes = hex::decode(&txid_hex)
            .map_err(|_| RpcError::InvalidParameter("Invalid txid hex".to_string()).into_error_object())?;

        if txid_bytes.len() != 32 {
            return Err(RpcError::InvalidParameter("Invalid txid length".to_string()).into_error_object());
        }

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_bytes);

        let electrum = ElectrumServer::new(ctx.db.clone(), ctx.chain_id);
        let tx = electrum.get_transaction(&txid)
            .map_err(|e| RpcError::Internal(e.to_string()).into_error_object())?
            .ok_or_else(|| RpcError::TxNotFound(txid_hex).into_error_object())?;

        let tx_hex = hex::encode(bincode::serialize(&tx).unwrap());
        Ok::<String, jsonrpsee::types::ErrorObjectOwned>(tx_hex)
    })?;

    // Get merkle proof for a transaction
    module.register_async_method("blockchain.transaction.get_merkle", |params, ctx| async move {
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        let txid_hex: String = params.one()?;
        let block_height: u64 = params.one()?;

        let txid_bytes = hex::decode(&txid_hex)
            .map_err(|_| RpcError::InvalidParameter("Invalid txid hex".to_string()).into_error_object())?;

        if txid_bytes.len() != 32 {
            return Err(RpcError::InvalidParameter("Invalid txid length".to_string()).into_error_object());
        }

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_bytes);

        // Get block at height
        let header = ctx.db.get_header_by_height(block_height)
            .map_err(|e| RpcError::Database(e.to_string()).into_error_object())?
            .ok_or_else(|| RpcError::BlockNotFound(format!("height {}", block_height)).into_error_object())?;

        let block_id = nulla_core::block_header_id(&header);

        let electrum = ElectrumServer::new(ctx.db.clone(), ctx.chain_id);
        let proof = electrum.get_merkle_proof(&txid, &block_id)
            .map_err(|e| RpcError::Internal(e.to_string()).into_error_object())?;

        Ok::<nulla_electrum::MerkleProof, jsonrpsee::types::ErrorObjectOwned>(proof)
    })?;

    // Get headers in range (batch header download)
    module.register_async_method("blockchain.block.headers", |params, ctx| async move {
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        let start_height: u64 = params.one()?;
        let count: u64 = params.one()?;

        // Limit to 2016 headers per request (Bitcoin checkpoint interval)
        let count = count.min(2016);

        let electrum = ElectrumServer::new(ctx.db.clone(), ctx.chain_id);
        let headers = electrum.get_headers_range(start_height, count)
            .map_err(|e| RpcError::Internal(e.to_string()).into_error_object())?;

        // Serialize headers as concatenated hex
        let mut hex_data = String::new();
        for header in headers {
            let header_bytes = bincode::serialize(&header).unwrap();
            hex_data.push_str(&hex::encode(header_bytes));
        }

        Ok::<String, jsonrpsee::types::ErrorObjectOwned>(hex_data)
    })?;

    Ok(())
}
