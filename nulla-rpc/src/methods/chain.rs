use jsonrpsee::RpcModule;

use crate::error::RpcError;
use crate::types::*;
use crate::RpcContext;

/// Calculate difficulty from target bytes
fn calculate_difficulty(target: &[u8; 32]) -> f64 {
    // Count leading zero bits
    let mut zero_bits = 0;
    for byte in target.iter() {
        if *byte == 0 {
            zero_bits += 8;
        } else {
            zero_bits += byte.leading_zeros() as usize;
            break;
        }
    }

    // Difficulty is 2^zero_bits
    2.0_f64.powi(zero_bits as i32)
}

/// Register chain RPC methods
pub fn register_methods(module: &mut RpcModule<RpcContext>) -> anyhow::Result<()> {
    module.register_async_method("getbestblockhash", |_params, ctx| async move {
        let tip = ctx.db.best_tip()
            .map_err(|e| RpcError::Database(e.to_string()).into_error_object())?
            .ok_or_else(|| RpcError::Internal("No tip found".to_string()).into_error_object())?;
        Ok::<String, jsonrpsee::types::ErrorObjectOwned>(hex::encode(tip.0))
    })?;

    module.register_async_method("getblockcount", |_params, ctx| async move {
        let tip = ctx.db.best_tip()
            .map_err(|e| RpcError::Database(e.to_string()).into_error_object())?
            .ok_or_else(|| RpcError::Internal("No tip found".to_string()).into_error_object())?;
        Ok::<u64, jsonrpsee::types::ErrorObjectOwned>(tip.1)
    })?;

    module.register_async_method("getblockhash", |params, ctx| async move {
        let height: u64 = params.one()?;
        let header = ctx.db.get_header_by_height(height)
            .map_err(|e| RpcError::Database(e.to_string()).into_error_object())?
            .ok_or_else(|| RpcError::BlockNotFound(format!("height {}", height)).into_error_object())?;

        let block_id = nulla_core::block_header_id(&header);
        Ok::<String, jsonrpsee::types::ErrorObjectOwned>(hex::encode(block_id))
    })?;

    module.register_async_method("getblockchaininfo", |_params, ctx| async move {
        let tip = ctx.db.best_tip()
            .map_err(|e| RpcError::Database(e.to_string()).into_error_object())?
            .ok_or_else(|| RpcError::Internal("No tip found".to_string()).into_error_object())?;

        let header = ctx.db.get_header(&tip.0)
            .map_err(|e| RpcError::Database(e.to_string()).into_error_object())?
            .ok_or_else(|| RpcError::Internal("Tip header not found".to_string()).into_error_object())?;

        let difficulty = calculate_difficulty(&header.target);

        Ok::<BlockchainInfo, jsonrpsee::types::ErrorObjectOwned>(BlockchainInfo {
            chain: "nulla".to_string(),
            blocks: tip.1,
            headers: tip.1,
            bestblockhash: hex::encode(tip.0),
            difficulty,
            mediantime: header.timestamp,
        })
    })?;

    module.register_async_method("getbalance", |params, ctx| async move {
        let address: String = params.one()?;

        // Decode address
        let addr = nulla_wallet::Address::from_hex(&address)
            .ok_or_else(|| RpcError::InvalidAddress("Invalid address hex".to_string()).into_error_object())?;

        // Get UTXOs for this address
        let utxos = ctx.db.get_utxos_by_address(&addr.0)
            .map_err(|e| RpcError::Database(e.to_string()).into_error_object())?;

        let balance: u64 = utxos.iter().map(|(_, txout)| txout.value_atoms).sum();

        Ok::<u64, jsonrpsee::types::ErrorObjectOwned>(balance)
    })?;

    Ok(())
}
