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
        // SECURITY FIX (HIGH-AUD-001): Enforce rate limiting
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        let tip = ctx.db.best_tip()
            .map_err(|e| RpcError::Database(e.to_string()).into_error_object())?
            .ok_or_else(|| RpcError::Internal("No tip found".to_string()).into_error_object())?;
        Ok::<String, jsonrpsee::types::ErrorObjectOwned>(hex::encode(tip.0))
    })?;

    module.register_async_method("getblockcount", |_params, ctx| async move {
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;
        let tip = ctx.db.best_tip()
            .map_err(|e| RpcError::Database(e.to_string()).into_error_object())?
            .ok_or_else(|| RpcError::Internal("No tip found".to_string()).into_error_object())?;
        Ok::<u64, jsonrpsee::types::ErrorObjectOwned>(tip.1)
    })?;

    module.register_async_method("getblockhash", |params, ctx| async move {
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;
        let height: u64 = params.one()?;
        let header = ctx.db.get_header_by_height(height)
            .map_err(|e| RpcError::Database(e.to_string()).into_error_object())?
            .ok_or_else(|| RpcError::BlockNotFound(format!("height {}", height)).into_error_object())?;

        let block_id = nulla_core::block_header_id(&header);
        Ok::<String, jsonrpsee::types::ErrorObjectOwned>(hex::encode(block_id))
    })?;

    module.register_async_method("getblockchaininfo", |_params, ctx| async move {
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;
        let tip = ctx.db.best_tip()
            .map_err(|e| RpcError::Database(e.to_string()).into_error_object())?
            .ok_or_else(|| RpcError::Internal("No tip found".to_string()).into_error_object())?;

        let header = ctx.db.get_header(&tip.0)
            .map_err(|e| RpcError::Database(e.to_string()).into_error_object())?
            .ok_or_else(|| RpcError::Internal("Tip header not found".to_string()).into_error_object())?;

        let difficulty = calculate_difficulty(&header.target);

        // Calculate current supply based on height
        let current_height = tip.1;
        let total_supply_atoms = nulla_core::emission::total_supply(current_height);
        let current_reward_atoms = nulla_core::calculate_block_reward(current_height);

        Ok::<BlockchainInfo, jsonrpsee::types::ErrorObjectOwned>(BlockchainInfo {
            chain: "nulla".to_string(),
            blocks: tip.1,
            headers: tip.1,
            bestblockhash: hex::encode(tip.0),
            difficulty,
            mediantime: header.timestamp,
            total_supply: total_supply_atoms as f64 / nulla_core::emission::ATOMS_PER_NULLA as f64,
            current_reward: current_reward_atoms as f64 / nulla_core::emission::ATOMS_PER_NULLA as f64,
        })
    })?;

    module.register_async_method("getemissioninfo", |params, ctx| async move {
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        // Optional height parameter (defaults to current height)
        let query_height: u64 = match params.one::<u64>() {
            Ok(h) => h,
            Err(_) => {
                // No parameter provided, use current height
                ctx.db.best_tip()
                    .map_err(|e| RpcError::Database(e.to_string()).into_error_object())?
                    .ok_or_else(|| RpcError::Internal("No tip found".to_string()).into_error_object())?
                    .1
            }
        };

        let reward_atoms = nulla_core::calculate_block_reward(query_height);
        let supply_atoms = nulla_core::emission::total_supply(query_height);
        let halvings = query_height / nulla_core::emission::HALVING_INTERVAL;
        let blocks_until_next_halving = nulla_core::emission::HALVING_INTERVAL - (query_height % nulla_core::emission::HALVING_INTERVAL);
        let is_tail_emission = halvings >= nulla_core::emission::MAX_HALVINGS as u64;

        Ok::<EmissionInfo, jsonrpsee::types::ErrorObjectOwned>(EmissionInfo {
            height: query_height,
            reward: reward_atoms as f64 / nulla_core::emission::ATOMS_PER_NULLA as f64,
            supply: supply_atoms as f64 / nulla_core::emission::ATOMS_PER_NULLA as f64,
            halvings: halvings as u32,
            blocks_until_next_halving: if is_tail_emission { 0 } else { blocks_until_next_halving },
            tail_emission: is_tail_emission,
            tail_emission_rate: nulla_core::emission::TAIL_EMISSION_ATOMS as f64 / nulla_core::emission::ATOMS_PER_NULLA as f64,
        })
    })?;

    module.register_async_method("getbalance", |params, ctx| async move {
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;
        let address: String = params.one()?;

        // Decode address
        let addr = nulla_wallet::Address::from_hex(&address)
            .ok_or_else(|| RpcError::InvalidAddress("Invalid address hex".to_string()).into_error_object())?;

        // Get UTXOs for this address
        let utxos = ctx.db.get_utxos_by_address(addr.hash())
            .map_err(|e| RpcError::Database(e.to_string()).into_error_object())?;

        let balance: u64 = utxos.iter().map(|(_, txout)| txout.value_atoms).sum();

        Ok::<u64, jsonrpsee::types::ErrorObjectOwned>(balance)
    })?;

    module.register_async_method("getpruninginfo", |_params, ctx| async move {
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        let config = ctx.db.pruning_config();
        let (_tip, current_height, _work) = ctx.db.best_tip()
            .map_err(|e| RpcError::Database(e.to_string()).into_error_object())?
            .unwrap_or(([0u8; 32], 0, 0));

        let prune_height = if config.enabled && current_height > config.keep_blocks {
            current_height - config.keep_blocks
        } else {
            0
        };

        Ok::<PruningInfo, jsonrpsee::types::ErrorObjectOwned>(PruningInfo {
            enabled: config.enabled,
            keep_blocks: config.keep_blocks,
            prune_height,
            current_height,
        })
    })?;

    Ok(())
}
