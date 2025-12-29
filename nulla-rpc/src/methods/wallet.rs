use jsonrpsee::RpcModule;

use crate::error::RpcError;
use crate::types::*;
use crate::RpcContext;

/// Register wallet RPC methods
pub fn register_methods(module: &mut RpcModule<RpcContext>) -> anyhow::Result<()> {
    module.register_async_method("getwalletinfo", |_params, ctx| async move {
        let wallet_lock = ctx.wallet.as_ref()
            .ok_or_else(|| RpcError::WalletNotLoaded.into_error_object())?;

        let wallet = wallet_lock.read().await;

        // Get wallet address
        let wallet_address = wallet.address();

        // Get balance
        let utxos = ctx.db.get_utxos_by_address(wallet_address.hash())
            .map_err(|e| RpcError::Database(e.to_string()).into_error_object())?;

        let balance: u64 = utxos.iter().map(|(_, txout)| txout.value_atoms).sum();

        // Count transactions (simplified)
        let txcount = utxos.len();

        Ok::<WalletInfo, jsonrpsee::types::ErrorObjectOwned>(WalletInfo {
            walletname: "nulla_wallet".to_string(),
            walletversion: 1,
            balance,
            txcount,
            keypoolsize: 1000, // HD wallet can derive many keys
        })
    })?;

    module.register_async_method("getnewaddress", |_params, ctx| async move {
        let wallet_lock = ctx.wallet.as_ref()
            .ok_or_else(|| RpcError::WalletNotLoaded.into_error_object())?;

        let wallet = wallet_lock.read().await;
        let address = wallet.address();

        Ok::<String, jsonrpsee::types::ErrorObjectOwned>(address.to_hex())
    })?;

    Ok(())
}
