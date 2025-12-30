use jsonrpsee::RpcModule;

use crate::error::RpcError;
use crate::types::*;
use crate::RpcContext;

/// Register network/admin RPC methods
pub fn register_methods(module: &mut RpcModule<RpcContext>) -> anyhow::Result<()> {
    module.register_async_method("uptime", |_params, ctx| async move {
        // SECURITY FIX (HIGH-AUD-001): Enforce rate limiting
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        let elapsed = ctx.start_time.elapsed();
        Ok::<u64, jsonrpsee::types::ErrorObjectOwned>(elapsed.as_secs())
    })?;

    module.register_async_method("getpeerinfo", |_params, ctx| async move {
        // SECURITY FIX (HIGH-AUD-001): Enforce rate limiting
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        // This would require querying the network layer for peer information
        tracing::warn!("getpeerinfo not fully implemented - requires network layer integration");
        Ok::<Vec<PeerInfo>, jsonrpsee::types::ErrorObjectOwned>(vec![])
    })?;

    Ok(())
}
