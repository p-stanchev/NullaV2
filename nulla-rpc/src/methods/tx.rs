use jsonrpsee::RpcModule;

use crate::error::RpcError;
use crate::RpcContext;
use nulla_core::Tx;
use nulla_net::NetworkCommand;

/// Register transaction RPC methods
pub fn register_methods(module: &mut RpcModule<RpcContext>) -> anyhow::Result<()> {
    module.register_async_method("sendrawtransaction", |params, ctx| async move {
        let hex: String = params.one()?;

        // Decode hex to transaction
        let tx_bytes = hex::decode(&hex)
            .map_err(|e| RpcError::InvalidParameter(format!("Invalid hex: {}", e)).into_error_object())?;

        let tx: Tx = bincode::deserialize(&tx_bytes)
            .map_err(|e| RpcError::Deserialization(e.to_string()).into_error_object())?;

        // Validate transaction structure
        if let Err(e) = nulla_core::validate_tx_structure(&tx) {
            return Err(RpcError::InvalidTransaction(e.to_string()).into_error_object());
        }

        // Verify signatures
        if let Err(e) = ctx.db.verify_tx_signatures(&tx) {
            return Err(RpcError::InvalidTransaction(format!("Signature verification failed: {}", e)).into_error_object());
        }

        // Validate inputs exist and are unspent
        if let Err(e) = ctx.db.validate_tx_inputs(&tx) {
            return Err(RpcError::InvalidTransaction(format!("Input validation failed: {}", e)).into_error_object());
        }

        // Calculate and validate transaction fee
        let fee = ctx.db.calculate_tx_fee(&tx)
            .map_err(|e| RpcError::InvalidTransaction(format!("Fee calculation failed: {}", e)).into_error_object())?;

        // Check minimum fee requirement (spam prevention)
        if fee < nulla_wallet::MIN_TX_FEE_ATOMS {
            return Err(RpcError::InvalidTransaction(format!(
                "Transaction fee ({} atoms) below minimum ({} atoms). Fee required: {} NULLA",
                fee,
                nulla_wallet::MIN_TX_FEE_ATOMS,
                nulla_wallet::atoms_to_nulla(nulla_wallet::MIN_TX_FEE_ATOMS)
            )).into_error_object());
        }

        // Add to mempool
        ctx.db.put_mempool_tx(&tx)
            .map_err(|e| RpcError::Mempool(e.to_string()).into_error_object())?;

        // Broadcast to network
        let _ = ctx.network_tx.send(NetworkCommand::PublishFullTx { tx: tx.clone() }).await;

        let txid = nulla_core::tx_id(&tx);
        Ok::<String, jsonrpsee::types::ErrorObjectOwned>(hex::encode(txid))
    })?;

    Ok(())
}
