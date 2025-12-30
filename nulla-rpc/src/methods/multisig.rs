//! Multi-signature RPC methods for the Nulla blockchain.

use crate::error::RpcError;
use crate::RpcContext;
use nulla_wallet::{create_multisig, Psbt};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSigInfo {
    pub address: String,
    pub redeem_script: String,
    pub required: u8,
    pub total: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtInfo {
    pub psbt_hex: String,
    pub complete: bool,
    pub signatures: Vec<usize>, // Number of signatures per input
}

/// Register multi-signature RPC methods.
pub fn register_methods(module: &mut jsonrpsee::RpcModule<RpcContext>) -> anyhow::Result<()> {
    // createmultisig - Create a multi-signature address
    module.register_method("createmultisig", |params, ctx| {
        // SECURITY FIX (HIGH-AUD-001): Enforce rate limiting
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        let (required, pubkeys_hex): (u8, Vec<String>) = params.parse()?;

        // Parse public keys from hex
        let mut pubkeys = Vec::new();
        for pk_hex in pubkeys_hex {
            let pk_bytes = hex::decode(&pk_hex)
                .map_err(|e| RpcError::InvalidParameter(format!("Invalid pubkey hex: {}", e)).into_error_object())?;

            if pk_bytes.len() != 32 {
                return Err(RpcError::InvalidParameter("Public key must be 32 bytes".to_string()).into_error_object());
            }

            let pk_array: [u8; 32] = pk_bytes.try_into().unwrap();
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_array)
                .map_err(|e| RpcError::InvalidParameter(format!("Invalid Ed25519 pubkey: {}", e)).into_error_object())?;

            pubkeys.push(vk);
        }

        // Create multisig address
        let (address, config) = create_multisig(required, pubkeys)
            .map_err(|e| RpcError::InvalidTransaction(e.to_string()).into_error_object())?;

        Ok::<MultiSigInfo, jsonrpsee::types::ErrorObjectOwned>(MultiSigInfo {
            address: address.to_hex(),
            redeem_script: hex::encode(config.redeem_script()),
            required: config.required,
            total: config.total,
        })
    })?;

    // createpsbt - Create a Partially Signed Bitcoin Transaction
    module.register_method("createpsbt", |params, ctx| {
        // SECURITY FIX (HIGH-AUD-001): Enforce rate limiting
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        let tx_hex: String = params.one()?;

        // Decode transaction
        let tx_bytes = hex::decode(&tx_hex)
            .map_err(|e| RpcError::InvalidParameter(format!("Invalid transaction hex: {}", e)).into_error_object())?;

        let tx: nulla_core::Tx = bincode::deserialize(&tx_bytes)
            .map_err(|e| RpcError::InvalidParameter(format!("Invalid transaction: {}", e)).into_error_object())?;

        // Create PSBT with chain_id from context (SECURITY FIX: CRIT-NEW-001)
        let psbt = Psbt::new(tx, ctx.chain_id);
        let psbt_hex = psbt.to_hex()
            .map_err(|e| RpcError::InvalidTransaction(e.to_string()).into_error_object())?;

        Ok::<String, jsonrpsee::types::ErrorObjectOwned>(psbt_hex)
    })?;

    // signpsbt - Sign a PSBT with wallet keys
    module.register_async_method("signpsbt", |params, ctx| async move {
        // SECURITY FIX (HIGH-AUD-001): Enforce rate limiting
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        let psbt_hex: String = params.one()?;

        // Get wallet
        let wallet_lock = ctx.wallet.as_ref()
            .ok_or_else(|| RpcError::WalletNotLoaded.into_error_object())?;

        let wallet = wallet_lock.read().await;

        // Decode PSBT
        let mut psbt = Psbt::from_hex(&psbt_hex)
            .map_err(|e| RpcError::InvalidParameter(format!("Invalid PSBT hex: {}", e)).into_error_object())?;

        // Get signing key from wallet
        let signing_key_bytes = wallet.keypair().to_bytes();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_key_bytes);

        // Sign all inputs with wallet key
        let num_inputs = psbt.unsigned_tx.inputs.len();
        for i in 0..num_inputs {
            psbt.sign_input(i, &signing_key)
                .map_err(|e| RpcError::InvalidTransaction(e.to_string()).into_error_object())?;
        }

        // Return updated PSBT
        let result_hex = psbt.to_hex()
            .map_err(|e| RpcError::InvalidTransaction(e.to_string()).into_error_object())?;

        Ok::<String, jsonrpsee::types::ErrorObjectOwned>(result_hex)
    })?;

    // combinepsbt - Combine multiple PSBTs
    module.register_method("combinepsbt", |params, ctx| {
        // SECURITY FIX (HIGH-AUD-001): Enforce rate limiting
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        let psbt_hexes: Vec<String> = params.parse()?;

        if psbt_hexes.is_empty() {
            return Err(RpcError::InvalidParameter("Need at least one PSBT".to_string()).into_error_object());
        }

        // Decode first PSBT
        let mut combined = Psbt::from_hex(&psbt_hexes[0])
            .map_err(|e| RpcError::InvalidParameter(format!("Invalid PSBT hex: {}", e)).into_error_object())?;

        // Merge signatures from other PSBTs
        for psbt_hex in &psbt_hexes[1..] {
            let psbt = Psbt::from_hex(psbt_hex)
                .map_err(|e| RpcError::InvalidParameter(format!("Invalid PSBT hex: {}", e)).into_error_object())?;

            // Merge signatures for each input
            for (i, input) in psbt.inputs.iter().enumerate() {
                if i >= combined.inputs.len() {
                    break;
                }

                // Copy over any signatures we don't have
                for (pubkey, sig) in &input.partial_sigs {
                    combined.inputs[i].partial_sigs.insert(pubkey.clone(), sig.clone());
                }

                // Copy redeem script if we don't have one
                if combined.inputs[i].redeem_script.is_none() && input.redeem_script.is_some() {
                    combined.inputs[i].redeem_script = input.redeem_script.clone();
                }

                // Copy required_sigs if we don't have one
                if combined.inputs[i].required_sigs.is_none() && input.required_sigs.is_some() {
                    combined.inputs[i].required_sigs = input.required_sigs;
                }
            }
        }

        let result_hex = combined.to_hex()
            .map_err(|e| RpcError::InvalidTransaction(e.to_string()).into_error_object())?;

        Ok::<String, jsonrpsee::types::ErrorObjectOwned>(result_hex)
    })?;

    // finalizepsbt - Finalize a PSBT into a complete transaction
    module.register_method("finalizepsbt", |params, ctx| {
        // SECURITY FIX (HIGH-AUD-001): Enforce rate limiting
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        let psbt_hex: String = params.one()?;

        // Decode PSBT
        let psbt = Psbt::from_hex(&psbt_hex)
            .map_err(|e| RpcError::InvalidParameter(format!("Invalid PSBT hex: {}", e)).into_error_object())?;

        // Check if complete
        if !psbt.is_complete() {
            return Err(RpcError::InvalidTransaction("PSBT is not complete - need more signatures".to_string()).into_error_object());
        }

        // Finalize
        let final_tx = psbt.finalize()
            .map_err(|e| RpcError::InvalidTransaction(e.to_string()).into_error_object())?;

        // Serialize and return
        let tx_bytes = bincode::serialize(&final_tx)
            .map_err(|e| RpcError::InvalidParameter(format!("Serialization failed: {}", e)).into_error_object())?;

        Ok::<String, jsonrpsee::types::ErrorObjectOwned>(hex::encode(tx_bytes))
    })?;

    // decodepsbt - Decode a PSBT to JSON
    module.register_method("decodepsbt", |params, ctx| {
        // SECURITY FIX (HIGH-AUD-001): Enforce rate limiting
        ctx.check_rate_limit().map_err(|e| RpcError::TooManyRequests(e.to_string()).into_error_object())?;

        let psbt_hex: String = params.one()?;

        // Decode PSBT
        let psbt = Psbt::from_hex(&psbt_hex)
            .map_err(|e| RpcError::InvalidParameter(format!("Invalid PSBT hex: {}", e)).into_error_object())?;

        // Get signature counts
        let signatures: Vec<usize> = (0..psbt.inputs.len())
            .map(|i| psbt.signature_count(i))
            .collect();

        Ok::<PsbtInfo, jsonrpsee::types::ErrorObjectOwned>(PsbtInfo {
            psbt_hex: psbt_hex.clone(),
            complete: psbt.is_complete(),
            signatures,
        })
    })?;

    Ok(())
}
