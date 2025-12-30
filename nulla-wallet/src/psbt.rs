//! Partially Signed Bitcoin Transaction (PSBT) format for Nulla.
//!
//! This module implements a simplified PSBT-like format that allows:
//! - Multiple parties to sign a transaction incrementally
//! - Offline signing workflows
//! - Safe transaction construction and signing coordination

use crate::WalletError;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use nulla_core::{Tx, TxOut};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Partially Signed Transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Psbt {
    /// The unsigned transaction (signatures are empty)
    pub unsigned_tx: Tx,

    /// Input metadata for each input
    pub inputs: Vec<PsbtInput>,

    /// Output metadata for each output
    pub outputs: Vec<PsbtOutput>,

    /// Chain ID for replay protection (SECURITY FIX: CRIT-NEW-001)
    /// This ensures signatures can't be replayed across different chains
    pub chain_id: [u8; 4],
}

/// Metadata for a transaction input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtInput {
    /// The previous output being spent
    pub previous_output: Option<TxOut>,

    /// For P2SH inputs, the redeem script
    pub redeem_script: Option<Vec<u8>>,

    /// Partial signatures: pubkey -> signature
    pub partial_sigs: HashMap<Vec<u8>, Vec<u8>>,

    /// Required number of signatures (for multisig)
    pub required_sigs: Option<u8>,
}

/// Metadata for a transaction output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtOutput {
    /// The redeem script for this output (if P2SH)
    pub redeem_script: Option<Vec<u8>>,
}

impl Psbt {
    /// Create a new PSBT from an unsigned transaction with chain ID
    ///
    /// # Security
    /// The chain_id is included in all signature hashes to prevent replay attacks
    /// across different chains (mainnet, testnet, etc.)
    pub fn new(unsigned_tx: Tx, chain_id: [u8; 4]) -> Self {
        let input_count = unsigned_tx.inputs.len();
        let output_count = unsigned_tx.outputs.len();

        Self {
            unsigned_tx,
            inputs: vec![PsbtInput::default(); input_count],
            outputs: vec![PsbtOutput::default(); output_count],
            chain_id,
        }
    }

    /// Add a signature to a specific input
    pub fn add_signature(
        &mut self,
        input_index: usize,
        pubkey: &VerifyingKey,
        signature: Signature,
    ) -> Result<(), WalletError> {
        if input_index >= self.inputs.len() {
            return Err(WalletError::InvalidInput("Input index out of bounds".into()));
        }

        let pubkey_bytes = pubkey.to_bytes().to_vec();
        let sig_bytes = signature.to_bytes().to_vec();

        self.inputs[input_index]
            .partial_sigs
            .insert(pubkey_bytes, sig_bytes);

        Ok(())
    }

    /// Sign an input with a private key
    ///
    /// # Security (CRIT-NEW-001 FIX)
    /// The signature hash now includes the chain_id to prevent replay attacks.
    /// This ensures that signatures created for one chain (e.g., mainnet) cannot
    /// be replayed on another chain (e.g., testnet).
    pub fn sign_input(
        &mut self,
        input_index: usize,
        signing_key: &SigningKey,
    ) -> Result<(), WalletError> {
        if input_index >= self.inputs.len() {
            return Err(WalletError::InvalidInput("Input index out of bounds".into()));
        }

        // SECURITY: Compute sighash WITH chain_id for replay protection
        let sighash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&self.chain_id);  // Include chain_id first
            let tx_data = bincode::serialize(&self.unsigned_tx)
                .map_err(|e| WalletError::InvalidInput(format!("Serialization failed: {}", e)))?;
            hasher.update(&tx_data);
            hasher.finalize().as_bytes().to_vec()
        };

        // Sign the sighash
        let signature = signing_key.sign(&sighash);
        let verifying_key = signing_key.verifying_key();

        self.add_signature(input_index, &verifying_key, signature)?;

        Ok(())
    }

    /// Set the redeem script for an input (for P2SH multisig)
    ///
    /// This validates that the redeem script is a valid multisig script before storing it.
    pub fn set_input_redeem_script(
        &mut self,
        input_index: usize,
        redeem_script: Vec<u8>,
    ) -> Result<(), WalletError> {
        if input_index >= self.inputs.len() {
            return Err(WalletError::InvalidInput("Input index out of bounds".into()));
        }

        // SECURITY: Validate redeem script before storing to prevent malformed scripts
        // from causing crashes during finalization
        let script = nulla_core::Script::new(redeem_script.clone());

        // Verify it's a valid script type (P2PKH, P2SH, or Multisig)
        match script.script_type() {
            Some(nulla_core::ScriptType::P2PKH) |
            Some(nulla_core::ScriptType::P2SH) => {
                // Valid script type
            }
            None => {
                // For multisig, try to parse it
                if script.parse_multisig().is_err() {
                    return Err(WalletError::InvalidInput(
                        "Redeem script is not a valid P2PKH, P2SH, or multisig script".into()
                    ));
                }
            }
        }

        // Additional validation: ensure script is not too large (prevent DoS)
        if redeem_script.len() > 10_000 {
            return Err(WalletError::InvalidInput(
                "Redeem script too large (max 10KB)".into()
            ));
        }

        self.inputs[input_index].redeem_script = Some(redeem_script);

        Ok(())
    }

    /// Set the previous output for an input (needed for validation)
    pub fn set_input_previous_output(
        &mut self,
        input_index: usize,
        previous_output: TxOut,
    ) -> Result<(), WalletError> {
        if input_index >= self.inputs.len() {
            return Err(WalletError::InvalidInput("Input index out of bounds".into()));
        }

        self.inputs[input_index].previous_output = Some(previous_output);

        Ok(())
    }

    /// Set the required signatures for a multisig input
    pub fn set_input_required_sigs(
        &mut self,
        input_index: usize,
        required: u8,
    ) -> Result<(), WalletError> {
        if input_index >= self.inputs.len() {
            return Err(WalletError::InvalidInput("Input index out of bounds".into()));
        }

        self.inputs[input_index].required_sigs = Some(required);

        Ok(())
    }

    /// Check if an input has enough signatures to be finalized
    pub fn input_is_complete(&self, input_index: usize) -> bool {
        if input_index >= self.inputs.len() {
            return false;
        }

        let input = &self.inputs[input_index];

        // If required_sigs is set (multisig), check if we have enough
        if let Some(required) = input.required_sigs {
            return input.partial_sigs.len() >= required as usize;
        }

        // For single-sig, just need one signature
        !input.partial_sigs.is_empty()
    }

    /// Check if all inputs have enough signatures
    pub fn is_complete(&self) -> bool {
        (0..self.inputs.len()).all(|i| self.input_is_complete(i))
    }

    /// Finalize the PSBT into a complete signed transaction
    ///
    /// This combines all the partial signatures into the actual transaction.
    /// For P2PKH: Uses the single signature and pubkey
    /// For P2SH: Uses all signatures + redeem script
    ///
    /// # Security (CRIT-NEW-001 FIX)
    /// All signatures are verified with the chain_id before finalization to ensure
    /// they were created for the correct chain. This prevents tampering with the
    /// chain_id after signatures are collected.
    pub fn finalize(&self) -> Result<Tx, WalletError> {
        if !self.is_complete() {
            return Err(WalletError::InvalidInput("PSBT is not complete - need more signatures".into()));
        }

        // SECURITY: Compute sighash with chain_id for signature verification
        let sighash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&self.chain_id);
            let tx_data = bincode::serialize(&self.unsigned_tx)
                .map_err(|e| WalletError::InvalidInput(format!("Serialization failed: {}", e)))?;
            hasher.update(&tx_data);
            hasher.finalize().as_bytes().to_vec()
        };

        // SECURITY: Verify all signatures before finalizing
        for (i, input_meta) in self.inputs.iter().enumerate() {
            if input_meta.partial_sigs.is_empty() {
                return Err(WalletError::InvalidInput(format!("Input {} has no signatures", i)));
            }

            // Verify each signature with the chain_id-included sighash
            for (pubkey_bytes, sig_bytes) in &input_meta.partial_sigs {
                let signature = Signature::from_bytes(&sig_bytes.as_slice().try_into()
                    .map_err(|_| WalletError::InvalidInput("Invalid signature length".into()))?);

                let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes.as_slice().try_into()
                    .map_err(|_| WalletError::InvalidInput("Invalid public key length".into()))?)
                    .map_err(|_| WalletError::InvalidInput("Invalid public key".into()))?;

                // SECURITY FIX (CRIT-002): verify_strict() prevents signature malleability
                verifying_key.verify_strict(&sighash, &signature)
                    .map_err(|_| WalletError::InvalidInput(
                        format!("Signature verification failed for input {} - this may indicate \
                                a chain_id mismatch or tampered signatures", i)
                    ))?;
            }
        }

        let mut tx = self.unsigned_tx.clone();

        for (i, input_meta) in self.inputs.iter().enumerate() {
            if input_meta.partial_sigs.is_empty() {
                return Err(WalletError::InvalidInput(format!("Input {} has no signatures", i)));
            }

            // Check if this is a P2SH input (has redeem script)
            if let Some(redeem_script) = &input_meta.redeem_script {
                // P2SH multisig: Store signatures in a specific format
                // For now, we'll concatenate: [num_sigs][sig1][sig2]...[redeem_script_len][redeem_script]

                let sigs: Vec<&Vec<u8>> = input_meta.partial_sigs.values().collect();

                // Build the scriptSig for P2SH
                // Format: <sig1> <sig2> ... <redeem_script>
                // We store this as: num_sigs + all_sigs + redeem_script
                let mut script_sig = Vec::new();

                // Number of signatures (1 byte)
                script_sig.push(sigs.len() as u8);

                // All signatures (64 bytes each)
                for sig in &sigs {
                    script_sig.extend_from_slice(sig);
                }

                // Redeem script length (2 bytes)
                let script_len = redeem_script.len() as u16;
                script_sig.extend_from_slice(&script_len.to_le_bytes());

                // Redeem script
                script_sig.extend_from_slice(redeem_script);

                // For P2SH, we store the script_sig data in the sig field
                // and leave pubkey empty (it's in the redeem script)
                tx.inputs[i].sig = script_sig;
                tx.inputs[i].pubkey = Vec::new();

            } else {
                // P2PKH single-sig: Use first (and only) signature
                let (pubkey, sig) = input_meta.partial_sigs.iter().next().unwrap();

                tx.inputs[i].sig = sig.clone();
                tx.inputs[i].pubkey = pubkey.clone();
            }
        }

        Ok(tx)
    }

    /// Extract signatures from the PSBT for a specific input
    pub fn get_signatures(&self, input_index: usize) -> Option<&HashMap<Vec<u8>, Vec<u8>>> {
        self.inputs.get(input_index).map(|input| &input.partial_sigs)
    }

    /// Get the number of signatures for a specific input
    pub fn signature_count(&self, input_index: usize) -> usize {
        self.inputs
            .get(input_index)
            .map(|input| input.partial_sigs.len())
            .unwrap_or(0)
    }

    /// Serialize the PSBT to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, WalletError> {
        bincode::serialize(self).map_err(|e| e.into())
    }

    /// Deserialize a PSBT from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WalletError> {
        bincode::deserialize(bytes).map_err(|e| e.into())
    }

    /// Serialize to hex string
    pub fn to_hex(&self) -> Result<String, WalletError> {
        let bytes = self.to_bytes()?;
        Ok(hex::encode(bytes))
    }

    /// Deserialize from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, WalletError> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| WalletError::InvalidInput(format!("Invalid hex: {}", e)))?;
        Self::from_bytes(&bytes)
    }
}

impl Default for PsbtInput {
    fn default() -> Self {
        Self {
            previous_output: None,
            redeem_script: None,
            partial_sigs: HashMap::new(),
            required_sigs: None,
        }
    }
}

impl Default for PsbtOutput {
    fn default() -> Self {
        Self {
            redeem_script: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use nulla_core::{OutPoint, TxIn, Script};

    const TEST_CHAIN_ID: [u8; 4] = *b"TEST";  // Testnet chain ID

    #[test]
    fn test_psbt_creation() {
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                prevout: OutPoint {
                    txid: [0u8; 32],
                    vout: 0,
                },
                sig: Vec::new(),
                pubkey: Vec::new(),
            }],
            outputs: vec![TxOut {
                value_atoms: 1000,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        };

        let psbt = Psbt::new(tx.clone(), TEST_CHAIN_ID);

        assert_eq!(psbt.unsigned_tx.version, tx.version);
        assert_eq!(psbt.inputs.len(), 1);
        assert_eq!(psbt.outputs.len(), 1);
        assert_eq!(psbt.chain_id, TEST_CHAIN_ID);
        assert!(!psbt.is_complete());
    }

    #[test]
    fn test_psbt_single_sig() {
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                prevout: OutPoint {
                    txid: [1u8; 32],
                    vout: 0,
                },
                sig: Vec::new(),
                pubkey: Vec::new(),
            }],
            outputs: vec![TxOut {
                value_atoms: 1000,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        };

        let mut psbt = Psbt::new(tx, TEST_CHAIN_ID);

        // Sign with a key
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        psbt.sign_input(0, &signing_key).unwrap();

        assert!(psbt.input_is_complete(0));
        assert!(psbt.is_complete());
        assert_eq!(psbt.signature_count(0), 1);

        // Finalize
        let final_tx = psbt.finalize().unwrap();
        assert!(!final_tx.inputs[0].sig.is_empty());
        assert!(!final_tx.inputs[0].pubkey.is_empty());
    }

    #[test]
    fn test_psbt_multisig_2_of_3() {
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                prevout: OutPoint {
                    txid: [2u8; 32],
                    vout: 0,
                },
                sig: Vec::new(),
                pubkey: Vec::new(),
            }],
            outputs: vec![TxOut {
                value_atoms: 5000,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        };

        let mut psbt = Psbt::new(tx, TEST_CHAIN_ID);

        // Create redeem script for 2-of-3
        let pk1 = [0x01; 32];
        let pk2 = [0x02; 32];
        let pk3 = [0x03; 32];
        let redeem_script = Script::multisig(2, &[pk1, pk2, pk3]).unwrap();

        psbt.set_input_redeem_script(0, redeem_script.bytes).unwrap();
        psbt.set_input_required_sigs(0, 2).unwrap();

        // Sign with first two keys
        let sk1 = SigningKey::from_bytes(&[0x11; 32]);
        let sk2 = SigningKey::from_bytes(&[0x22; 32]);

        psbt.sign_input(0, &sk1).unwrap();
        assert!(!psbt.is_complete());
        assert_eq!(psbt.signature_count(0), 1);

        psbt.sign_input(0, &sk2).unwrap();
        assert!(psbt.is_complete());
        assert_eq!(psbt.signature_count(0), 2);

        // Finalize
        let final_tx = psbt.finalize().unwrap();
        assert!(!final_tx.inputs[0].sig.is_empty());
        assert!(final_tx.inputs[0].pubkey.is_empty()); // P2SH doesn't use pubkey field
    }

    #[test]
    fn test_psbt_serialization() {
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                prevout: OutPoint {
                    txid: [3u8; 32],
                    vout: 1,
                },
                sig: Vec::new(),
                pubkey: Vec::new(),
            }],
            outputs: vec![TxOut {
                value_atoms: 2000,
                script_pubkey: vec![0x76, 0xa9],
            }],
            lock_time: 0,
        };

        let mut psbt = Psbt::new(tx, TEST_CHAIN_ID);
        let sk = SigningKey::from_bytes(&[0x99; 32]);
        psbt.sign_input(0, &sk).unwrap();

        // Serialize and deserialize
        let hex = psbt.to_hex().unwrap();
        let psbt2 = Psbt::from_hex(&hex).unwrap();

        assert_eq!(psbt.signature_count(0), psbt2.signature_count(0));
        assert_eq!(psbt.is_complete(), psbt2.is_complete());
        assert_eq!(psbt.chain_id, psbt2.chain_id);
    }

    /// SECURITY TEST (CRIT-NEW-001): Test replay protection across chains
    #[test]
    fn test_psbt_replay_protection() {
        let chain_id_main = *b"MAIN";
        let chain_id_test = *b"TEST";

        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                prevout: OutPoint {
                    txid: [4u8; 32],
                    vout: 0,
                },
                sig: Vec::new(),
                pubkey: Vec::new(),
            }],
            outputs: vec![TxOut {
                value_atoms: 1000,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        };

        // Create PSBT with mainnet chain_id
        let signing_key = SigningKey::from_bytes(&[0x55; 32]);
        let mut psbt_main = Psbt::new(tx.clone(), chain_id_main);
        psbt_main.sign_input(0, &signing_key).unwrap();

        // Finalize with correct chain_id should succeed
        assert!(psbt_main.finalize().is_ok());

        // Try to tamper with chain_id after signing
        let mut psbt_tampered = psbt_main.clone();
        psbt_tampered.chain_id = chain_id_test;

        // Finalization should fail because signatures were created with different chain_id
        let result = psbt_tampered.finalize();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("chain_id mismatch"));
    }
}
