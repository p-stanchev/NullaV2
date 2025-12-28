//! Wallet functionality for the Nulla blockchain.
//!
//! This crate provides:
//! - Key generation (Ed25519 keypairs)
//! - Address derivation from public keys
//! - Transaction signing
//! - UTXO management for wallet balances

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use nulla_core::{OutPoint, Tx, TxIn, TxOut};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Number of atoms per NULLA.
pub const ATOMS_PER_NULLA: u64 = 100_000_000;

/// Block reward in atoms (8 NULLA = 800,000,000 atoms).
pub const BLOCK_REWARD_ATOMS: u64 = 8 * ATOMS_PER_NULLA;

/// Convert atoms to NULLA with 8 decimal places.
pub fn atoms_to_nulla(atoms: u64) -> f64 {
    atoms as f64 / ATOMS_PER_NULLA as f64
}

/// Convert NULLA to atoms.
pub fn nulla_to_atoms(nulla: f64) -> u64 {
    (nulla * ATOMS_PER_NULLA as f64) as u64
}

/// Wallet errors.
#[derive(Debug, Error)]
pub enum WalletError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("insufficient balance")]
    InsufficientBalance,
    #[error(transparent)]
    Serialization(#[from] bincode::Error),
}

/// Result type for wallet operations.
pub type Result<T> = std::result::Result<T, WalletError>;

/// A wallet keypair for signing transactions.
#[derive(Clone)]
pub struct Keypair {
    /// Ed25519 signing key (private key).
    signing_key: SigningKey,
}

impl Keypair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        Self { signing_key }
    }

    /// Create a keypair from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self { signing_key }
    }

    /// Get the private key bytes (for serialization/storage).
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.signing_key.as_bytes()
    }

    /// Get the public key (verifying key).
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the address derived from the public key.
    ///
    /// Address format: BLAKE3(public_key)[0..20]
    /// This creates a 20-byte address similar to Bitcoin/Ethereum.
    pub fn address(&self) -> Address {
        Address::from_public_key(&self.public_key())
    }

    /// Sign a transaction.
    ///
    /// This creates a signature over the transaction data (excluding signatures).
    pub fn sign_transaction(&self, tx: &Tx) -> Result<Vec<u8>> {
        let tx_data = bincode::serialize(tx)?;
        let signature = self.signing_key.sign(&tx_data);
        Ok(signature.to_bytes().to_vec())
    }

    /// Get the raw signing key bytes (32 bytes).
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.signing_key.as_bytes()
    }
}

/// A 20-byte address derived from a public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub [u8; 20]);

impl Address {
    /// Derive an address from a public key using BLAKE3.
    pub fn from_public_key(public_key: &VerifyingKey) -> Self {
        let pubkey_bytes = public_key.to_bytes();
        let hash = blake3::hash(&pubkey_bytes);
        let hash_bytes: &[u8; 32] = hash.as_bytes();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash_bytes[0..20]);
        Address(addr)
    }

    /// Convert address to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse address from hex string.
    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex::decode(s).ok()?;
        if bytes.len() != 20 {
            return None;
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&bytes);
        Some(Address(addr))
    }

    /// Convert address to a script_pubkey for TxOut.
    ///
    /// Format: [OP_DUP, OP_HASH160, <20-byte address>, OP_EQUALVERIFY, OP_CHECKSIG]
    /// This is a simplified P2PKH-like script.
    pub fn to_script_pubkey(&self) -> Vec<u8> {
        let mut script = Vec::with_capacity(25);
        script.push(0x76); // OP_DUP
        script.push(0xa9); // OP_HASH160
        script.push(0x14); // Push 20 bytes
        script.extend_from_slice(&self.0);
        script.push(0x88); // OP_EQUALVERIFY
        script.push(0xac); // OP_CHECKSIG
        script
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Simple wallet for managing keys and creating transactions.
#[derive(Clone)]
pub struct Wallet {
    /// The wallet's keypair.
    keypair: Keypair,
}

impl Wallet {
    /// Create a new wallet with a random keypair.
    pub fn new() -> Self {
        Self {
            keypair: Keypair::generate(),
        }
    }

    /// Create a wallet from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            keypair: Keypair::from_seed(seed),
        }
    }

    /// Get the wallet's address.
    pub fn address(&self) -> Address {
        self.keypair.address()
    }

    /// Get the wallet's public key.
    pub fn public_key(&self) -> VerifyingKey {
        self.keypair.public_key()
    }

    /// Get the keypair for signing.
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    /// Create and sign a transaction.
    ///
    /// This is a helper that creates a transaction with the given inputs and outputs,
    /// then signs all inputs with this wallet's keypair.
    pub fn create_transaction(
        &self,
        inputs: Vec<TxIn>,
        outputs: Vec<TxOut>,
        lock_time: u64,
    ) -> Result<Tx> {
        let mut tx = Tx {
            version: 1,
            inputs,
            outputs,
            lock_time,
        };

        // Sign each input with the wallet's keypair and add the public key.
        let signature = self.keypair.sign_transaction(&tx)?;
        let pubkey_bytes = self.keypair.public_key().to_bytes().to_vec();

        for input in &mut tx.inputs {
            input.sig = signature.clone();
            input.pubkey = pubkey_bytes.clone();
        }

        Ok(tx)
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}

/// UTXO (Unspent Transaction Output) for wallet balance tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletUtxo {
    /// The outpoint (txid + vout) that can be spent.
    pub outpoint: OutPoint,
    /// The output containing value and script.
    pub output: TxOut,
}

/// Calculate total balance from a list of UTXOs.
pub fn calculate_balance(utxos: &[WalletUtxo]) -> u64 {
    utxos.iter().map(|u| u.output.value_atoms).sum()
}

/// Create a coinbase transaction (block reward) to a specific address.
///
/// The coinbase transaction has:
/// - One null input (txid all zeros, vout 0xFFFFFFFF)
/// - One output paying the block reward to the recipient address
/// - Block height encoded in the signature field for uniqueness
pub fn create_coinbase(recipient: &Address, block_height: u64, reward_atoms: u64) -> Tx {
    Tx {
        version: 1,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0xFFFF_FFFF,
            },
            // Encode block height in the signature field for uniqueness (like Bitcoin's coinbase script)
            sig: block_height.to_le_bytes().to_vec(),
            // Coinbase doesn't need a public key
            pubkey: vec![],
        }],
        outputs: vec![TxOut {
            value_atoms: reward_atoms,
            script_pubkey: recipient.to_script_pubkey(),
        }],
        lock_time: 0,
    }
}

/// Verify an Ed25519 signature on a transaction.
///
/// Returns Ok(()) if the signature is valid, Err otherwise.
pub fn verify_signature(tx: &Tx, signature_bytes: &[u8], public_key: &VerifyingKey) -> Result<()> {
    // Parse the signature (64 bytes for Ed25519)
    if signature_bytes.len() != 64 {
        return Err(WalletError::InvalidSignature);
    }

    let signature = Signature::from_bytes(
        signature_bytes
            .try_into()
            .map_err(|_| WalletError::InvalidSignature)?,
    );

    // Serialize transaction for verification (same as signing)
    let tx_data = bincode::serialize(tx)?;

    // Verify the signature
    public_key
        .verify(&tx_data, &signature)
        .map_err(|_| WalletError::InvalidSignature)
}

/// Extract public key from a script_pubkey (P2PKH-like format).
///
/// Returns None if the script is not in the expected format.
/// Format: [OP_DUP, OP_HASH160, <20-byte address>, OP_EQUALVERIFY, OP_CHECKSIG]
///
/// Note: This is a simplified version. A full implementation would actually
/// execute the script and verify the signature. For now, we just extract
/// the address and verify signatures separately.
pub fn extract_address_from_script(script_pubkey: &[u8]) -> Option<Address> {
    if script_pubkey.len() != 25 {
        return None;
    }

    if script_pubkey[0] != 0x76
        || script_pubkey[1] != 0xa9
        || script_pubkey[2] != 0x14
        || script_pubkey[23] != 0x88
        || script_pubkey[24] != 0xac
    {
        return None;
    }

    let mut addr = [0u8; 20];
    addr.copy_from_slice(&script_pubkey[3..23]);
    Some(Address(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = Keypair::generate();
        let address = keypair.address();
        assert_eq!(address.0.len(), 20);
    }

    #[test]
    fn test_address_from_public_key() {
        let keypair = Keypair::generate();
        let pubkey = keypair.public_key();
        let addr1 = Address::from_public_key(&pubkey);
        let addr2 = keypair.address();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_address_hex() {
        let keypair = Keypair::generate();
        let addr = keypair.address();
        let hex = addr.to_hex();
        assert_eq!(hex.len(), 40); // 20 bytes = 40 hex chars
        let parsed = Address::from_hex(&hex).unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_deterministic_from_seed() {
        let seed = [42u8; 32];
        let wallet1 = Wallet::from_seed(&seed);
        let wallet2 = Wallet::from_seed(&seed);
        assert_eq!(wallet1.address(), wallet2.address());
    }
}
