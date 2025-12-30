//! Wallet functionality for the Nulla blockchain.
//!
//! This crate provides:
//! - Key generation (Ed25519 keypairs)
//! - HD (Hierarchical Deterministic) wallet support
//! - Address derivation from public keys (P2PKH and P2SH)
//! - Multi-signature wallet support
//! - Transaction signing
//! - UTXO management for wallet balances

pub mod address;
pub mod multisig;
pub mod psbt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use nulla_core::{OutPoint, Tx, TxIn, TxOut};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Re-export address types
pub use address::{Address, AddressVersion};
// Re-export multisig types
pub use multisig::{MultiSigConfig, create_2_of_2, create_2_of_3, create_multisig};
// Re-export PSBT types
pub use psbt::{Psbt, PsbtInput, PsbtOutput};

/// Number of atoms per NULLA.
pub const ATOMS_PER_NULLA: u64 = 100_000_000;

/// Block reward in atoms (8 NULLA = 800,000,000 atoms).
pub const BLOCK_REWARD_ATOMS: u64 = 8 * ATOMS_PER_NULLA;

/// Minimum transaction fee in atoms to prevent spam (0.0001 NULLA = 10,000 atoms).
/// This is 1/80,000th of the block reward, making it cheap but not free.
pub const MIN_TX_FEE_ATOMS: u64 = 10_000;

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
    #[error("invalid derivation path")]
    InvalidDerivationPath,
    #[error("invalid password")]
    InvalidPassword,
    #[error("wallet file not found")]
    WalletNotFound,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error(transparent)]
    Serialization(#[from] bincode::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Result type for wallet operations.
pub type Result<T> = std::result::Result<T, WalletError>;

/// Derive a child key from a master seed using a derivation index.
///
/// Uses BLAKE3-based key derivation similar to BIP32 but simplified for Ed25519.
/// Derivation path format: m/purpose'/coin_type'/account'/change/index
///
/// For Nulla:
/// - purpose = 44 (BIP44)
/// - coin_type = 0 (use 0 for now, can be registered later)
/// - account = 0 (first account)
/// - change = 0 (receiving addresses) or 1 (change addresses)
/// - index = address index (0, 1, 2, ...)
///
/// Example: m/44'/0'/0'/0/0 = first receiving address
fn derive_key(master_seed: &[u8; 32], path: &[u32]) -> [u8; 32] {
    let mut key = *master_seed;

    for &index in path {
        // Create derivation data: current_key || index
        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(&key);
        data.extend_from_slice(&index.to_le_bytes());

        // Hash to derive child key
        let hash = blake3::hash(&data);
        key = *hash.as_bytes();
    }

    key
}

/// Parse a BIP44-style derivation path like "m/44'/0'/0'/0/0" into indices.
///
/// The ' symbol indicates hardened derivation (we add 0x80000000 to the index).
/// For simplicity, all our derivations are hardened for security.
pub fn parse_derivation_path(path: &str) -> Result<Vec<u32>> {
    if !path.starts_with("m/") && !path.starts_with("M/") {
        return Err(WalletError::InvalidDerivationPath);
    }

    let path = &path[2..]; // Skip "m/"
    if path.is_empty() {
        return Ok(vec![]); // Master key
    }

    let mut indices = Vec::new();
    for part in path.split('/') {
        let (num_str, hardened) = if part.ends_with('\'') || part.ends_with('h') {
            (&part[..part.len() - 1], true)
        } else {
            (part, false)
        };

        let index: u32 = num_str
            .parse()
            .map_err(|_| WalletError::InvalidDerivationPath)?;

        // Add hardening bit (0x80000000) if hardened
        let final_index = if hardened {
            index | 0x8000_0000
        } else {
            index
        };

        indices.push(final_index);
    }

    Ok(indices)
}

/// A wallet keypair for signing transactions.
/// SECURITY FIX (CRIT-005): Implements ZeroizeOnDrop to clear private keys from memory.
#[derive(Clone, ZeroizeOnDrop)]
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
        // SECURITY FIX (CRIT-005): Zeroize seed after use
        seed.zeroize();
        Self { signing_key }
    }

    /// Create a keypair from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self { signing_key }
    }

    /// Derive a keypair from a master seed using a derivation path.
    ///
    /// Path format: "m/44'/0'/0'/0/0" (BIP44-style)
    /// - m/44'/0'/0'/0/0 = first receiving address
    /// - m/44'/0'/0'/0/1 = second receiving address
    /// - m/44'/0'/0'/1/0 = first change address
    ///
    /// Example:
    /// ```
    /// use nulla_wallet::Keypair;
    /// let master_seed = [42u8; 32];
    /// let keypair = Keypair::from_derivation_path(&master_seed, "m/44'/0'/0'/0/0").unwrap();
    /// ```
    pub fn from_derivation_path(master_seed: &[u8; 32], path: &str) -> Result<Self> {
        let indices = parse_derivation_path(path)?;
        let derived_seed = derive_key(master_seed, &indices);
        Ok(Self::from_seed(&derived_seed))
    }

    /// Get the private key bytes (for serialization/storage).
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.signing_key.as_bytes()
    }

    /// Get the public key (verifying key).
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the P2PKH address derived from the public key.
    ///
    /// Address format: version byte (0x00) + BLAKE3(public_key)[0..20]
    /// This creates a versioned P2PKH address.
    pub fn address(&self) -> Address {
        Address::p2pkh_from_public_key(&self.public_key())
    }

    /// Sign a transaction with chain ID for replay protection.
    ///
    /// This creates a signature over the transaction data including the chain ID,
    /// preventing transactions from being replayed on different chains or forks.
    ///
    /// # Arguments
    /// * `tx` - The transaction to sign
    /// * `chain_id` - The 4-byte chain identifier
    pub fn sign_transaction(&self, tx: &Tx, chain_id: &[u8; 4]) -> Result<Vec<u8>> {
        let sighash = compute_sighash(tx, chain_id)?;
        let signature = self.signing_key.sign(&sighash);
        Ok(signature.to_bytes().to_vec())
    }

    /// Legacy method for backward compatibility (without chain ID).
    /// WARNING: This is insecure and should not be used in production!
    #[deprecated(note = "Use sign_transaction with chain_id for replay protection")]
    pub fn sign_transaction_legacy(&self, tx: &Tx) -> Result<Vec<u8>> {
        let tx_data = bincode::serialize(tx)?;
        let signature = self.signing_key.sign(&tx_data);
        Ok(signature.to_bytes().to_vec())
    }

    /// Get the raw signing key bytes (32 bytes).
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.signing_key.as_bytes()
    }
}

// Old Address type removed - now using the new versioned Address from address module

/// Simple wallet for managing keys and creating transactions.
#[derive(Clone)]
pub struct Wallet {
    /// The wallet's keypair.
    keypair: Keypair,
    /// Optional master seed for HD wallet derivation.
    master_seed: Option<[u8; 32]>,
}

impl Wallet {
    /// Create a new wallet with a random keypair.
    pub fn new() -> Self {
        Self {
            keypair: Keypair::generate(),
            master_seed: None,
        }
    }

    /// Create a wallet from a 32-byte seed (non-HD wallet).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            keypair: Keypair::from_seed(seed),
            master_seed: None,
        }
    }

    /// Create an HD wallet from a master seed.
    ///
    /// This creates a wallet at the default derivation path: m/44'/0'/0'/0/0
    /// Use `derive_address()` to generate additional addresses from this master seed.
    pub fn from_master_seed(master_seed: &[u8; 32]) -> Result<Self> {
        let keypair = Keypair::from_derivation_path(master_seed, "m/44'/0'/0'/0/0")?;
        Ok(Self {
            keypair,
            master_seed: Some(*master_seed),
        })
    }

    /// Derive a new address from the master seed at the given index.
    ///
    /// This uses the BIP44 path: m/44'/0'/0'/0/{index}
    /// - index 0 = first receiving address (default wallet address)
    /// - index 1 = second receiving address
    /// - index 2 = third receiving address, etc.
    ///
    /// Returns None if this wallet was not created from a master seed.
    ///
    /// Example:
    /// ```
    /// use nulla_wallet::Wallet;
    /// let master_seed = [42u8; 32];
    /// let wallet = Wallet::from_master_seed(&master_seed).unwrap();
    /// let addr0 = wallet.address(); // Default address (index 0)
    /// let addr1 = wallet.derive_address(1).unwrap(); // Second address
    /// let addr2 = wallet.derive_address(2).unwrap(); // Third address
    /// ```
    pub fn derive_address(&self, index: u32) -> Result<Address> {
        match self.master_seed {
            Some(seed) => {
                let path = format!("m/44'/0'/0'/0/{}", index);
                let keypair = Keypair::from_derivation_path(&seed, &path)?;
                Ok(keypair.address())
            }
            None => Err(WalletError::InvalidDerivationPath),
        }
    }

    /// Derive a keypair at the given index for signing transactions.
    ///
    /// Similar to `derive_address()` but returns the full keypair for signing.
    /// Returns None if this wallet was not created from a master seed.
    pub fn derive_keypair(&self, index: u32) -> Result<Keypair> {
        match self.master_seed {
            Some(seed) => {
                let path = format!("m/44'/0'/0'/0/{}", index);
                Keypair::from_derivation_path(&seed, &path)
            }
            None => Err(WalletError::InvalidDerivationPath),
        }
    }

    /// Check if this is an HD wallet (created from a master seed).
    pub fn is_hd_wallet(&self) -> bool {
        self.master_seed.is_some()
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

    /// Create and sign a transaction with replay protection.
    ///
    /// This is a helper that creates a transaction with the given inputs and outputs,
    /// then signs all inputs with this wallet's keypair including the chain ID.
    ///
    /// # Arguments
    /// * `inputs` - Transaction inputs
    /// * `outputs` - Transaction outputs
    /// * `lock_time` - Locktime value
    /// * `chain_id` - 4-byte chain identifier for replay protection
    pub fn create_transaction(
        &self,
        inputs: Vec<TxIn>,
        outputs: Vec<TxOut>,
        lock_time: u64,
        chain_id: &[u8; 4],
    ) -> Result<Tx> {
        let mut tx = Tx {
            version: 1,
            inputs,
            outputs,
            lock_time,
        };

        // Sign each input with the wallet's keypair and add the public key.
        let signature = self.keypair.sign_transaction(&tx, chain_id)?;
        let pubkey_bytes = self.keypair.public_key().to_bytes().to_vec();

        for input in &mut tx.inputs {
            input.sig = signature.clone();
            input.pubkey = pubkey_bytes.clone();
        }

        Ok(tx)
    }

    /// Legacy transaction creation without chain ID.
    /// WARNING: This is insecure and vulnerable to replay attacks!
    #[deprecated(note = "Use create_transaction with chain_id for replay protection")]
    pub fn create_transaction_legacy(
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

        #[allow(deprecated)]
        let signature = self.keypair.sign_transaction_legacy(&tx)?;
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

/// Compute a sighash (signature hash) for a transaction.
///
/// The sighash includes:
/// - Chain ID (4 bytes) - prevents replay across chains
/// - Transaction version, inputs, outputs, lock_time (bincode serialized)
///
/// This implements a simplified version of BIP-143 style sighashing.
pub fn compute_sighash(tx: &Tx, chain_id: &[u8; 4]) -> Result<Vec<u8>> {
    let mut hasher = blake3::Hasher::new();

    // Include chain ID first for replay protection
    hasher.update(chain_id);

    // Serialize the transaction (this excludes signatures since they're cleared during signing)
    let tx_data = bincode::serialize(tx)?;
    hasher.update(&tx_data);

    Ok(hasher.finalize().as_bytes().to_vec())
}

/// Verify an Ed25519 signature on a transaction with chain ID.
///
/// Returns Ok(()) if the signature is valid, Err otherwise.
///
/// # Arguments
/// * `tx` - The transaction to verify
/// * `signature_bytes` - The Ed25519 signature (64 bytes)
/// * `public_key` - The Ed25519 public key
/// * `chain_id` - The 4-byte chain identifier for replay protection
pub fn verify_signature(
    tx: &Tx,
    signature_bytes: &[u8],
    public_key: &VerifyingKey,
    chain_id: &[u8; 4],
) -> Result<()> {
    // Parse the signature (64 bytes for Ed25519)
    if signature_bytes.len() != 64 {
        return Err(WalletError::InvalidSignature);
    }

    let signature = Signature::from_bytes(
        signature_bytes
            .try_into()
            .map_err(|_| WalletError::InvalidSignature)?,
    );

    // Compute sighash with chain ID
    let sighash = compute_sighash(tx, chain_id)?;

    // Verify the signature using strict verification
    // SECURITY FIX (CRIT-002): verify_strict() prevents signature malleability
    public_key
        .verify_strict(&sighash, &signature)
        .map_err(|_| WalletError::InvalidSignature)
}

/// Legacy signature verification without chain ID.
/// WARNING: This is insecure and vulnerable to replay attacks!
#[deprecated(note = "Use verify_signature with chain_id for replay protection")]
pub fn verify_signature_legacy(tx: &Tx, signature_bytes: &[u8], public_key: &VerifyingKey) -> Result<()> {
    if signature_bytes.len() != 64 {
        return Err(WalletError::InvalidSignature);
    }

    let signature = Signature::from_bytes(
        signature_bytes
            .try_into()
            .map_err(|_| WalletError::InvalidSignature)?,
    );

    let tx_data = bincode::serialize(tx)?;
    // SECURITY FIX (CRIT-002): verify_strict() prevents signature malleability
    public_key
        .verify_strict(&tx_data, &signature)
        .map_err(|_| WalletError::InvalidSignature)
}

/// Extract address from a script_pubkey.
///
/// Returns None if the script is not in a recognized format (P2PKH or P2SH).
/// Supports both:
/// - P2PKH: [OP_DUP, OP_HASH160, <20-byte address>, OP_EQUALVERIFY, OP_CHECKSIG]
/// - P2SH:  [OP_HASH160, <20-byte script-hash>, OP_EQUAL]
pub fn extract_address_from_script(script_pubkey: &[u8]) -> Option<Address> {
    Address::from_script_pubkey(script_pubkey)
}

/// Encrypted wallet file format.
///
/// The wallet file contains:
/// - 32 bytes: salt for Argon2id key derivation
/// - 12 bytes: nonce for ChaCha20-Poly1305
/// - 48 bytes: encrypted seed (32 bytes) + authentication tag (16 bytes)
/// - 1 byte: wallet type (0 = simple, 1 = HD)
/// - 4 bytes: Argon2id parameters (for future upgradability)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletFile {
    salt: [u8; 32],
    nonce: [u8; 12],
    ciphertext: Vec<u8>, // 32 bytes seed + 16 bytes auth tag = 48 bytes
    is_hd: bool,
    /// Argon2id parameters: [memory_cost_kb (3 bytes), iterations (1 byte)]
    kdf_params: [u8; 4],
}

/// Argon2id parameters for key derivation
const ARGON2_MEMORY_COST: u32 = 65536; // 64 MB
const ARGON2_TIME_COST: u32 = 3;       // 3 iterations
const ARGON2_PARALLELISM: u32 = 4;      // 4 parallel lanes

/// Derive an encryption key from a password using Argon2id.
///
/// This is a memory-hard key derivation function designed to resist
/// GPU and ASIC-based brute-force attacks.
fn derive_key_from_password(password: &str, salt: &[u8; 32]) -> Result<[u8; 32]> {
    use argon2::{Argon2, Algorithm, Version, Params};

    let params = Params::new(
        ARGON2_MEMORY_COST,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(32), // output length
    ).map_err(|e| WalletError::InvalidInput(format!("Argon2 params error: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output_key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut output_key)
        .map_err(|e| WalletError::InvalidInput(format!("Argon2 hash error: {}", e)))?;

    Ok(output_key)
}

/// Encrypt a seed with a password using ChaCha20-Poly1305.
///
/// ChaCha20-Poly1305 provides authenticated encryption, ensuring both
/// confidentiality and integrity of the encrypted data.
fn encrypt_seed(seed: &[u8; 32], password: &str, salt: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12])> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };
    use zeroize::Zeroize;

    // Derive encryption key from password
    let mut key = derive_key_from_password(password, salt)?;

    // Generate random nonce (number used once)
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create cipher
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| WalletError::InvalidInput(format!("Cipher init error: {}", e)))?;

    // Encrypt the seed
    let ciphertext = cipher.encrypt(nonce, seed.as_ref())
        .map_err(|e| WalletError::InvalidInput(format!("Encryption error: {}", e)))?;

    // Zero out the key from memory for security
    key.zeroize();

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt a seed with a password using ChaCha20-Poly1305.
///
/// Returns an error if the password is incorrect or if the ciphertext
/// has been tampered with (authentication tag check fails).
fn decrypt_seed(ciphertext: &[u8], nonce: &[u8; 12], password: &str, salt: &[u8; 32]) -> Result<[u8; 32]> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };
    use zeroize::Zeroize;

    // Derive encryption key from password
    let mut key = derive_key_from_password(password, salt)?;

    // Create cipher
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| WalletError::InvalidInput(format!("Cipher init error: {}", e)))?;

    let nonce_obj = Nonce::from_slice(nonce);

    // Decrypt and verify authentication tag
    let plaintext = cipher.decrypt(nonce_obj, ciphertext)
        .map_err(|_| WalletError::InvalidPassword)?;

    // Zero out the key from memory
    key.zeroize();

    // Ensure we got exactly 32 bytes back
    if plaintext.len() != 32 {
        return Err(WalletError::InvalidInput("Decrypted seed has wrong length".into()));
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

impl Wallet {
    /// Save the wallet to an encrypted file.
    ///
    /// The wallet file is encrypted with the provided password using BLAKE3-based
    /// key derivation and XOR encryption.
    ///
    /// # Arguments
    /// * `path` - Path to save the wallet file
    /// * `password` - Password to encrypt the wallet
    ///
    /// # Returns
    /// Returns Ok(()) if the wallet was saved successfully.
    ///
    /// # Example
    /// ```no_run
    /// use nulla_wallet::Wallet;
    /// let wallet = Wallet::new();
    /// wallet.save_to_file("wallet.dat", "my-secure-password").unwrap();
    /// ```
    pub fn save_to_file(&self, path: impl AsRef<Path>, password: &str) -> Result<()> {
        // Generate random salt
        let salt: [u8; 32] = rand::random();

        // Determine which seed to save
        let (seed, is_hd) = if let Some(master_seed) = self.master_seed {
            (master_seed, true)
        } else {
            (*self.keypair.secret_bytes(), false)
        };

        // Encrypt the seed with ChaCha20-Poly1305 + Argon2id
        let (ciphertext, nonce) = encrypt_seed(&seed, password, &salt)?;

        // Store KDF parameters for future upgradability
        let memory_kb_bytes = (ARGON2_MEMORY_COST as u32).to_le_bytes();
        let kdf_params = [
            memory_kb_bytes[0],
            memory_kb_bytes[1],
            memory_kb_bytes[2],
            ARGON2_TIME_COST as u8,
        ];

        // Create wallet file
        let wallet_file = WalletFile {
            salt,
            nonce,
            ciphertext,
            is_hd,
            kdf_params,
        };

        // Serialize and write to file
        let data = bincode::serialize(&wallet_file)?;
        fs::write(path, data)?;

        Ok(())
    }

    /// Load a wallet from an encrypted file.
    ///
    /// # Arguments
    /// * `path` - Path to the wallet file
    /// * `password` - Password to decrypt the wallet
    ///
    /// # Returns
    /// Returns the decrypted wallet if the password is correct.
    ///
    /// # Errors
    /// - `WalletNotFound` if the file doesn't exist
    /// - `InvalidPassword` if the password is incorrect (detected via invalid wallet data)
    ///
    /// # Example
    /// ```no_run
    /// use nulla_wallet::Wallet;
    /// let wallet = Wallet::load_from_file("wallet.dat", "my-secure-password").unwrap();
    /// println!("Wallet address: {}", wallet.address());
    /// ```
    pub fn load_from_file(path: impl AsRef<Path>, password: &str) -> Result<Self> {
        // Check if file exists
        if !path.as_ref().exists() {
            return Err(WalletError::WalletNotFound);
        }

        // Read and deserialize wallet file
        let data = fs::read(path)?;
        let wallet_file: WalletFile = bincode::deserialize(&data)?;

        // Decrypt the seed with authentication verification
        let decrypted_seed = decrypt_seed(
            &wallet_file.ciphertext,
            &wallet_file.nonce,
            password,
            &wallet_file.salt
        )?;

        // Create wallet from decrypted seed
        if wallet_file.is_hd {
            Self::from_master_seed(&decrypted_seed)
        } else {
            Ok(Self::from_seed(&decrypted_seed))
        }
    }

    /// Check if a wallet file exists.
    pub fn exists(path: impl AsRef<Path>) -> bool {
        path.as_ref().exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = Keypair::generate();
        let address = keypair.address();
        assert_eq!(address.hash().len(), 20);
    }

    #[test]
    fn test_address_from_public_key() {
        let keypair = Keypair::generate();
        let pubkey = keypair.public_key();
        let addr1 = Address::p2pkh_from_public_key(&pubkey);
        let addr2 = keypair.address();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_address_hex() {
        let keypair = Keypair::generate();
        let addr = keypair.address();
        let hex = addr.to_hex();
        assert_eq!(hex.len(), 42); // 1 version byte + 20 hash bytes = 42 hex chars
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

    #[test]
    fn test_hd_wallet_derivation() {
        let master_seed = [42u8; 32];
        let wallet = Wallet::from_master_seed(&master_seed).unwrap();

        assert!(wallet.is_hd_wallet());

        // Derive multiple addresses from the same seed
        let addr0 = wallet.address(); // Default (index 0)
        let addr1 = wallet.derive_address(1).unwrap();
        let addr2 = wallet.derive_address(2).unwrap();

        // All addresses should be different
        assert_ne!(addr0, addr1);
        assert_ne!(addr1, addr2);
        assert_ne!(addr0, addr2);

        // Same index should produce same address
        let addr1_again = wallet.derive_address(1).unwrap();
        assert_eq!(addr1, addr1_again);
    }

    #[test]
    fn test_hd_wallet_deterministic() {
        let master_seed = [123u8; 32];

        // Two wallets from same master seed should be identical
        let wallet1 = Wallet::from_master_seed(&master_seed).unwrap();
        let wallet2 = Wallet::from_master_seed(&master_seed).unwrap();

        assert_eq!(wallet1.address(), wallet2.address());
        assert_eq!(
            wallet1.derive_address(5).unwrap(),
            wallet2.derive_address(5).unwrap()
        );
    }

    #[test]
    fn test_derivation_path_parsing() {
        // Valid paths
        assert!(parse_derivation_path("m/44'/0'/0'/0/0").is_ok());
        assert!(parse_derivation_path("m/44'/0'/0'/1/5").is_ok());
        assert!(parse_derivation_path("M/0'/1'/2'").is_ok());

        // Invalid paths
        assert!(parse_derivation_path("44'/0'/0'/0/0").is_err()); // Missing m/
        assert!(parse_derivation_path("m/abc/0").is_err()); // Invalid number
        assert!(parse_derivation_path("").is_err()); // Empty
    }

    #[test]
    fn test_non_hd_wallet_cannot_derive() {
        let seed = [42u8; 32];
        let wallet = Wallet::from_seed(&seed);

        assert!(!wallet.is_hd_wallet());
        assert!(wallet.derive_address(1).is_err());
    }

    #[test]
    fn test_keypair_from_derivation_path() {
        let master_seed = [99u8; 32];

        let keypair1 = Keypair::from_derivation_path(&master_seed, "m/44'/0'/0'/0/0").unwrap();
        let keypair2 = Keypair::from_derivation_path(&master_seed, "m/44'/0'/0'/0/1").unwrap();

        // Different paths should produce different keys
        assert_ne!(keypair1.address(), keypair2.address());

        // Same path should produce same key
        let keypair1_again =
            Keypair::from_derivation_path(&master_seed, "m/44'/0'/0'/0/0").unwrap();
        assert_eq!(keypair1.address(), keypair1_again.address());
    }
}
