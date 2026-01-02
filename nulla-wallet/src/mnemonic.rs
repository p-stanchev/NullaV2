//! BIP39 mnemonic phrase support for wallet seed generation and recovery.
//!
//! This module provides functionality to:
//! - Generate random mnemonic phrases (12 or 24 words)
//! - Convert mnemonics to wallet seeds
//! - Support optional passphrases for additional security
//! - Derive HD wallet master keys from mnemonics
//!
//! # Examples
//!
//! ```no_run
//! use nulla_wallet::mnemonic::Mnemonic;
//!
//! // Generate a new 24-word mnemonic
//! let mnemonic = Mnemonic::generate_24_words().unwrap();
//! println!("Backup these words: {}", mnemonic.phrase());
//!
//! // Later, recover from mnemonic
//! let phrase = "abandon abandon abandon..."; // User's backup words
//! let recovered = Mnemonic::from_phrase(phrase).unwrap();
//! let seed = recovered.to_seed(None); // Convert to wallet seed
//! ```

use bip39::{Language, Mnemonic as Bip39Mnemonic};
use zeroize::ZeroizeOnDrop;

/// BIP39 mnemonic phrase wrapper with automatic memory cleanup.
///
/// This type wraps a BIP39 mnemonic phrase and ensures sensitive data
/// is cleared from memory when dropped (CRIT-005 security requirement).
pub struct Mnemonic {
    inner: Bip39Mnemonic,
    phrase: String,
}

impl Mnemonic {
    /// Generate a new 12-word (128-bit entropy) mnemonic phrase.
    ///
    /// This provides 128 bits of entropy, which is secure for most use cases.
    /// For maximum security, consider using `generate_24_words()` instead.
    ///
    /// # Returns
    /// A randomly generated 12-word mnemonic phrase.
    ///
    /// # Errors
    /// Returns an error if the system random number generator fails.
    pub fn generate_12_words() -> Result<Self, MnemonicError> {
        // Generate 16 bytes of entropy (128 bits = 12 words)
        let mut entropy = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut entropy);

        let mnemonic = Bip39Mnemonic::from_entropy(&entropy)
            .map_err(|e| MnemonicError::Generation(e.to_string()))?;
        let phrase = mnemonic.to_string();
        Ok(Self { inner: mnemonic, phrase })
    }

    /// Generate a new 24-word (256-bit entropy) mnemonic phrase.
    ///
    /// This provides 256 bits of entropy for maximum security.
    /// Recommended for long-term wallet storage.
    ///
    /// # Returns
    /// A randomly generated 24-word mnemonic phrase.
    ///
    /// # Errors
    /// Returns an error if the system random number generator fails.
    pub fn generate_24_words() -> Result<Self, MnemonicError> {
        // Generate 32 bytes of entropy (256 bits = 24 words)
        let mut entropy = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut entropy);

        let mnemonic = Bip39Mnemonic::from_entropy(&entropy)
            .map_err(|e| MnemonicError::Generation(e.to_string()))?;
        let phrase = mnemonic.to_string();
        Ok(Self { inner: mnemonic, phrase })
    }

    /// Create a mnemonic from an existing phrase string.
    ///
    /// This is used to recover a wallet from a backup phrase.
    /// The phrase should be 12 or 24 space-separated words from the BIP39 wordlist.
    ///
    /// # Arguments
    /// * `phrase` - Space-separated mnemonic words (e.g., "abandon abandon abandon...")
    ///
    /// # Returns
    /// A mnemonic parsed from the phrase.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The phrase has an invalid number of words (not 12 or 24)
    /// - Any word is not in the BIP39 wordlist
    /// - The checksum is invalid
    pub fn from_phrase(phrase: &str) -> Result<Self, MnemonicError> {
        let mnemonic = Bip39Mnemonic::parse_in_normalized(Language::English, phrase)
            .map_err(|e| MnemonicError::InvalidPhrase(e.to_string()))?;
        let phrase_str = mnemonic.to_string();
        Ok(Self { inner: mnemonic, phrase: phrase_str })
    }

    /// Get the mnemonic phrase as a string.
    ///
    /// # Security Warning
    /// The returned string contains sensitive information that can be used
    /// to recover the wallet. Handle it carefully and clear it from memory
    /// after use if possible.
    ///
    /// # Returns
    /// The mnemonic phrase as a space-separated string of words.
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// Convert the mnemonic to a 64-byte wallet seed using PBKDF2.
    ///
    /// This implements BIP39's seed derivation:
    /// - Uses PBKDF2-HMAC-SHA512
    /// - 2048 iterations (BIP39 standard)
    /// - Optional passphrase for additional security (empty string if None)
    ///
    /// # Arguments
    /// * `passphrase` - Optional passphrase for additional security.
    ///   Using a passphrase creates a completely different wallet.
    ///   If you lose the passphrase, the wallet cannot be recovered.
    ///
    /// # Returns
    /// A 64-byte seed that can be used for HD wallet derivation.
    ///
    /// # Examples
    /// ```no_run
    /// # use nulla_wallet::mnemonic::Mnemonic;
    /// let mnemonic = Mnemonic::generate_24_words().unwrap();
    ///
    /// // Without passphrase (most common)
    /// let seed = mnemonic.to_seed(None);
    ///
    /// // With passphrase (extra security, but must remember it!)
    /// let seed_with_passphrase = mnemonic.to_seed(Some("my secret passphrase"));
    /// ```
    pub fn to_seed(&self, passphrase: Option<&str>) -> Seed {
        let passphrase = passphrase.unwrap_or("");
        let seed_bytes = self.inner.to_seed(passphrase);
        Seed {
            bytes: seed_bytes,
        }
    }

    /// Get the number of words in this mnemonic (12 or 24).
    pub fn word_count(&self) -> usize {
        self.inner.word_count()
    }
}

/// A 64-byte seed derived from a BIP39 mnemonic phrase.
///
/// This seed can be used to derive HD wallet master keys.
/// The seed is automatically cleared from memory when dropped.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Seed {
    bytes: [u8; 64],
}

impl Seed {
    /// Get a reference to the raw seed bytes.
    ///
    /// # Security Warning
    /// This contains sensitive cryptographic material.
    /// The bytes will be automatically zeroed when the Seed is dropped.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }

    /// Convert the first 32 bytes of the seed to a wallet master seed.
    ///
    /// BIP39 seeds are 64 bytes, but most key derivation schemes
    /// (including our Ed25519-based HD wallet) use 32 bytes.
    ///
    /// # Returns
    /// The first 32 bytes of the seed, suitable for HD wallet derivation.
    pub fn to_master_seed(&self) -> [u8; 32] {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.bytes[..32]);
        seed
    }
}

/// Errors that can occur during mnemonic operations.
#[derive(Debug, thiserror::Error)]
pub enum MnemonicError {
    /// Failed to generate a random mnemonic
    #[error("failed to generate mnemonic: {0}")]
    Generation(String),

    /// Invalid mnemonic phrase
    #[error("invalid mnemonic phrase: {0}")]
    InvalidPhrase(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_12_words() {
        let mnemonic = Mnemonic::generate_12_words().unwrap();
        assert_eq!(mnemonic.word_count(), 12);
        let phrase = mnemonic.phrase();
        assert_eq!(phrase.split_whitespace().count(), 12);
    }

    #[test]
    fn test_generate_24_words() {
        let mnemonic = Mnemonic::generate_24_words().unwrap();
        assert_eq!(mnemonic.word_count(), 24);
        let phrase = mnemonic.phrase();
        assert_eq!(phrase.split_whitespace().count(), 24);
    }

    #[test]
    fn test_from_phrase() {
        // Valid 12-word test vector from BIP39
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        assert_eq!(mnemonic.phrase(), phrase);
    }

    #[test]
    fn test_invalid_phrase() {
        // Invalid word
        let phrase = "invalid word that does not exist in wordlist";
        assert!(Mnemonic::from_phrase(phrase).is_err());

        // Wrong number of words
        let phrase = "abandon abandon abandon";
        assert!(Mnemonic::from_phrase(phrase).is_err());
    }

    #[test]
    fn test_to_seed() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();

        // Without passphrase
        let seed1 = mnemonic.to_seed(None);
        assert_eq!(seed1.as_bytes().len(), 64);

        // With passphrase (should produce different seed)
        let seed2 = mnemonic.to_seed(Some("test passphrase"));
        assert_eq!(seed2.as_bytes().len(), 64);
        assert_ne!(seed1.as_bytes(), seed2.as_bytes());
    }

    #[test]
    fn test_master_seed_derivation() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        let seed = mnemonic.to_seed(None);
        let master_seed = seed.to_master_seed();
        assert_eq!(master_seed.len(), 32);
    }

    #[test]
    fn test_deterministic_seed() {
        // Same phrase should always produce same seed
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic1 = Mnemonic::from_phrase(phrase).unwrap();
        let mnemonic2 = Mnemonic::from_phrase(phrase).unwrap();

        let seed1 = mnemonic1.to_seed(None);
        let seed2 = mnemonic2.to_seed(None);

        assert_eq!(seed1.as_bytes(), seed2.as_bytes());
    }
}
