//! Multi-signature wallet support.
//!
//! This module provides functionality for creating and managing multi-signature wallets.

use crate::{Address, WalletError};
use ed25519_dalek::VerifyingKey;
use nulla_core::Script;
use serde::{Deserialize, Serialize};

/// Multi-signature wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSigConfig {
    /// Number of required signatures (M)
    pub required: u8,
    /// Total number of public keys (N)
    pub total: u8,
    /// Public keys of all participants
    pub pubkeys: Vec<[u8; 32]>,
    /// The redeem script
    pub redeem_script: Vec<u8>,
}

impl MultiSigConfig {
    /// Create a new multi-sig configuration
    pub fn new(required: u8, pubkeys: Vec<VerifyingKey>) -> Result<Self, WalletError> {
        if required == 0 {
            return Err(WalletError::InvalidInput("Required signatures must be > 0".into()));
        }

        let total = pubkeys.len() as u8;
        if total == 0 {
            return Err(WalletError::InvalidInput("Must have at least one public key".into()));
        }

        if required > total {
            return Err(WalletError::InvalidInput(
                format!("Required signatures ({}) cannot exceed total keys ({})", required, total)
            ));
        }

        if total > 15 {
            return Err(WalletError::InvalidInput("Maximum 15 public keys supported".into()));
        }

        // Convert VerifyingKeys to [u8; 32]
        let pubkey_bytes: Vec<[u8; 32]> = pubkeys
            .iter()
            .map(|pk| pk.to_bytes())
            .collect();

        // Create the redeem script
        let redeem_script = Script::multisig(required, &pubkey_bytes)
            .map_err(|e| WalletError::InvalidInput(format!("Failed to create multisig script: {}", e)))?;

        Ok(Self {
            required,
            total,
            pubkeys: pubkey_bytes,
            redeem_script: redeem_script.bytes,
        })
    }

    /// Get the P2SH address for this multi-sig configuration
    pub fn address(&self) -> Address {
        let script = Script::new(self.redeem_script.clone());
        Address::p2sh_from_script(&script)
    }

    /// Get the redeem script
    pub fn redeem_script(&self) -> &[u8] {
        &self.redeem_script
    }

    /// Verify that this configuration is valid
    pub fn validate(&self) -> Result<(), WalletError> {
        if self.required == 0 {
            return Err(WalletError::InvalidInput("Required signatures must be > 0".into()));
        }

        if self.total == 0 {
            return Err(WalletError::InvalidInput("Total keys must be > 0".into()));
        }

        if self.required > self.total {
            return Err(WalletError::InvalidInput(
                format!("Required ({}) cannot exceed total ({})", self.required, self.total)
            ));
        }

        if self.pubkeys.len() != self.total as usize {
            return Err(WalletError::InvalidInput(
                format!("Pubkey count ({}) doesn't match total ({})", self.pubkeys.len(), self.total)
            ));
        }

        // Verify the redeem script is valid
        let script = Script::new(self.redeem_script.clone());
        let (m, parsed_pubkeys) = script.parse_multisig()
            .map_err(|e| WalletError::InvalidInput(format!("Invalid redeem script: {}", e)))?;

        if m != self.required {
            return Err(WalletError::InvalidInput(
                format!("Script M ({}) doesn't match required ({})", m, self.required)
            ));
        }

        if parsed_pubkeys.len() != self.total as usize {
            return Err(WalletError::InvalidInput(
                format!("Script pubkey count ({}) doesn't match total ({})", parsed_pubkeys.len(), self.total)
            ));
        }

        Ok(())
    }
}

/// Create a 2-of-2 multi-sig address from two public keys
pub fn create_2_of_2(pubkey1: &VerifyingKey, pubkey2: &VerifyingKey) -> Result<(Address, MultiSigConfig), WalletError> {
    let config = MultiSigConfig::new(2, vec![*pubkey1, *pubkey2])?;
    let address = config.address();
    Ok((address, config))
}

/// Create a 2-of-3 multi-sig address from three public keys
pub fn create_2_of_3(
    pubkey1: &VerifyingKey,
    pubkey2: &VerifyingKey,
    pubkey3: &VerifyingKey,
) -> Result<(Address, MultiSigConfig), WalletError> {
    let config = MultiSigConfig::new(2, vec![*pubkey1, *pubkey2, *pubkey3])?;
    let address = config.address();
    Ok((address, config))
}

/// Create a M-of-N multi-sig address from a list of public keys
pub fn create_multisig(required: u8, pubkeys: Vec<VerifyingKey>) -> Result<(Address, MultiSigConfig), WalletError> {
    let config = MultiSigConfig::new(required, pubkeys)?;
    let address = config.address();
    Ok((address, config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_2_of_2_multisig() {
        let sk1 = SigningKey::from_bytes(&[0x01; 32]);
        let sk2 = SigningKey::from_bytes(&[0x02; 32]);
        let pk1 = sk1.verifying_key();
        let pk2 = sk2.verifying_key();

        let (address, config) = create_2_of_2(&pk1, &pk2).unwrap();

        assert_eq!(config.required, 2);
        assert_eq!(config.total, 2);
        assert_eq!(config.pubkeys.len(), 2);
        assert!(address.is_p2sh());

        // Validate config
        config.validate().unwrap();
    }

    #[test]
    fn test_2_of_3_multisig() {
        let sk1 = SigningKey::from_bytes(&[0x01; 32]);
        let sk2 = SigningKey::from_bytes(&[0x02; 32]);
        let sk3 = SigningKey::from_bytes(&[0x03; 32]);
        let pk1 = sk1.verifying_key();
        let pk2 = sk2.verifying_key();
        let pk3 = sk3.verifying_key();

        let (address, config) = create_2_of_3(&pk1, &pk2, &pk3).unwrap();

        assert_eq!(config.required, 2);
        assert_eq!(config.total, 3);
        assert_eq!(config.pubkeys.len(), 3);
        assert!(address.is_p2sh());

        config.validate().unwrap();
    }

    #[test]
    fn test_invalid_m_greater_than_n() {
        let sk1 = SigningKey::from_bytes(&[0x01; 32]);
        let sk2 = SigningKey::from_bytes(&[0x02; 32]);
        let pk1 = sk1.verifying_key();
        let pk2 = sk2.verifying_key();

        let result = create_multisig(3, vec![pk1, pk2]);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_pubkeys() {
        // Create 15 public keys (maximum)
        let pubkeys: Vec<VerifyingKey> = (0u8..15)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i + 1;
                SigningKey::from_bytes(&bytes).verifying_key()
            })
            .collect();

        let (address, config) = create_multisig(10, pubkeys).unwrap();
        assert_eq!(config.required, 10);
        assert_eq!(config.total, 15);
        assert!(address.is_p2sh());
    }

    #[test]
    fn test_too_many_pubkeys() {
        // Try to create with 16 public keys (should fail)
        let pubkeys: Vec<VerifyingKey> = (0u8..16)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i + 1;
                SigningKey::from_bytes(&bytes).verifying_key()
            })
            .collect();

        let result = create_multisig(10, pubkeys);
        assert!(result.is_err());
    }
}
