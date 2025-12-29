//! Enhanced address format with version bytes supporting P2PKH and P2SH.
//!
//! Address format:
//! - Version 0 (P2PKH): 1 version byte + 20 hash bytes = 21 bytes total
//! - Version 1 (P2SH): 1 version byte + 20 script hash bytes = 21 bytes total
//!
//! Displayed as hex with version prefix for clarity.

use ed25519_dalek::VerifyingKey;
use nulla_core::Script;
use serde::{Deserialize, Serialize};

/// Address version byte
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AddressVersion {
    /// Pay-to-Public-Key-Hash (single signature)
    P2PKH = 0x00,
    /// Pay-to-Script-Hash (multi-signature or other scripts)
    P2SH = 0x01,
}

impl AddressVersion {
    /// Convert byte to address version
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(AddressVersion::P2PKH),
            0x01 => Some(AddressVersion::P2SH),
            _ => None,
        }
    }

    /// Convert to byte
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Enhanced address with version byte (21 bytes total: 1 version + 20 hash)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address {
    /// Address version (P2PKH or P2SH)
    pub version: AddressVersion,
    /// 20-byte hash (either pubkey hash or script hash)
    pub hash: [u8; 20],
}

impl Address {
    /// Create a P2PKH address from a public key (version 0)
    pub fn p2pkh_from_public_key(public_key: &VerifyingKey) -> Self {
        let pubkey_bytes = public_key.to_bytes();
        let hash = blake3::hash(&pubkey_bytes);
        let hash_bytes: &[u8; 32] = hash.as_bytes();
        let mut addr_hash = [0u8; 20];
        addr_hash.copy_from_slice(&hash_bytes[0..20]);

        Self {
            version: AddressVersion::P2PKH,
            hash: addr_hash,
        }
    }

    /// Create a P2SH address from a script (version 1)
    pub fn p2sh_from_script(script: &Script) -> Self {
        let script_hash = script.hash160();

        Self {
            version: AddressVersion::P2SH,
            hash: script_hash,
        }
    }

    /// Convert address to hex string with version prefix
    /// Format: "00" + hex(20-byte-hash) for P2PKH
    ///         "01" + hex(20-byte-hash) for P2SH
    pub fn to_hex(&self) -> String {
        format!("{:02x}{}", self.version.as_u8(), hex::encode(self.hash))
    }

    /// Parse address from hex string
    /// Expects 42 hex characters: 2 for version + 40 for hash
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 42 {
            return None;
        }

        // Parse version byte
        let version_hex = &s[0..2];
        let version_byte = u8::from_str_radix(version_hex, 16).ok()?;
        let version = AddressVersion::from_u8(version_byte)?;

        // Parse hash
        let hash_hex = &s[2..];
        let hash_bytes = hex::decode(hash_hex).ok()?;
        if hash_bytes.len() != 20 {
            return None;
        }

        let mut hash = [0u8; 20];
        hash.copy_from_slice(&hash_bytes);

        Some(Self { version, hash })
    }

    /// Convert address to script_pubkey for TxOut
    ///
    /// For P2PKH: [OP_DUP, OP_HASH160, <20-byte hash>, OP_EQUALVERIFY, OP_CHECKSIG]
    /// For P2SH:  [OP_HASH160, <20-byte hash>, OP_EQUAL]
    pub fn to_script_pubkey(&self) -> Vec<u8> {
        match self.version {
            AddressVersion::P2PKH => Script::p2pkh(&self.hash).bytes,
            AddressVersion::P2SH => Script::p2sh(&self.hash).bytes,
        }
    }

    /// Extract address from a script_pubkey
    /// Returns None if the script is not a recognized P2PKH or P2SH format
    pub fn from_script_pubkey(script: &[u8]) -> Option<Self> {
        let script_obj = Script::new(script.to_vec());

        match script_obj.script_type() {
            Some(nulla_core::ScriptType::P2PKH) => {
                let hash = script_obj.extract_hash()?;
                Some(Self {
                    version: AddressVersion::P2PKH,
                    hash,
                })
            }
            Some(nulla_core::ScriptType::P2SH) => {
                let hash = script_obj.extract_hash()?;
                Some(Self {
                    version: AddressVersion::P2SH,
                    hash,
                })
            }
            None => None,
        }
    }

    /// Get the raw 20-byte hash
    pub fn hash(&self) -> &[u8; 20] {
        &self.hash
    }

    /// Check if this is a P2PKH address
    pub fn is_p2pkh(&self) -> bool {
        matches!(self.version, AddressVersion::P2PKH)
    }

    /// Check if this is a P2SH address
    pub fn is_p2sh(&self) -> bool {
        matches!(self.version, AddressVersion::P2SH)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_p2pkh_address() {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let verifying_key = signing_key.verifying_key();
        let addr = Address::p2pkh_from_public_key(&verifying_key);

        assert_eq!(addr.version, AddressVersion::P2PKH);
        assert!(addr.is_p2pkh());
        assert!(!addr.is_p2sh());

        // Should be 42 hex chars (2 for version + 40 for hash)
        let hex = addr.to_hex();
        assert_eq!(hex.len(), 42);
        assert!(hex.starts_with("00"));

        // Round trip
        let parsed = Address::from_hex(&hex).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_p2sh_address() {
        let pubkey1 = [0x01u8; 32];
        let pubkey2 = [0x02u8; 32];
        let pubkeys = [pubkey1, pubkey2];
        let redeem_script = Script::multisig(2, &pubkeys).unwrap();

        let addr = Address::p2sh_from_script(&redeem_script);

        assert_eq!(addr.version, AddressVersion::P2SH);
        assert!(!addr.is_p2pkh());
        assert!(addr.is_p2sh());

        // Should be 42 hex chars
        let hex = addr.to_hex();
        assert_eq!(hex.len(), 42);
        assert!(hex.starts_with("01"));

        // Round trip
        let parsed = Address::from_hex(&hex).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_script_pubkey_generation() {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let verifying_key = signing_key.verifying_key();

        // P2PKH
        let p2pkh_addr = Address::p2pkh_from_public_key(&verifying_key);
        let p2pkh_script = p2pkh_addr.to_script_pubkey();
        assert_eq!(p2pkh_script.len(), 25); // P2PKH is 25 bytes

        // P2SH
        let redeem_script = Script::multisig(2, &[[0x01; 32], [0x02; 32]]).unwrap();
        let p2sh_addr = Address::p2sh_from_script(&redeem_script);
        let p2sh_script = p2sh_addr.to_script_pubkey();
        assert_eq!(p2sh_script.len(), 23); // P2SH is 23 bytes
    }

    #[test]
    fn test_from_script_pubkey() {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let verifying_key = signing_key.verifying_key();

        // P2PKH round trip
        let p2pkh_addr = Address::p2pkh_from_public_key(&verifying_key);
        let script = p2pkh_addr.to_script_pubkey();
        let recovered = Address::from_script_pubkey(&script).unwrap();
        assert_eq!(recovered, p2pkh_addr);

        // P2SH round trip
        let redeem_script = Script::multisig(2, &[[0x01; 32], [0x02; 32]]).unwrap();
        let p2sh_addr = Address::p2sh_from_script(&redeem_script);
        let script = p2sh_addr.to_script_pubkey();
        let recovered = Address::from_script_pubkey(&script).unwrap();
        assert_eq!(recovered, p2sh_addr);
    }
}
