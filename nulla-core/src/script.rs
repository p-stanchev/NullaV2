//! Script system for transaction validation.
//!
//! This module implements a simple Bitcoin-style script system supporting:
//! - P2PKH (Pay-to-Public-Key-Hash) - single signature, version 0
//! - P2SH (Pay-to-Script-Hash) - multi-signature, version 1
//!
//! Script opcodes are a minimal subset needed for basic functionality.

use serde::{Deserialize, Serialize};

/// Script opcodes (Bitcoin-compatible subset)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    // Constants
    Op0 = 0x00,
    OpPushData1 = 0x4c, // Next byte contains number of bytes to push

    // Stack operations
    OpDup = 0x76,
    OpEqual = 0x87,
    OpEqualVerify = 0x88,

    // Crypto operations
    OpHash160 = 0xa9, // BLAKE3 hash truncated to 20 bytes
    OpCheckSig = 0xac,
    OpCheckMultiSig = 0xae,

    // Constants for push operations (1-75 bytes)
    // Values 0x01-0x4b indicate direct push of that many bytes
}

impl OpCode {
    /// Convert byte to opcode if it's a known opcode
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(OpCode::Op0),
            0x4c => Some(OpCode::OpPushData1),
            0x76 => Some(OpCode::OpDup),
            0x87 => Some(OpCode::OpEqual),
            0x88 => Some(OpCode::OpEqualVerify),
            0xa9 => Some(OpCode::OpHash160),
            0xac => Some(OpCode::OpCheckSig),
            0xae => Some(OpCode::OpCheckMultiSig),
            _ => None,
        }
    }
}

/// Script type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptType {
    /// Pay-to-Public-Key-Hash (single signature)
    P2PKH,
    /// Pay-to-Script-Hash (multi-signature or other scripts)
    P2SH,
}

/// A script is a sequence of opcodes and data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Script {
    pub bytes: Vec<u8>,
}

impl Script {
    /// Create a new script from raw bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Create a P2PKH script: OP_DUP OP_HASH160 <20-byte-addr> OP_EQUALVERIFY OP_CHECKSIG
    pub fn p2pkh(address: &[u8; 20]) -> Self {
        let mut script = Vec::with_capacity(25);
        script.push(OpCode::OpDup as u8);
        script.push(OpCode::OpHash160 as u8);
        script.push(0x14); // Push 20 bytes
        script.extend_from_slice(address);
        script.push(OpCode::OpEqualVerify as u8);
        script.push(OpCode::OpCheckSig as u8);
        Self::new(script)
    }

    /// Create a P2SH script: OP_HASH160 <20-byte-script-hash> OP_EQUAL
    pub fn p2sh(script_hash: &[u8; 20]) -> Self {
        let mut script = Vec::with_capacity(23);
        script.push(OpCode::OpHash160 as u8);
        script.push(0x14); // Push 20 bytes
        script.extend_from_slice(script_hash);
        script.push(OpCode::OpEqual as u8);
        Self::new(script)
    }

    /// Create a bare M-of-N multisig redeem script
    /// Format: <M> <pubkey1> <pubkey2> ... <pubkeyN> <N> OP_CHECKMULTISIG
    pub fn multisig(m: u8, pubkeys: &[[u8; 32]]) -> Result<Self, ScriptError> {
        let n = pubkeys.len() as u8;

        if m == 0 || n == 0 {
            return Err(ScriptError::InvalidMultisig("M and N must be > 0".into()));
        }
        if m > n {
            return Err(ScriptError::InvalidMultisig("M cannot exceed N".into()));
        }
        if n > 15 {
            return Err(ScriptError::InvalidMultisig("N cannot exceed 15".into()));
        }

        let mut script = Vec::new();

        // Push M (using OP_1 through OP_15, which are 0x51-0x5f)
        script.push(0x50 + m);

        // Push each public key (32 bytes each)
        for pubkey in pubkeys {
            script.push(0x20); // Push 32 bytes
            script.extend_from_slice(pubkey);
        }

        // Push N
        script.push(0x50 + n);

        // OP_CHECKMULTISIG
        script.push(OpCode::OpCheckMultiSig as u8);

        Ok(Self::new(script))
    }

    /// Determine the script type
    pub fn script_type(&self) -> Option<ScriptType> {
        if self.bytes.len() == 25
            && self.bytes[0] == OpCode::OpDup as u8
            && self.bytes[1] == OpCode::OpHash160 as u8
            && self.bytes[2] == 0x14
            && self.bytes[23] == OpCode::OpEqualVerify as u8
            && self.bytes[24] == OpCode::OpCheckSig as u8
        {
            return Some(ScriptType::P2PKH);
        }

        if self.bytes.len() == 23
            && self.bytes[0] == OpCode::OpHash160 as u8
            && self.bytes[1] == 0x14
            && self.bytes[22] == OpCode::OpEqual as u8
        {
            return Some(ScriptType::P2SH);
        }

        None
    }

    /// Extract the 20-byte hash from a P2PKH or P2SH script
    pub fn extract_hash(&self) -> Option<[u8; 20]> {
        match self.script_type() {
            Some(ScriptType::P2PKH) => {
                // P2PKH: hash is at bytes 3..23
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&self.bytes[3..23]);
                Some(hash)
            }
            Some(ScriptType::P2SH) => {
                // P2SH: hash is at bytes 2..22
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&self.bytes[2..22]);
                Some(hash)
            }
            None => None,
        }
    }

    /// Parse a multisig script to extract M, N, and public keys
    pub fn parse_multisig(&self) -> Result<(u8, Vec<[u8; 32]>), ScriptError> {
        if self.bytes.is_empty() {
            return Err(ScriptError::InvalidMultisig("Empty script".into()));
        }

        let mut pos = 0;

        // Read M
        if pos >= self.bytes.len() {
            return Err(ScriptError::InvalidMultisig("Missing M value".into()));
        }
        let m_byte = self.bytes[pos];
        if m_byte < 0x51 || m_byte > 0x5f {
            return Err(ScriptError::InvalidMultisig("Invalid M value (must be OP_1 to OP_15)".into()));
        }
        let m = m_byte - 0x50;
        pos += 1;

        // Read public keys
        let mut pubkeys = Vec::new();
        while pos < self.bytes.len() {
            let op = self.bytes[pos];

            // If we hit the N value (OP_1 through OP_15), we're done with pubkeys
            if op >= 0x51 && op <= 0x5f {
                break;
            }

            // Expect push of 32 bytes
            if op != 0x20 {
                return Err(ScriptError::InvalidMultisig(
                    format!("Expected 32-byte pubkey push, got 0x{:02x}", op)
                ));
            }
            pos += 1;

            if pos + 32 > self.bytes.len() {
                return Err(ScriptError::InvalidMultisig("Incomplete pubkey data".into()));
            }

            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(&self.bytes[pos..pos + 32]);
            pubkeys.push(pubkey);
            pos += 32;
        }

        // Read N
        if pos >= self.bytes.len() {
            return Err(ScriptError::InvalidMultisig("Missing N value".into()));
        }
        let n_byte = self.bytes[pos];
        if n_byte < 0x51 || n_byte > 0x5f {
            return Err(ScriptError::InvalidMultisig("Invalid N value (must be OP_1 to OP_15)".into()));
        }
        let n = n_byte - 0x50;
        pos += 1;

        // Verify OP_CHECKMULTISIG
        if pos >= self.bytes.len() || self.bytes[pos] != OpCode::OpCheckMultiSig as u8 {
            return Err(ScriptError::InvalidMultisig("Missing OP_CHECKMULTISIG".into()));
        }
        pos += 1;

        // Should be at end of script
        if pos != self.bytes.len() {
            return Err(ScriptError::InvalidMultisig("Extra data after OP_CHECKMULTISIG".into()));
        }

        // Validate counts
        if pubkeys.len() != n as usize {
            return Err(ScriptError::InvalidMultisig(
                format!("Pubkey count {} doesn't match N value {}", pubkeys.len(), n)
            ));
        }
        if m > n {
            return Err(ScriptError::InvalidMultisig("M cannot exceed N".into()));
        }

        Ok((m, pubkeys))
    }

    /// Calculate BLAKE3 hash truncated to 20 bytes (used for script hashing)
    pub fn hash160(&self) -> [u8; 20] {
        let hash = blake3::hash(&self.bytes);
        let mut result = [0u8; 20];
        result.copy_from_slice(&hash.as_bytes()[..20]);
        result
    }
}

/// Script execution errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum ScriptError {
    #[error("Invalid multisig script: {0}")]
    InvalidMultisig(String),

    #[error("Script execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Stack underflow")]
    StackUnderflow,

    #[error("Script verification failed")]
    VerificationFailed,
}

/// Resource limits for script execution to prevent DoS attacks
pub mod limits {
    /// Maximum number of operations allowed in a single script execution
    pub const MAX_OPERATIONS: usize = 10_000;

    /// Maximum stack depth to prevent memory exhaustion
    pub const MAX_STACK_DEPTH: usize = 1_000;

    /// Maximum execution time for a single script (in milliseconds)
    pub const MAX_EXECUTION_TIME_MS: u128 = 1_000;
}

/// Script interpreter for validating transactions with resource limits
pub struct ScriptInterpreter {
    stack: Vec<Vec<u8>>,
    /// Number of operations executed so far
    op_count: usize,
    /// Timestamp when execution started
    start_time: std::time::Instant,
}

impl ScriptInterpreter {
    /// Create a new script interpreter
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            op_count: 0,
            start_time: std::time::Instant::now(),
        }
    }

    /// Check resource limits and increment operation counter
    fn check_limits(&mut self) -> Result<(), ScriptError> {
        // Increment operation count
        self.op_count += 1;

        // Check operation limit
        if self.op_count > limits::MAX_OPERATIONS {
            return Err(ScriptError::ExecutionFailed(
                format!("Operation limit exceeded: {} > {}", self.op_count, limits::MAX_OPERATIONS)
            ));
        }

        // Check stack depth limit
        if self.stack.len() > limits::MAX_STACK_DEPTH {
            return Err(ScriptError::ExecutionFailed(
                format!("Stack depth limit exceeded: {} > {}", self.stack.len(), limits::MAX_STACK_DEPTH)
            ));
        }

        // Check execution time limit
        let elapsed = self.start_time.elapsed().as_millis();
        if elapsed > limits::MAX_EXECUTION_TIME_MS {
            return Err(ScriptError::ExecutionFailed(
                format!("Execution time limit exceeded: {} ms > {} ms", elapsed, limits::MAX_EXECUTION_TIME_MS)
            ));
        }

        Ok(())
    }

    /// Execute a P2PKH script verification
    ///
    /// Validates: scriptSig (signature + pubkey) satisfies scriptPubKey
    ///
    /// # Arguments
    /// * `signature` - Input signature data (64 bytes for Ed25519)
    /// * `pubkey` - Public key (32 bytes for Ed25519)
    /// * `script_pubkey` - Output script (P2PKH format)
    /// * `sighash` - The signature hash (already includes chain ID and tx data)
    pub fn verify_p2pkh(
        &mut self,
        signature: &[u8],
        pubkey: &[u8],
        script_pubkey: &Script,
        sighash: &[u8],
    ) -> Result<(), ScriptError> {
        // Check resource limits
        self.check_limits()?;

        // Extract the expected address hash from scriptPubKey
        let expected_hash = script_pubkey
            .extract_hash()
            .ok_or_else(|| ScriptError::ExecutionFailed("Not a P2PKH script".into()))?;

        // Verify pubkey length (Ed25519 = 32 bytes)
        if pubkey.len() != 32 {
            return Err(ScriptError::InvalidSignature);
        }

        // Hash the pubkey and verify it matches the address
        let pubkey_hash = blake3::hash(pubkey);
        let pubkey_hash_20 = &pubkey_hash.as_bytes()[..20];

        if pubkey_hash_20 != expected_hash {
            return Err(ScriptError::VerificationFailed);
        }

        // Verify signature (Ed25519 = 64 bytes)
        if signature.len() != 64 {
            return Err(ScriptError::InvalidSignature);
        }

        // Parse Ed25519 signature and public key
        use ed25519_dalek::{Signature, VerifyingKey};

        let sig = Signature::from_slice(signature)
            .map_err(|_| ScriptError::InvalidSignature)?;

        let vk = VerifyingKey::from_bytes(
            pubkey.try_into()
                .map_err(|_| ScriptError::InvalidSignature)?
        ).map_err(|_| ScriptError::InvalidSignature)?;

        // Verify the signature against the sighash using strict verification
        // SECURITY FIX (CRIT-002): verify_strict() prevents signature malleability
        vk.verify_strict(sighash, &sig)
            .map_err(|_| ScriptError::SignatureVerificationFailed)?;

        Ok(())
    }

    /// Execute a P2SH script verification
    ///
    /// For P2SH, the scriptSig contains signatures followed by the redeem script.
    /// The scriptPubKey contains the hash of the redeem script.
    ///
    /// # Arguments
    /// * `signatures` - Array of signatures
    /// * `redeem_script` - The actual script being redeemed (multisig script)
    /// * `script_pubkey` - Output script (P2SH format - contains script hash)
    /// * `sighash` - The signature hash (already includes chain ID and tx data)
    pub fn verify_p2sh(
        &mut self,
        signatures: &[Vec<u8>],
        redeem_script: &Script,
        script_pubkey: &Script,
        sighash: &[u8],
    ) -> Result<(), ScriptError> {
        // Check resource limits
        self.check_limits()?;

        // Extract expected script hash from scriptPubKey
        let expected_script_hash = script_pubkey
            .extract_hash()
            .ok_or_else(|| ScriptError::ExecutionFailed("Not a P2SH script".into()))?;

        // Hash the redeem script and verify it matches
        let actual_script_hash = redeem_script.hash160();
        if actual_script_hash != expected_script_hash {
            return Err(ScriptError::VerificationFailed);
        }

        // Parse the redeem script as a multisig script
        let (required_sigs, pubkeys) = redeem_script.parse_multisig()?;

        // Verify we have enough signatures
        if signatures.len() < required_sigs as usize {
            return Err(ScriptError::ExecutionFailed(
                format!("Need {} signatures, got {}", required_sigs, signatures.len())
            ));
        }

        // Verify signatures against public keys
        // In Bitcoin, signatures must be in the same order as pubkeys (or a subset)
        let mut sig_index = 0;
        let mut verified_count = 0;

        for pubkey in &pubkeys {
            if sig_index >= signatures.len() {
                break;
            }

            let signature = &signatures[sig_index];

            // Try to verify this signature with this pubkey
            if self.verify_signature_with_pubkey(signature, pubkey, sighash).is_ok() {
                verified_count += 1;
                sig_index += 1;
            }
        }

        // Check if we verified enough signatures
        if verified_count < required_sigs as usize {
            return Err(ScriptError::SignatureVerificationFailed);
        }

        Ok(())
    }

    /// Verify a single signature against a public key
    fn verify_signature_with_pubkey(
        &mut self,
        signature: &[u8],
        pubkey: &[u8; 32],
        sighash: &[u8],
    ) -> Result<(), ScriptError> {
        use ed25519_dalek::{Signature, VerifyingKey};

        // Check resource limits (signature verification counts as an operation)
        if self.op_count > limits::MAX_OPERATIONS {
            return Err(ScriptError::ExecutionFailed(
                format!("Operation limit exceeded during signature verification")
            ));
        }

        if signature.len() != 64 {
            return Err(ScriptError::InvalidSignature);
        }

        let sig = Signature::from_slice(signature)
            .map_err(|_| ScriptError::InvalidSignature)?;

        let vk = VerifyingKey::from_bytes(pubkey)
            .map_err(|_| ScriptError::InvalidSignature)?;

        // SECURITY FIX (CRIT-002): verify_strict() prevents signature malleability
        vk.verify_strict(sighash, &sig)
            .map_err(|_| ScriptError::SignatureVerificationFailed)?;

        Ok(())
    }

    /// Clear the stack (useful for testing or reusing the interpreter)
    pub fn clear(&mut self) {
        self.stack.clear();
    }
}

impl Default for ScriptInterpreter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2pkh_script() {
        let addr = [0x42u8; 20];
        let script = Script::p2pkh(&addr);

        assert_eq!(script.script_type(), Some(ScriptType::P2PKH));
        assert_eq!(script.extract_hash(), Some(addr));
    }

    #[test]
    fn test_p2sh_script() {
        let script_hash = [0x99u8; 20];
        let script = Script::p2sh(&script_hash);

        assert_eq!(script.script_type(), Some(ScriptType::P2SH));
        assert_eq!(script.extract_hash(), Some(script_hash));
    }

    #[test]
    fn test_multisig_2_of_3() {
        let pubkey1 = [0x01u8; 32];
        let pubkey2 = [0x02u8; 32];
        let pubkey3 = [0x03u8; 32];
        let pubkeys = [pubkey1, pubkey2, pubkey3];

        let script = Script::multisig(2, &pubkeys).unwrap();
        let (m, parsed_pubkeys) = script.parse_multisig().unwrap();

        assert_eq!(m, 2);
        assert_eq!(parsed_pubkeys.len(), 3);
        assert_eq!(parsed_pubkeys[0], pubkey1);
        assert_eq!(parsed_pubkeys[1], pubkey2);
        assert_eq!(parsed_pubkeys[2], pubkey3);
    }

    #[test]
    fn test_multisig_invalid_m_greater_than_n() {
        let pubkey1 = [0x01u8; 32];
        let pubkey2 = [0x02u8; 32];
        let pubkeys = [pubkey1, pubkey2];

        let result = Script::multisig(3, &pubkeys);
        assert!(result.is_err());
    }

    #[test]
    fn test_script_hash() {
        let pubkey1 = [0x01u8; 32];
        let pubkey2 = [0x02u8; 32];
        let pubkeys = [pubkey1, pubkey2];

        let redeem_script = Script::multisig(2, &pubkeys).unwrap();
        let script_hash = redeem_script.hash160();

        // Script hash should be 20 bytes
        assert_eq!(script_hash.len(), 20);

        // Creating P2SH script with this hash
        let p2sh = Script::p2sh(&script_hash);
        assert_eq!(p2sh.extract_hash(), Some(script_hash));
    }
}
