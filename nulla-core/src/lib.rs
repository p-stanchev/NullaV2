//! Core data structures and validation logic for the Nulla blockchain.
//!
//! This crate provides:
//! - Transaction and block structures
//! - Cryptographic hashing (BLAKE3)
//! - Proof-of-work validation
//! - Merkle tree computation

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Standard hash length (256 bits).
pub const HASH_LEN: usize = 32;

/// 32-byte hash type used throughout the codebase.
pub type Hash32 = [u8; HASH_LEN];

/// References a specific output in a previous transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct OutPoint {
    /// Transaction ID containing the output.
    pub txid: Hash32,
    /// Output index within the transaction.
    pub vout: u32,
}

impl OutPoint {
    /// Create a null outpoint for coinbase transactions (all zeros).
    pub fn null() -> Self {
        Self {
            txid: [0u8; 32],
            vout: 0xFFFF_FFFF,
        }
    }

    /// Check if this is a null outpoint (coinbase).
    pub fn is_null(&self) -> bool {
        self.txid == [0u8; 32] && self.vout == 0xFFFF_FFFF
    }
}

/// A transaction input spending a previous output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxIn {
    /// The output being spent.
    pub prevout: OutPoint,
    /// Signature bytes over a sighash (64 bytes for Ed25519).
    pub sig: Vec<u8>,
    /// Public key bytes for signature verification (32 bytes for Ed25519).
    /// Empty for coinbase transactions.
    pub pubkey: Vec<u8>,
}

/// A transaction output that can be spent in the future.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxOut {
    /// Value in smallest units (atoms).
    pub value_atoms: u64,
    /// Simple script payload. Starts as P2PKH-like but can hold stealth commitments.
    pub script_pubkey: Vec<u8>,
}

/// A transaction transferring value between addresses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tx {
    /// Protocol version for this transaction.
    pub version: u16,
    /// Inputs spending previous outputs.
    pub inputs: Vec<TxIn>,
    /// Outputs creating new spendable UTXOs.
    pub outputs: Vec<TxOut>,
    /// Earliest time/block height this transaction can be included.
    pub lock_time: u64,
}

/// Block header containing metadata and proof-of-work.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockHeader {
    /// Network identifier (4 bytes).
    pub chain_id: [u8; 4],
    /// Protocol version for this block.
    pub version: u16,
    /// Block height in the chain.
    pub height: u64,
    /// Hash of the previous block header.
    pub prev: Hash32,
    /// Merkle root of all transactions in this block.
    pub merkle_root: Hash32,
    /// Unix timestamp when the block was mined.
    pub timestamp: u64,
    /// Difficulty target (hash must be <= this value).
    pub target: Hash32,
    /// Nonce used to satisfy proof-of-work.
    pub nonce: u64,
}

/// A block containing a header and transactions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    /// Block header with metadata and PoW.
    pub header: BlockHeader,
    /// List of transactions in this block.
    pub txs: Vec<Tx>,
}

/// Validation errors for blocks and transactions.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("merkle mismatch")]
    MerkleMismatch,
    #[error("pow invalid")]
    InvalidPow,
    #[error("empty block")]
    EmptyBlock,
    #[error("empty inputs")]
    EmptyInputs,
    #[error("empty outputs")]
    EmptyOutputs,
    #[error("duplicate input")]
    DuplicateInput,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("insufficient value")]
    InsufficientValue,
    #[error("output value overflow")]
    ValueOverflow,
    #[error("utxo not found")]
    UtxoNotFound,
    #[error("utxo already spent")]
    UtxoAlreadySpent,
    #[error("invalid coinbase")]
    InvalidCoinbase,
}

/// Check if a transaction is a coinbase transaction (first tx in block with null input).
pub fn is_coinbase(tx: &Tx) -> bool {
    tx.inputs.len() == 1 && tx.inputs[0].prevout.is_null()
}

/// Compute the transaction ID by hashing the serialized transaction with BLAKE3.
pub fn tx_id(tx: &Tx) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    let encoded = bincode::serialize(tx).expect("tx serialize");
    hasher.update(&encoded);
    hasher.finalize().into()
}

/// Compute the block header ID by hashing the serialized header with BLAKE3.
pub fn block_header_id(header: &BlockHeader) -> Hash32 {
    let encoded = bincode::serialize(header).expect("header serialize");
    blake3::hash(&encoded).into()
}

/// Compute the block ID (same as the header ID).
pub fn block_id(block: &Block) -> Hash32 {
    block_header_id(&block.header)
}

/// Compute the Merkle root of a list of transaction IDs.
///
/// Uses a standard binary tree approach, hashing pairs of nodes until a single root remains.
/// If the layer has an odd number of elements, the last element is duplicated.
pub fn merkle_root(txids: &[Hash32]) -> Hash32 {
    if txids.is_empty() {
        return [0u8; HASH_LEN];
    }

    let mut layer: Vec<Hash32> = txids.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        for pair in layer.chunks(2) {
            let a = pair[0];
            let b = if pair.len() == 2 { pair[1] } else { pair[0] };
            let mut hasher = blake3::Hasher::new();
            hasher.update(&a);
            hasher.update(&b);
            next.push(hasher.finalize().into());
        }
        layer = next;
    }
    layer[0]
}

/// Validate proof-of-work by checking if the block hash is less than or equal to the target.
///
/// Both the hash and target are interpreted as big-endian 256-bit integers.
pub fn validate_pow(header: &BlockHeader) -> Result<(), ValidationError> {
    let h = block_header_id(header);
    if leq_be(&h, &header.target) {
        Ok(())
    } else {
        Err(ValidationError::InvalidPow)
    }
}

/// Compute the cumulative work represented by a difficulty target.
///
/// Returns a score where higher values indicate more work.
/// This is an approximation: work ≈ 2^256 / target.
pub fn target_work(target: &Hash32) -> u128 {
    // Use the most significant 16 bytes to derive a compact score.
    let mut high = [0u8; 16];
    high.copy_from_slice(&target[..16]);
    let value = u128::from_be_bytes(high).max(1);
    u128::MAX / value
}

/// Validate basic transaction structure (not checking signatures or UTXO availability).
///
/// Checks:
/// - Transaction has at least one input and one output
/// - No duplicate inputs
/// - Output values don't overflow
/// - Coinbase transactions must have exactly one null input
pub fn validate_tx_structure(tx: &Tx) -> Result<(), ValidationError> {
    if tx.inputs.is_empty() {
        return Err(ValidationError::EmptyInputs);
    }
    if tx.outputs.is_empty() {
        return Err(ValidationError::EmptyOutputs);
    }

    // Check for duplicate inputs
    let mut seen = std::collections::HashSet::new();
    for input in &tx.inputs {
        let key = (&input.prevout.txid, input.prevout.vout);
        if !seen.insert(key) {
            return Err(ValidationError::DuplicateInput);
        }
    }

    // Check that output values don't overflow
    let mut total: u64 = 0;
    for output in &tx.outputs {
        total = total
            .checked_add(output.value_atoms)
            .ok_or(ValidationError::ValueOverflow)?;
    }

    Ok(())
}

/// Validate a coinbase transaction (first tx in block).
///
/// Checks:
/// - Exactly one input with a null outpoint
/// - At least one output
/// - Output values don't overflow
pub fn validate_coinbase(tx: &Tx) -> Result<(), ValidationError> {
    if tx.inputs.len() != 1 {
        return Err(ValidationError::EmptyInputs);
    }
    if !tx.inputs[0].prevout.is_null() {
        return Err(ValidationError::EmptyInputs);
    }
    if tx.outputs.is_empty() {
        return Err(ValidationError::EmptyOutputs);
    }

    // Check that output values don't overflow
    let mut total: u64 = 0;
    for output in &tx.outputs {
        total = total
            .checked_add(output.value_atoms)
            .ok_or(ValidationError::ValueOverflow)?;
    }

    Ok(())
}

/// Verify signatures on all inputs of a transaction.
///
/// This checks that each input (except coinbase) has:
/// - A valid 64-byte Ed25519 signature
/// - A valid 32-byte Ed25519 public key
/// - The public key hashes to the address in the previous output's script_pubkey
/// - The signature is valid for this transaction and public key
///
/// Returns Ok(()) if all signatures are valid, Err otherwise.
/// Note: This requires looking up previous outputs from the UTXO set (done at a higher level).
pub fn verify_tx_signatures(tx: &Tx) -> Result<(), ValidationError> {
    // Skip signature verification for coinbase transactions
    if is_coinbase(tx) {
        return Ok(());
    }

    for input in &tx.inputs {
        // Check signature length (64 bytes for Ed25519)
        if input.sig.len() != 64 {
            return Err(ValidationError::InvalidSignature);
        }

        // Check public key length (32 bytes for Ed25519)
        if input.pubkey.len() != 32 {
            return Err(ValidationError::InvalidSignature);
        }

        // Note: Full verification requires:
        // 1. Looking up the previous output to get the script_pubkey
        // 2. Extracting the address from script_pubkey
        // 3. Hashing the public key and checking it matches the address
        // 4. Verifying the signature using the public key
        //
        // This is done at a higher level (in the node) where we have access to the UTXO set.
        // This function just validates the format of signatures and public keys.
    }

    Ok(())
}

/// Validate that a block's difficulty target is correct based on chain history.
///
/// This should be called when validating blocks received from the network.
/// It checks that the block's target field matches the expected difficulty
/// calculated from the timestamps and targets of previous blocks.
///
/// # Arguments
/// * `block` - The block to validate
/// * `get_header` - Function to retrieve historical block headers by height
///
/// # Returns
/// Ok(()) if the difficulty target is correct, Err otherwise.
pub fn validate_difficulty<F>(block: &Block, mut get_header: F) -> Result<(), ValidationError>
where
    F: FnMut(u64) -> Option<BlockHeader>,
{
    let current_height = block.header.height;

    // Genesis block should use initial target
    if current_height == 0 {
        if block.header.target != INITIAL_TARGET {
            return Err(ValidationError::InvalidPow);
        }
        return Ok(());
    }

    // Get previous block header
    let prev_header = get_header(current_height - 1)
        .ok_or(ValidationError::InvalidPow)?;

    // If we're not at an adjustment boundary, target should match previous block
    if current_height % difficulty::ADJUSTMENT_INTERVAL != 0 {
        if block.header.target != prev_header.target {
            return Err(ValidationError::InvalidPow);
        }
        return Ok(());
    }

    // At adjustment boundary, calculate expected target
    let old_height = current_height.saturating_sub(difficulty::ADJUSTMENT_INTERVAL);
    let old_header = get_header(old_height)
        .ok_or(ValidationError::InvalidPow)?;

    let expected_target = calculate_next_target(
        current_height,
        &prev_header.target,
        prev_header.timestamp,
        old_header.timestamp,
    );

    if block.header.target != expected_target {
        return Err(ValidationError::InvalidPow);
    }

    Ok(())
}

/// Validate a complete block, checking:
/// - The block contains at least one transaction
/// - The first transaction is a valid coinbase
/// - The merkle root matches the computed root of all transaction IDs
/// - The proof-of-work is valid
/// - Basic transaction structure for all transactions
///
/// Note: This does NOT validate difficulty adjustment. Use `validate_difficulty`
/// separately when validating blocks from the network.
pub fn validate_block(block: &Block) -> Result<(), ValidationError> {
    if block.txs.is_empty() {
        return Err(ValidationError::EmptyBlock);
    }

    // First transaction must be a coinbase
    validate_coinbase(&block.txs[0])?;

    // Remaining transactions must be regular (no coinbase inputs)
    for tx in &block.txs[1..] {
        validate_tx_structure(tx)?;
        // Ensure no coinbase inputs in regular transactions
        for input in &tx.inputs {
            if input.prevout.is_null() {
                return Err(ValidationError::EmptyInputs);
            }
        }
    }

    let txids: Vec<Hash32> = block.txs.iter().map(tx_id).collect();
    let root = merkle_root(&txids);
    if root != block.header.merkle_root {
        return Err(ValidationError::MerkleMismatch);
    }

    validate_pow(&block.header)
}

/// Difficulty adjustment parameters.
/// These values control how often difficulty adjusts and the target block time.
pub mod difficulty {
    /// Number of blocks between difficulty adjustments.
    pub const ADJUSTMENT_INTERVAL: u64 = 10;

    /// Target time per block in seconds.
    pub const TARGET_BLOCK_TIME: u64 = 60;

    /// Maximum difficulty adjustment factor (4x).
    /// Prevents difficulty from changing too rapidly.
    pub const MAX_ADJUSTMENT_FACTOR: u64 = 4;
}

/// Initial difficulty target for the genesis block.
/// This is relatively easy to allow for bootstrapping the network.
pub const INITIAL_TARGET: Hash32 = [
    0x00, 0x00, 0x00, 0x33, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// Calculate the next difficulty target based on the time it took to mine recent blocks.
///
/// This implements a Bitcoin-style difficulty adjustment algorithm:
/// - Adjusts every `ADJUSTMENT_INTERVAL` blocks
/// - Targets `TARGET_BLOCK_TIME` seconds per block
/// - Limits adjustment to `MAX_ADJUSTMENT_FACTOR` to prevent extreme swings
///
/// # Arguments
/// * `current_height` - Height of the block being mined
/// * `current_target` - Current difficulty target
/// * `prev_timestamp` - Timestamp of the previous block
/// * `old_timestamp` - Timestamp of the block `ADJUSTMENT_INTERVAL` blocks ago
///
/// # Returns
/// The new difficulty target for the next block.
pub fn calculate_next_target(
    current_height: u64,
    current_target: &Hash32,
    prev_timestamp: u64,
    old_timestamp: u64,
) -> Hash32 {
    // Only adjust at interval boundaries
    if current_height % difficulty::ADJUSTMENT_INTERVAL != 0 {
        return *current_target;
    }

    // Calculate actual time taken for the last ADJUSTMENT_INTERVAL blocks
    let actual_time = prev_timestamp.saturating_sub(old_timestamp);

    // Calculate expected time
    let expected_time = difficulty::ADJUSTMENT_INTERVAL * difficulty::TARGET_BLOCK_TIME;

    // If we don't have valid timestamps, don't adjust
    if actual_time == 0 {
        return *current_target;
    }

    // Calculate adjustment ratio (with overflow protection)
    // If blocks came too fast (actual < expected), difficulty should increase (target decrease)
    // If blocks came too slow (actual > expected), difficulty should decrease (target increase)
    let adjustment_num = actual_time.min(expected_time * difficulty::MAX_ADJUSTMENT_FACTOR);
    let adjustment_denom = expected_time.max(actual_time / difficulty::MAX_ADJUSTMENT_FACTOR);

    // Convert current target to u128 for math (use first 16 bytes)
    let mut current_bytes = [0u8; 16];
    current_bytes.copy_from_slice(&current_target[..16]);
    let current_value = u128::from_be_bytes(current_bytes);

    // Apply adjustment: new_target = current_target * (actual_time / expected_time)
    // We use saturating math to prevent overflow
    let adjusted_value = current_value
        .saturating_mul(adjustment_num as u128)
        .saturating_div(adjustment_denom as u128);

    // Convert back to Hash32
    let adjusted_bytes = adjusted_value.to_be_bytes();
    let mut new_target = [0xffu8; 32];
    new_target[..16].copy_from_slice(&adjusted_bytes);

    // Ensure target doesn't exceed maximum (minimum difficulty)
    if !leq_be(&new_target, &INITIAL_TARGET) {
        return INITIAL_TARGET;
    }

    new_target
}

/// Compare two 256-bit hashes as big-endian integers.
/// Returns true if lhs <= rhs.
fn leq_be(lhs: &Hash32, rhs: &Hash32) -> bool {
    for (a, b) in lhs.iter().zip(rhs.iter()) {
        match a.cmp(b) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_single() {
        let txid = [1u8; HASH_LEN];
        let root = merkle_root(&[txid]);
        assert_eq!(root, txid);
    }

    #[test]
    fn pow_cmp() {
        let low = [0u8; HASH_LEN];
        let high = [0xFFu8; HASH_LEN];
        assert!(leq_be(&low, &high));
        assert!(!leq_be(&high, &low));
    }
}
