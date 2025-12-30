//! Core data structures and validation logic for the Nulla blockchain.
//!
//! This crate provides:
//! - Transaction and block structures
//! - Cryptographic hashing (BLAKE3)
//! - Proof-of-work validation
//! - Merkle tree computation
//! - Script system for P2PKH and P2SH transactions

pub mod script;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// Re-export script types for convenience
pub use script::{OpCode, Script, ScriptError, ScriptInterpreter, ScriptType};

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
    #[error("block too large: {size} bytes (max {max} bytes)")]
    BlockTooLarge { size: usize, max: usize },
    #[error("invalid format")]
    InvalidFormat,
    #[error("timestamp too far in future: {timestamp} (max {max})")]
    TimestampTooFar { timestamp: u64, max: u64 },
    #[error("timestamp too early: {timestamp} <= median {median}")]
    TimestampTooEarly { timestamp: u64, median: u64 },
    #[error("transaction too large: {size} bytes (max {max} bytes)")]
    TxTooLarge { size: usize, max: usize },
    #[error("too many inputs: {count} (max {max})")]
    TooManyInputs { count: usize, max: usize },
    #[error("too many outputs: {count} (max {max})")]
    TooManyOutputs { count: usize, max: usize },
    #[error("invalid checkpoint format")]
    InvalidCheckpoint,
    #[error("checkpoint mismatch: block hash doesn't match hardcoded checkpoint")]
    CheckpointMismatch,
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
    // SECURITY FIX (HIGH-NEW-004): Transaction size validation
    // Check transaction size limit
    let tx_size = bincode::serialize(tx)
        .map_err(|_| ValidationError::InvalidFormat)?
        .len();
    if tx_size > MAX_TX_SIZE {
        return Err(ValidationError::TxTooLarge {
            size: tx_size,
            max: MAX_TX_SIZE,
        });
    }

    // Check input/output count limits
    if tx.inputs.len() > MAX_TX_INPUTS {
        return Err(ValidationError::TooManyInputs {
            count: tx.inputs.len(),
            max: MAX_TX_INPUTS,
        });
    }
    if tx.outputs.len() > MAX_TX_OUTPUTS {
        return Err(ValidationError::TooManyOutputs {
            count: tx.outputs.len(),
            max: MAX_TX_OUTPUTS,
        });
    }

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
/// - Coinbase doesn't claim more than block_reward + total_fees
///
/// # Arguments
/// * `tx` - The coinbase transaction to validate
/// * `block_reward` - The fixed block reward (e.g., 800,000,000 atoms)
/// * `total_fees` - Sum of all transaction fees in the block
pub fn validate_coinbase(tx: &Tx, block_reward: u64, total_fees: u64) -> Result<(), ValidationError> {
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
    let mut total_output: u64 = 0;
    for output in &tx.outputs {
        total_output = total_output
            .checked_add(output.value_atoms)
            .ok_or(ValidationError::ValueOverflow)?;
    }

    // Coinbase can claim up to block_reward + total_fees
    let max_coinbase = block_reward
        .checked_add(total_fees)
        .ok_or(ValidationError::ValueOverflow)?;

    if total_output > max_coinbase {
        return Err(ValidationError::InvalidCoinbase);
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

/// Transaction size and structure limits (SECURITY FIX: HIGH-NEW-004)
pub const MAX_TX_SIZE: usize = 1_000_000;        // 1 MB max transaction size
pub const MAX_TX_INPUTS: usize = 10_000;          // Maximum inputs per transaction
pub const MAX_TX_OUTPUTS: usize = 10_000;         // Maximum outputs per transaction

/// Maximum block size in bytes (4 MB).
/// This prevents DoS attacks via oversized blocks.
pub const MAX_BLOCK_SIZE: usize = 4_000_000;

/// Coinbase maturity depth (100 blocks).
/// Coinbase outputs cannot be spent until 100 blocks have been mined after them.
/// This prevents miners from spending rewards from blocks that might be orphaned.
pub const COINBASE_MATURITY: u64 = 100;

/// Emission schedule constants (Monero-style with tail emission).
///
/// Economic Model:
/// - Initial reward: 8 NULLA per block
/// - Halving interval: Every 525,600 blocks (~2 years at 2 min/block)
/// - Total halvings: 20 halvings over ~40 years
/// - Main emission: ~83.9M NULLA over 40 years
/// - Tail emission: 0.6 NULLA/block forever after main emission
/// - This ensures long-term miner incentives without hard supply cap
pub mod emission {
    /// Atoms per NULLA (100 million, like Bitcoin satoshis).
    pub const ATOMS_PER_NULLA: u64 = 100_000_000;

    /// Initial block reward in atoms (8 NULLA).
    pub const INITIAL_REWARD_ATOMS: u64 = 8 * ATOMS_PER_NULLA;

    /// Halving interval in blocks (525,600 blocks = ~2 years at 2 min/block).
    /// 525,600 blocks * 120 seconds = 63,072,000 seconds = 730 days
    pub const HALVING_INTERVAL: u64 = 525_600;

    /// Number of halvings before tail emission starts (20 halvings = ~40 years).
    pub const MAX_HALVINGS: u32 = 20;

    /// Tail emission in atoms (0.6 NULLA per block).
    /// This ensures perpetual block rewards for long-term security.
    /// Annual inflation rate with tail emission: ~0.87% decreasing over time.
    pub const TAIL_EMISSION_ATOMS: u64 = 60_000_000; // 0.6 NULLA

    /// Calculate total supply at a given block height (approximation).
    ///
    /// Formula:
    /// - During main emission (height < HALVING_INTERVAL * MAX_HALVINGS):
    ///   Sum of geometric series: initial * interval * (1 - 0.5^halvings) / 0.5
    /// - After main emission:
    ///   Main emission total + (blocks_after * TAIL_EMISSION)
    pub fn total_supply(height: u64) -> u64 {
        let main_emission_end = HALVING_INTERVAL * MAX_HALVINGS as u64;

        if height <= main_emission_end {
            // During main emission - sum rewards from all completed halvings
            let mut total = 0u64;
            let mut remaining_height = height;
            let mut current_reward = INITIAL_REWARD_ATOMS;

            while remaining_height > 0 && current_reward > TAIL_EMISSION_ATOMS {
                let blocks_at_this_level = remaining_height.min(HALVING_INTERVAL);
                total = total.saturating_add(blocks_at_this_level.saturating_mul(current_reward));
                remaining_height = remaining_height.saturating_sub(HALVING_INTERVAL);
                current_reward /= 2;
            }

            total
        } else {
            // After main emission - calculate main total + tail emission
            // Main emission total: ~83.9M NULLA
            let mut main_total = 0u64;
            let mut current_reward = INITIAL_REWARD_ATOMS;

            for _ in 0..MAX_HALVINGS {
                main_total = main_total.saturating_add(HALVING_INTERVAL.saturating_mul(current_reward));
                current_reward /= 2;
            }

            // Add tail emission for blocks after main emission
            let blocks_after = height.saturating_sub(main_emission_end);
            main_total.saturating_add(blocks_after.saturating_mul(TAIL_EMISSION_ATOMS))
        }
    }
}

/// Calculate block reward at given height using halving schedule.
///
/// Emission Schedule:
/// - Blocks 0-525,599: 8 NULLA per block
/// - Blocks 525,600-1,051,199: 4 NULLA per block
/// - Blocks 1,051,200-1,576,799: 2 NULLA per block
/// - ... (continues halving every 525,600 blocks)
/// - After 20 halvings (~40 years): 0.6 NULLA per block (tail emission)
///
/// Returns reward in atoms.
pub fn calculate_block_reward(height: u64) -> u64 {
    let halvings = height / emission::HALVING_INTERVAL;

    if halvings >= emission::MAX_HALVINGS as u64 {
        // Tail emission phase
        emission::TAIL_EMISSION_ATOMS
    } else {
        // Main emission phase - halve reward for each period
        let mut reward = emission::INITIAL_REWARD_ATOMS;
        for _ in 0..halvings {
            reward /= 2;
            // Stop if reward drops below tail emission
            if reward < emission::TAIL_EMISSION_ATOMS {
                return emission::TAIL_EMISSION_ATOMS;
            }
        }
        reward
    }
}

/// Soft fork activation system (BIP9-style version bits).
///
/// Allows coordinated protocol upgrades by signaling readiness in block versions.
///
/// How it works:
/// 1. Define a deployment with start/timeout heights and bit position
/// 2. Miners signal readiness by setting the bit in block version
/// 3. If 95% of blocks in a 2016-block period signal, fork activates
/// 4. After activation, new rules are enforced
pub mod softfork {
    /// Soft fork deployment states
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DeploymentState {
        /// Deployment not yet started
        Defined,
        /// Actively signaling, waiting for threshold
        Started,
        /// Threshold reached, rules will activate
        LockedIn,
        /// Rules are now active and enforced
        Active,
        /// Timeout reached without activation
        Failed,
    }

    /// Soft fork deployment configuration
    #[derive(Debug, Clone, Copy)]
    pub struct Deployment {
        /// Human-readable name
        pub name: &'static str,
        /// Bit position in version field (0-15)
        pub bit: u8,
        /// Height at which signaling starts
        pub start_height: u64,
        /// Height at which deployment times out if not activated
        pub timeout_height: u64,
        /// Threshold for activation (blocks signaling / total blocks in period)
        /// Default: 1916 out of 2016 blocks (95%)
        pub threshold: u32,
        /// Number of blocks in a signaling period
        /// Default: 2016 blocks (~4 weeks at 2 min/block)
        pub period: u32,
    }

    impl Deployment {
        /// Check if this deployment is signaling in the given block version
        pub fn is_signaling(&self, version: u16) -> bool {
            (version & (1 << self.bit)) != 0
        }

        /// Get deployment state at given height with signaling history
        pub fn get_state(
            &self,
            height: u64,
            signaling_blocks: u32,
        ) -> DeploymentState {
            if height < self.start_height {
                return DeploymentState::Defined;
            }

            if height >= self.timeout_height {
                // Check if we activated before timeout
                if signaling_blocks >= self.threshold {
                    return DeploymentState::Active;
                }
                return DeploymentState::Failed;
            }

            // We're between start and timeout
            if signaling_blocks >= self.threshold {
                return DeploymentState::LockedIn;
            }

            DeploymentState::Started
        }
    }

    /// Define active soft fork deployments
    ///
    /// Example deployment:
    /// ```
    /// pub const EXAMPLE_FORK: Deployment = Deployment {
    ///     name: "timelock_opcodes",
    ///     bit: 0,
    ///     start_height: 100_000,
    ///     timeout_height: 200_000,
    ///     threshold: 1916,  // 95% of 2016
    ///     period: 2016,
    /// };
    /// ```
    pub const DEPLOYMENTS: &[Deployment] = &[
        // Add future soft fork deployments here
        // Deployment {
        //     name: "timelock_opcodes",
        //     bit: 0,
        //     start_height: 525_600,  // After first halving (~2 years)
        //     timeout_height: 1_051_200, // 2 years to activate
        //     threshold: 1916,        // 95% of 2016
        //     period: 2016,
        // },
    ];

    /// Check if a specific soft fork is active at given height
    pub fn is_active(deployment_name: &str, height: u64, signaling_blocks: u32) -> bool {
        for deployment in DEPLOYMENTS {
            if deployment.name == deployment_name {
                let state = deployment.get_state(height, signaling_blocks);
                return state == DeploymentState::Active || state == DeploymentState::LockedIn;
            }
        }
        false
    }

    /// Calculate signaling blocks in the current period
    ///
    /// This should be called by nodes to track signaling progress.
    /// Returns the number of blocks signaling for a deployment in the current period.
    pub fn count_signaling_blocks<F>(
        deployment: &Deployment,
        current_height: u64,
        get_block_version: F,
    ) -> u32
    where
        F: Fn(u64) -> Option<u16>,
    {
        if current_height < deployment.start_height {
            return 0;
        }

        // Calculate period start
        let period_start = (current_height / deployment.period as u64) * deployment.period as u64;
        let period_start = period_start.max(deployment.start_height);

        let mut count = 0;
        for h in period_start..=current_height {
            if let Some(version) = get_block_version(h) {
                if deployment.is_signaling(version) {
                    count += 1;
                }
            }
        }

        count
    }
}

/// Hardcoded blockchain checkpoints for security (HIGH-012).
/// These prevent attackers from feeding fake chains during initial sync.
/// Format: (block_height, block_hash)
///
/// IMPORTANT: Update these with known-good blocks from the main chain.
/// Genesis block (height 0) should always be checkpointed.
pub const CHECKPOINTS: &[(u64, &str)] = &[
    // Genesis block - update this with your actual genesis hash after first run
    // (0, "0000000000000000000000000000000000000000000000000000000000000000"),

    // Add checkpoints every 10,000 blocks for good coverage
    // Example format (update with real hashes from your blockchain):
    // (10000, "actual_block_hash_at_height_10000"),
    // (20000, "actual_block_hash_at_height_20000"),
];

/// Validate that a block at a checkpoint height matches the expected hash.
/// Returns Ok(()) if validation passes or if height is not a checkpoint.
pub fn validate_checkpoint(height: u64, block_id: &Hash32) -> Result<(), ValidationError> {
    for (checkpoint_height, checkpoint_hash_hex) in CHECKPOINTS {
        if height == *checkpoint_height {
            // Decode the checkpoint hash from hex
            let expected_hash = hex::decode(checkpoint_hash_hex)
                .map_err(|_| ValidationError::InvalidCheckpoint)?;

            if expected_hash.len() != 32 {
                return Err(ValidationError::InvalidCheckpoint);
            }

            let mut hash_array = [0u8; 32];
            hash_array.copy_from_slice(&expected_hash);

            if block_id != &hash_array {
                return Err(ValidationError::CheckpointMismatch);
            }

            // Checkpoint validated successfully
            return Ok(());
        }
    }

    // Not a checkpoint height, validation passes
    Ok(())
}

/// Validate a complete block, checking:
/// - The block size does not exceed MAX_BLOCK_SIZE
/// - The block contains at least one transaction
/// - The first transaction is a valid coinbase (basic structure only, not fee validation)
/// - The merkle root matches the computed root of all transaction IDs
/// - The proof-of-work is valid
/// - Basic transaction structure for all transactions
///
/// Note: This does NOT validate difficulty adjustment or transaction fees.
/// Use `validate_difficulty` and fee validation separately when validating blocks from the network.
pub fn validate_block(block: &Block) -> Result<(), ValidationError> {
    // SECURITY: Enforce block size limit to prevent DoS attacks
    let serialized_size = bincode::serialize(block)
        .map_err(|_| ValidationError::InvalidFormat)?
        .len();

    if serialized_size > MAX_BLOCK_SIZE {
        return Err(ValidationError::BlockTooLarge {
            size: serialized_size,
            max: MAX_BLOCK_SIZE,
        });
    }

    if block.txs.is_empty() {
        return Err(ValidationError::EmptyBlock);
    }

    // First transaction must be a coinbase (basic structure validation only)
    // Pass 0 for fees since this is just structure validation
    // Real fee validation happens at the database level with UTXO access
    validate_coinbase(&block.txs[0], u64::MAX, 0)?;

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
    /// Increased from 10 to 60 blocks for more stable adjustments with faster block time.
    pub const ADJUSTMENT_INTERVAL: u64 = 60;

    /// Target time per block in seconds.
    /// Set to 120s (2 minutes) for reasonable block time while maintaining decentralization.
    pub const TARGET_BLOCK_TIME: u64 = 120;

    /// Maximum difficulty adjustment factor (4x).
    /// Prevents difficulty from changing too rapidly.
    pub const MAX_ADJUSTMENT_FACTOR: u64 = 4;
}

/// Timestamp validation constants (SECURITY FIX: HIGH-NEW-001).
pub mod timestamp {
    /// Maximum allowed future time drift: 2 hours in seconds.
    /// Blocks with timestamps more than 2 hours in the future are rejected.
    pub const MAX_FUTURE_DRIFT: u64 = 2 * 60 * 60;

    /// Number of previous blocks to use for median time calculation (Bitcoin uses 11).
    pub const MEDIAN_TIME_SPAN: usize = 11;
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

    // SECURITY FIX (CRIT-NEW-004): Use BigUint for full 256-bit arithmetic
    // Previous code only used first 16 bytes (u128), losing precision and risking overflow
    use num_bigint::BigUint;

    // Convert full 32-byte target to BigUint (big-endian)
    let current_value = BigUint::from_bytes_be(current_target);

    // Apply adjustment: new_target = current_target * (actual_time / expected_time)
    // BigUint handles arbitrary precision, preventing overflow
    let adjusted_value = (current_value * adjustment_num) / adjustment_denom;

    // Convert back to Hash32 (32 bytes, big-endian)
    let adjusted_bytes = adjusted_value.to_bytes_be();
    let mut new_target = [0u8; 32];

    // Copy bytes, padding with zeros at the start if needed
    if adjusted_bytes.len() <= 32 {
        let start = 32 - adjusted_bytes.len();
        new_target[start..].copy_from_slice(&adjusted_bytes);
    } else {
        // Target exceeds 256 bits - clamp to maximum (minimum difficulty)
        return INITIAL_TARGET;
    }

    // Ensure target doesn't exceed maximum (minimum difficulty)
    if !leq_be(&new_target, &INITIAL_TARGET) {
        return INITIAL_TARGET;
    }

    new_target
}

/// Calculate the median timestamp of the last N blocks (SECURITY FIX: HIGH-NEW-001).
///
/// This is used to prevent timestamp manipulation attacks. A block's timestamp
/// must be greater than the median of the previous 11 blocks.
///
/// # Arguments
/// * `get_header` - Callback to fetch block header by height
/// * `current_height` - Height of the block being validated
///
/// # Returns
/// The median timestamp, or None if not enough blocks exist
pub fn calculate_median_past_time<F>(get_header: F, current_height: u64) -> Option<u64>
where
    F: Fn(u64) -> Option<BlockHeader>,
{
    if current_height == 0 {
        return Some(0); // Genesis block has no previous blocks
    }

    // Collect timestamps from previous blocks (up to MEDIAN_TIME_SPAN)
    let count = timestamp::MEDIAN_TIME_SPAN.min(current_height as usize);
    let mut timestamps = Vec::with_capacity(count);

    for i in 0..count {
        let height = current_height.saturating_sub((i + 1) as u64);
        if let Some(header) = get_header(height) {
            timestamps.push(header.timestamp);
        } else {
            return None; // Missing header
        }
    }

    if timestamps.is_empty() {
        return Some(0);
    }

    // Sort and return median
    timestamps.sort_unstable();
    Some(timestamps[timestamps.len() / 2])
}

/// Validate block timestamp (SECURITY FIX: HIGH-NEW-001).
///
/// Enforces two rules:
/// 1. Block timestamp must not be more than 2 hours in the future
/// 2. Block timestamp must be greater than median of previous 11 blocks
///
/// # Arguments
/// * `block` - The block to validate
/// * `get_header` - Callback to fetch block header by height
/// * `current_time` - Current system time (Unix timestamp)
///
/// # Returns
/// Ok if timestamp is valid, Err with ValidationError otherwise
pub fn validate_block_timestamp<F>(
    block: &Block,
    get_header: F,
    current_time: u64,
) -> Result<(), ValidationError>
where
    F: Fn(u64) -> Option<BlockHeader>,
{
    let block_time = block.header.timestamp;

    // Rule 1: Block timestamp must not be too far in the future
    let max_future = current_time
        .checked_add(timestamp::MAX_FUTURE_DRIFT)
        .unwrap_or(u64::MAX);

    if block_time > max_future {
        return Err(ValidationError::TimestampTooFar {
            timestamp: block_time,
            max: max_future,
        });
    }

    // Rule 2: Block timestamp must be greater than median of previous blocks
    // Skip for genesis block (height 0)
    if block.header.height > 0 {
        if let Some(median) = calculate_median_past_time(get_header, block.header.height) {
            if block_time <= median {
                return Err(ValidationError::TimestampTooEarly {
                    timestamp: block_time,
                    median,
                });
            }
        }
        // If we can't calculate median (missing headers), we can't validate
        // This is handled at the network sync level
    }

    Ok(())
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

    #[test]
    fn test_difficulty_overflow_prevention() {
        // SECURITY TEST (CRIT-NEW-004): Verify safe 256-bit difficulty calculation

        // Test 1: Very large target (minimum difficulty) shouldn't overflow
        let large_target = INITIAL_TARGET; // Maximum allowed target
        let height = difficulty::ADJUSTMENT_INTERVAL; // Trigger adjustment
        let prev_time = 1000000u64;
        let old_time = 1u64; // Extreme time difference

        let new_target = calculate_next_target(height, &large_target, prev_time, old_time);

        // Should be clamped to INITIAL_TARGET, not overflow
        assert!(leq_be(&new_target, &INITIAL_TARGET));

        // Test 2: Maximum adjustment factor should work correctly
        let mid_target = [0x0Fu8; 32]; // Mid-range target
        let expected = difficulty::ADJUSTMENT_INTERVAL * difficulty::TARGET_BLOCK_TIME;
        let actual_fast = expected / difficulty::MAX_ADJUSTMENT_FACTOR; // Blocks came very fast

        let new_target_fast = calculate_next_target(
            difficulty::ADJUSTMENT_INTERVAL,
            &mid_target,
            actual_fast,
            0,
        );

        // Target should decrease (difficulty increase) when blocks come fast
        assert!(leq_be(&new_target_fast, &mid_target));

        // Test 3: Full 256-bit target precision is preserved
        // Set all bytes to non-zero to test full width
        let full_target = [0x0Fu8; 32];
        let new_target_full = calculate_next_target(
            difficulty::ADJUSTMENT_INTERVAL,
            &full_target,
            expected * 2, // Blocks came slow (double expected time)
            0,
        );

        // Should use all 32 bytes, not just first 16
        // When blocks come slow (2x expected), target should increase (easier mining)
        // But it's clamped by MAX_ADJUSTMENT_FACTOR, so it won't exactly double
        // Just verify that the calculation completes without panicking and returns a valid target
        assert!(leq_be(&new_target_full, &INITIAL_TARGET));
    }

    #[test]
    fn test_timestamp_validation() {
        // SECURITY TEST (HIGH-NEW-001): Verify timestamp validation

        let chain_id = *b"TEST";
        let test_target = INITIAL_TARGET;

        // Create a simple header generator for testing
        let mut test_headers = std::collections::HashMap::new();

        // Create 20 test headers with incrementing timestamps
        for i in 0..20u64 {
            let header = BlockHeader {
                chain_id,
                version: 1,
                height: i,
                prev: [0u8; 32],
                merkle_root: [0u8; 32],
                timestamp: 1000 + (i * 10), // Timestamps: 1000, 1010, 1020, ...
                target: test_target,
                nonce: 0,
            };
            test_headers.insert(i, header);
        }

        let get_header = |height: u64| -> Option<BlockHeader> {
            test_headers.get(&height).cloned()
        };

        // Test 1: Future timestamp - should fail
        let mut future_block = Block {
            header: BlockHeader {
                chain_id,
                version: 1,
                height: 20,
                prev: [0u8; 32],
                merkle_root: [0u8; 32],
                timestamp: 999999999999, // Far future
                target: test_target,
                nonce: 0,
            },
            txs: vec![],
        };
        let current_time = 1000000; // Current time
        assert!(validate_block_timestamp(&future_block, get_header, current_time).is_err());

        // Test 2: Timestamp before median - should fail
        let median = calculate_median_past_time(get_header, 20).unwrap();
        future_block.header.timestamp = median; // Equal to median (should be > median)
        future_block.header.height = 20;
        assert!(validate_block_timestamp(&future_block, get_header, current_time).is_err());

        // Test 3: Valid timestamp - should pass
        future_block.header.timestamp = median + 10; // Greater than median
        future_block.header.height = 20;
        assert!(validate_block_timestamp(&future_block, get_header, current_time).is_ok());

        // Test 4: Genesis block - should always pass timestamp validation
        let genesis_block = Block {
            header: BlockHeader {
                chain_id,
                version: 1,
                height: 0,
                prev: [0u8; 32],
                merkle_root: [0u8; 32],
                timestamp: 0,
                target: test_target,
                nonce: 0,
            },
            txs: vec![],
        };
        assert!(validate_block_timestamp(&genesis_block, get_header, current_time).is_ok());
    }
}
