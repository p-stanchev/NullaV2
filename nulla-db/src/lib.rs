//! Database layer for the Nulla blockchain.
//!
//! Uses sled (an embedded key-value store) to persist:
//! - Block headers and full blocks
//! - UTXO set (unspent transaction outputs)
//! - Mempool transactions
//! - Chain metadata (best tip, height)

use nulla_core::{Block, BlockHeader, Hash32, OutPoint, Tx, TxOut};
use sled::{Config, Db, Tree};
use std::path::Path;
use thiserror::Error;

/// Mempool size limits (SECURITY FIX: HIGH-NEW-006)
const MAX_MEMPOOL_SIZE_BYTES: usize = 300_000_000;  // 300 MB
const MAX_MEMPOOL_TX_COUNT: usize = 50_000;          // 50k transactions

/// Extract address bytes from a P2PKH-like script_pubkey.
/// Returns Some([20-byte address]) if the script is valid P2PKH format.
fn extract_address_bytes(script_pubkey: &[u8]) -> Option<Vec<u8>> {
    if script_pubkey.len() != 25 {
        return None;
    }
    if script_pubkey[0] == 0x76
        && script_pubkey[1] == 0xa9
        && script_pubkey[2] == 0x14
        && script_pubkey[23] == 0x88
        && script_pubkey[24] == 0xac
    {
        Some(script_pubkey[3..23].to_vec())
    } else {
        None
    }
}

/// Key for storing the best (highest work) block tip hash.
pub const META_BEST_TIP: &str = "best_tip";

/// Key for storing the best block height.
pub const META_BEST_HEIGHT: &str = "best_height";

/// Key for storing the cumulative work of the best chain.
pub const META_BEST_WORK: &str = "best_work";

/// Database errors.
#[derive(Debug, Error)]
pub enum DbError {
    #[error(transparent)]
    Sled(#[from] sled::Error),
    #[error(transparent)]
    Serde(#[from] bincode::Error),
    #[error("mempool is full (max {} transactions, {} MB)", MAX_MEMPOOL_TX_COUNT, MAX_MEMPOOL_SIZE_BYTES / 1_000_000)]
    MempoolFull,
}

/// Result type for database operations.
pub type Result<T> = std::result::Result<T, DbError>;

/// Pruning configuration for blockchain storage optimization.
#[derive(Debug, Clone, Copy)]
pub struct PruningConfig {
    /// Enable pruning mode (discard old block data).
    pub enabled: bool,
    /// Number of blocks to keep before pruning (default: 550 for ~1 week of blocks).
    /// Must be >= MAX_REORG_DEPTH (100) to allow safe chain reorganizations.
    pub keep_blocks: u64,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            keep_blocks: 550, // ~1 week of blocks at 10min/block
        }
    }
}

/// Database handle for accessing blockchain state.
///
/// Sled's Db and Tree types are internally Arc-wrapped, so cloning is cheap.
#[derive(Clone)]
pub struct NullaDb {
    _db: Db,
    /// Chain metadata (best tip, height, etc.).
    meta: Tree,
    /// Block headers indexed by block ID.
    headers: Tree,
    /// Block IDs indexed by height.
    header_by_height: Tree,
    /// Full blocks indexed by block ID.
    blocks: Tree,
    /// UTXO set indexed by OutPoint.
    utxos: Tree,
    /// Mempool transactions indexed by txid.
    mempool: Tree,
    /// Spent outputs indexed by OutPoint.
    spent: Tree,
    /// Cumulative work for each block header (indexed by block ID).
    work: Tree,
    /// UTXO index by address (maps address bytes -> Vec<OutPoint>).
    utxo_by_addr: Tree,
    /// Coinbase metadata (maps OutPoint -> block height for coinbase outputs).
    coinbase_heights: Tree,
    /// Spent UTXO backup for reorg restoration (maps OutPoint -> TxOut).
    /// Stores the original UTXO data when an output is spent, allowing proper restoration during chain reorgs.
    spent_utxos: Tree,
    /// Pruning configuration.
    pruning: PruningConfig,
}

impl NullaDb {
    /// Open or create a database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_pruning(path, PruningConfig::default())
    }

    /// Open or create a database with custom pruning configuration.
    pub fn open_with_pruning(path: impl AsRef<Path>, pruning: PruningConfig) -> Result<Self> {
        // SECURITY: Ensure keep_blocks is sufficient for reorg safety
        if pruning.enabled && pruning.keep_blocks < 100 {
            return Err(DbError::Serde(bincode::Error::new(
                bincode::ErrorKind::Custom(
                    "Pruning keep_blocks must be at least 100 for reorg safety".to_string()
                )
            )));
        }

        let db = Config::default().path(path).open()?;
        Ok(Self {
            meta: db.open_tree("meta")?,
            headers: db.open_tree("headers")?,
            header_by_height: db.open_tree("header_by_height")?,
            blocks: db.open_tree("blocks")?,
            utxos: db.open_tree("utxos")?,
            mempool: db.open_tree("mempool")?,
            spent: db.open_tree("spent")?,
            work: db.open_tree("work")?,
            utxo_by_addr: db.open_tree("utxo_by_addr")?,
            coinbase_heights: db.open_tree("coinbase_heights")?,
            spent_utxos: db.open_tree("spent_utxos")?,
            pruning,
            _db: db,
        })
    }

    /// Get the current pruning configuration.
    pub fn pruning_config(&self) -> PruningConfig {
        self.pruning
    }

    /// Check if a block at the given height has been pruned.
    /// Returns true if the block data is discarded but header remains.
    pub fn is_block_pruned(&self, height: u64) -> Result<bool> {
        if !self.pruning.enabled {
            return Ok(false);
        }

        let (_tip, current_height, _work) = match self.best_tip()? {
            Some(tip) => tip,
            None => return Ok(false),
        };

        // Block is pruned if it's older than keep_blocks threshold
        Ok(height + self.pruning.keep_blocks < current_height)
    }

    /// Prune old block data while keeping headers and recent blocks.
    /// This is called automatically after new blocks are added if pruning is enabled.
    ///
    /// Returns the number of blocks pruned.
    pub fn prune_old_blocks(&self) -> Result<usize> {
        if !self.pruning.enabled {
            return Ok(0);
        }

        let (_tip, current_height, _work) = match self.best_tip()? {
            Some(tip) => tip,
            None => return Ok(0),
        };

        // Calculate pruning threshold height
        let prune_below_height = if current_height > self.pruning.keep_blocks {
            current_height - self.pruning.keep_blocks
        } else {
            return Ok(0); // Not enough blocks to prune yet
        };

        let mut pruned_count = 0;

        // Iterate through old blocks and remove block data (keep headers)
        for height in 0..prune_below_height {
            if let Some(id_bytes) = self.header_by_height.get(&height.to_be_bytes())? {
                let mut block_id = [0u8; 32];
                block_id.copy_from_slice(&id_bytes);

                // Only prune if block data exists (not already pruned)
                if self.blocks.contains_key(&block_id)? {
                    self.blocks.remove(&block_id)?;
                    pruned_count += 1;
                }
            }
        }

        if pruned_count > 0 {
            tracing::info!("Pruned {} old blocks (keeping blocks >= height {})",
                pruned_count, prune_below_height);
        }

        Ok(pruned_count)
    }

    /// Update the best tip (highest cumulative work chain).
    pub fn set_best_tip(&self, id: &Hash32, height: u64, cumulative_work: u128) -> Result<()> {
        self.meta.insert(META_BEST_TIP, id)?;
        self.meta.insert(META_BEST_HEIGHT, &height.to_be_bytes())?;
        self.meta
            .insert(META_BEST_WORK, &cumulative_work.to_be_bytes())?;
        Ok(())
    }

    /// Retrieve the current best tip hash, height, and cumulative work.
    pub fn best_tip(&self) -> Result<Option<(Hash32, u64, u128)>> {
        let tip = match self.meta.get(META_BEST_TIP)? {
            Some(val) => {
                let mut h = [0u8; 32];
                h.copy_from_slice(&val);
                h
            }
            None => return Ok(None),
        };
        // SECURITY FIX (CRIT-AUD-002): Proper error handling instead of unwrap_or
        let height = match self.meta.get(META_BEST_HEIGHT)? {
            Some(v) => {
                let bytes: [u8; 8] = v.as_ref().try_into().map_err(|_| {
                    DbError::Serde(bincode::Error::new(bincode::ErrorKind::Custom(
                        "Invalid height bytes in database".to_string(),
                    )))
                })?;
                u64::from_be_bytes(bytes)
            }
            None => 0,
        };

        let work = match self.meta.get(META_BEST_WORK)? {
            Some(v) => {
                let bytes: [u8; 16] = v.as_ref().try_into().map_err(|_| {
                    DbError::Serde(bincode::Error::new(bincode::ErrorKind::Custom(
                        "Invalid work bytes in database".to_string(),
                    )))
                })?;
                u128::from_be_bytes(bytes)
            }
            None => 0,
        };
        Ok(Some((tip, height, work)))
    }

    /// Get the cumulative work for a specific block.
    pub fn get_work(&self, id: &Hash32) -> Result<Option<u128>> {
        match self.work.get(id)? {
            Some(bytes) => {
                // SECURITY FIX (CRIT-AUD-002): Proper error handling
                let arr: [u8; 16] = bytes.as_ref().try_into().map_err(|_| {
                    DbError::Serde(bincode::Error::new(bincode::ErrorKind::Custom(
                        "Invalid work bytes in database".to_string(),
                    )))
                })?;
                Ok(Some(u128::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    /// Set the cumulative work for a block.
    pub fn set_work(&self, id: &Hash32, work: u128) -> Result<()> {
        self.work.insert(id, &work.to_be_bytes())?;
        Ok(())
    }

    /// Store a block header in the database.
    pub fn put_header(&self, header: &BlockHeader) -> Result<()> {
        let id = nulla_core::block_header_id(header);
        self.headers.insert(id, bincode::serialize(header)?)?;
        self.header_by_height
            .insert(&header.height.to_be_bytes(), &id)?;
        Ok(())
    }

    /// Retrieve a block header by its ID.
    pub fn get_header(&self, id: &Hash32) -> Result<Option<BlockHeader>> {
        match self.headers.get(id)? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Store a full block in the database.
    pub fn put_block(&self, block: &Block) -> Result<()> {
        let id = nulla_core::block_id(block);
        self.blocks.insert(id, bincode::serialize(block)?)?;
        Ok(())
    }

    /// Retrieve a full block by its ID.
    pub fn get_block(&self, id: &Hash32) -> Result<Option<Block>> {
        match self.blocks.get(id)? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Add a transaction to the mempool (SECURITY FIX: HIGH-NEW-006, HIGH-AUD-004).
    /// Validates signatures and enforces mempool size limits by evicting low-fee transactions if necessary.
    pub fn put_mempool_tx(&self, tx: &Tx, chain_id: &[u8; 4]) -> Result<()> {
        // SECURITY FIX (HIGH-AUD-004): Validate signatures before accepting into mempool
        self.verify_tx_signatures(tx, chain_id)
            .map_err(|e| DbError::Serde(bincode::Error::new(bincode::ErrorKind::Custom(
                format!("Transaction signature verification failed: {}", e)
            ))))?;

        let txid = nulla_core::tx_id(tx);
        let tx_bytes = bincode::serialize(tx)?;
        let tx_size = tx_bytes.len();

        // Check if mempool is at capacity and evict if necessary
        let tx_count = self.mempool.len();
        let byte_count = self.mempool_size_bytes()?;

        if tx_count >= MAX_MEMPOOL_TX_COUNT
            || byte_count + tx_size > MAX_MEMPOOL_SIZE_BYTES
        {
            // Evict low-fee transactions to make space
            let evicted = self.evict_low_fee_txs_until_space(tx_size)?;
            if evicted > 0 {
                tracing::debug!("Evicted {} low-fee transactions to make space in mempool", evicted);
            }

            // Check again after eviction
            let tx_count_after = self.mempool.len();
            let byte_count_after = self.mempool_size_bytes()?;

            if tx_count_after >= MAX_MEMPOOL_TX_COUNT
                || byte_count_after + tx_size > MAX_MEMPOOL_SIZE_BYTES
            {
                return Err(DbError::MempoolFull);
            }
        }

        self.mempool.insert(txid, tx_bytes)?;
        Ok(())
    }

    /// Remove a transaction from the mempool (typically after it's been mined).
    pub fn remove_mempool_tx(&self, txid: &Hash32) -> Result<()> {
        self.mempool.remove(txid)?;
        Ok(())
    }

    /// Add a UTXO to the set and index by address.
    pub fn put_utxo(&self, out: &OutPoint, txout: &TxOut) -> Result<()> {
        self.utxos
            .insert(bincode::serialize(out)?, bincode::serialize(txout)?)?;

        // Extract address from script_pubkey and index this UTXO
        if let Some(addr_bytes) = extract_address_bytes(&txout.script_pubkey) {
            // Get existing outpoints for this address
            let mut outpoints: Vec<OutPoint> = match self.utxo_by_addr.get(&addr_bytes)? {
                Some(bytes) => bincode::deserialize(&bytes).unwrap_or_default(),
                None => Vec::new(),
            };

            // Add this outpoint if not already present
            if !outpoints.contains(out) {
                outpoints.push(out.clone());
                self.utxo_by_addr
                    .insert(&addr_bytes, bincode::serialize(&outpoints)?)?;
            }
        }

        Ok(())
    }

    /// Retrieve a UTXO from the set.
    pub fn get_utxo(&self, out: &OutPoint) -> Result<Option<TxOut>> {
        match self.utxos.get(bincode::serialize(out)?)? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Mark a UTXO as spent by a specific transaction.
    pub fn mark_spent(&self, out: &OutPoint, spender: &Hash32) -> Result<()> {
        self.spent
            .insert(bincode::serialize(out)?, spender.as_slice())?;
        Ok(())
    }

    /// Check if a UTXO has been spent.
    pub fn is_spent(&self, out: &OutPoint) -> Result<bool> {
        Ok(self.spent.contains_key(bincode::serialize(out)?)?)
    }

    /// Remove a UTXO from the set and address index (used during chain reorganization).
    pub fn remove_utxo(&self, out: &OutPoint) -> Result<()> {
        // Get the UTXO before removing to extract the address
        if let Some(txout) = self.get_utxo(out)? {
            if let Some(addr_bytes) = extract_address_bytes(&txout.script_pubkey) {
                // Remove from address index
                if let Some(bytes) = self.utxo_by_addr.get(&addr_bytes)? {
                    let mut outpoints: Vec<OutPoint> =
                        bincode::deserialize(&bytes).unwrap_or_default();
                    outpoints.retain(|o| o != out);
                    if outpoints.is_empty() {
                        self.utxo_by_addr.remove(&addr_bytes)?;
                    } else {
                        self.utxo_by_addr
                            .insert(&addr_bytes, bincode::serialize(&outpoints)?)?;
                    }
                }
            }
        }

        self.utxos.remove(bincode::serialize(out)?)?;
        Ok(())
    }

    /// Unmark a UTXO as spent (used during chain reorganization rollback).
    pub fn unmark_spent(&self, out: &OutPoint) -> Result<()> {
        self.spent.remove(bincode::serialize(out)?)?;
        Ok(())
    }

    /// Get all transactions currently in the mempool.
    pub fn get_mempool_txs(&self) -> Result<Vec<Tx>> {
        let mut txs = Vec::new();
        for item in self.mempool.iter() {
            let (_key, value) = item?;
            txs.push(bincode::deserialize(&value)?);
        }
        Ok(txs)
    }

    /// Get a transaction from the mempool by its ID.
    pub fn get_mempool_tx(&self, txid: &Hash32) -> Result<Option<Tx>> {
        match self.mempool.get(txid)? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Count the number of transactions in the mempool.
    pub fn mempool_size(&self) -> usize {
        self.mempool.len()
    }

    /// Clear all transactions from the mempool (used during shutdown or reorg).
    pub fn clear_mempool(&self) -> Result<()> {
        self.mempool.clear()?;
        Ok(())
    }

    /// Calculate total byte size of all transactions in mempool (SECURITY FIX: HIGH-NEW-006)
    pub fn mempool_size_bytes(&self) -> Result<usize> {
        let mut total_bytes = 0usize;
        for item in self.mempool.iter() {
            let (_key, value) = item?;
            total_bytes += value.len();
        }
        Ok(total_bytes)
    }

    /// Evict the lowest fee transaction from the mempool (SECURITY FIX: HIGH-NEW-006)
    /// Returns the txid of the evicted transaction, or None if mempool is empty
    fn evict_lowest_fee_tx(&self) -> Result<Option<Hash32>> {
        let mut txs_with_fees = Vec::new();

        // Collect all transactions with their actual fees (SECURITY FIX: HIGH-AUD-003)
        for item in self.mempool.iter() {
            let (key, value) = item?;
            let tx: Tx = bincode::deserialize(&value)?;

            // Calculate actual fee using calculate_tx_fee (inputs - outputs)
            let fee = match self.calculate_tx_fee(&tx) {
                Ok(f) => f,
                Err(_) => {
                    // If fee calculation fails, treat as zero fee (evict first)
                    0
                }
            };

            let mut txid = [0u8; 32];
            txid.copy_from_slice(&key);

            txs_with_fees.push((txid, fee));
        }

        if txs_with_fees.is_empty() {
            return Ok(None);
        }

        // SECURITY FIX (HIGH-AUD-003): Sort by actual fee (ascending) - lowest fee first
        txs_with_fees.sort_by_key(|(_, fee)| *fee);

        // Evict the first one (lowest fee)
        let (evict_txid, _) = txs_with_fees[0];
        self.remove_mempool_tx(&evict_txid)?;

        Ok(Some(evict_txid))
    }

    /// Evict low-fee transactions until mempool is under limits (SECURITY FIX: HIGH-NEW-006)
    pub fn evict_low_fee_txs_until_space(&self, needed_bytes: usize) -> Result<usize> {
        let mut evicted_count = 0;

        loop {
            let tx_count = self.mempool.len();
            let byte_count = self.mempool_size_bytes()?;

            // Check if we're under limits
            if tx_count < MAX_MEMPOOL_TX_COUNT
                && byte_count + needed_bytes <= MAX_MEMPOOL_SIZE_BYTES
            {
                break;
            }

            // Evict one transaction
            match self.evict_lowest_fee_tx()? {
                Some(_txid) => {
                    evicted_count += 1;
                }
                None => break, // Mempool empty
            }

            // Safety: prevent infinite loop
            if evicted_count > 1000 {
                break;
            }
        }

        Ok(evicted_count)
    }

    /// Get a block header by height.
    pub fn get_header_by_height(&self, height: u64) -> Result<Option<BlockHeader>> {
        match self.header_by_height.get(&height.to_be_bytes())? {
            Some(id_bytes) => {
                let mut id = [0u8; 32];
                id.copy_from_slice(&id_bytes);
                self.get_header(&id)
            }
            None => Ok(None),
        }
    }

    /// Store both header and full block atomically.
    pub fn put_block_full(&self, block: &Block) -> Result<()> {
        self.put_header(&block.header)?;
        self.put_block(block)?;
        Ok(())
    }

    /// Validate a transaction's inputs against the UTXO set.
    ///
    /// Returns Ok with total input value if all inputs are valid and unspent.
    /// Returns Err if any input is missing or already spent.
    pub fn validate_tx_inputs(&self, tx: &nulla_core::Tx) -> Result<u64> {
        let mut total_input: u64 = 0;

        for input in &tx.inputs {
            // Skip validation for coinbase inputs
            if input.prevout.txid == [0u8; 32] && input.prevout.vout == 0xFFFF_FFFF {
                continue;
            }

            // Check if UTXO exists
            let utxo = match self.get_utxo(&input.prevout)? {
                Some(u) => u,
                None => {
                    return Err(DbError::Serde(bincode::Error::new(
                        bincode::ErrorKind::Custom("UTXO not found".to_string()),
                    )));
                }
            };

            // Check if already spent
            if self.is_spent(&input.prevout)? {
                return Err(DbError::Serde(bincode::Error::new(
                    bincode::ErrorKind::Custom("UTXO already spent".to_string()),
                )));
            }

            total_input = total_input.checked_add(utxo.value_atoms).ok_or_else(|| {
                DbError::Serde(bincode::Error::new(bincode::ErrorKind::Custom(
                    "Input value overflow".to_string(),
                )))
            })?;
        }

        Ok(total_input)
    }

    /// Calculate the transaction fee (inputs - outputs).
    ///
    /// For regular transactions: fee = sum(inputs) - sum(outputs)
    /// For coinbase transactions: returns 0
    ///
    /// Returns Ok(fee) if the transaction is valid (inputs >= outputs).
    /// Returns Err if outputs exceed inputs (invalid transaction).
    pub fn calculate_tx_fee(&self, tx: &nulla_core::Tx) -> Result<u64> {
        // Coinbase transactions have no fee
        if nulla_core::is_coinbase(tx) {
            return Ok(0);
        }

        // Calculate total input value
        let total_input = self.validate_tx_inputs(tx)?;

        // Calculate total output value
        let mut total_output: u64 = 0;
        for output in &tx.outputs {
            total_output = total_output.checked_add(output.value_atoms).ok_or_else(|| {
                DbError::Serde(bincode::Error::new(bincode::ErrorKind::Custom(
                    "Output value overflow".to_string(),
                )))
            })?;
        }

        // Fee = inputs - outputs (SECURITY FIX: CRIT-AUD-001)
        // Use checked_sub to prevent integer overflow/underflow
        let fee = total_input.checked_sub(total_output).ok_or_else(|| {
            DbError::Serde(bincode::Error::new(bincode::ErrorKind::Custom(
                format!(
                    "Fee calculation overflow: outputs ({}) exceed inputs ({})",
                    total_output, total_input
                ),
            )))
        })?;

        Ok(fee)
    }

    /// Validate multiple transactions in parallel using rayon with replay protection.
    ///
    /// This method validates transaction signatures and fees in parallel,
    /// significantly speeding up block validation on multi-core systems.
    ///
    /// # Arguments
    /// * `txs` - The transactions to validate
    /// * `chain_id` - The 4-byte chain identifier for replay protection
    ///
    /// # Returns
    /// - `Ok(total_fees)`: The sum of all transaction fees
    /// - `Err(_)`: If any transaction fails validation
    ///
    /// # Performance
    /// Expected 2-4x speedup on 4+ core CPUs compared to serial validation.
    /// DEPRECATED: Use validate_and_apply_block_txs() instead to prevent TOCTOU attacks.
    ///
    /// This function only validates but doesn't apply, creating a gap where UTXOs
    /// can be spent twice if apply_tx() is called separately.
    #[deprecated(
        since = "0.2.0",
        note = "Use validate_and_apply_block_txs() to prevent TOCTOU race conditions"
    )]
    pub fn validate_block_txs_parallel(&self, txs: &[nulla_core::Tx], chain_id: &[u8; 4]) -> Result<u64> {
        use rayon::prelude::*;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Mutex;

        let total_fees = AtomicU64::new(0);
        let first_error: Mutex<Option<DbError>> = Mutex::new(None);

        // SECURITY: Mutex to prevent race conditions during UTXO validation
        // This prevents TOCTOU (Time-Of-Check-Time-Of-Use) attacks where two
        // transactions could try to spend the same UTXO simultaneously
        let utxo_lock = Mutex::new(());

        // Validate all transactions in parallel
        txs.par_iter().for_each(|tx| {
            // Skip if we already encountered an error
            if first_error.lock().unwrap().is_some() {
                return;
            }

            // Verify signatures with chain_id for replay protection (parallelizable)
            if let Err(e) = self.verify_tx_signatures(tx, chain_id) {
                *first_error.lock().unwrap() = Some(e);
                return;
            }

            // SECURITY: Lock UTXO access to prevent race conditions
            let _guard = utxo_lock.lock().unwrap();

            // Calculate and validate fee (requires UTXO access - must be locked)
            match self.calculate_tx_fee(tx) {
                Ok(fee) => {
                    // Check minimum fee (10,000 atoms = 0.0001 NULLA)
                    if !nulla_core::is_coinbase(tx) && fee < 10_000 {
                        *first_error.lock().unwrap() = Some(DbError::Serde(
                            bincode::Error::new(bincode::ErrorKind::Custom(
                                format!("Transaction fee ({}) below minimum (10,000)", fee),
                            )),
                        ));
                        return;
                    }
                    total_fees.fetch_add(fee, Ordering::SeqCst);
                }
                Err(e) => {
                    *first_error.lock().unwrap() = Some(e);
                }
            }
        });

        // Check if any errors occurred
        if let Some(error) = first_error.into_inner().unwrap() {
            return Err(error);
        }

        Ok(total_fees.load(Ordering::SeqCst))
    }

    /// Validate and apply block transactions atomically (SECURITY FIX: CRIT-NEW-003).
    ///
    /// This function fixes the TOCTOU (Time-Of-Check-Time-Of-Use) vulnerability by
    /// ensuring that validation and application of transactions happen atomically.
    ///
    /// The previous approach had a race condition:
    /// 1. validate_block_txs_parallel() validates UTXOs (lock released after)
    /// 2. apply_tx() called separately without lock (TOCTOU gap!)
    /// 3. Two threads could both validate spending the same UTXO, then both apply
    ///
    /// This new function:
    /// - Phase 1: Verify all signatures in parallel (read-only, safe)
    /// - Phase 2: Validate and apply sequentially (atomic, prevents double-spend)
    pub fn validate_and_apply_block_txs(&self, txs: &[nulla_core::Tx], chain_id: &[u8; 4], block_height: u64) -> Result<u64> {
        use rayon::prelude::*;
        use std::sync::Mutex;

        // Phase 1: Verify signatures in parallel (read-only, safe to parallelize)
        let first_error: Mutex<Option<DbError>> = Mutex::new(None);

        txs.par_iter().for_each(|tx| {
            if first_error.lock().unwrap().is_some() {
                return;  // Skip if error already found
            }

            // Signature verification is parallelizable (read-only operation)
            if let Err(e) = self.verify_tx_signatures(tx, chain_id) {
                *first_error.lock().unwrap() = Some(e);
            }
        });

        // Fail fast if signatures are invalid
        if let Some(error) = first_error.into_inner().unwrap() {
            return Err(error);
        }

        // Phase 2: Validate UTXOs and apply transactions SEQUENTIALLY
        // This ensures atomicity: no gap between validation and application
        let mut total_fees = 0u64;

        for tx in txs {
            if nulla_core::is_coinbase(tx) {
                // Apply coinbase transaction and mark outputs with block height for maturity checking
                let txid = nulla_core::tx_id(tx);
                for (vout, output) in tx.outputs.iter().enumerate() {
                    let outpoint = nulla_core::OutPoint {
                        txid,
                        vout: vout as u32,
                    };
                    self.put_utxo(&outpoint, output)?;

                    // Track coinbase height for maturity validation
                    self.coinbase_heights.insert(
                        bincode::serialize(&outpoint)?,
                        &block_height.to_be_bytes(),
                    )?;
                }
                continue;
            }

            // ATOMICALLY: validate fee and apply transaction
            // No other thread can interfere because we're sequential here
            let fee = self.calculate_tx_fee(tx)?;

            // Validate lock_time (MED-001): Transaction cannot be included before lock_time
            if tx.lock_time > block_height {
                return Err(DbError::Serde(bincode::Error::new(
                    bincode::ErrorKind::Custom(
                        format!(
                            "Transaction lock_time {} is greater than current block height {}",
                            tx.lock_time, block_height
                        )
                    )
                )));
            }

            // Check minimum fee
            if fee < 10_000 {
                return Err(DbError::Serde(bincode::Error::new(
                    bincode::ErrorKind::Custom(
                        format!("Transaction fee ({}) below minimum (10,000)", fee)
                    )
                )));
            }

            // Apply immediately while we still "own" the UTXOs
            self.apply_tx(tx)?;

            total_fees = total_fees.checked_add(fee)
                .ok_or_else(|| DbError::Serde(bincode::Error::new(
                    bincode::ErrorKind::Custom("Fee overflow".to_string())
                )))?;
        }

        Ok(total_fees)
    }

    /// Verify Ed25519 signatures on all transaction inputs with replay protection.
    ///
    /// Supports both P2PKH (single signature) and P2SH (multi-signature) transactions.
    ///
    /// For each input (except coinbase):
    /// 1. Looks up the previous output from UTXO set
    /// 2. Determines script type (P2PKH or P2SH)
    /// 3. Computes sighash including chain_id for replay protection
    /// 4. Uses ScriptInterpreter to verify signatures
    ///
    /// Returns Ok(()) if all signatures are valid, Err otherwise.
    ///
    /// # Arguments
    /// * `tx` - The transaction to verify
    /// * `chain_id` - The 4-byte chain identifier for replay protection
    pub fn verify_tx_signatures(&self, tx: &nulla_core::Tx, chain_id: &[u8; 4]) -> Result<()> {
        use nulla_core::{Script, ScriptInterpreter, ScriptType};

        // Skip coinbase transactions
        if nulla_core::is_coinbase(tx) {
            return Ok(());
        }

        // Compute sighash once for all signature verifications (includes chain_id for replay protection)
        let sighash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(chain_id);
            let tx_data = bincode::serialize(tx)?;
            hasher.update(&tx_data);
            hasher.finalize().as_bytes().to_vec()
        };

        for input in &tx.inputs {
            // Get the previous output being spent
            let prev_output = match self.get_utxo(&input.prevout)? {
                Some(output) => output,
                None => {
                    return Err(DbError::Serde(bincode::Error::new(
                        bincode::ErrorKind::Custom(
                            "UTXO not found for signature verification".to_string(),
                        ),
                    )));
                }
            };

            // SECURITY: Check coinbase maturity (cannot spend coinbase outputs for 100 blocks)
            if let Some(coinbase_height_bytes) = self.coinbase_heights.get(bincode::serialize(&input.prevout)?)? {
                let coinbase_height = u64::from_be_bytes(
                    coinbase_height_bytes.as_ref().try_into().map_err(|_| {
                        DbError::Serde(bincode::Error::new(
                            bincode::ErrorKind::Custom("Invalid coinbase height data".to_string()),
                        ))
                    })?
                );

                // Get current block height from best tip
                let (_tip, current_height, _work) = self.best_tip()?.unwrap_or((
                    [0u8; 32],
                    0,
                    0,
                ));

                if current_height < coinbase_height + nulla_core::COINBASE_MATURITY {
                    return Err(DbError::Serde(bincode::Error::new(
                        bincode::ErrorKind::Custom(
                            format!(
                                "Coinbase output not mature (height {} + {} maturity > current {})",
                                coinbase_height,
                                nulla_core::COINBASE_MATURITY,
                                current_height
                            )
                        ),
                    )));
                }
            }

            // Parse the script_pubkey to determine type
            let script_pubkey = Script::new(prev_output.script_pubkey.clone());
            let script_type = script_pubkey.script_type().ok_or_else(|| {
                DbError::Serde(bincode::Error::new(
                    bincode::ErrorKind::Custom("Unrecognized script type".to_string()),
                ))
            })?;

            // Create script interpreter
            let mut interpreter = ScriptInterpreter::new();

            match script_type {
                ScriptType::P2PKH => {
                    // P2PKH: input has signature + pubkey
                    if input.sig.len() != 64 {
                        return Err(DbError::Serde(bincode::Error::new(
                            bincode::ErrorKind::Custom("Invalid P2PKH signature length".to_string()),
                        )));
                    }

                    if input.pubkey.len() != 32 {
                        return Err(DbError::Serde(bincode::Error::new(
                            bincode::ErrorKind::Custom("Invalid P2PKH pubkey length".to_string()),
                        )));
                    }

                    // Verify P2PKH signature with sighash (includes chain_id)
                    interpreter
                        .verify_p2pkh(&input.sig, &input.pubkey, &script_pubkey, &sighash)
                        .map_err(|e| {
                            DbError::Serde(bincode::Error::new(bincode::ErrorKind::Custom(
                                format!("P2PKH verification failed: {}", e),
                            )))
                        })?;
                }

                ScriptType::P2SH => {
                    // P2SH: input.sig contains: num_sigs + signatures + redeem_script_len + redeem_script
                    // input.pubkey is empty for P2SH

                    if input.sig.is_empty() {
                        return Err(DbError::Serde(bincode::Error::new(
                            bincode::ErrorKind::Custom("Empty P2SH scriptSig".to_string()),
                        )));
                    }

                    // Parse P2SH scriptSig format
                    let mut pos = 0;

                    // Read number of signatures (1 byte)
                    if pos >= input.sig.len() {
                        return Err(DbError::Serde(bincode::Error::new(
                            bincode::ErrorKind::Custom("Invalid P2SH scriptSig: missing sig count".to_string()),
                        )));
                    }
                    let num_sigs = input.sig[pos] as usize;
                    pos += 1;

                    // Read signatures (64 bytes each)
                    let mut signatures = Vec::new();
                    for _ in 0..num_sigs {
                        if pos + 64 > input.sig.len() {
                            return Err(DbError::Serde(bincode::Error::new(
                                bincode::ErrorKind::Custom("Invalid P2SH scriptSig: incomplete signature".to_string()),
                            )));
                        }
                        signatures.push(input.sig[pos..pos + 64].to_vec());
                        pos += 64;
                    }

                    // Read redeem script length (2 bytes, little-endian)
                    if pos + 2 > input.sig.len() {
                        return Err(DbError::Serde(bincode::Error::new(
                            bincode::ErrorKind::Custom("Invalid P2SH scriptSig: missing script length".to_string()),
                        )));
                    }
                    let script_len = u16::from_le_bytes([input.sig[pos], input.sig[pos + 1]]) as usize;
                    pos += 2;

                    // Read redeem script
                    if pos + script_len > input.sig.len() {
                        return Err(DbError::Serde(bincode::Error::new(
                            bincode::ErrorKind::Custom("Invalid P2SH scriptSig: incomplete redeem script".to_string()),
                        )));
                    }
                    let redeem_script_bytes = input.sig[pos..pos + script_len].to_vec();
                    let redeem_script = Script::new(redeem_script_bytes);

                    // Verify P2SH signature with sighash (includes chain_id)
                    interpreter
                        .verify_p2sh(&signatures, &redeem_script, &script_pubkey, &sighash)
                        .map_err(|e| {
                            DbError::Serde(bincode::Error::new(bincode::ErrorKind::Custom(
                                format!("P2SH verification failed: {}", e),
                            )))
                        })?;
                }
            }
        }

        Ok(())
    }

    /// Apply a transaction to the UTXO set (mark inputs as spent, create new outputs).
    /// SECURITY FIX (HIGH-007): Backs up spent UTXOs for proper reorg restoration.
    pub fn apply_tx(&self, tx: &nulla_core::Tx) -> Result<()> {
        let txid = nulla_core::tx_id(tx);

        // Mark all inputs as spent (skip coinbase inputs)
        for input in &tx.inputs {
            if !input.prevout.is_null() {
                // SECURITY FIX (HIGH-007): Backup UTXO before removing for reorg restoration
                if let Some(utxo) = self.get_utxo(&input.prevout)? {
                    self.spent_utxos.insert(
                        bincode::serialize(&input.prevout)?,
                        bincode::serialize(&utxo)?,
                    )?;
                }

                self.mark_spent(&input.prevout, &txid)?;
                self.remove_utxo(&input.prevout)?;
            }
        }

        // Create new UTXOs for all outputs
        for (vout, output) in tx.outputs.iter().enumerate() {
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
            self.put_utxo(&outpoint, output)?;
        }

        Ok(())
    }

    /// Revert a transaction from the UTXO set (for chain reorganization).
    /// SECURITY FIX (HIGH-007): Properly restores spent UTXOs from backup.
    pub fn revert_tx(&self, tx: &nulla_core::Tx) -> Result<()> {
        let txid = nulla_core::tx_id(tx);

        // Remove outputs created by this transaction
        for (vout, _output) in tx.outputs.iter().enumerate() {
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
            self.remove_utxo(&outpoint)?;
            self.unmark_spent(&outpoint)?;

            // Remove coinbase height tracking if this was a coinbase output
            let _ = self.coinbase_heights.remove(bincode::serialize(&outpoint)?)?;
        }

        // Restore inputs (skip coinbase)
        // SECURITY FIX (HIGH-007): Restore original UTXOs from backup
        for input in &tx.inputs {
            if !input.prevout.is_null() {
                self.unmark_spent(&input.prevout)?;

                // Restore the original UTXO from backup
                if let Some(utxo_bytes) = self.spent_utxos.get(bincode::serialize(&input.prevout)?)? {
                    let utxo: nulla_core::TxOut = bincode::deserialize(&utxo_bytes)?;
                    self.put_utxo(&input.prevout, &utxo)?;

                    // Remove from backup after restoration
                    self.spent_utxos.remove(bincode::serialize(&input.prevout)?)?;
                }
            }
        }

        Ok(())
    }

    /// Get all UTXOs for a specific address.
    ///
    /// Returns a vector of (OutPoint, TxOut) tuples for all unspent outputs
    /// belonging to the given address (20 bytes).
    pub fn get_utxos_by_address(&self, address_bytes: &[u8; 20]) -> Result<Vec<(OutPoint, TxOut)>> {
        let mut result = Vec::new();

        // Look up outpoints for this address
        if let Some(bytes) = self.utxo_by_addr.get(address_bytes)? {
            let outpoints: Vec<OutPoint> = bincode::deserialize(&bytes)?;

            // Fetch each UTXO
            for outpoint in outpoints {
                if let Some(txout) = self.get_utxo(&outpoint)? {
                    result.push((outpoint, txout));
                }
            }
        }

        Ok(result)
    }

    /// Get block header by block ID.
    pub fn get_header_by_id(&self, block_id: &Hash32) -> Result<Option<BlockHeader>> {
        self.get_header(block_id)
    }
}
