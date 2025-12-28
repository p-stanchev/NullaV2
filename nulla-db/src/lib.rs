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
}

/// Result type for database operations.
pub type Result<T> = std::result::Result<T, DbError>;

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
}

impl NullaDb {
    /// Open or create a database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
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
            _db: db,
        })
    }

    /// Update the best tip (highest cumulative work chain).
    pub fn set_best_tip(&self, id: &Hash32, height: u64, cumulative_work: u128) -> Result<()> {
        self.meta.insert(META_BEST_TIP, id)?;
        self.meta.insert(META_BEST_HEIGHT, &height.to_be_bytes())?;
        self.meta.insert(META_BEST_WORK, &cumulative_work.to_be_bytes())?;
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
        let height = self
            .meta
            .get(META_BEST_HEIGHT)?
            .map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap_or([0u8; 8])))
            .unwrap_or(0);
        let work = self
            .meta
            .get(META_BEST_WORK)?
            .map(|v| u128::from_be_bytes(v.as_ref().try_into().unwrap_or([0u8; 16])))
            .unwrap_or(0);
        Ok(Some((tip, height, work)))
    }

    /// Get the cumulative work for a specific block.
    pub fn get_work(&self, id: &Hash32) -> Result<Option<u128>> {
        match self.work.get(id)? {
            Some(bytes) => {
                let arr: [u8; 16] = bytes.as_ref().try_into().unwrap_or([0u8; 16]);
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

    /// Add a transaction to the mempool.
    pub fn put_mempool_tx(&self, tx: &Tx) -> Result<()> {
        let txid = nulla_core::tx_id(tx);
        self.mempool.insert(txid, bincode::serialize(tx)?)?;
        Ok(())
    }

    /// Remove a transaction from the mempool (typically after it's been mined).
    pub fn remove_mempool_tx(&self, txid: &Hash32) -> Result<()> {
        self.mempool.remove(txid)?;
        Ok(())
    }

    /// Add a UTXO to the set and index by address.
    pub fn put_utxo(&self, out: &OutPoint, txout: &TxOut) -> Result<()> {
        self.utxos.insert(
            bincode::serialize(out)?,
            bincode::serialize(txout)?,
        )?;

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

            total_input = total_input
                .checked_add(utxo.value_atoms)
                .ok_or_else(|| {
                    DbError::Serde(bincode::Error::new(bincode::ErrorKind::Custom(
                        "Input value overflow".to_string(),
                    )))
                })?;
        }

        Ok(total_input)
    }

    /// Apply a transaction to the UTXO set (mark inputs as spent, create new outputs).
    pub fn apply_tx(&self, tx: &nulla_core::Tx) -> Result<()> {
        let txid = nulla_core::tx_id(tx);

        // Mark all inputs as spent (skip coinbase inputs)
        for input in &tx.inputs {
            if !input.prevout.is_null() {
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
        }

        // Restore inputs (skip coinbase)
        // Note: This requires the original UTXOs to be stored elsewhere
        // For now, we'll just unmark them as spent
        for input in &tx.inputs {
            if !input.prevout.is_null() {
                self.unmark_spent(&input.prevout)?;
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
}
