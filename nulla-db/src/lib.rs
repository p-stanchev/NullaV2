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

    /// Add a UTXO to the set.
    pub fn put_utxo(&self, out: &OutPoint, txout: &TxOut) -> Result<()> {
        self.utxos.insert(
            bincode::serialize(out)?,
            bincode::serialize(txout)?,
        )?;
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

    /// Remove a UTXO from the set (used during chain reorganization).
    pub fn remove_utxo(&self, out: &OutPoint) -> Result<()> {
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
}
