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
            _db: db,
        })
    }

    /// Update the best tip (highest cumulative work chain).
    pub fn set_best_tip(&self, id: &Hash32, height: u64) -> Result<()> {
        self.meta.insert(META_BEST_TIP, id)?;
        self.meta.insert(META_BEST_HEIGHT, &height.to_be_bytes())?;
        Ok(())
    }

    /// Retrieve the current best tip hash and height.
    pub fn best_tip(&self) -> Result<Option<(Hash32, u64)>> {
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
        Ok(Some((tip, height)))
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
}
