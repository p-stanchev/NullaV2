//! Electrum-style protocol for light wallets.
//!
//! This module provides SPV (Simplified Payment Verification) capabilities
//! allowing lightweight clients to verify transactions without downloading
//! the entire blockchain.
//!
//! ## Features
//! - Header-only sync (download block headers, not full blocks)
//! - Merkle proof generation and verification
//! - Address subscription for balance tracking
//! - Transaction broadcasting
//! - UTXO queries for specific addresses
//!
//! ## Protocol
//! The Electrum protocol is JSON-RPC based and provides these key methods:
//! - `blockchain.headers.subscribe` - Subscribe to new headers
//! - `blockchain.scripthash.subscribe` - Subscribe to address changes
//! - `blockchain.scripthash.get_balance` - Get address balance
//! - `blockchain.scripthash.get_history` - Get transaction history
//! - `blockchain.scripthash.listunspent` - List UTXOs
//! - `blockchain.transaction.broadcast` - Broadcast transaction
//! - `blockchain.transaction.get` - Get transaction by ID
//! - `blockchain.transaction.get_merkle` - Get merkle proof

use nulla_core::{BlockHeader, Hash32, OutPoint, Tx, TxOut};
use nulla_db::NullaDb;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Electrum protocol errors.
#[derive(Debug, Error)]
pub enum ElectrumError {
    #[error("database error: {0}")]
    Database(#[from] nulla_db::DbError),
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("transaction not found: {0}")]
    TransactionNotFound(String),
    #[error("block not found: {0}")]
    BlockNotFound(String),
    #[error("merkle proof generation failed: {0}")]
    MerkleProofFailed(String),
}

pub type Result<T> = std::result::Result<T, ElectrumError>;

/// Electrum protocol server state.
pub struct ElectrumServer {
    db: NullaDb,
    chain_id: [u8; 4],
}

impl ElectrumServer {
    /// Create a new Electrum server.
    pub fn new(db: NullaDb, chain_id: [u8; 4]) -> Self {
        Self { db, chain_id }
    }

    /// Get the current blockchain tip header.
    pub fn get_tip_header(&self) -> Result<BlockHeader> {
        let (tip_id, _height, _work) = self.db.best_tip()?
            .ok_or_else(|| ElectrumError::BlockNotFound("no tip found".to_string()))?;

        self.db.get_header(&tip_id)?
            .ok_or_else(|| ElectrumError::BlockNotFound("tip header not found".to_string()))
    }

    /// Get block header by height.
    pub fn get_header_by_height(&self, height: u64) -> Result<Option<BlockHeader>> {
        Ok(self.db.get_header_by_height(height)?)
    }

    /// Get headers in a range (for header sync).
    /// Returns up to `count` headers starting from `start_height`.
    pub fn get_headers_range(&self, start_height: u64, count: u64) -> Result<Vec<BlockHeader>> {
        let mut headers = Vec::new();
        for height in start_height..start_height + count {
            if let Some(header) = self.get_header_by_height(height)? {
                headers.push(header);
            } else {
                break; // No more headers available
            }
        }
        Ok(headers)
    }

    /// Get balance for an address.
    pub fn get_balance(&self, address: &[u8; 20]) -> Result<u64> {
        let utxos = self.db.get_utxos_by_address(address)?;
        let balance = utxos.iter().map(|(_, txout)| txout.value_atoms).sum();
        Ok(balance)
    }

    /// Get UTXOs for an address.
    pub fn get_utxos(&self, address: &[u8; 20]) -> Result<Vec<(OutPoint, TxOut, u64)>> {
        let utxos = self.db.get_utxos_by_address(address)?;
        let (_tip, current_height, _work) = self.db.best_tip()?
            .unwrap_or(([0u8; 32], 0, 0));

        // Add height information to each UTXO (needed for confirmations)
        let mut result = Vec::new();
        for (outpoint, txout) in utxos {
            // For now, we don't track which block each tx was in
            // This would require an additional index (txid -> block_height)
            // For MVP, we'll return 0 confirmations
            result.push((outpoint, txout, current_height));
        }
        Ok(result)
    }

    /// Get transaction by ID from mempool or blockchain.
    /// Note: This requires the full block to be available (won't work with pruned blocks).
    pub fn get_transaction(&self, txid: &Hash32) -> Result<Option<Tx>> {
        // First check mempool
        if let Some(tx) = self.db.get_mempool_tx(txid)? {
            return Ok(Some(tx));
        }

        // For blockchain transactions, we'd need a tx index
        // This is not implemented yet - would require txid -> block_id mapping
        Ok(None)
    }

    /// Generate merkle proof for a transaction in a block.
    /// Returns the merkle branch and position of the transaction.
    pub fn get_merkle_proof(&self, txid: &Hash32, block_id: &Hash32) -> Result<MerkleProof> {
        let block = self.db.get_block(block_id)?
            .ok_or_else(|| ElectrumError::BlockNotFound(hex::encode(block_id)))?;

        // Find transaction index in block
        let tx_index = block.txs.iter()
            .position(|tx| &nulla_core::tx_id(tx) == txid)
            .ok_or_else(|| ElectrumError::TransactionNotFound(hex::encode(txid)))?;

        // Build merkle tree and extract proof
        let merkle_branch = compute_merkle_branch(&block.txs, tx_index);

        Ok(MerkleProof {
            merkle_root: block.header.merkle_root,
            merkle_branch,
            tx_index: tx_index as u32,
            block_height: block.header.height,
        })
    }

    /// Broadcast a transaction to the mempool.
    pub fn broadcast_transaction(&self, tx: Tx) -> Result<Hash32> {
        let txid = nulla_core::tx_id(&tx);
        self.db.put_mempool_tx(&tx, &self.chain_id)?;
        Ok(txid)
    }
}

/// Merkle proof for SPV verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Root hash of the merkle tree (should match block header).
    pub merkle_root: Hash32,
    /// Branch hashes needed to verify the transaction.
    pub merkle_branch: Vec<Hash32>,
    /// Index of the transaction in the block.
    pub tx_index: u32,
    /// Block height (for confirmation count).
    pub block_height: u64,
}

impl MerkleProof {
    /// Verify that a transaction hash is included in the merkle tree.
    pub fn verify(&self, txid: &Hash32) -> bool {
        let mut hash = *txid;
        let mut index = self.tx_index;

        for branch_hash in &self.merkle_branch {
            let mut hasher = blake3::Hasher::new();
            if index % 2 == 0 {
                // Transaction is on the left
                hasher.update(&hash);
                hasher.update(branch_hash);
            } else {
                // Transaction is on the right
                hasher.update(branch_hash);
                hasher.update(&hash);
            }
            hash = *hasher.finalize().as_bytes();
            index /= 2;
        }

        hash == self.merkle_root
    }
}

/// Compute merkle branch for a transaction at given index.
fn compute_merkle_branch(txs: &[Tx], tx_index: usize) -> Vec<Hash32> {
    let mut branch = Vec::new();
    let mut hashes: Vec<Hash32> = txs.iter().map(|tx| nulla_core::tx_id(tx)).collect();
    let mut index = tx_index;

    while hashes.len() > 1 {
        let mut next_level = Vec::new();

        for i in (0..hashes.len()).step_by(2) {
            // Find sibling for merkle proof
            let sibling_index = if i == index {
                if i + 1 < hashes.len() {
                    i + 1
                } else {
                    i // Duplicate last hash if odd number
                }
            } else if i + 1 == index {
                i
            } else {
                usize::MAX // Not relevant to our branch
            };

            if sibling_index != usize::MAX {
                branch.push(hashes[sibling_index]);
            }

            // Compute parent hash
            let left = hashes[i];
            let right = if i + 1 < hashes.len() {
                hashes[i + 1]
            } else {
                hashes[i] // Duplicate if odd
            };

            let mut hasher = blake3::Hasher::new();
            hasher.update(&left);
            hasher.update(&right);
            next_level.push(*hasher.finalize().as_bytes());
        }

        hashes = next_level;
        index /= 2;
    }

    branch
}

/// Header subscription response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderNotification {
    pub height: u64,
    pub hex: String,
}

/// Address balance response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressBalance {
    pub confirmed: u64,
    pub unconfirmed: u64,
}

/// Transaction history item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryItem {
    pub txid: String,
    pub height: u64,
    pub fee: Option<u64>,
}

/// Unspent output item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnspentItem {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_proof_verification() {
        // Create sample transactions
        let tx1 = Tx {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        };
        let tx2 = Tx {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 1,
        };
        let tx3 = Tx {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 2,
        };

        let txs = vec![tx1.clone(), tx2.clone(), tx3.clone()];
        let txid = nulla_core::tx_id(&tx2);

        // Compute merkle branch
        let branch = compute_merkle_branch(&txs, 1);

        // Compute merkle root manually
        let h1 = nulla_core::tx_id(&tx1);
        let h2 = nulla_core::tx_id(&tx2);
        let h3 = nulla_core::tx_id(&tx3);

        let mut hasher = blake3::Hasher::new();
        hasher.update(&h1);
        hasher.update(&h2);
        let parent1 = *hasher.finalize().as_bytes();

        let mut hasher = blake3::Hasher::new();
        hasher.update(&h3);
        hasher.update(&h3); // Duplicate
        let parent2 = *hasher.finalize().as_bytes();

        let mut hasher = blake3::Hasher::new();
        hasher.update(&parent1);
        hasher.update(&parent2);
        let root = *hasher.finalize().as_bytes();

        // Create proof
        let proof = MerkleProof {
            merkle_root: root,
            merkle_branch: branch,
            tx_index: 1,
            block_height: 100,
        };

        // Verify proof
        assert!(proof.verify(&txid));
    }
}
