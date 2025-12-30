use serde::{Deserialize, Serialize};

/// Blockchain information response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainInfo {
    pub chain: String,
    pub blocks: u64,
    pub headers: u64,
    pub bestblockhash: String,
    pub difficulty: f64,
    pub mediantime: u64,
    pub total_supply: f64,
    pub current_reward: f64,
}

/// Emission schedule information response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmissionInfo {
    pub height: u64,
    pub reward: f64,
    pub supply: f64,
    pub halvings: u32,
    pub blocks_until_next_halving: u64,
    pub tail_emission: bool,
    pub tail_emission_rate: f64,
}

/// Mempool information response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolInfo {
    pub size: usize,
    pub bytes: usize,
}

/// Address validation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    pub isvalid: bool,
    pub address: Option<String>,
}

/// UTXO information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnspentOutput {
    pub txid: String,
    pub vout: u32,
    pub address: String,
    pub amount: u64,
    pub confirmations: u64,
}

/// Transaction information (verbose)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInfo {
    pub txid: String,
    pub hash: String,
    pub size: usize,
    pub vsize: usize,
    pub version: u32,
    pub locktime: u64,
    pub vin: Vec<TxInput>,
    pub vout: Vec<TxOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockhash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmations: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocktime: Option<u64>,
}

/// Transaction input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInput {
    pub txid: String,
    pub vout: u32,
    pub sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<Vec<String>>,
}

/// Transaction output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutput {
    pub value: u64,
    pub n: u32,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: ScriptPubKey,
}

/// Script public key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptPubKey {
    pub hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(rename = "type")]
    pub script_type: String,
}

/// Block information (verbose)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    pub hash: String,
    pub confirmations: u64,
    pub height: u64,
    pub version: u32,
    pub merkleroot: String,
    pub time: u64,
    pub mediantime: u64,
    pub nonce: u64,
    pub bits: String,
    pub difficulty: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previousblockhash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nextblockhash: Option<String>,
    pub tx: Vec<String>,
    pub size: usize,
}

/// Block header information (verbose)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeaderInfo {
    pub hash: String,
    pub confirmations: u64,
    pub height: u64,
    pub version: u32,
    pub merkleroot: String,
    pub time: u64,
    pub mediantime: u64,
    pub nonce: u64,
    pub bits: String,
    pub difficulty: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previousblockhash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nextblockhash: Option<String>,
}

/// Wallet information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    pub walletname: String,
    pub walletversion: u32,
    pub balance: u64,
    pub txcount: usize,
    pub keypoolsize: u32,
}

/// Peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: String,
    pub addr: String,
    pub addrbind: String,
    pub addrlocal: String,
    pub network: String,
    pub version: String,
    pub subver: String,
    pub inbound: bool,
    pub conntime: u64,
    pub timeoffset: i64,
    pub pingtime: f64,
    pub synced_headers: u64,
    pub synced_blocks: u64,
}

/// Pruning mode information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruningInfo {
    pub enabled: bool,
    pub keep_blocks: u64,
    pub prune_height: u64,
    pub current_height: u64,
}
