use std::{path::PathBuf, str::FromStr};

use anyhow::Result;
use clap::Parser;
use nulla_core::{BlockHeader, Hash32};
use nulla_db::NullaDb;
use nulla_net::{self, protocol, NetConfig, NetworkCommand, NetworkEvent};
use tokio::signal;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

/// Command-line arguments for the Nulla node.
#[derive(Parser, Debug)]
#[command(name = "nulla", about = "Nulla minimal node", version)]
struct Args {
    /// Chain identifier (max 4 bytes). Used to isolate different networks.
    #[arg(long, default_value = "NULL")]
    chain_id: String,

    /// Multiaddress(es) to listen on (e.g., /ip4/0.0.0.0/tcp/27444).
    #[arg(long, value_parser)]
    listen: Vec<String>,

    /// Multiaddress(es) of peers to connect to on startup.
    #[arg(long, value_parser)]
    peers: Vec<String>,

    /// Path to the database directory.
    #[arg(long, default_value = "./data")]
    db: PathBuf,

    /// Enable the gossip networking stack.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    gossip: bool,

    /// Disable the gossip networking stack.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_gossip: bool,

    /// Enable Dandelion++ transaction privacy protocol.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    dandelion: bool,

    /// Disable Dandelion++ transaction privacy protocol.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_dandelion: bool,

    /// Enable cover traffic for network-level privacy (reduces timing analysis).
    #[arg(long, action = clap::ArgAction::SetTrue)]
    cover_traffic: bool,

    /// Enable stub miner (for gossip testing only; broadcasts dummy blocks).
    #[arg(long, default_value_t = false)]
    mine: bool,

    /// RPC server bind address (placeholder; not yet wired).
    #[arg(long, default_value = "127.0.0.1:27447")]
    rpc: String,

    /// Miner payout address (placeholder for future coinbase construction).
    #[arg(long)]
    miner_address: Option<String>,

    /// SOCKS5 proxy address (placeholder; not yet wired).
    #[arg(long)]
    socks5: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();
    let chain_id = chain_id_bytes(&args.chain_id);

    info!("starting nulla-node chain_id={:?}", args.chain_id);

    // Open the database for blocks, headers, UTXOs, and mempool.
    let db = NullaDb::open(&args.db)?;

    // Parse multiaddresses for listening and peer connections.
    let listen_addrs = parse_multiaddrs(&args.listen)?;
    let peer_addrs = parse_multiaddrs(&args.peers)?;

    // Determine if gossip should be enabled (default true unless --no-gossip is set).
    let gossip_enabled = !args.no_gossip && (args.gossip || args.listen.is_empty() || !args.listen.is_empty());

    // Determine if Dandelion++ should be enabled (default true unless --no-dandelion is set).
    let dandelion_enabled = !args.no_dandelion && (args.dandelion || true);

    if gossip_enabled {
        let net_cfg = NetConfig {
            chain_id,
            listen: listen_addrs,
            peers: peer_addrs,
            dandelion: dandelion_enabled,
            cover_traffic: args.cover_traffic,
        };
        let handle = nulla_net::spawn_network(net_cfg).await?;
        info!("local peer id {}", handle.local_peer_id);

        // Spawn event handler for inbound network events and request/response.
        let cmd_tx = handle.commands.clone();
        tokio::spawn(handle_network_events(handle.events, cmd_tx.clone(), db.clone()));

        // If mining is enabled, spawn the stub miner task.
        if args.mine {
            spawn_miner(chain_id, cmd_tx)?;
        }
    } else {
        info!("gossip stack disabled; node running in local-only mode");
    }

    // Wait for Ctrl+C to shut down gracefully.
    signal::ctrl_c().await?;
    info!("shutting down");
    Ok(())
}

/// Initialize tracing/logging for the node.
fn init_tracing() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// Convert a chain ID string to a 4-byte array (truncated or zero-padded).
fn chain_id_bytes(input: &str) -> [u8; 4] {
    let mut bytes = [0u8; 4];
    let slice = input.as_bytes();
    for i in 0..4.min(slice.len()) {
        bytes[i] = slice[i];
    }
    bytes
}

/// Parse a list of multiaddress strings into libp2p Multiaddr objects.
fn parse_multiaddrs(list: &[String]) -> Result<Vec<libp2p::Multiaddr>> {
    list.iter()
        .map(|s| libp2p::Multiaddr::from_str(s))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!(e))
}

/// Handle network events and respond to requests.
async fn handle_network_events(
    rx: async_channel::Receiver<NetworkEvent>,
    cmd_tx: async_channel::Sender<NetworkCommand>,
    db: NullaDb,
) {
    while let Ok(evt) = rx.recv().await {
        match evt {
            NetworkEvent::TxInv { from, txid } => {
                info!("inv tx from {from}: {}", hex::encode(txid));
            }
            NetworkEvent::BlockInv { from, header } => {
                info!(
                    "inv block from {from} height={} id={}",
                    header.height,
                    hex::encode(nulla_core::block_header_id(&header))
                );
                // Store the header in the database.
                if let Err(e) = db.put_header(&header) {
                    warn!("failed to store header: {e}");
                }
            }
            NetworkEvent::Request { peer, req, channel } => {
                info!("request from {peer:?}: {:?}", req);
                // Handle the request and send a response.
                let resp = handle_request(&db, req);
                let _ = cmd_tx
                    .send(NetworkCommand::SendResponse { channel, resp })
                    .await;
            }
            NetworkEvent::Response { peer, resp } => {
                info!("response from {peer:?}: {:?}", resp);
            }
            NetworkEvent::NewListen(addr) => info!("listening on {addr}"),
            NetworkEvent::PeerConnected(peer) => info!("peer connected {peer}"),
            NetworkEvent::PeerDisconnected(peer) => info!("peer disconnected {peer}"),
        }
    }
}

/// Handle an incoming request and generate a response.
fn handle_request(db: &NullaDb, req: protocol::Req) -> protocol::Resp {
    match req {
        protocol::Req::GetTip => {
            // Return the best known tip.
            match db.best_tip() {
                Ok(Some((id, height))) => {
                    // For now, cumulative work is a stub (just use height).
                    protocol::Resp::Tip {
                        height,
                        id,
                        cumulative_work: height as u128,
                    }
                }
                _ => protocol::Resp::Err { code: 404 },
            }
        }
        protocol::Req::GetBlock { id } => {
            // Return a full block by ID.
            match db.get_block(&id) {
                Ok(block) => protocol::Resp::Block { block },
                Err(_) => protocol::Resp::Err { code: 500 },
            }
        }
        protocol::Req::GetHeaders { from, limit } => {
            // Stub: return an empty list for now.
            // A full implementation would traverse the chain from the given hash.
            info!("get headers from {} limit {}", hex::encode(from), limit);
            protocol::Resp::Headers { headers: vec![] }
        }
        protocol::Req::GetTx { id } => {
            // Stub: return None for now.
            info!("get tx {}", hex::encode(id));
            protocol::Resp::Tx { tx: None }
        }
        protocol::Req::PeerExchange { want } => {
            // Stub: return an empty list of peer addresses.
            info!("peer exchange want {}", want);
            protocol::Resp::PeerExchange { addrs: vec![] }
        }
        protocol::Req::GetAddr => {
            // Stub: return an empty list of addresses.
            protocol::Resp::Addr { addrs: vec![] }
        }
        protocol::Req::StemTx { txid, hops_left } => {
            // Dandelion++ stem relay (handled elsewhere, return error here).
            warn!("stem tx {} hops_left {}", hex::encode(txid), hops_left);
            protocol::Resp::Err { code: 400 }
        }
    }
}

/// Spawn a stub miner that periodically broadcasts dummy blocks for testing gossip.
fn spawn_miner(chain_id: [u8; 4], cmd_tx: async_channel::Sender<NetworkCommand>) -> Result<()> {
    tokio::spawn(async move {
        info!("miner started (stub, no real chain state yet)");
        loop {
            // Create and broadcast a dummy block header to exercise the gossip network.
            let header = dummy_header(chain_id);
            let _ = cmd_tx
                .send(NetworkCommand::PublishBlock { header })
                .await;
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });
    Ok(())
}

/// Generate a dummy block header with a very low difficulty target.
fn dummy_header(chain_id: [u8; 4]) -> BlockHeader {
    let mut target = [0xffu8; 32];
    target[0] = 0x0f; // Very easy difficulty for testing
    BlockHeader {
        chain_id,
        version: 1,
        height: 0,
        prev: Hash32::default(),
        merkle_root: Hash32::default(),
        timestamp: chrono::Utc::now().timestamp() as u64,
        target,
        nonce: rand::random(),
    }
}
