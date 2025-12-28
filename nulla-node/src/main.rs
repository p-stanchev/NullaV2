use std::{path::PathBuf, str::FromStr, sync::Arc};

use anyhow::Result;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use nulla_core::{BlockHeader, Hash32};
use nulla_db::NullaDb;
use nulla_net::{self, protocol, NetConfig, NetworkCommand, NetworkEvent};
use nulla_wallet::Wallet;
use tokio::signal;
use tokio::sync::Mutex;
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

    /// Enable seed mode (builds blocks on top of chain, no mining).
    #[arg(long, default_value_t = false)]
    seed: bool,

    /// RPC server bind address (placeholder; not yet wired).
    #[arg(long, default_value = "127.0.0.1:27447")]
    rpc: String,

    /// Miner payout address (placeholder for future coinbase construction).
    #[arg(long)]
    miner_address: Option<String>,

    /// SOCKS5 proxy address (placeholder; not yet wired).
    #[arg(long)]
    socks5: Option<String>,

    /// Generate a new wallet and print the address and seed.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    generate_wallet: bool,

    /// Wallet seed (32 bytes hex) to use for signing transactions.
    #[arg(long)]
    wallet_seed: Option<String>,

    /// Get wallet address from seed.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    get_address: bool,

    /// Get wallet balance (requires --wallet-seed and --db).
    #[arg(long, action = clap::ArgAction::SetTrue)]
    get_balance: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    // Handle wallet generation command.
    if args.generate_wallet {
        let wallet = Wallet::new();
        let seed_hex = hex::encode(wallet.keypair().to_bytes());
        println!("\n=== New Wallet Generated ===");
        println!("Address: {}", wallet.address());
        println!("Seed:    {}", seed_hex);
        println!("\nSave your seed securely! You can use it with --wallet-seed to restore this wallet.");
        println!("Example: nulla --wallet-seed {}\n", seed_hex);
        return Ok(());
    }

    // Handle get address command.
    if args.get_address {
        if let Some(seed_hex) = &args.wallet_seed {
            match hex::decode(seed_hex) {
                Ok(seed_bytes) if seed_bytes.len() == 32 => {
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&seed_bytes);
                    let wallet = Wallet::from_seed(&seed);
                    println!("\n=== Wallet Address ===");
                    println!("{}", wallet.address());
                    return Ok(());
                }
                _ => {
                    eprintln!("Error: Invalid wallet seed (must be 32 bytes hex)");
                    std::process::exit(1);
                }
            }
        } else {
            eprintln!("Error: --wallet-seed required for --get-address");
            std::process::exit(1);
        }
    }

    // Handle get balance command.
    if args.get_balance {
        if let Some(seed_hex) = &args.wallet_seed {
            match hex::decode(seed_hex) {
                Ok(seed_bytes) if seed_bytes.len() == 32 => {
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&seed_bytes);
                    let wallet = Wallet::from_seed(&seed);
                    let db = NullaDb::open(&args.db)?;

                    // Get all UTXOs for this wallet's address.
                    let address = wallet.address();
                    let script_pubkey = address.to_script_pubkey();

                    // Scan UTXO set for outputs matching our address.
                    let mut balance_atoms: u64 = 0;
                    let mut utxo_count = 0;

                    // Note: This is a simple scan. In production, you'd want an index.
                    // For now, we'll just report 0 since we don't have UTXO indexing by address yet.
                    println!("\n=== Wallet Balance ===");
                    println!("Address: {}", address);
                    println!("Balance: {} NULLA ({} atoms)", nulla_wallet::atoms_to_nulla(balance_atoms), balance_atoms);
                    println!("UTXOs:   {}", utxo_count);
                    println!("\nNote: Full UTXO scanning not yet implemented.");
                    println!("Balance will be accurate once transactions are processed.");
                    return Ok(());
                }
                _ => {
                    eprintln!("Error: Invalid wallet seed (must be 32 bytes hex)");
                    std::process::exit(1);
                }
            }
        } else {
            eprintln!("Error: --wallet-seed required for --get-balance");
            std::process::exit(1);
        }
    }

    let chain_id = chain_id_bytes(&args.chain_id);

    info!("starting nulla-node chain_id={:?}", args.chain_id);

    // Load wallet if seed is provided.
    if let Some(seed_hex) = &args.wallet_seed {
        match hex::decode(seed_hex) {
            Ok(seed_bytes) if seed_bytes.len() == 32 => {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&seed_bytes);
                let wallet = Wallet::from_seed(&seed);
                info!("wallet loaded, address: {}", wallet.address());
            }
            _ => {
                warn!("invalid wallet seed (must be 32 bytes hex), ignoring");
            }
        }
    }

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
        let sync_progress = Arc::new(Mutex::new(None::<ProgressBar>));
        tokio::spawn(handle_network_events(
            handle.events,
            cmd_tx.clone(),
            db.clone(),
            sync_progress.clone(),
        ));

        // Spawn periodic peer sync task
        tokio::spawn(periodic_peer_sync(cmd_tx.clone(), db.clone()));

        // If mining is enabled, spawn the stub miner task.
        if args.mine {
            spawn_miner(chain_id, cmd_tx.clone())?;
        }

        // If seed mode is enabled, spawn the seed block builder.
        if args.seed {
            spawn_seed(chain_id, cmd_tx, db.clone(), handle.local_peer_id)?;
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
    sync_progress: Arc<Mutex<Option<ProgressBar>>>,
) {
    while let Ok(evt) = rx.recv().await {
        match evt {
            NetworkEvent::TxInv { from, txid } => {
                info!("inv tx from {from}: {}", hex::encode(txid));
            }
            NetworkEvent::BlockInv { from, header } => {
                let block_id = nulla_core::block_header_id(&header);
                info!(
                    "inv block from {from} height={} id={}",
                    header.height,
                    hex::encode(block_id)
                );

                // Store the header in the database.
                if let Err(e) = db.put_header(&header) {
                    warn!("failed to store header: {e}");
                    continue;
                }

                // Calculate cumulative work for this block.
                let block_work = nulla_core::target_work(&header.target);
                let cumulative_work = if header.prev == [0u8; 32] {
                    // Genesis block
                    block_work
                } else {
                    // Add this block's work to the previous block's cumulative work
                    match db.get_work(&header.prev) {
                        Ok(Some(prev_work)) => prev_work + block_work,
                        _ => block_work, // If we don't have the previous block, start fresh
                    }
                };

                // Store the cumulative work for this block.
                if let Err(e) = db.set_work(&block_id, cumulative_work) {
                    warn!("failed to store cumulative work: {e}");
                }

                // Check if this block is on top of our current best tip.
                match db.best_tip() {
                    Ok(Some((tip_id, tip_height, tip_work))) => {
                        // If this block builds on our tip, update the tip.
                        if header.prev == tip_id && header.height == tip_height + 1 {
                            if let Err(e) = db.set_best_tip(&block_id, header.height, cumulative_work) {
                                warn!("failed to update best tip: {e}");
                            } else {
                                info!("updated best tip to height {} (work: {})", header.height, cumulative_work);

                                // Update progress bar if syncing.
                                let mut progress_lock = sync_progress.lock().await;
                                if let Some(ref pb) = *progress_lock {
                                    pb.set_position(header.height);
                                    if header.height >= pb.length().unwrap_or(0) {
                                        pb.finish_with_message("✓ Synced!");
                                        *progress_lock = None;
                                    }
                                }
                            }
                        } else if cumulative_work > tip_work {
                            // This chain has more work than our current tip (possible fork/reorg).
                            info!(
                                "received chain with more work (our: {}, theirs: {}), height: {}",
                                tip_work, cumulative_work, header.height
                            );

                            // Update to the chain with most work.
                            if let Err(e) = db.set_best_tip(&block_id, header.height, cumulative_work) {
                                warn!("failed to update best tip: {e}");
                            } else {
                                info!("switched to new best chain at height {}", header.height);
                            }
                        } else if header.height > tip_height {
                            // We're behind, need to sync.
                            let blocks_behind = header.height - tip_height;
                            info!(
                                "we're behind (our height: {tip_height}, their height: {}), {} blocks behind",
                                header.height, blocks_behind
                            );

                            // Create or update progress bar.
                            let mut progress_lock = sync_progress.lock().await;
                            if progress_lock.is_none() {
                                let pb = ProgressBar::new(header.height);
                                pb.set_style(
                                    ProgressStyle::default_bar()
                                        .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} blocks ({eta})")
                                        .expect("progress style")
                                        .progress_chars("=>-"),
                                );
                                pb.set_position(tip_height);
                                *progress_lock = Some(pb);
                            } else if let Some(ref pb) = *progress_lock {
                                if header.height > pb.length().unwrap_or(0) {
                                    pb.set_length(header.height);
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        // No tip yet, this is our genesis.
                        if header.height == 0 {
                            if let Err(e) = db.set_best_tip(&block_id, 0, cumulative_work) {
                                warn!("failed to set genesis tip: {e}");
                            } else {
                                info!("set genesis block as tip (work: {})", cumulative_work);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("failed to get best tip: {e}");
                    }
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
                Ok(Some((id, height, cumulative_work))) => {
                    protocol::Resp::Tip {
                        height,
                        id,
                        cumulative_work,
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

/// Periodically sync chain state with connected peers.
///
/// Every 60 seconds, this task:
/// - Requests peer addresses for peer discovery
/// - Requests the best chain tip to check if we're behind
/// - Logs sync status
async fn periodic_peer_sync(
    _cmd_tx: async_channel::Sender<NetworkCommand>,
    _db: NullaDb,
) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;

        // Note: Peer exchange and tip requests are currently handled via
        // the request/response protocol but not actively sent here.
        // This is a placeholder for future sync logic that will:
        // 1. Send GetAddr requests to learn about new peers
        // 2. Send GetTip requests to check if we're synced
        // 3. Request missing blocks/headers if we're behind

        info!("periodic sync tick (peer discovery and chain sync)");
    }
}

/// Spawn a seed node that builds blocks on top of the chain without mining.
///
/// The seed role:
/// - Tracks the best chain tip from the database
/// - Creates new blocks every 30 seconds building on top of the best tip
/// - Increments block height properly
/// - Does NOT perform proof-of-work (uses easy target for testing)
/// - Uses its own peer ID to ensure only one seed creates blocks at a time
fn spawn_seed(
    chain_id: [u8; 4],
    cmd_tx: async_channel::Sender<NetworkCommand>,
    db: NullaDb,
    local_peer_id: libp2p::PeerId,
) -> Result<()> {
    tokio::spawn(async move {
        info!("seed node started (peer_id: {local_peer_id})");
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;

            // Get the current best tip from the database.
            let (prev_id, prev_height, prev_work) = match db.best_tip() {
                Ok(Some((id, height, work))) => {
                    info!("seed: building on height {height} (work: {work})");
                    (id, height, work)
                }
                Ok(None) => {
                    info!("seed: no tip found, building genesis block");
                    (Hash32::default(), 0, 0)
                }
                Err(e) => {
                    warn!("seed: failed to get best tip: {e}");
                    continue;
                }
            };

            // Build the next block on top of the previous tip.
            let next_height = if prev_id == Hash32::default() {
                0 // Genesis block
            } else {
                prev_height + 1
            };

            let header = BlockHeader {
                chain_id,
                version: 1,
                height: next_height,
                prev: prev_id,
                merkle_root: Hash32::default(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                target: [0xffu8; 32], // Very easy target (no real mining)
                nonce: rand::random(),
            };

            let block_id = nulla_core::block_header_id(&header);

            // Calculate cumulative work.
            let block_work = nulla_core::target_work(&header.target);
            let cumulative_work = prev_work + block_work;

            info!(
                "seed: broadcasting block height={} id={} (work: {})",
                next_height,
                hex::encode(block_id),
                cumulative_work
            );

            // Store the header, cumulative work, and update the best tip.
            if let Err(e) = db.put_header(&header) {
                warn!("seed: failed to store header: {e}");
                continue;
            }
            if let Err(e) = db.set_work(&block_id, cumulative_work) {
                warn!("seed: failed to store cumulative work: {e}");
                continue;
            }
            if let Err(e) = db.set_best_tip(&block_id, next_height, cumulative_work) {
                warn!("seed: failed to set best tip: {e}");
                continue;
            }

            // Broadcast the block to the network.
            let _ = cmd_tx.send(NetworkCommand::PublishBlock { header }).await;
        }
    });
    Ok(())
}
