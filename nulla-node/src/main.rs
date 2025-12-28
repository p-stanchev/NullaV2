use std::{
    path::PathBuf,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::Result;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use nulla_core::Hash32;
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

    /// Enable seed node mode (relay and sync blocks, no mining).
    #[arg(long, default_value_t = false)]
    seed: bool,

    /// Enable mining (creates blocks with proof-of-work).
    #[arg(long, default_value_t = false)]
    mine: bool,

    /// RPC server bind address (placeholder; not yet wired).
    #[arg(long, default_value = "127.0.0.1:27447")]
    rpc: String,

    /// Miner payout address for block rewards (40-char hex, 20 bytes).
    /// Use this instead of --wallet-seed for mining to avoid exposing private keys.
    /// Example: --miner-address 79bc6374ccc99f1211770ce007e05f6235b98c8b
    #[arg(long)]
    miner_address: Option<String>,

    /// SOCKS5 proxy address (placeholder; not yet wired).
    #[arg(long)]
    socks5: Option<String>,

    /// Generate a new wallet and print the address and seed.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    generate_wallet: bool,

    /// Wallet seed (32 bytes hex) to use for signing transactions.
    /// WARNING: Only use for transaction signing, NOT for mining!
    /// For mining, use --miner-address instead to avoid exposing your private key.
    #[arg(long)]
    wallet_seed: Option<String>,

    /// Get wallet address from seed.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    get_address: bool,

    /// Get wallet balance (requires --wallet-seed and --db).
    /// DEPRECATED: Use --balance <ADDRESS> instead.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    get_balance: bool,

    /// Check balance for any address (40-char hex, 20 bytes).
    /// Example: --balance 79bc6374ccc99f1211770ce007e05f6235b98c8b
    /// Works with any address - check your own balance or someone else's.
    #[arg(long)]
    balance: Option<String>,

    /// Send NULLA to an address (requires --wallet-seed, --to, and --amount).
    /// Example: --send --to 79bc6374ccc99f1211770ce007e05f6235b98c8b --amount 5.0
    #[arg(long, action = clap::ArgAction::SetTrue)]
    send: bool,

    /// Recipient address for sending NULLA (40-char hex, 20 bytes).
    #[arg(long)]
    to: Option<String>,

    /// Amount to send in NULLA (e.g., 5.0 = 500000000 atoms).
    #[arg(long)]
    amount: Option<f64>,
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
        println!("\nIMPORTANT: Save your seed NOW! This will not be shown again.");
        println!("IMPORTANT: Anyone with this seed can spend your funds.");
        println!("\nTo use this wallet later:");
        println!("  --wallet-seed {}", seed_hex);
        println!("\nTo check balance:");
        println!("  --balance {}\n", wallet.address());
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

                    // Fetch UTXOs from the address index
                    let utxos = db.get_utxos_by_address(&address.0)?;
                    let balance_atoms: u64 = utxos.iter().map(|(_, txout)| txout.value_atoms).sum();
                    let utxo_count = utxos.len();

                    println!("\n=== Wallet Balance ===");
                    println!("Address: {}", address);
                    println!(
                        "Balance: {} NULLA ({} atoms)",
                        nulla_wallet::atoms_to_nulla(balance_atoms),
                        balance_atoms
                    );
                    println!("UTXOs:   {}", utxo_count);

                    if !utxos.is_empty() {
                        println!("\nUTXO Details:");
                        for (outpoint, txout) in utxos {
                            println!(
                                "  {} vout:{} = {} atoms",
                                hex::encode(&outpoint.txid[..8]),
                                outpoint.vout,
                                txout.value_atoms
                            );
                        }
                    }

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

    // Handle balance check command (new, better version - works with any address).
    if let Some(addr_hex) = &args.balance {
        match nulla_wallet::Address::from_hex(addr_hex) {
            Some(address) => {
                let db = NullaDb::open(&args.db)?;

                // Fetch UTXOs from the address index
                let utxos = db.get_utxos_by_address(&address.0)?;
                let balance_atoms: u64 = utxos.iter().map(|(_, txout)| txout.value_atoms).sum();

                println!("\n{} NULLA", nulla_wallet::atoms_to_nulla(balance_atoms));

                return Ok(());
            }
            None => {
                eprintln!("Error: Invalid address (must be 40-char hex, 20 bytes)");
                eprintln!("Example: nulla --balance 79bc6374ccc99f1211770ce007e05f6235b98c8b");
                std::process::exit(1);
            }
        }
    }

    // Handle send transaction command.
    if args.send {
        // Validate required arguments.
        let wallet_seed = match &args.wallet_seed {
            Some(s) => s,
            None => {
                eprintln!("Error: --wallet-seed required for --send");
                std::process::exit(1);
            }
        };
        let to_addr = match &args.to {
            Some(s) => s,
            None => {
                eprintln!("Error: --to <ADDRESS> required for --send");
                std::process::exit(1);
            }
        };
        let amount_nulla = match args.amount {
            Some(a) => a,
            None => {
                eprintln!("Error: --amount <NULLA> required for --send");
                std::process::exit(1);
            }
        };

        // Parse wallet seed.
        let seed_bytes = match hex::decode(wallet_seed) {
            Ok(bytes) if bytes.len() == 32 => bytes,
            _ => {
                eprintln!("Error: Invalid wallet seed (must be 32 bytes hex)");
                std::process::exit(1);
            }
        };
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        let wallet = Wallet::from_seed(&seed);

        // Parse recipient address.
        let recipient = match nulla_wallet::Address::from_hex(to_addr) {
            Some(addr) => addr,
            None => {
                eprintln!("Error: Invalid recipient address (must be 40-char hex, 20 bytes)");
                std::process::exit(1);
            }
        };

        // Convert amount to atoms.
        let amount_atoms = nulla_wallet::nulla_to_atoms(amount_nulla);
        if amount_atoms == 0 {
            eprintln!("Error: Amount must be greater than 0");
            std::process::exit(1);
        }

        // Open database and get wallet UTXOs.
        let db = NullaDb::open(&args.db)?;
        let sender_addr = wallet.address();
        let utxos = db.get_utxos_by_address(&sender_addr.0)?;

        if utxos.is_empty() {
            eprintln!("Error: No UTXOs available (balance is 0)");
            std::process::exit(1);
        }

        // Select UTXOs to cover the amount (simple first-fit algorithm).
        let mut selected_utxos = Vec::new();
        let mut selected_value: u64 = 0;
        for (outpoint, txout) in utxos {
            selected_utxos.push((outpoint, txout.clone()));
            selected_value += txout.value_atoms;
            if selected_value >= amount_atoms {
                break;
            }
        }

        if selected_value < amount_atoms {
            let balance = nulla_wallet::atoms_to_nulla(selected_value);
            eprintln!("Error: Insufficient balance");
            eprintln!(
                "Available: {} NULLA, Required: {} NULLA",
                balance, amount_nulla
            );
            std::process::exit(1);
        }

        // Create transaction inputs.
        use nulla_core::TxIn;
        let inputs: Vec<TxIn> = selected_utxos
            .iter()
            .map(|(outpoint, _)| TxIn {
                prevout: outpoint.clone(),
                sig: vec![],    // Will be filled by wallet
                pubkey: vec![], // Will be filled by wallet
            })
            .collect();

        // Create transaction outputs (payment + change).
        use nulla_core::TxOut;
        let mut outputs = vec![TxOut {
            value_atoms: amount_atoms,
            script_pubkey: recipient.to_script_pubkey(),
        }];

        // Add change output if there's any leftover.
        let change = selected_value - amount_atoms;
        if change > 0 {
            outputs.push(TxOut {
                value_atoms: change,
                script_pubkey: sender_addr.to_script_pubkey(),
            });
        }

        // Create and sign the transaction.
        let tx = match wallet.create_transaction(inputs, outputs, 0) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Error creating transaction: {}", e);
                std::process::exit(1);
            }
        };

        let txid = nulla_core::tx_id(&tx);

        // Validate transaction signatures before broadcasting.
        if let Err(e) = db.verify_tx_signatures(&tx) {
            eprintln!("Error: Transaction signature verification failed: {}", e);
            std::process::exit(1);
        }

        // Validate transaction inputs before broadcasting.
        if let Err(e) = db.validate_tx_inputs(&tx) {
            eprintln!("Error: Transaction input validation failed: {}", e);
            std::process::exit(1);
        }

        // Add transaction to mempool.
        if let Err(e) = db.put_mempool_tx(&tx) {
            eprintln!("Error adding transaction to mempool: {}", e);
            std::process::exit(1);
        }

        println!("\n=== Transaction Created ===");
        println!("From:   {}", sender_addr);
        println!("To:     {}", recipient);
        println!("Amount: {} NULLA ({} atoms)", amount_nulla, amount_atoms);
        if change > 0 {
            println!(
                "Change: {} NULLA ({} atoms)",
                nulla_wallet::atoms_to_nulla(change),
                change
            );
        }
        println!("TxID:   {}", hex::encode(txid));
        println!("\nBroadcasting transaction to peers...");

        // Setup networking to broadcast the transaction.
        let chain_id = chain_id_bytes(&args.chain_id);
        let listen_addrs = parse_multiaddrs(&args.listen)?;
        let peer_addrs = parse_multiaddrs(&args.peers)?;

        if peer_addrs.is_empty() {
            eprintln!("\nError: No peers configured!");
            eprintln!("Transaction created but NOT broadcasted (no peers online).");
            eprintln!("The transaction is saved in the local mempool.");
            eprintln!("To broadcast, restart the node with --peers to connect to the network.");
            std::process::exit(1);
        }

        let net_cfg = nulla_net::NetConfig {
            chain_id,
            listen: listen_addrs,
            peers: peer_addrs.clone(),
            dandelion: false, // Disable Dandelion for direct broadcast
            cover_traffic: false,
        };

        let handle = nulla_net::spawn_network(net_cfg).await?;
        println!("Connected to {} peer(s)", peer_addrs.len());

        // Wait a bit for connections to establish.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Broadcast the full transaction to the network.
        handle
            .commands
            .send(nulla_net::NetworkCommand::PublishFullTx { tx })
            .await?;

        println!("Transaction broadcasted successfully!");
        println!("\nThe transaction will be included in the next block.");

        return Ok(());
    }

    let chain_id = chain_id_bytes(&args.chain_id);

    info!("starting nulla-node chain_id={:?}", args.chain_id);

    // Load wallet if seed is provided.
    let wallet = if let Some(seed_hex) = &args.wallet_seed {
        match hex::decode(seed_hex) {
            Ok(seed_bytes) if seed_bytes.len() == 32 => {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&seed_bytes);
                let wallet = Wallet::from_seed(&seed);
                info!("wallet loaded, address: {}", wallet.address());
                Some(wallet)
            }
            _ => {
                warn!("invalid wallet seed (must be 32 bytes hex), ignoring");
                None
            }
        }
    } else {
        None
    };

    // Parse miner address if provided (for receiving block rewards without exposing private key).
    let miner_address = if let Some(addr_hex) = &args.miner_address {
        match nulla_wallet::Address::from_hex(addr_hex) {
            Some(addr) => {
                info!("miner address loaded: {}", addr);
                Some(addr)
            }
            None => {
                warn!("invalid miner address (must be 40-char hex, 20 bytes), ignoring");
                None
            }
        }
    } else {
        None
    };

    // Open the database for blocks, headers, UTXOs, and mempool.
    let db = NullaDb::open(&args.db)?;

    // Parse multiaddresses for listening and peer connections.
    let listen_addrs = parse_multiaddrs(&args.listen)?;
    let peer_addrs = parse_multiaddrs(&args.peers)?;

    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let _ = signal::ctrl_c().await;
            shutdown.store(true, Ordering::SeqCst);
        });
    }

    // Determine if gossip should be enabled (default true unless --no-gossip is set).
    let gossip_enabled =
        !args.no_gossip && (args.gossip || args.listen.is_empty() || !args.listen.is_empty());

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

        // If seed mode is enabled, spawn the seed node (relay/sync only).
        if args.seed {
            spawn_seed(chain_id, cmd_tx.clone(), db.clone(), handle.local_peer_id)?;
        }

        // If mining is enabled, spawn the miner block builder.
        if args.mine {
            // Determine coinbase address (prefer miner_address for security)
            let coinbase_addr = miner_address.or_else(|| wallet.as_ref().map(|w| w.address()));

            if coinbase_addr.is_none() {
                warn!("mining enabled but no address provided; use --miner-address or --wallet-seed to receive block rewards");
            }
            spawn_miner_real(
                chain_id,
                cmd_tx.clone(),
                db.clone(),
                handle.local_peer_id,
                coinbase_addr,
                shutdown.clone(),
            )?;
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

                // Check if we already have this transaction in the mempool
                if db.get_mempool_tx(&txid).unwrap_or(None).is_some() {
                    info!("tx {} already in mempool, skipping", hex::encode(txid));
                } else {
                    // We don't have this transaction yet, request it from the peer
                    info!("requesting tx {} from {}", hex::encode(txid), from);
                    // Note: We would send a GetTx request here, but for now we just log it
                    // In a full implementation, we'd use the request/response protocol
                }
            }
            NetworkEvent::FullTx { from, tx } => {
                let txid = nulla_core::tx_id(&tx);
                info!("received full tx from {from}: {}", hex::encode(txid));

                // Check if we already have this transaction
                if db.get_mempool_tx(&txid).unwrap_or(None).is_some() {
                    info!("tx {} already in mempool, skipping", hex::encode(txid));
                    continue;
                }

                // Validate transaction signatures
                if let Err(e) = db.verify_tx_signatures(&tx) {
                    warn!("received invalid transaction (signature verification failed): {e}");
                    continue;
                }

                // Validate transaction inputs (check UTXOs exist and aren't spent)
                if let Err(e) = db.validate_tx_inputs(&tx) {
                    warn!("received invalid transaction (input validation failed): {e}");
                    continue;
                }

                // Add to mempool
                if let Err(e) = db.put_mempool_tx(&tx) {
                    warn!("failed to add transaction to mempool: {e}");
                    continue;
                }

                info!(
                    "transaction {} added to mempool, relaying to peers",
                    hex::encode(txid)
                );

                // Relay the transaction to all other peers (gossip protocol)
                let _ = cmd_tx
                    .send(nulla_net::NetworkCommand::PublishFullTx { tx })
                    .await;
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
                            if let Err(e) =
                                db.set_best_tip(&block_id, header.height, cumulative_work)
                            {
                                warn!("failed to update best tip: {e}");
                            } else {
                                info!(
                                    "updated best tip to height {} (work: {})",
                                    header.height, cumulative_work
                                );

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
                            if let Err(e) =
                                db.set_best_tip(&block_id, header.height, cumulative_work)
                            {
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
            NetworkEvent::FullBlock { from, block } => {
                let block_id = nulla_core::block_id(&block);
                info!(
                    "full block from {from} height={} id={} txs={}",
                    block.header.height,
                    hex::encode(block_id),
                    block.txs.len()
                );

                // Validate the block structure
                if let Err(e) = nulla_core::validate_block(&block) {
                    warn!("received invalid block (structure): {e}");
                    continue;
                }

                // Verify signatures on all transactions (except coinbase)
                let mut block_valid = true;
                for (i, tx) in block.txs.iter().enumerate() {
                    if let Err(e) = db.verify_tx_signatures(tx) {
                        warn!("block rejected: transaction {i} has invalid signature: {e}");
                        block_valid = false;
                        break;
                    }
                }
                if !block_valid {
                    continue;
                }

                // Validate UTXO inputs for all transactions (except coinbase)
                for (i, tx) in block.txs.iter().enumerate() {
                    if !nulla_core::is_coinbase(tx) {
                        if let Err(e) = db.validate_tx_inputs(tx) {
                            warn!("block rejected: transaction {i} has invalid inputs: {e}");
                            block_valid = false;
                            break;
                        }
                    }
                }
                if !block_valid {
                    continue;
                }

                // Store the full block
                if let Err(e) = db.put_block_full(&block) {
                    warn!("failed to store full block: {e}");
                    continue;
                }

                // Calculate cumulative work
                let block_work = nulla_core::target_work(&block.header.target);
                let cumulative_work = if block.header.prev == [0u8; 32] {
                    block_work
                } else {
                    match db.get_work(&block.header.prev) {
                        Ok(Some(prev_work)) => prev_work + block_work,
                        _ => block_work,
                    }
                };

                // Store cumulative work
                if let Err(e) = db.set_work(&block_id, cumulative_work) {
                    warn!("failed to store cumulative work: {e}");
                }

                // Apply transactions to UTXO set (coinbase and regular txs)
                for tx in &block.txs {
                    if let Err(e) = db.apply_tx(tx) {
                        warn!("failed to apply transaction: {e}");
                    }
                }

                // Remove transactions from mempool (they're now in a block)
                for tx in block.txs.iter().skip(1) {
                    // Skip coinbase
                    let txid = nulla_core::tx_id(tx);
                    let _ = db.remove_mempool_tx(&txid);
                }

                // Update best tip if appropriate
                match db.best_tip() {
                    Ok(Some((tip_id, tip_height, tip_work))) => {
                        if block.header.prev == tip_id && block.header.height == tip_height + 1 {
                            if let Err(e) =
                                db.set_best_tip(&block_id, block.header.height, cumulative_work)
                            {
                                warn!("failed to update best tip: {e}");
                            } else {
                                info!(
                                    "updated best tip to height {} (work: {})",
                                    block.header.height, cumulative_work
                                );

                                // Update progress bar
                                let mut progress_lock = sync_progress.lock().await;
                                if let Some(ref pb) = *progress_lock {
                                    pb.set_position(block.header.height);
                                    if block.header.height >= pb.length().unwrap_or(0) {
                                        pb.finish_with_message("✓ Synced!");
                                        *progress_lock = None;
                                    }
                                }
                            }
                        } else if cumulative_work > tip_work {
                            info!(
                                "received chain with more work (our: {}, theirs: {}), height: {}",
                                tip_work, cumulative_work, block.header.height
                            );
                            if let Err(e) =
                                db.set_best_tip(&block_id, block.header.height, cumulative_work)
                            {
                                warn!("failed to update best tip: {e}");
                            } else {
                                info!(
                                    "switched to new best chain at height {}",
                                    block.header.height
                                );
                            }
                        } else if block.header.height > tip_height {
                            let blocks_behind = block.header.height - tip_height;
                            info!(
                                "we're behind (our height: {tip_height}, their height: {}), {} blocks behind",
                                block.header.height, blocks_behind
                            );

                            // Create or update progress bar
                            let mut progress_lock = sync_progress.lock().await;
                            if progress_lock.is_none() {
                                let pb = ProgressBar::new(block.header.height);
                                pb.set_style(
                                    ProgressStyle::default_bar()
                                        .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} blocks ({eta})")
                                        .expect("progress style")
                                        .progress_chars("=>-"),
                                );
                                pb.set_position(tip_height);
                                *progress_lock = Some(pb);
                            } else if let Some(ref pb) = *progress_lock {
                                if block.header.height > pb.length().unwrap_or(0) {
                                    pb.set_length(block.header.height);
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        if block.header.height == 0 {
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
                Ok(Some((id, height, cumulative_work))) => protocol::Resp::Tip {
                    height,
                    id,
                    cumulative_work,
                },
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
            // Traverse the chain backwards from the given hash and return block headers.
            info!("get headers from {} limit {}", hex::encode(from), limit);

            let mut headers = Vec::new();
            let mut current_id = from;
            let max_headers = limit.min(500); // Cap at 500 to prevent abuse

            for _ in 0..max_headers {
                match db.get_block(&current_id) {
                    Ok(Some(block)) => {
                        let header = block.header.clone();
                        let prev = header.prev;
                        headers.push(header);

                        // Stop at genesis (prev == all zeros)
                        if prev == [0u8; 32] {
                            break;
                        }
                        current_id = prev;
                    }
                    _ => break, // Block not found or error, stop traversal
                }
            }

            info!("returning {} headers", headers.len());
            protocol::Resp::Headers { headers }
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

/// Periodically sync chain state with connected peers.
///
/// Every 60 seconds, this task:
/// - Logs current chain state
/// - Ensures peers are kept in sync via gossipsub
async fn periodic_peer_sync(_cmd_tx: async_channel::Sender<NetworkCommand>, db: NullaDb) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;

        // Log current chain state for monitoring
        match db.best_tip() {
            Ok(Some((tip_id, height, work))) => {
                info!(
                    "sync tick: height={} tip={} work={} mempool={}",
                    height,
                    hex::encode(&tip_id[..8]),
                    work,
                    db.mempool_size()
                );
            }
            Ok(None) => {
                info!("sync tick: no chain tip yet, waiting for blocks");
            }
            Err(e) => {
                warn!("sync tick: failed to get chain state: {}", e);
            }
        }

        // Note: Blockchain synchronization happens automatically via gossipsub.
        // When peers receive blocks, they:
        // 1. Validate and store the block
        // 2. Update their chain tip if the block extends the best chain
        // 3. Re-broadcast the block to other peers
        //
        // This creates a natural gossip-based synchronization where all peers
        // eventually converge on the same chain state.
    }
}

/// Spawn a seed node that relays and syncs blocks without mining.
///
/// Seed nodes:
/// - Connect to peers and relay blocks/transactions
/// - Sync blockchain state from the network
/// - Do NOT create new blocks
/// - Help bootstrap and maintain network connectivity
fn spawn_seed(
    _chain_id: [u8; 4],
    _cmd_tx: async_channel::Sender<NetworkCommand>,
    db: NullaDb,
    local_peer_id: libp2p::PeerId,
) -> Result<()> {
    tokio::spawn(async move {
        info!("seed node started (peer_id: {local_peer_id})");
        info!("seed: relay mode active - will sync and relay blocks but not mine");

        // Seed node just needs to stay alive and let the networking layer
        // handle block relay and synchronization. The periodic_peer_sync
        // and handle_network_events tasks handle the actual syncing.

        // Log periodic status updates
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;

            match db.best_tip() {
                Ok(Some((tip_id, height, work))) => {
                    info!(
                        "seed: synced to height {} (tip: {}, work: {})",
                        height,
                        hex::encode(&tip_id[..8]),
                        work
                    );
                }
                Ok(None) => {
                    info!("seed: waiting for blockchain data from peers...");
                }
                Err(e) => {
                    warn!("seed: failed to get best tip: {e}");
                }
            }
        }
    });
    Ok(())
}

/// Spawn a miner that builds blocks on top of the chain with proof-of-work.
///
/// Miners:
/// - Tracks the best chain tip from the database
/// - Creates new blocks building on top of the best tip
/// - Performs actual proof-of-work mining to find valid nonces
/// - Includes transactions from the mempool
/// - Broadcasts found blocks to all peers
fn spawn_miner_real(
    chain_id: [u8; 4],
    cmd_tx: async_channel::Sender<NetworkCommand>,
    db: NullaDb,
    local_peer_id: libp2p::PeerId,
    coinbase_addr: Option<nulla_wallet::Address>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    tokio::spawn(async move {
        info!("miner started (peer_id: {local_peer_id})");

        // Log coinbase recipient address
        if let Some(addr) = coinbase_addr {
            info!("miner: coinbase rewards will be sent to {}", addr);
        } else {
            warn!("miner: no address provided, blocks will have dummy coinbase (no real rewards)");
        }

        loop {
            if shutdown.load(Ordering::Relaxed) {
                info!("miner: shutdown requested");
                break;
            }
            // Get the current best tip from the database.
            let (prev_id, prev_height, prev_work) = match db.best_tip() {
                Ok(Some((id, height, work))) => {
                    info!("miner: building on height {height} (work: {work})");
                    (id, height, work)
                }
                Ok(None) => {
                    info!("miner: no tip found, building genesis block");
                    (Hash32::default(), 0, 0)
                }
                Err(e) => {
                    warn!("miner: failed to get best tip: {e}");
                    continue;
                }
            };

            // Build the next block on top of the previous tip.
            let next_height = if prev_id == Hash32::default() {
                0 // Genesis block
            } else {
                prev_height + 1
            };

            // Create coinbase transaction if we have a wallet
            use nulla_core::{Block, Tx};
            let mut txs: Vec<Tx> = if let Some(addr) = coinbase_addr {
                vec![nulla_wallet::create_coinbase(
                    &addr,
                    next_height,
                    nulla_wallet::BLOCK_REWARD_ATOMS,
                )]
            } else {
                // Create a dummy coinbase with no outputs (for testing without wallet)
                vec![Tx {
                    version: 1,
                    inputs: vec![nulla_core::TxIn {
                        prevout: nulla_core::OutPoint::null(),
                        sig: next_height.to_le_bytes().to_vec(),
                        pubkey: vec![], // Coinbase doesn't need a public key
                    }],
                    outputs: vec![nulla_core::TxOut {
                        value_atoms: nulla_wallet::BLOCK_REWARD_ATOMS,
                        script_pubkey: vec![0x00; 25], // Dummy script
                    }],
                    lock_time: 0,
                }]
            };

            // Include transactions from the mempool
            match db.get_mempool_txs() {
                Ok(mempool_txs) if !mempool_txs.is_empty() => {
                    info!(
                        "miner: including {} transaction(s) from mempool",
                        mempool_txs.len()
                    );
                    txs.extend(mempool_txs);
                }
                Ok(_) => {
                    info!("miner: mempool is empty, block will only contain coinbase");
                }
                Err(e) => {
                    warn!("miner: failed to get mempool transactions: {e}");
                }
            }

            // Compute merkle root
            let txids: Vec<Hash32> = txs.iter().map(nulla_core::tx_id).collect();
            let merkle_root = nulla_core::merkle_root(&txids);

            // Set mining difficulty target (requires multiple leading zero bits)
            let mut target = [0xffu8; 32];
            target[0] = 0x00; // First byte must be 0x00
            target[1] = 0x00; // Second byte must be 0x00
            target[2] = 0x00; // Third byte must be 0x00
            target[3] = 0x33; // Fourth byte capped (~5x harder than 24-bit)

            // Mine for a valid nonce using all available CPU threads
            // Use all available threads, with a sensible minimum so even small systems
            // still get a decent amount of parallelism (e.g., low-core VMs).
            let worker_count = std::thread::available_parallelism()
                .map(|n| n.get().max(16))
                .unwrap_or(16);
            info!(
                "miner: mining block at height {} with {} workers...",
                next_height, worker_count
            );

            let stop = Arc::new(AtomicBool::new(false));
            let nonce_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let (found_tx, found_rx) = std::sync::mpsc::channel();
            let mut handles = Vec::with_capacity(worker_count);

            // Base header shared by workers (each mutates the nonce)
            let base_header = nulla_core::BlockHeader {
                chain_id,
                version: 1,
                height: next_height,
                prev: prev_id,
                merkle_root,
                timestamp: chrono::Utc::now().timestamp() as u64,
                target,
                nonce: 0,
            };

            let stride = worker_count as u64;

            // Heartbeat logger to show progress across all workers
            {
                let stop_flag = stop.clone();
                let shutdown_flag = shutdown.clone();
                let counter = nonce_counter.clone();
                std::thread::spawn(move || {
                    let mut last = 0;
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                        let current = counter.load(Ordering::Relaxed);
                        let delta = current.saturating_sub(last);
                        last = current;
                        info!(
                            "miner: tried {} nonces (+{} last 1s, ~{} H/s)...",
                            current, delta, delta
                        );
                        if stop_flag.load(Ordering::Relaxed)
                            || shutdown_flag.load(Ordering::Relaxed)
                        {
                            break;
                        }
                    }
                });
            }

            for worker_id in 0..worker_count {
                let stop_flag = stop.clone();
                let shutdown_flag = shutdown.clone();
                let tx_found = found_tx.clone();
                let mut header = base_header.clone();
                header.nonce = worker_id as u64;
                let counter = nonce_counter.clone();

                handles.push(std::thread::spawn(move || {
                    let mut nonce = header.nonce;
                    while !stop_flag.load(Ordering::Relaxed)
                        && !shutdown_flag.load(Ordering::Relaxed)
                    {
                        header.nonce = nonce;
                        counter.fetch_add(1, Ordering::Relaxed);
                        if nulla_core::validate_pow(&header).is_ok() {
                            let _ = tx_found.send(header.clone());
                            stop_flag.store(true, Ordering::SeqCst);
                            break;
                        }
                        nonce = nonce.wrapping_add(stride);
                    }
                }));
            }
            drop(found_tx);

            let header = match found_rx.recv() {
                Ok(h) => h,
                Err(_) => {
                    if shutdown.load(Ordering::Relaxed) {
                        info!("miner: shutdown requested");
                    }
                    stop.store(true, Ordering::SeqCst);
                    for handle in handles {
                        let _ = handle.join();
                    }
                    break;
                }
            };
            stop.store(true, Ordering::SeqCst);
            for handle in handles {
                let _ = handle.join();
            }

            let block_id = nulla_core::block_header_id(&header);

            let block = Block {
                header: header.clone(),
                txs,
            };

            // Calculate cumulative work.
            let block_work = nulla_core::target_work(&header.target);
            let cumulative_work = prev_work + block_work;

            info!(
                "miner: broadcasting block height={} id={} (work: {}, reward: {} NULLA)",
                next_height,
                hex::encode(block_id),
                cumulative_work,
                nulla_wallet::atoms_to_nulla(nulla_wallet::BLOCK_REWARD_ATOMS)
            );

            // Store the full block (header + transactions).
            if let Err(e) = db.put_block_full(&block) {
                warn!("miner: failed to store block: {e}");
                continue;
            }
            if let Err(e) = db.set_work(&block_id, cumulative_work) {
                warn!("miner: failed to store cumulative work: {e}");
                continue;
            }
            if let Err(e) = db.set_best_tip(&block_id, next_height, cumulative_work) {
                warn!("miner: failed to set best tip: {e}");
                continue;
            }

            // Apply all transactions (including coinbase) to UTXO set
            for tx in &block.txs {
                if let Err(e) = db.apply_tx(tx) {
                    warn!("miner: failed to apply transaction: {e}");
                }
            }

            // Remove transactions from mempool now that they're in a block
            for (i, tx) in block.txs.iter().enumerate().skip(1) {
                // Skip coinbase (index 0)
                let txid = nulla_core::tx_id(tx);
                if let Err(e) = db.remove_mempool_tx(&txid) {
                    warn!("miner: failed to remove tx {} from mempool: {e}", i);
                }
            }

            // Broadcast the full block to the network (includes transactions).
            let _ = cmd_tx
                .send(NetworkCommand::PublishFullBlock { block })
                .await;
        }
    });
    Ok(())
}
