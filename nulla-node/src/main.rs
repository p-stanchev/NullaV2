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
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

/// Maximum depth for chain reorganizations (SECURITY FIX: HIGH-NEW-002).
/// Reorgs deeper than 30 blocks are rejected to prevent DoS attacks.
/// Bitcoin uses ~6 blocks for finality; 30 blocks (60 minutes) provides practical finality.
const MAX_REORG_DEPTH: usize = 30;

/// Hardcoded bootstrap seed nodes.
/// These nodes are always added to the peer list to help new nodes join the network.
/// Users can add additional peers via --peers flag.
const BOOTSTRAP_SEEDS: &[&str] = &[
    "/ip4/45.155.53.102/tcp/27444", // Primary seed node (EU)
];

/// Show error message when user tries to use deprecated --wallet-seed parameter.
fn reject_wallet_seed_parameter() -> ! {
    eprintln!("ERROR: --wallet-seed has been REMOVED for security reasons.");
    eprintln!("");
    eprintln!("Command-line arguments expose seeds in:");
    eprintln!("  • Process listings (ps, top, htop)");
    eprintln!("  • Shell history files");
    eprintln!("  • System logs and monitoring");
    eprintln!("");
    eprintln!("Use one of these SECURE alternatives:");
    eprintln!("");
    eprintln!("1. Environment variable (for automation):");
    eprintln!("   NULLA_WALLET_SEED=<seed_hex> nulla-node ...");
    eprintln!("");
    eprintln!("2. Interactive prompt (for manual use):");
    eprintln!("   nulla-node --wallet-seed-stdin ...");
    eprintln!("");
    eprintln!("3. Encrypted wallet file (RECOMMENDED):");
    eprintln!("   nulla-node --wallet-file wallet.dat --wallet-password <password>");
    eprintln!("");
    eprintln!("4. BIP39 mnemonic phrase:");
    eprintln!("   nulla-node --from-mnemonic \"word1 word2 ...\"");
    std::process::exit(1);
}

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

    /// Number of stem hops in Dandelion++ before fluff phase (default: 8).
    /// Higher values = better privacy but longer propagation time.
    #[arg(long, default_value = "8")]
    dandelion_stem_hops: u8,

    /// Probability (0.0-1.0) of early fluff in Dandelion++ (default: 0.1).
    /// Higher values = less predictable but potentially weaker privacy.
    #[arg(long, default_value = "0.1")]
    dandelion_fluff_probability: f32,

    /// Minimum broadcast delay in milliseconds (default: 100).
    /// Adds random delay before broadcasting to obfuscate transaction timing.
    #[arg(long, default_value = "100")]
    min_broadcast_delay_ms: u64,

    /// Maximum broadcast delay in milliseconds (default: 500).
    /// Adds random delay before broadcasting to obfuscate transaction timing.
    #[arg(long, default_value = "500")]
    max_broadcast_delay_ms: u64,

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
    /// Using an address allows cold mining without exposing private keys on the mining node.
    /// Example: --miner-address 79bc6374ccc99f1211770ce007e05f6235b98c8b
    #[arg(long)]
    miner_address: Option<String>,

    /// SOCKS5 proxy address (placeholder; not yet wired).
    #[arg(long)]
    socks5: Option<String>,

    /// Generate a new wallet and print the address and seed.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    generate_wallet: bool,

    /// Generate a new HD (Hierarchical Deterministic) wallet.
    /// Allows deriving multiple addresses from a single master seed.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    generate_hd_wallet: bool,

    /// Generate a new HD wallet with BIP39 mnemonic phrase (12 or 24 words).
    /// This creates a user-friendly backup with memorable words instead of hex.
    /// Example: --generate-mnemonic 24 (generates 24-word phrase)
    #[arg(long)]
    generate_mnemonic: Option<u32>,

    /// Recover wallet from BIP39 mnemonic phrase.
    /// Provide the phrase as a quoted string.
    /// Example: --from-mnemonic "abandon abandon abandon..."
    #[arg(long)]
    from_mnemonic: Option<String>,

    /// Optional passphrase for BIP39 mnemonic (extra security layer).
    /// Using a passphrase creates a completely different wallet.
    /// WARNING: If you lose the passphrase, you cannot recover your wallet!
    #[arg(long)]
    mnemonic_passphrase: Option<String>,

    /// Derive addresses from HD wallet master seed.
    /// Format: --derive-address <count>
    /// Example: --derive-address 5 (shows first 5 addresses)
    /// Requires: NULLA_WALLET_SEED environment variable
    #[arg(long)]
    derive_address: Option<u32>,

    /// REMOVED FOR SECURITY: This parameter has been removed as it exposes seeds.
    /// Use secure alternatives: NULLA_WALLET_SEED env var, --wallet-seed-stdin, or --wallet-file
    #[arg(long, hide = true)]
    wallet_seed: Option<String>,

    /// Read wallet seed from stdin (secure, not visible in ps).
    /// The node will prompt for the seed on startup.
    /// This is more secure than --wallet-seed as it doesn't expose the seed in process listings.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    wallet_seed_stdin: bool,

    /// Get wallet address from seed.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    get_address: bool,

    /// Get wallet balance (requires NULLA_WALLET_SEED env var and --db).
    /// DEPRECATED: Use --balance <ADDRESS> instead.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    get_balance: bool,

    /// Check balance for any address (40-char hex, 20 bytes).
    /// Example: --balance 79bc6374ccc99f1211770ce007e05f6235b98c8b
    /// Works with any address - check your own balance or someone else's.
    #[arg(long)]
    balance: Option<String>,

    /// Send NULLA to an address (requires --wallet-file, --to, and --amount).
    /// Example: --send --to 79bc6374ccc99f1211770ce007e05f6235b98c8b --amount 5.0 --wallet-file wallet.dat
    #[arg(long, action = clap::ArgAction::SetTrue)]
    send: bool,

    /// Create a new encrypted wallet file.
    /// Creates a new HD wallet and saves it to the specified file with password encryption.
    /// Example: --create-wallet wallet.dat
    #[arg(long)]
    create_wallet: Option<String>,

    /// Load wallet from an encrypted file.
    /// Example: --wallet-file wallet.dat
    #[arg(long)]
    wallet_file: Option<String>,

    /// Password for wallet file encryption/decryption.
    /// Use with --create-wallet or --wallet-file.
    #[arg(long)]
    wallet_password: Option<String>,

    /// Recipient address for sending NULLA (40-char hex, 20 bytes).
    #[arg(long)]
    to: Option<String>,

    /// Amount to send in NULLA (e.g., 5.0 = 500000000 atoms).
    #[arg(long)]
    amount: Option<f64>,

    /// Enable pruning mode to reduce disk usage (discards old block data, keeps headers + UTXO set).
    /// Full nodes keep all blocks; pruned nodes only keep recent blocks.
    #[arg(long, default_value_t = false)]
    prune: bool,

    /// Number of recent blocks to keep when pruning (default: 550 = ~1 week).
    /// Must be >= 100 for safe chain reorganizations.
    #[arg(long, default_value_t = 550)]
    prune_keep_blocks: u64,
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
        println!("  NULLA_WALLET_SEED={} nulla-node --mine", seed_hex);
        println!("\nTo check balance:");
        println!("  --balance {}\n", wallet.address());
        return Ok(());
    }

    // Handle HD wallet generation command.
    if args.generate_hd_wallet {
        let mut master_seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut master_seed);
        let wallet = Wallet::from_master_seed(&master_seed).map_err(|e| anyhow::anyhow!("{}", e))?;
        let seed_hex = hex::encode(master_seed);

        println!("\n=== New HD Wallet Generated ===");
        println!("Master Seed: {}", seed_hex);
        println!("\nFirst 5 Addresses:");
        for i in 0..5 {
            let addr = wallet.derive_address(i).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("  [{}] {}", i, addr);
        }
        println!("\nIMPORTANT: Save your MASTER SEED! This will not be shown again.");
        println!("IMPORTANT: Anyone with this seed can spend funds from ALL derived addresses.");
        println!("\nTo derive more addresses:");
        println!("  NULLA_WALLET_SEED={} nulla-node --derive-address 10", seed_hex);
        println!("\nTo check balance of any address:");
        println!("  --balance <ADDRESS>\n");
        return Ok(());
    }

    // Handle BIP39 mnemonic generation command.
    if let Some(word_count) = args.generate_mnemonic {
        use nulla_wallet::Mnemonic;

        let mnemonic = match word_count {
            12 => Mnemonic::generate_12_words()
                .map_err(|e| anyhow::anyhow!("Failed to generate mnemonic: {}", e))?,
            24 => Mnemonic::generate_24_words()
                .map_err(|e| anyhow::anyhow!("Failed to generate mnemonic: {}", e))?,
            _ => return Err(anyhow::anyhow!("Invalid word count. Use 12 or 24.")),
        };

        let passphrase = args.mnemonic_passphrase.as_deref();
        let wallet = Wallet::from_mnemonic(&mnemonic, passphrase)
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        println!("\n=== New HD Wallet Generated with BIP39 Mnemonic ===");
        println!("\nBACKUP THESE {} WORDS (write them down!):", word_count);
        println!("\n{}\n", mnemonic.phrase());
        if passphrase.is_some() {
            println!("WARNING: Passphrase enabled (you must remember it to recover!)");
        }
        println!("\nFirst 5 Addresses:");
        for i in 0..5 {
            let addr = wallet.derive_address(i).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("  [{}] {}", i, addr);
        }
        println!("\nCRITICAL: Write down these {} words and keep them safe!", word_count);
        println!("   These words are your ONLY backup. If you lose them, your funds are GONE FOREVER.");
        println!("   Anyone with these words can steal your funds.");
        println!("\nTo recover this wallet later:");
        println!("  --from-mnemonic \"{}\"", mnemonic.phrase());
        if passphrase.is_some() {
            println!("  --mnemonic-passphrase \"<your passphrase>\"");
        }
        println!();
        return Ok(());
    }

    // Handle BIP39 mnemonic recovery command.
    if let Some(phrase) = &args.from_mnemonic {
        use nulla_wallet::Mnemonic;

        let mnemonic = Mnemonic::from_phrase(phrase)
            .map_err(|e| anyhow::anyhow!("Invalid mnemonic phrase: {}", e))?;

        let passphrase = args.mnemonic_passphrase.as_deref();
        let wallet = Wallet::from_mnemonic(&mnemonic, passphrase)
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        println!("\n=== Wallet Recovered from Mnemonic ===");
        println!("\nFirst 10 Addresses:");
        for i in 0..10 {
            let addr = wallet.derive_address(i).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("  [{}] {}", i, addr);
        }
        println!("\nTo use this wallet for mining:");
        println!("  --from-mnemonic \"{}\" --mine", phrase);
        if passphrase.is_some() {
            println!("  --mnemonic-passphrase \"<your passphrase>\"");
        }
        println!();
        return Ok(());
    }

    // Handle create wallet file command.
    if let Some(wallet_path) = &args.create_wallet {
        let password = args.wallet_password.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Error: --wallet-password required for --create-wallet")
        })?;

        if Wallet::exists(wallet_path) {
            eprintln!("Error: Wallet file already exists at {}", wallet_path);
            eprintln!("Choose a different filename or delete the existing file.");
            std::process::exit(1);
        }

        // Generate new HD wallet
        let mut master_seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut master_seed);
        let wallet = Wallet::from_master_seed(&master_seed).map_err(|e| anyhow::anyhow!("{}", e))?;

        // Save to encrypted file
        wallet.save_to_file(wallet_path, password).map_err(|e| anyhow::anyhow!("{}", e))?;

        println!("\n=== Encrypted Wallet Created ===");
        println!("File: {}", wallet_path);
        println!("\nFirst 5 Addresses:");
        for i in 0..5 {
            let addr = wallet.derive_address(i).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("  [{}] {}", i, addr);
        }
        println!("\nIMPORTANT: Remember your password! It cannot be recovered.");
        println!("IMPORTANT: Back up your wallet file: {}", wallet_path);
        println!("\nTo use this wallet:");
        println!("  --wallet-file {} --wallet-password <PASSWORD>", wallet_path);
        println!("\nTo check balance:");
        println!("  --balance {}\n", wallet.address());
        return Ok(());
    }

    // Handle derive address command.
    if let Some(count) = args.derive_address {
        if args.wallet_seed.is_some() {
            reject_wallet_seed_parameter();
        }
        if let Some(seed_hex) = std::env::var("NULLA_WALLET_SEED").ok() {
            match hex::decode(seed_hex) {
                Ok(seed_bytes) if seed_bytes.len() == 32 => {
                    let mut master_seed = [0u8; 32];
                    master_seed.copy_from_slice(&seed_bytes);
                    let wallet = Wallet::from_master_seed(&master_seed).map_err(|e| anyhow::anyhow!("{}", e))?;

                    println!("\n=== HD Wallet Addresses ===");
                    println!("Derivation Path: m/44'/0'/0'/0/<index>\n");
                    for i in 0..count {
                        let addr = wallet.derive_address(i).map_err(|e| anyhow::anyhow!("{}", e))?;
                        println!("  [{}] {}", i, addr);
                    }
                    println!();
                    return Ok(());
                }
                _ => {
                    eprintln!("Error: Invalid master seed (must be 32 bytes hex)");
                    std::process::exit(1);
                }
            }
        } else {
            eprintln!("Error: NULLA_WALLET_SEED environment variable required for --derive-address");
            eprintln!("Example: NULLA_WALLET_SEED=<32_byte_hex> nulla-node --derive-address 10");
            std::process::exit(1);
        }
    }

    // Handle get address command.
    if args.get_address {
        if args.wallet_seed.is_some() {
            reject_wallet_seed_parameter();
        }
        if let Some(seed_hex) = std::env::var("NULLA_WALLET_SEED").ok().as_ref() {
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
            eprintln!("Error: NULLA_WALLET_SEED environment variable required for --get-address");
            eprintln!("Example: NULLA_WALLET_SEED=<32_byte_hex> nulla-node --get-address");
            std::process::exit(1);
        }
    }

    // Handle get balance command.
    if args.get_balance {
        if args.wallet_seed.is_some() {
            reject_wallet_seed_parameter();
        }
        if let Some(seed_hex) = std::env::var("NULLA_WALLET_SEED").ok().as_ref() {
            match hex::decode(seed_hex) {
                Ok(seed_bytes) if seed_bytes.len() == 32 => {
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&seed_bytes);
                    let wallet = Wallet::from_seed(&seed);
                    let db = NullaDb::open(&args.db)?;

                    // Get all UTXOs for this wallet's address.
                    let address = wallet.address();

                    // Fetch UTXOs from the address index
                    let utxos = db.get_utxos_by_address(address.hash())?;
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
            eprintln!("Error: NULLA_WALLET_SEED environment variable required for --get-balance");
            eprintln!("Example: NULLA_WALLET_SEED=<32_byte_hex> nulla-node --get-balance --db blockchain.db");
            std::process::exit(1);
        }
    }

    // Handle balance check command (new, better version - works with any address).
    if let Some(addr_hex) = &args.balance {
        match nulla_wallet::Address::from_hex(addr_hex) {
            Some(address) => {
                let db = NullaDb::open(&args.db)?;

                // Fetch UTXOs from the address index
                let utxos = db.get_utxos_by_address(address.hash())?;
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

        // Load wallet from file or seed.
        let wallet = if let Some(wallet_path) = &args.wallet_file {
            let password = args.wallet_password.as_ref().ok_or_else(|| {
                anyhow::anyhow!("Error: --wallet-password required with --wallet-file")
            })?;
            match Wallet::load_from_file(wallet_path, password) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("Error loading wallet file: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            if args.wallet_seed.is_some() {
                reject_wallet_seed_parameter();
            }
            eprintln!("Error: --wallet-file required for --send");
            eprintln!("Example: nulla-node --send --to <address> --amount 10 --wallet-file wallet.dat --wallet-password <pass>");
            std::process::exit(1);
        };

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
        let utxos = db.get_utxos_by_address(sender_addr.hash())?;

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

        // Create and sign the transaction with chain_id for replay protection.
        let chain_id = chain_id_bytes(&args.chain_id);
        let tx = match wallet.create_transaction(inputs, outputs, 0, &chain_id) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Error creating transaction: {}", e);
                std::process::exit(1);
            }
        };

        let txid = nulla_core::tx_id(&tx);

        // Validate transaction signatures before broadcasting.
        if let Err(e) = db.verify_tx_signatures(&tx, &chain_id) {
            eprintln!("Error: Transaction signature verification failed: {}", e);
            std::process::exit(1);
        }

        // Validate transaction inputs before broadcasting.
        if let Err(e) = db.validate_tx_inputs(&tx) {
            eprintln!("Error: Transaction input validation failed: {}", e);
            std::process::exit(1);
        }

        // Calculate and validate transaction fee
        match db.calculate_tx_fee(&tx) {
            Ok(fee) => {
                if fee < nulla_wallet::MIN_TX_FEE_ATOMS {
                    eprintln!(
                        "Error: Transaction fee ({} atoms = {} NULLA) below minimum ({} atoms = {} NULLA)",
                        fee,
                        nulla_wallet::atoms_to_nulla(fee),
                        nulla_wallet::MIN_TX_FEE_ATOMS,
                        nulla_wallet::atoms_to_nulla(nulla_wallet::MIN_TX_FEE_ATOMS)
                    );
                    eprintln!("Hint: Reduce the amount sent to leave more for the fee");
                    std::process::exit(1);
                }
                println!("Transaction fee: {} atoms ({} NULLA)", fee, nulla_wallet::atoms_to_nulla(fee));
            }
            Err(e) => {
                eprintln!("Error: Transaction fee calculation failed: {}", e);
                std::process::exit(1);
            }
        }

        // Add transaction to mempool (signature validation enforced)
        if let Err(e) = db.put_mempool_tx(&tx, &chain_id) {
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
        let user_peers = parse_multiaddrs(&args.peers)?;

        // Merge user peers with hardcoded bootstrap seeds and deduplicate
        let peer_addrs = merge_peers_with_bootstrap(user_peers);

        if peer_addrs.is_empty() {
            eprintln!("\nError: No peers configured and bootstrap seeds unavailable!");
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
            dandelion_stem_hops: 8,
            dandelion_fluff_probability: 0.1,
            min_broadcast_delay_ms: 100,
            max_broadcast_delay_ms: 500,
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

    // SECURITY FIX (CRIT-NEW-002): Secure wallet loading
    let wallet = if let Some(wallet_path) = &args.wallet_file {
        // Option 1: Load from encrypted wallet file (most secure)
        let password = args.wallet_password.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Error: --wallet-password required with --wallet-file")
        })?;

        match Wallet::load_from_file(wallet_path, password) {
            Ok(wallet) => {
                info!("wallet loaded from file: {}", wallet_path);
                info!("wallet address: {}", wallet.address());
                Some(wallet)
            }
            Err(e) => {
                eprintln!("Error loading wallet file: {}", e);
                eprintln!("Make sure the password is correct and the file exists.");
                std::process::exit(1);
            }
        }
    } else if let Ok(seed_hex) = std::env::var("NULLA_WALLET_SEED") {
        // Option 2: Load from environment variable (secure - not in ps)
        use zeroize::Zeroize;

        match hex::decode(&seed_hex) {
            Ok(seed_bytes) if seed_bytes.len() == 32 => {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&seed_bytes);
                let wallet = Wallet::from_seed(&seed);
                info!("wallet loaded from NULLA_WALLET_SEED environment variable");
                info!("wallet address: {}", wallet.address());

                // Zeroize the seed after use
                seed.zeroize();

                Some(wallet)
            }
            _ => {
                warn!("invalid NULLA_WALLET_SEED (must be 32 bytes hex), ignoring");
                None
            }
        }
    } else if args.wallet_seed_stdin {
        // Option 3: Load from stdin (secure - not in ps or shell history)
        use std::io::{self, BufRead};
        use zeroize::Zeroize;

        println!("Enter wallet seed (32 bytes hex):");
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;

        let seed_hex = line.trim();
        match hex::decode(seed_hex) {
            Ok(seed_bytes) if seed_bytes.len() == 32 => {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&seed_bytes);
                let wallet = Wallet::from_seed(&seed);
                info!("wallet loaded from stdin");
                info!("wallet address: {}", wallet.address());

                // Zeroize sensitive data
                seed.zeroize();
                line.zeroize();

                Some(wallet)
            }
            _ => {
                eprintln!("Error: Invalid wallet seed (must be 32 bytes hex)");
                std::process::exit(1);
            }
        }
    } else if args.wallet_seed.is_some() {
        // SECURITY FIX (HIGH-AUD-001): --wallet-seed parameter removed
        reject_wallet_seed_parameter();
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

    // Configure pruning if enabled.
    let pruning_config = nulla_db::PruningConfig {
        enabled: args.prune,
        keep_blocks: args.prune_keep_blocks,
    };

    // Open the database for blocks, headers, UTXOs, and mempool.
    let db = NullaDb::open_with_pruning(&args.db, pruning_config)?;

    if args.prune {
        info!("pruning mode enabled (keeping {} recent blocks)", args.prune_keep_blocks);
    }

    // Parse multiaddresses for listening and peer connections.
    let listen_addrs = parse_multiaddrs(&args.listen)?;
    let user_peers = parse_multiaddrs(&args.peers)?;

    // Merge user peers with hardcoded bootstrap seeds and deduplicate
    let peer_addrs = merge_peers_with_bootstrap(user_peers);

    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let _ = signal::ctrl_c().await;
            shutdown.store(true, Ordering::SeqCst);
        });
    }

    // Gossip is enabled by default unless --no-gossip is explicitly set
    let gossip_enabled = !args.no_gossip;

    // Dandelion++ is enabled by default unless --no-dandelion is explicitly set
    let dandelion_enabled = !args.no_dandelion;

    // Store network command channel outside the if block for RPC access
    let cmd_tx = if gossip_enabled {
        // Clone peer_addrs before moving it into NetConfig
        let peer_addrs_for_sync = peer_addrs.clone();

        let net_cfg = NetConfig {
            chain_id,
            listen: listen_addrs,
            peers: peer_addrs,
            dandelion: dandelion_enabled,
            cover_traffic: args.cover_traffic,
            dandelion_stem_hops: args.dandelion_stem_hops,
            dandelion_fluff_probability: args.dandelion_fluff_probability,
            min_broadcast_delay_ms: args.min_broadcast_delay_ms,
            max_broadcast_delay_ms: args.max_broadcast_delay_ms,
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
            args.seed,
            chain_id,
        ));

        // Spawn periodic peer sync task with peer list for reconnection
        tokio::spawn(periodic_peer_sync(cmd_tx.clone(), db.clone(), peer_addrs_for_sync));

        // If seed mode is enabled, spawn the seed node (relay/sync only).
        if args.seed {
            spawn_seed(chain_id, cmd_tx.clone(), db.clone(), handle.local_peer_id)?;
        }

        // If mining is enabled, spawn the miner block builder.
        if args.mine {
            // Determine coinbase address (prefer miner_address for security)
            let coinbase_addr = miner_address.or_else(|| wallet.as_ref().map(|w| w.address()));

            if coinbase_addr.is_none() {
                warn!("mining enabled but no address provided; use --miner-address or load a wallet to receive block rewards");
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

        cmd_tx
    } else {
        info!("gossip stack disabled; node running in local-only mode");
        // Return a dummy channel when gossip is disabled
        let (tx, _rx) = async_channel::bounded(100);
        tx
    };

    // Start RPC server if RPC argument provided
    let _rpc_handle = if !args.rpc.is_empty() {
        let wallet_arc = wallet.as_ref()
            .map(|w| Arc::new(tokio::sync::RwLock::new(w.clone())));

        // SECURITY FIX (HIGH-NEW-003): Use RpcContext::new() which includes rate limiting
        let rpc_ctx = nulla_rpc::RpcContext::new(
            db.clone(),
            cmd_tx.clone(),
            wallet_arc,
            std::time::Instant::now(),
            chain_id,
        );

        match nulla_rpc::spawn_rpc_server(args.rpc.clone(), rpc_ctx).await {
            Ok(handle) => {
                info!("RPC server started on {}", args.rpc);
                Some(handle)
            }
            Err(e) => {
                warn!("Failed to start RPC server: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Wait for Ctrl+C to shut down gracefully.
    signal::ctrl_c().await?;
    info!("shutting down");

    // Stop RPC server if running
    if let Some(handle) = _rpc_handle {
        let _ = handle.stop();
    }

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

/// Merge user-provided peers with hardcoded bootstrap seeds and remove duplicates.
fn merge_peers_with_bootstrap(user_peers: Vec<libp2p::Multiaddr>) -> Vec<libp2p::Multiaddr> {
    use std::collections::HashSet;

    let mut peer_set = HashSet::new();
    let mut final_peers = Vec::new();

    // Add hardcoded bootstrap seeds first
    for seed in BOOTSTRAP_SEEDS {
        if let Ok(addr) = libp2p::Multiaddr::from_str(seed) {
            let addr_str = addr.to_string();
            if peer_set.insert(addr_str) {
                final_peers.push(addr);
                info!("bootstrap seed: {}", seed);
            }
        }
    }

    // Add user-provided peers (skip duplicates)
    for addr in user_peers {
        let addr_str = addr.to_string();
        if peer_set.insert(addr_str) {
            final_peers.push(addr);
        } else {
            debug!("duplicate peer address skipped: {}", addr);
        }
    }

    final_peers
}

/// Handle network events and respond to requests.
async fn handle_network_events(
    rx: async_channel::Receiver<NetworkEvent>,
    cmd_tx: async_channel::Sender<NetworkCommand>,
    db: NullaDb,
    sync_progress: Arc<Mutex<Option<ProgressBar>>>,
    _seed_mode: bool,
    chain_id: [u8; 4],
) {
    use std::collections::{HashSet, HashMap};
    use nulla_core::OutPoint;

    // SECURITY: Track spent outpoints in mempool to prevent double-spend attacks
    // This prevents adding conflicting transactions to the mempool
    let mut mempool_spent: HashSet<OutPoint> = HashSet::new();

    // Track connected peers to avoid duplicate connection log messages
    let mut connected_peers: HashSet<libp2p::PeerId> = HashSet::new();

    // Orphan block pool: blocks waiting for their parent to arrive
    // Maps block_id -> (block, peer_id)
    let mut orphan_blocks: HashMap<Hash32, (nulla_core::Block, Option<libp2p::PeerId>)> = HashMap::new();
    // Maps parent_id -> Vec<child_block_ids> for quick lookup
    let mut orphan_children: HashMap<Hash32, Vec<Hash32>> = HashMap::new();

    // TODO (MED-004, CRIT-003): Implement per-IP connection limits for eclipse attack protection
    // libp2p doesn't directly expose peer IP addresses from PeerId
    // Would need to track connection manager events to get actual IP addresses
    // For now, rely on libp2p's built-in connection limits

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

                // SECURITY: Check for double-spend in mempool before validation
                // This prevents the same UTXO from being spent by multiple mempool transactions
                let mut has_double_spend = false;
                for input in &tx.inputs {
                    if mempool_spent.contains(&input.prevout) {
                        warn!(
                            "rejected transaction {}: double-spend detected in mempool (outpoint {}:{})",
                            hex::encode(txid),
                            hex::encode(input.prevout.txid),
                            input.prevout.vout
                        );
                        has_double_spend = true;
                        break;
                    }
                }
                if has_double_spend {
                    continue;
                }

                // Validate transaction signatures with chain_id for replay protection
                if let Err(e) = db.verify_tx_signatures(&tx, &chain_id) {
                    warn!("received invalid transaction (signature verification failed): {e}");
                    continue;
                }

                // Validate transaction inputs (check UTXOs exist and aren't spent)
                if let Err(e) = db.validate_tx_inputs(&tx) {
                    warn!("received invalid transaction (input validation failed): {e}");
                    continue;
                }

                // Calculate and validate transaction fee (spam prevention)
                match db.calculate_tx_fee(&tx) {
                    Ok(fee) => {
                        if fee < nulla_wallet::MIN_TX_FEE_ATOMS {
                            warn!(
                                "rejected transaction {} with insufficient fee: {} atoms (minimum: {} atoms)",
                                hex::encode(txid),
                                fee,
                                nulla_wallet::MIN_TX_FEE_ATOMS
                            );
                            continue;
                        }
                    }
                    Err(e) => {
                        warn!("rejected transaction {}: fee calculation failed: {e}", hex::encode(txid));
                        continue;
                    }
                }

                // Add to mempool (signature validation enforced in put_mempool_tx)
                if let Err(e) = db.put_mempool_tx(&tx, &chain_id) {
                    warn!("failed to add transaction to mempool: {e}");
                    continue;
                }

                // SECURITY: Mark all inputs as spent in mempool tracker
                for input in &tx.inputs {
                    mempool_spent.insert(input.prevout.clone());
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

                // Clone header for potential re-broadcast
                let header_clone = header.clone();

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
                                        pb.finish_with_message("Synced!");
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

                // Re-broadcast header to gossip network (relay to other peers)
                match cmd_tx.send(nulla_net::NetworkCommand::PublishBlock { header: header_clone }).await {
                    Ok(_) => debug!("re-broadcast header command sent"),
                    Err(e) => warn!("FAILED to send header re-broadcast command: {:?}", e),
                }
            }
            NetworkEvent::FullBlock { from, block } => {
                let block_id = nulla_core::block_id(&block);
                let block_clone = block.clone();

                // Check if parent exists
                let has_parent = block.header.prev == [0u8; 32] ||
                    db.get_block(&block.header.prev).ok().flatten().is_some();

                if !has_parent {
                    // Store as orphan and wait for parent
                    debug!("storing orphan block {} at height {} (missing parent {})",
                        hex::encode(block_id), block.header.height, hex::encode(block.header.prev));
                    orphan_blocks.insert(block_id, (block.clone(), Some(from)));
                    orphan_children.entry(block.header.prev)
                        .or_insert_with(Vec::new)
                        .push(block_id);
                    continue;
                }

                // SECURITY FIX (HIGH-AUD-005): Clean up mempool spent tracking when block is processed
                // Store transactions before processing so we can clean up spent tracking
                let block_txs = block.txs.clone();

                let is_valid = process_full_block(&db, &sync_progress, block, Some(from), &chain_id).await;

                // Re-broadcast valid blocks to gossip network (relay to other peers)
                if is_valid {
                    // Remove spent outpoints for transactions that were in this block
                    for tx in block_txs.iter().skip(1) {
                        for input in &tx.inputs {
                            mempool_spent.remove(&input.prevout);
                        }
                    }
                    let height = block_clone.header.height;
                    match cmd_tx.send(nulla_net::NetworkCommand::PublishFullBlock { block: block_clone }).await {
                        Ok(_) => debug!("re-broadcast command sent for block at height {}", height),
                        Err(e) => warn!("FAILED to send re-broadcast command: {:?}", e),
                    }

                    // Process orphan children if any
                    if let Some(children_ids) = orphan_children.remove(&block_id) {
                        info!("processing {} orphan children of block {}", children_ids.len(), hex::encode(block_id));
                        for child_id in children_ids {
                            if let Some((child_block, child_from)) = orphan_blocks.remove(&child_id) {
                                debug!("processing orphan child {} at height {}", hex::encode(child_id), child_block.header.height);
                                let child_clone = child_block.clone();
                                let child_txs = child_block.txs.clone();
                                let child_valid = process_full_block(&db, &sync_progress, child_block, child_from, &chain_id).await;
                                if child_valid {
                                    // SECURITY FIX (HIGH-AUD-005): Clean up mempool spent tracking
                                    for tx in child_txs.iter().skip(1) {
                                        for input in &tx.inputs {
                                            mempool_spent.remove(&input.prevout);
                                        }
                                    }
                                    let child_height = child_clone.header.height;
                                    match cmd_tx.send(nulla_net::NetworkCommand::PublishFullBlock { block: child_clone }).await {
                                        Ok(_) => debug!("re-broadcast command sent for orphan child at height {}", child_height),
                                        Err(e) => warn!("FAILED to send re-broadcast command for orphan: {:?}", e),
                                    }

                                    // Recursively process grandchildren
                                    if let Some(grandchildren) = orphan_children.remove(&child_id) {
                                        // Re-insert grandchildren for next iteration
                                        for grandchild_id in grandchildren {
                                            if let Some((gc_block, gc_from)) = orphan_blocks.remove(&grandchild_id) {
                                                orphan_blocks.insert(grandchild_id, (gc_block, gc_from));
                                                orphan_children.entry(child_id).or_insert_with(Vec::new).push(grandchild_id);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            NetworkEvent::Request { peer, req, channel } => {
                // Only log GetHeaders and GetBlock requests at debug level to reduce clutter during sync
                match &req {
                    protocol::Req::GetHeaders { .. } | protocol::Req::GetBlock { .. } => {
                        debug!("request from {peer:?}: {:?}", req);
                    }
                    _ => {
                        info!("request from {peer:?}: {:?}", req);
                    }
                }
                // Handle the request and send a response.
                let resp = handle_request(&db, req);
                let _ = cmd_tx
                    .send(NetworkCommand::SendResponse { channel, resp })
                    .await;
            }
            NetworkEvent::Response { peer, resp } => {
                // Only log Headers and Block responses at debug level to reduce clutter during sync
                match &resp {
                    protocol::Resp::Headers { .. } | protocol::Resp::Block { .. } => {
                        debug!("response from {peer:?}: {:?}", resp);
                    }
                    _ => {
                        info!("response from {peer:?}: {:?}", resp);
                    }
                }

                // Handle mempool sync for all nodes (not just seed mode)
                if let protocol::Resp::Mempool { txs } = &resp {
                    // Only log if we actually received transactions
                    if !txs.is_empty() {
                        info!("received {} mempool transactions from {peer}", txs.len());
                    } else {
                        debug!("received 0 mempool transactions from {peer}");
                    }
                    for tx in txs {
                        // SECURITY: Check for double-spend in mempool before adding
                        let mut has_double_spend = false;
                        for input in &tx.inputs {
                            if mempool_spent.contains(&input.prevout) {
                                let txid = nulla_core::tx_id(tx);
                                warn!(
                                    "rejected mempool sync tx {}: double-spend detected",
                                    hex::encode(txid)
                                );
                                has_double_spend = true;
                                break;
                            }
                        }
                        if has_double_spend {
                            continue;
                        }

                        // Validate transaction before adding to mempool
                        match db.validate_tx_inputs(tx) {
                            Ok(total_input) => {
                                if let Err(e) = db.verify_tx_signatures(tx, &chain_id) {
                                    warn!("invalid signature in mempool tx: {}", e);
                                    continue;
                                }

                                let total_output: u64 = tx.outputs.iter().map(|o| o.value_atoms).sum();
                                if total_output > total_input {
                                    warn!("mempool tx outputs exceed inputs");
                                    continue;
                                }

                                // Add to local mempool (signature validation enforced in put_mempool_tx)
                                let txid = nulla_core::tx_id(tx);
                                if let Err(e) = db.put_mempool_tx(tx, &chain_id) {
                                    warn!("failed to add mempool tx {}: {}", hex::encode(txid), e);
                                } else {
                                    // SECURITY: Mark inputs as spent in mempool tracker
                                    for input in &tx.inputs {
                                        mempool_spent.insert(input.prevout.clone());
                                    }
                                    info!("added mempool tx {} from peer", hex::encode(txid));
                                }
                            }
                            Err(e) => {
                                warn!("invalid UTXO in mempool tx: {}", e);
                            }
                        }
                    }
                }

                // ALL nodes (not just seed nodes) should sync blocks from peers
                match resp {
                    protocol::Resp::Tip {
                        height,
                        id,
                        cumulative_work: _,
                    } => {
                        let local_tip =
                            db.best_tip().ok().flatten();
                        let local_height = local_tip.as_ref().map(|(_, h, _)| *h).unwrap_or(0);
                        if height > local_height {
                            // GetHeaders walks backwards from the given block
                            // So we pass the PEER'S tip and it returns headers backwards to genesis
                            // We'll process them in reverse order to apply them forward
                            info!("requesting headers from {} starting at peer's tip {} (local height: {}, peer height: {})",
                                peer, hex::encode(id), local_height, height);
                            let _ = cmd_tx
                                .send(NetworkCommand::SendRequest {
                                    peer,
                                    req: protocol::Req::GetHeaders {
                                        from: id,
                                        limit: protocol::MAX_HEADERS as u32,
                                    },
                                })
                                .await;
                        }
                    }
                    protocol::Resp::Headers { headers } => {
                        info!("received {} headers from {}", headers.len(), peer);

                        // Headers come in REVERSE order (newest to oldest)
                        // We need to process them in FORWARD order (oldest to newest)
                        let mut headers_vec = headers.clone();
                        headers_vec.reverse();

                        let mut requested = 0usize;
                        for header in headers_vec {
                            let block_id = nulla_core::block_header_id(&header);
                            if db.get_block(&block_id).ok().flatten().is_none() {
                                let _ = db.put_header(&header);
                                debug!("requesting block {} at height {}", hex::encode(block_id), header.height);
                                let _ = cmd_tx
                                    .send(NetworkCommand::SendRequest {
                                        peer,
                                        req: protocol::Req::GetBlock { id: block_id },
                                    })
                                    .await;
                                requested += 1;
                                if requested >= 128 {
                                    break;
                                }
                            }
                        }
                        info!("requested {} blocks from {}", requested, peer);
                    }
                    protocol::Resp::Block { block } => {
                        if let Some(block) = block {
                            let block_id = nulla_core::block_id(&block);

                            // Check if parent exists
                            let has_parent = block.header.prev == [0u8; 32] ||
                                db.get_block(&block.header.prev).ok().flatten().is_some();

                            if !has_parent {
                                // Store as orphan and wait for parent
                                debug!("storing orphan block {} at height {} (missing parent {})",
                                    hex::encode(block_id), block.header.height, hex::encode(block.header.prev));
                                orphan_blocks.insert(block_id, (block.clone(), Some(peer)));
                                orphan_children.entry(block.header.prev)
                                    .or_insert_with(Vec::new)
                                    .push(block_id);
                            } else {
                                let block_txs = block.txs.clone();
                                let is_valid = process_full_block(&db, &sync_progress, block, Some(peer), &chain_id).await;

                                // Process orphan children if this block's processing succeeded
                                if is_valid {
                                    // SECURITY FIX (HIGH-AUD-005): Clean up mempool spent tracking
                                    for tx in block_txs.iter().skip(1) {
                                        for input in &tx.inputs {
                                            mempool_spent.remove(&input.prevout);
                                        }
                                    }
                                    if let Some(children_ids) = orphan_children.remove(&block_id) {
                                        info!("processing {} orphan children of block {}", children_ids.len(), hex::encode(block_id));
                                        for child_id in children_ids {
                                            if let Some((child_block, child_from)) = orphan_blocks.remove(&child_id) {
                                                debug!("processing orphan child {} at height {}", hex::encode(child_id), child_block.header.height);
                                                let child_txs = child_block.txs.clone();
                                                let child_valid = process_full_block(&db, &sync_progress, child_block, child_from, &chain_id).await;
                                                // SECURITY FIX (HIGH-AUD-005): Clean up mempool spent tracking
                                                if child_valid {
                                                    for tx in child_txs.iter().skip(1) {
                                                        for input in &tx.inputs {
                                                            mempool_spent.remove(&input.prevout);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            NetworkEvent::NewListen(addr) => info!("listening on {addr}"),
            NetworkEvent::PeerConnected(peer) => {
                // Only log first connection to avoid duplicate messages
                if connected_peers.insert(peer) {
                    info!("peer connected {peer}");

                    // Request mempool synchronization from the newly connected peer
                    let _ = cmd_tx
                        .send(NetworkCommand::SendRequest {
                            peer,
                            req: protocol::Req::GetMempool { limit: 100 },
                        })
                        .await;

                    // ALL nodes should request tip to sync blocks (not just seed nodes)
                    let _ = cmd_tx
                        .send(NetworkCommand::SendRequest {
                            peer,
                            req: protocol::Req::GetTip,
                        })
                        .await;
                }
            }
            NetworkEvent::PeerDisconnected(peer) => {
                // Remove from tracking and log disconnection
                if connected_peers.remove(&peer) {
                    info!("peer disconnected {peer}");
                }
            }
            NetworkEvent::BroadcastFailed { reason } => {
                warn!("broadcast failed: {}", reason);
            }
        }
    }
}

/// Perform a chain reorganization from old_tip to new_tip.
///
/// This function:
/// 1. Finds the common ancestor between old and new chains
/// 2. Reverts blocks from old chain back to the common ancestor
/// 3. Applies blocks from the common ancestor to the new tip
async fn perform_reorg(
    db: &NullaDb,
    old_tip: [u8; 32],
    new_tip: [u8; 32],
) -> anyhow::Result<()> {
    info!("starting chain reorganization");
    info!("  old tip: {}", hex::encode(old_tip));
    info!("  new tip: {}", hex::encode(new_tip));

    // Step 1: Build paths from both tips back to genesis
    let mut old_path = vec![old_tip];
    let mut new_path = vec![new_tip];

    // Build old chain path
    let mut current = old_tip;
    while current != [0u8; 32] {
        if let Some(block) = db.get_block(&current)? {
            current = block.header.prev;
            old_path.push(current);
        } else {
            break;
        }
    }

    // Build new chain path
    current = new_tip;
    while current != [0u8; 32] {
        if let Some(block) = db.get_block(&current)? {
            current = block.header.prev;
            new_path.push(current);
        } else {
            break;
        }
    }

    // Step 2: Find common ancestor
    let mut common_ancestor = None;
    for old_block in &old_path {
        if new_path.contains(old_block) {
            common_ancestor = Some(*old_block);
            break;
        }
    }

    let common_ancestor = common_ancestor.ok_or_else(|| anyhow::anyhow!("no common ancestor found"))?;
    info!("  common ancestor: {}", hex::encode(common_ancestor));

    // Step 3: Revert blocks from old chain
    let blocks_to_revert: Vec<[u8; 32]> = old_path
        .iter()
        .take_while(|&&id| id != common_ancestor)
        .copied()
        .collect();

    // SECURITY FIX (HIGH-NEW-002): Enforce maximum reorg depth
    let reorg_depth = blocks_to_revert.len();
    if reorg_depth > MAX_REORG_DEPTH {
        warn!(
            "SECURITY: Rejecting reorg of depth {} (max: {})",
            reorg_depth, MAX_REORG_DEPTH
        );
        return Err(anyhow::anyhow!(
            "reorg depth {} exceeds maximum allowed depth of {}",
            reorg_depth,
            MAX_REORG_DEPTH
        ));
    }

    if reorg_depth > 10 {
        warn!(
            "WARNING: Deep reorg of {} blocks detected (common ancestor: {})",
            reorg_depth,
            hex::encode(common_ancestor)
        );
    }

    info!("  reverting {} blocks from old chain", blocks_to_revert.len());
    for block_id in blocks_to_revert {
        if let Some(block) = db.get_block(&block_id)? {
            // Revert transactions in reverse order (except coinbase)
            for tx in block.txs.iter().skip(1).rev() {
                if let Err(e) = db.revert_tx(tx) {
                    warn!("failed to revert tx during reorg: {}", e);
                }
            }
            info!("    reverted block at height {}", block.header.height);
        }
    }

    // Step 4: Apply blocks from new chain
    let blocks_to_apply: Vec<[u8; 32]> = new_path
        .iter()
        .take_while(|&&id| id != common_ancestor)
        .copied()
        .collect();

    info!("  applying {} blocks from new chain", blocks_to_apply.len());
    // Apply in reverse order (from common ancestor to new tip)
    for block_id in blocks_to_apply.iter().rev() {
        if let Some(block) = db.get_block(block_id)? {
            // Apply transactions (skip coinbase)
            for tx in block.txs.iter().skip(1) {
                if let Err(e) = db.apply_tx(tx) {
                    warn!("failed to apply tx during reorg: {}", e);
                }
            }
            info!("    applied block at height {}", block.header.height);
        }
    }

    info!("chain reorganization complete");
    Ok(())
}

async fn process_full_block(
    db: &NullaDb,
    sync_progress: &Arc<Mutex<Option<ProgressBar>>>,
    block: nulla_core::Block,
    from: Option<libp2p::PeerId>,
    chain_id: &[u8; 4],
) -> bool {
    let block_id = nulla_core::block_id(&block);
    if let Some(peer) = from {
        info!(
            "full block from {peer} height={} id={} txs={}",
            block.header.height,
            hex::encode(block_id),
            block.txs.len()
        );
    } else {
        info!(
            "full block height={} id={} txs={}",
            block.header.height,
            hex::encode(block_id),
            block.txs.len()
        );
    }

    // Check if we already have this block
    if db.get_block(&block_id).ok().flatten().is_some() {
        debug!("already have block {} at height {}, skipping", hex::encode(block_id), block.header.height);
        return false; // Don't re-broadcast blocks we already have
    }

    // Parent check is now done by the caller (orphan pool logic)

    if let Err(e) = nulla_core::validate_block(&block) {
        warn!("received invalid block (structure): {e}");
        return false;
    }

    // Validate difficulty target is correct
    let get_header = |height: u64| -> Option<nulla_core::BlockHeader> {
        db.get_header_by_height(height).ok().flatten()
    };
    if let Err(e) = nulla_core::validate_difficulty(&block, get_header) {
        warn!("received block with invalid difficulty target: {e}");
        return false;
    }

    // Validate block timestamp (SECURITY FIX: HIGH-NEW-001)
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if let Err(e) = nulla_core::validate_block_timestamp(&block, get_header, current_time) {
        warn!("received block with invalid timestamp: {e}");
        return false;
    }

    // Validate checkpoint (SECURITY FIX: HIGH-012)
    if let Err(e) = nulla_core::validate_checkpoint(block.header.height, &block_id) {
        warn!("received block failed checkpoint validation: {e}");
        return false;
    }

    // Validate and apply all transactions atomically (SECURITY FIX: CRIT-NEW-003)
    // Signatures verified in parallel, UTXO validation + application sequential (atomic)
    // Also tracks coinbase heights for maturity validation
    let total_fees = match db.validate_and_apply_block_txs(&block.txs, chain_id, block.header.height) {
        Ok(fees) => fees,
        Err(e) => {
            warn!("block rejected: atomic validation failed: {e}");
            return false;
        }
    };

    // Calculate block reward based on height (emission schedule with tail emission)
    let block_reward = nulla_core::calculate_block_reward(block.header.height);

    // Validate coinbase doesn't claim more than block_reward + total_fees
    if let Err(e) = nulla_core::validate_coinbase(
        &block.txs[0],
        block_reward,
        total_fees,
    ) {
        warn!(
            "block rejected: coinbase validation failed (height: {}, reward: {}, fees: {}, error: {})",
            block.header.height, block_reward, total_fees, e
        );
        return false;
    }

    if let Err(e) = db.put_block_full(&block) {
        warn!("failed to store full block: {e}");
        return false;
    }

    let block_work = nulla_core::target_work(&block.header.target);
    let cumulative_work = if block.header.prev == [0u8; 32] {
        block_work
    } else {
        match db.get_work(&block.header.prev) {
            Ok(Some(prev_work)) => prev_work + block_work,
            _ => block_work,
        }
    };

    if let Err(e) = db.set_work(&block_id, cumulative_work) {
        warn!("failed to store cumulative work: {e}");
    }

    // Transactions already applied atomically by validate_and_apply_block_txs() above
    // SECURITY: Removed separate apply_tx() loop to prevent TOCTOU (CRIT-NEW-003)

    for tx in block.txs.iter().skip(1) {
        let txid = nulla_core::tx_id(tx);
        let _ = db.remove_mempool_tx(&txid);
    }

    match db.best_tip() {
        Ok(Some((tip_id, tip_height, tip_work))) => {
            if block.header.prev == tip_id && block.header.height == tip_height + 1 {
                if let Err(e) = db.set_best_tip(&block_id, block.header.height, cumulative_work) {
                    warn!("failed to update best tip: {e}");
                } else {
                    info!(
                        "updated best tip to height {} (work: {})",
                        block.header.height, cumulative_work
                    );

                    // Prune old blocks if pruning is enabled
                    if let Err(e) = db.prune_old_blocks() {
                        warn!("pruning failed: {e}");
                    }

                    let mut progress_lock = sync_progress.lock().await;
                    if let Some(ref pb) = *progress_lock {
                        pb.set_position(block.header.height);
                        if block.header.height >= pb.length().unwrap_or(0) {
                            pb.finish_with_message("Synced!");
                            *progress_lock = None;
                        }
                    }
                }
            } else if cumulative_work > tip_work {
                info!(
                    "received chain with more work (our: {}, theirs: {}), height: {}",
                    tip_work, cumulative_work, block.header.height
                );

                // Perform chain reorganization
                info!("triggering chain reorganization");
                if let Err(e) = perform_reorg(db, tip_id, block_id).await {
                    warn!("reorganization failed: {}", e);
                    return false;
                }

                // Update best tip after successful reorg
                if let Err(e) = db.set_best_tip(&block_id, block.header.height, cumulative_work) {
                    warn!("failed to update best tip after reorg: {e}");
                } else {
                    info!(
                        "switched to new best chain at height {} after reorg",
                        block.header.height
                    );

                    // Prune old blocks if pruning is enabled
                    if let Err(e) = db.prune_old_blocks() {
                        warn!("pruning failed: {e}");
                    }
                }
            } else if block.header.height > tip_height {
                let blocks_behind = block.header.height - tip_height;
                info!(
                    "we're behind (our height: {tip_height}, their height: {}), {} blocks behind",
                    block.header.height, blocks_behind
                );

                let mut progress_lock = sync_progress.lock().await;
                if progress_lock.is_none() {
                    let pb = ProgressBar::new(block.header.height);
                    pb.set_style(
                        ProgressStyle::default_bar()
                            .template(
                                "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} blocks ({eta})",
                            )
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

    // Block was successfully validated and stored
    true
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
            // SECURITY FIX (HIGH-NEW-005): Validate starting hash before processing
            info!("get headers from {} limit {}", hex::encode(from), limit);

            // Validate that the starting block exists
            match db.get_block(&from) {
                Ok(Some(_)) => {
                    // Starting block exists, proceed with traversal
                }
                Ok(None) => {
                    // Block not found - this could be a probe attack or outdated peer
                    warn!(
                        "SECURITY: GetHeaders request for non-existent block {}",
                        hex::encode(from)
                    );
                    return protocol::Resp::Err { code: 404 }; // Not Found
                }
                Err(e) => {
                    warn!("Database error in GetHeaders: {}", e);
                    return protocol::Resp::Err { code: 500 }; // Internal Server Error
                }
            }

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
        protocol::Req::GetMempool { limit } => {
            // Return mempool transactions up to the specified limit.
            match db.get_mempool_txs() {
                Ok(all_txs) => {
                    let max_txs = limit.min(100) as usize; // Cap at 100 transactions
                    let txs = all_txs.into_iter().take(max_txs).collect();
                    info!("returning {} mempool transactions", max_txs.min(db.mempool_size()));
                    protocol::Resp::Mempool { txs }
                }
                Err(e) => {
                    warn!("failed to get mempool txs: {}", e);
                    protocol::Resp::Err { code: 500 }
                }
            }
        }
    }
}

/// Spawn a stub miner that periodically broadcasts dummy blocks for testing gossip.

/// Periodically sync chain state with connected peers.
///
/// Every 60 seconds, this task:
/// - Logs current chain state
/// - Ensures peers are kept in sync via gossipsub
async fn periodic_peer_sync(
    cmd_tx: async_channel::Sender<NetworkCommand>,
    db: NullaDb,
    peers: Vec<libp2p::Multiaddr>,
) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;

        // Attempt to dial all peers to maintain connections and discover new peers
        if !peers.is_empty() {
            info!("attempting to dial {} peer(s) to maintain connectivity", peers.len());
            for peer in &peers {
                debug!("dialing peer: {}", peer);
                let _ = cmd_tx.send(NetworkCommand::Dial(peer.clone())).await;
            }
        }

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

        // Wait for initial peer connection before mining (prevents creating competing genesis chains)
        info!("miner: waiting up to 10 minutes for peer connection before mining...");

        let mut sync_started = false;
        let mut last_height = 0u64;
        let mut stable_count = 0u8;

        // Wait in 1-second intervals so we can check for shutdown
        // 10 minutes = 600 seconds = 10 attempts at 60-second peer dial interval
        for i in 0..600 {
            if shutdown.load(Ordering::Relaxed) {
                info!("miner: shutdown requested during initial wait");
                return;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            // Check every 2 seconds if we've synced blocks
            if i > 0 && i % 2 == 0 {
                // Check if we have any blocks from the network
                if let Ok(Some((_, height, _))) = db.best_tip() {
                    if height > 0 {
                        if !sync_started {
                            info!("miner: peer connected! syncing blocks from network...");
                            sync_started = true;
                            last_height = height;
                        } else {
                            // Check if sync is progressing or complete
                            if height > last_height {
                                info!("miner: sync progress - now at height {}", height);
                                last_height = height;
                                stable_count = 0; // Reset stability counter
                            } else if height == last_height {
                                stable_count += 1;
                                // If height hasn't changed for 10 seconds (5 checks * 2 seconds), sync is complete
                                if stable_count >= 5 {
                                    info!("miner: sync complete at height {}, starting mining!", height);
                                    break;
                                }
                            }
                        }
                    }
                }

                // Show progress every minute
                if i % 60 == 0 && !sync_started {
                    info!("miner: still waiting for peer connection... ({} minutes elapsed)", i / 60);
                }
            }
        }

        if !sync_started {
            info!("miner: no peers connected after 10 minutes, will create genesis block");
        }

        // Check if we have a tip from the network (not genesis)
        if let Ok(Some((_, height, _))) = db.best_tip() {
            if height > 0 {
                info!("miner: synced to height {}, starting mining", height);
            } else {
                info!("miner: no network blocks found, will create genesis");
            }
        } else {
            info!("miner: no blocks found, will create genesis");
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

            // Calculate block reward based on height (emission schedule with tail emission)
            let block_reward = nulla_core::calculate_block_reward(next_height);

            // Create coinbase transaction if we have a wallet
            use nulla_core::{Block, Tx};
            let mut txs: Vec<Tx> = if let Some(addr) = coinbase_addr {
                vec![nulla_wallet::create_coinbase(
                    &addr,
                    next_height,
                    block_reward,
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
                        value_atoms: block_reward,
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

            // Calculate difficulty target based on chain history
            let target = if next_height == 0 {
                // Genesis block uses initial target
                nulla_core::INITIAL_TARGET
            } else if next_height % nulla_core::difficulty::ADJUSTMENT_INTERVAL != 0 {
                // Not at adjustment boundary, use previous block's target
                match db.get_header(&prev_id) {
                    Ok(Some(prev_header)) => prev_header.target,
                    _ => {
                        warn!("miner: failed to get previous header for target, using initial target");
                        nulla_core::INITIAL_TARGET
                    }
                }
            } else {
                // At adjustment boundary, calculate new target
                let Some(prev_header) = db.get_header(&prev_id).ok().flatten() else {
                    warn!("miner: failed to get previous header, using initial target");
                    continue;
                };

                let old_height = next_height.saturating_sub(nulla_core::difficulty::ADJUSTMENT_INTERVAL);
                let old_header = match db.get_header_by_height(old_height) {
                    Ok(Some(h)) => h,
                    _ => {
                        warn!("miner: failed to get old header for difficulty adjustment, using previous target");
                        continue;
                    }
                };

                let new_target = nulla_core::calculate_next_target(
                    next_height,
                    &prev_header.target,
                    prev_header.timestamp,
                    old_header.timestamp,
                );

                info!(
                    "miner: difficulty adjustment at height {} (prev_target: {:02x}{:02x}{:02x}{:02x}, new_target: {:02x}{:02x}{:02x}{:02x})",
                    next_height,
                    prev_header.target[0], prev_header.target[1], prev_header.target[2], prev_header.target[3],
                    new_target[0], new_target[1], new_target[2], new_target[3]
                );

                new_target
            };

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
                nulla_wallet::atoms_to_nulla(block_reward)
            );

            // Validate and apply all transactions atomically (SECURITY FIX: CRIT-006)
            // This matches the same atomic validation used for received blocks
            // Also tracks coinbase heights for maturity validation
            let _total_fees = match db.validate_and_apply_block_txs(&block.txs, &chain_id, next_height) {
                Ok(fees) => fees,
                Err(e) => {
                    warn!("miner: block validation failed (should not happen): {e}");
                    continue;
                }
            };

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

            // Transactions already applied atomically by validate_and_apply_block_txs() above
            // SECURITY: Removed separate apply_tx() loop to prevent double-application (CRIT-006)

            // Remove transactions from mempool now that they're in a block
            for (i, tx) in block.txs.iter().enumerate().skip(1) {
                // Skip coinbase (index 0)
                let txid = nulla_core::tx_id(tx);
                if let Err(e) = db.remove_mempool_tx(&txid) {
                    warn!("miner: failed to remove tx {} from mempool: {e}", i);
                }
            }

            // Prune old blocks if pruning is enabled
            if let Err(e) = db.prune_old_blocks() {
                warn!("miner: pruning failed: {e}");
            }

            // Broadcast the full block to the network (includes transactions).
            info!("miner: sending PublishFullBlock command for height {} (channel capacity: {}, len: {})",
                next_height, cmd_tx.capacity().unwrap_or(0), cmd_tx.len());
            match cmd_tx.send(NetworkCommand::PublishFullBlock { block }).await {
                Ok(_) => info!("miner: PublishFullBlock command sent successfully (channel len after send: {})", cmd_tx.len()),
                Err(e) => error!("miner: FAILED to send PublishFullBlock command: {:?}", e),
            }
        }
    });
    Ok(())
}
