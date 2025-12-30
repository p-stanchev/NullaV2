use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use std::num::NonZeroU32;

use anyhow::{anyhow, Result};
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::RpcModule;
use async_channel::Sender;
use tokio::sync::RwLock;
use governor::{Quota, RateLimiter};
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};

use nulla_db::NullaDb;
use nulla_net::NetworkCommand;
use nulla_wallet::Wallet;

mod methods;
mod types;
mod error;

pub use error::RpcError;
pub use types::*;

/// RPC server security limits (SECURITY FIX: HIGH-NEW-003)
const MAX_CONNECTIONS: u32 = 10;
const MAX_REQUEST_SIZE: u32 = 10 * 1024 * 1024;  // 10 MB
const MAX_RESPONSE_SIZE: u32 = 10 * 1024 * 1024; // 10 MB
const RATE_LIMIT_PER_SECOND: u32 = 100;

/// Shared context for all RPC methods
#[derive(Clone)]
pub struct RpcContext {
    pub db: NullaDb,
    pub network_tx: Sender<NetworkCommand>,
    pub wallet: Option<Arc<RwLock<Wallet>>>,
    pub start_time: Instant,
    pub chain_id: [u8; 4],
    pub rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
}

impl RpcContext {
    /// Create a new RPC context with rate limiting (SECURITY FIX: HIGH-NEW-003)
    pub fn new(
        db: NullaDb,
        network_tx: Sender<NetworkCommand>,
        wallet: Option<Arc<RwLock<Wallet>>>,
        start_time: Instant,
        chain_id: [u8; 4],
    ) -> Self {
        // Create rate limiter: 100 requests per second
        let quota = Quota::per_second(NonZeroU32::new(RATE_LIMIT_PER_SECOND).unwrap());
        let rate_limiter = Arc::new(RateLimiter::direct(quota));

        Self {
            db,
            network_tx,
            wallet,
            start_time,
            chain_id,
            rate_limiter,
        }
    }

    /// Check rate limit before processing request (SECURITY FIX: HIGH-NEW-003)
    /// Returns Ok(()) if request is allowed, Err if rate limited
    pub fn check_rate_limit(&self) -> Result<()> {
        if self.rate_limiter.check().is_err() {
            return Err(anyhow!("Rate limit exceeded. Maximum {} requests per second.", RATE_LIMIT_PER_SECOND));
        }
        Ok(())
    }
}

/// Spawns the JSON-RPC 2.0 HTTP server
///
/// # Security
/// This function enforces localhost-only binding to prevent unauthorized remote access.
/// Attempts to bind to non-loopback addresses will return an error.
///
/// # Arguments
/// * `bind_addr` - Address to bind to (e.g., "127.0.0.1:27447")
/// * `ctx` - Shared RPC context with database, network, and wallet access
///
/// # Returns
/// A ServerHandle that can be used to stop the server
pub async fn spawn_rpc_server(
    bind_addr: String,
    ctx: RpcContext,
) -> Result<ServerHandle> {
    let addr: SocketAddr = bind_addr.parse()
        .map_err(|e| anyhow!("Invalid bind address '{}': {}", bind_addr, e))?;

    // SECURITY: Enforce localhost-only binding
    if !addr.ip().is_loopback() {
        return Err(anyhow!(
            "RPC server must bind to localhost (127.0.0.1 or ::1) only. Got: {}",
            addr.ip()
        ));
    }

    // Build the server with security limits (SECURITY FIX: HIGH-NEW-003)
    let server = ServerBuilder::default()
        .max_connections(MAX_CONNECTIONS)
        .max_request_body_size(MAX_REQUEST_SIZE)
        .max_response_body_size(MAX_RESPONSE_SIZE)
        .build(addr)
        .await
        .map_err(|e| anyhow!("Failed to build RPC server: {}", e))?;

    // Create RPC module with our context
    let mut module = RpcModule::new(ctx);

    // Register all method categories
    methods::chain::register_methods(&mut module)?;
    methods::tx::register_methods(&mut module)?;
    methods::wallet::register_methods(&mut module)?;
    methods::network::register_methods(&mut module)?;
    methods::multisig::register_methods(&mut module)?;
    methods::electrum::register_methods(&mut module)?;

    // Start the server
    let handle = server.start(module);

    Ok(handle)
}
