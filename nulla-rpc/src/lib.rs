use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, Result};
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::RpcModule;
use async_channel::Sender;
use tokio::sync::RwLock;

use nulla_db::NullaDb;
use nulla_net::NetworkCommand;
use nulla_wallet::Wallet;

mod methods;
mod types;
mod error;

pub use error::RpcError;
pub use types::*;

/// Shared context for all RPC methods
#[derive(Clone)]
pub struct RpcContext {
    pub db: NullaDb,
    pub network_tx: Sender<NetworkCommand>,
    pub wallet: Option<Arc<RwLock<Wallet>>>,
    pub start_time: Instant,
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

    // Build the server
    let server = ServerBuilder::default()
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

    // Start the server
    let handle = server.start(module);

    Ok(handle)
}
