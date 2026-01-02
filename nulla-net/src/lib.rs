//! Networking layer for the Nulla blockchain.
//!
//! This crate provides:
//! - libp2p-based P2P networking with Noise encryption and Yamux multiplexing
//! - Gossipsub for transaction and block propagation
//! - Kademlia DHT for peer discovery
//! - Request/response protocol for block and header sync
//! - Dandelion++ transaction privacy protocol
//! - Cover traffic support

use std::time::Duration;

use async_channel::{Receiver, Sender};
use futures::prelude::*;
use libp2p::{
    identify, multiaddr::Protocol, noise, ping, request_response, swarm::SwarmEvent, tcp,
    Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use thiserror::Error;
use tokio::select;
use tracing::info;

use nulla_core::{block_header_id, Block, BlockHeader, Hash32};

mod behaviour;
mod gossip;
mod kad;
mod reqresp;

pub use behaviour::Behaviour;

/// Protocol definitions and message types.
pub mod protocol {
    use super::*;
    use nulla_core::{Block, BlockHeader, Tx};
    use serde::{Deserialize, Serialize};

    /// Maximum number of headers returned in a single response.
    pub const MAX_HEADERS: usize = 2048;

    /// Maximum block size in bytes.
    /// Increased from 1 MB to 4 MB for 4x higher transaction capacity per block.
    pub const MAX_BLOCK_SIZE: usize = 4_000_000;

    /// Maximum transaction size in bytes.
    pub const MAX_TX_SIZE: usize = 100_000;

    /// Maximum network message size in bytes (16 MB).
    /// This prevents memory exhaustion attacks from oversized messages.
    /// Set higher than MAX_BLOCK_SIZE to allow for protocol overhead.
    pub const MAX_MESSAGE_SIZE: usize = 16_000_000;

    /// Maximum number of peer addresses in a PeerExchange response.
    pub const MAX_PX_ADDRS: usize = 32;

    /// Messages broadcast via gossipsub.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum GossipMsg {
        /// Transaction inventory announcement.
        InvTx { txid: Hash32 },
        /// Block inventory announcement (includes full header).
        InvBlock { header: BlockHeader },
        /// Full block broadcast (for small networks, includes all transactions).
        FullBlock { block: Block },
        /// Full transaction broadcast (includes complete transaction data).
        FullTx { tx: Tx },
        /// Cover traffic noise message for network privacy.
        Noise { bytes: [u8; 32] },
    }

    /// Request messages sent between peers.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum Req {
        /// Get the best chain tip.
        GetTip,
        /// Request headers starting from a given block hash.
        GetHeaders { from: Hash32, limit: u32 },
        /// Request a full block by ID.
        GetBlock { id: Hash32 },
        /// Request a transaction by ID.
        GetTx { id: Hash32 },
        /// Request peer addresses (for bootstrapping).
        PeerExchange { want: u16 },
        /// Request known peer addresses.
        GetAddr,
        /// Dandelion++ stem-phase transaction relay.
        StemTx { txid: Hash32, hops_left: u8 },
        /// Request mempool transactions (for initial sync).
        GetMempool { limit: u32 },
    }

    /// Response messages.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum Resp {
        /// Chain tip information.
        Tip {
            height: u64,
            id: Hash32,
            cumulative_work: u128,
        },
        /// List of block headers.
        Headers { headers: Vec<BlockHeader> },
        /// Full block (or None if not found).
        Block { block: Option<Block> },
        /// Transaction (or None if not found).
        Tx { tx: Option<Tx> },
        /// List of peer addresses.
        PeerExchange { addrs: Vec<Vec<u8>> },
        /// List of known addresses.
        Addr { addrs: Vec<Vec<u8>> },
        /// Mempool transactions.
        Mempool { txs: Vec<Tx> },
        /// Error response.
        Err { code: u16 },
    }

    /// Generate the gossipsub topic for transaction inventory messages.
    pub fn topic_inv_tx(chain: &[u8; 4]) -> String {
        format!("/nulla/{}/inv_tx", String::from_utf8_lossy(chain))
    }

    /// Generate the gossipsub topic for block inventory messages.
    pub fn topic_inv_block(chain: &[u8; 4]) -> String {
        format!("/nulla/{}/inv_block", String::from_utf8_lossy(chain))
    }
}

/// Dandelion++ transaction privacy protocol implementation.
///
/// Dandelion++ provides transaction anonymity by relaying transactions through a "stem" phase
/// (point-to-point forwarding) before broadcasting them in a "fluff" phase (gossip).
/// This makes it harder for network observers to determine the transaction origin.
pub mod dandelion {
    use super::*;
    use lru::LruCache;
    use rand::{seq::SliceRandom, Rng};
    use std::num::NonZeroUsize;
    use std::time::Instant;

    /// Action to take when processing a transaction in Dandelion++ mode.
    #[derive(Debug)]
    pub enum Action {
        /// Forward the transaction to a specific peer (stem phase).
        Forward {
            peer: PeerId,
            txid: Hash32,
            hops_left: u8,
        },
        /// Broadcast the transaction via gossip (fluff phase).
        Fluff { txid: Hash32 },
        /// Drop the transaction (already seen or invalid).
        Drop,
    }

    /// Dandelion++ state machine for transaction privacy.
    pub struct Dandelion {
        /// The peer we're currently relaying stem transactions to.
        pub stem_peer: Option<PeerId>,
        /// When the current stem peer expires and should be rotated.
        pub stem_deadline: Instant,
        /// Default number of stem hops before fluffing.
        pub stem_hops_default: u8,
        /// How long before a stem peer is rotated.
        pub stem_timeout: Duration,
        /// Probability of switching to fluff phase early (adds randomness).
        pub fluff_probability: f32,
        /// Cache of recently seen transaction IDs to prevent loops.
        pub seen: LruCache<Hash32, Instant>,
        /// How long to remember a transaction ID.
        pub seen_ttl: Duration,
        /// Random number generator for probabilistic decisions.
        pub rng: rand::rngs::StdRng,
        /// Minimum delay before broadcasting a transaction (milliseconds).
        pub min_broadcast_delay_ms: u64,
        /// Maximum delay before broadcasting a transaction (milliseconds).
        pub max_broadcast_delay_ms: u64,
    }

    impl Dandelion {
        /// Create a new Dandelion++ state machine with default parameters.
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            let seed: [u8; 32] = rand::thread_rng().gen();
            Self {
                stem_peer: None,
                stem_deadline: Instant::now(),
                stem_hops_default: 8,
                stem_timeout: Duration::from_secs(10),
                fluff_probability: 0.1,
                seen: LruCache::new(NonZeroUsize::new(2048).unwrap()),
                seen_ttl: Duration::from_secs(1800),
                rng: rand::SeedableRng::from_seed(seed),
                // Default: 100-500ms random delay before broadcasting
                min_broadcast_delay_ms: 100,
                max_broadcast_delay_ms: 500,
            }
        }

        /// Generate a random broadcast delay to obfuscate transaction timing.
        /// Returns a Duration between min_broadcast_delay_ms and max_broadcast_delay_ms.
        pub fn random_broadcast_delay(&mut self) -> Duration {
            let delay_ms = self.rng.gen_range(self.min_broadcast_delay_ms..=self.max_broadcast_delay_ms);
            Duration::from_millis(delay_ms)
        }

        /// Randomly select a new stem peer from the connected peers.
        ///
        /// Uses improved selection algorithm:
        /// - Avoids immediately re-selecting the same peer
        /// - Randomizes stem_timeout to prevent predictable rotation patterns
        pub fn rotate_peer(&mut self, peers: &[PeerId]) {
            if peers.is_empty() {
                self.stem_peer = None;
                return;
            }

            // Filter out current stem peer to ensure we rotate to a different peer
            let candidates: Vec<_> = if let Some(current) = self.stem_peer {
                peers.iter().filter(|&p| p != &current).copied().collect()
            } else {
                peers.to_vec()
            };

            // If filtering left us with no candidates, use all peers
            let selection_pool = if candidates.is_empty() { peers } else { &candidates };

            if let Some(peer) = selection_pool.choose(&mut self.rng) {
                self.stem_peer = Some(*peer);

                // Randomize stem rotation timeout between 8-12 seconds (avg 10s)
                // This prevents timing correlation attacks
                let base_timeout = self.stem_timeout.as_secs();
                let jitter = self.rng.gen_range(0..=4) as i64 - 2; // -2 to +2 seconds
                let timeout_secs = (base_timeout as i64 + jitter).max(5) as u64;

                self.stem_deadline = Instant::now() + Duration::from_secs(timeout_secs);
                tracing::debug!("rotated stem peer, next rotation in {}s", timeout_secs);
            }
        }

        /// Handle a locally created transaction (start of stem phase).
        pub fn on_local_tx(&mut self, txid: Hash32, connected: &[PeerId]) -> Action {
            self.seen.put(txid, Instant::now());
            if self.stem_peer.is_none() && !connected.is_empty() {
                self.rotate_peer(connected);
            }
            match self.stem_peer {
                Some(peer) => Action::Forward {
                    peer,
                    txid,
                    hops_left: self.stem_hops_default,
                },
                None => Action::Fluff { txid },
            }
        }

        /// Handle an incoming stem transaction from another peer.
        pub fn on_stem(&mut self, txid: Hash32, hops_left: u8, connected: &[PeerId]) -> Action {
            if self.seen.contains(&txid) {
                return Action::Drop;
            }
            self.seen.put(txid, Instant::now());
            let should_fluff = hops_left == 0
                || Instant::now() > self.stem_deadline
                || self.rng.gen::<f32>() < self.fluff_probability;
            if should_fluff {
                Action::Fluff { txid }
            } else {
                if self.stem_peer.is_none() && !connected.is_empty() {
                    self.rotate_peer(connected);
                }
                match self.stem_peer {
                    Some(peer) => Action::Forward {
                        peer,
                        txid,
                        hops_left: hops_left.saturating_sub(1),
                    },
                    None => Action::Fluff { txid },
                }
            }
        }

        /// Mark a transaction as seen, returning false if it was recently seen.
        pub fn mark_seen(&mut self, txid: Hash32) -> bool {
            let now = Instant::now();
            if let Some(ts) = self.seen.get(&txid).cloned() {
                if now.duration_since(ts) < self.seen_ttl {
                    return false;
                }
            }
            self.seen.put(txid, now);
            true
        }
    }
}

/// Network configuration.
#[derive(Clone, Debug)]
pub struct NetConfig {
    /// Chain identifier (4 bytes).
    pub chain_id: [u8; 4],
    /// Multiaddresses to listen on.
    pub listen: Vec<Multiaddr>,
    /// Initial peers to connect to.
    pub peers: Vec<Multiaddr>,
    /// Enable Dandelion++ transaction privacy.
    pub dandelion: bool,
    /// Enable cover traffic.
    pub cover_traffic: bool,
    /// Number of stem hops in Dandelion++ before fluff phase.
    pub dandelion_stem_hops: u8,
    /// Probability of early fluff in Dandelion++ (0.0-1.0).
    pub dandelion_fluff_probability: f32,
    /// Minimum broadcast delay in milliseconds.
    pub min_broadcast_delay_ms: u64,
    /// Maximum broadcast delay in milliseconds.
    pub max_broadcast_delay_ms: u64,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            chain_id: *b"NULL",
            listen: Vec::new(),
            peers: Vec::new(),
            dandelion: true,
            cover_traffic: false,
            dandelion_stem_hops: 8,
            dandelion_fluff_probability: 0.1,
            min_broadcast_delay_ms: 100,
            max_broadcast_delay_ms: 500,
        }
    }
}

/// Commands sent to the network task.
#[derive(Debug)]
pub enum NetworkCommand {
    /// Dial a new peer.
    Dial(Multiaddr),
    /// Publish a transaction to the network.
    PublishTx { txid: Hash32 },
    /// Publish a full transaction to the network (includes transaction data).
    PublishFullTx { tx: nulla_core::Tx },
    /// Publish a block to the network.
    PublishBlock { header: BlockHeader },
    /// Publish a full block to the network (includes all transactions).
    PublishFullBlock { block: Block },
    /// Send a request to a peer.
    SendRequest { peer: PeerId, req: protocol::Req },
    /// Send a response to a peer.
    SendResponse {
        channel: ResponseChannel,
        resp: protocol::Resp,
    },
}

/// Events emitted by the network task.
#[derive(Debug)]
pub enum NetworkEvent {
    /// Received a transaction inventory announcement.
    TxInv { from: PeerId, txid: Hash32 },
    /// Received a full transaction.
    FullTx { from: PeerId, tx: nulla_core::Tx },
    /// Received a block inventory announcement.
    BlockInv { from: PeerId, header: BlockHeader },
    /// Received a full block.
    FullBlock { from: PeerId, block: Block },
    /// Received a request from a peer.
    Request {
        peer: PeerId,
        req: protocol::Req,
        channel: ResponseChannel,
    },
    /// Received a response from a peer.
    Response { peer: PeerId, resp: protocol::Resp },
    /// Started listening on a new address.
    NewListen(Multiaddr),
    /// A peer connected.
    PeerConnected(PeerId),
    /// A peer disconnected.
    PeerDisconnected(PeerId),
    /// Broadcast failed due to no connected peers.
    BroadcastFailed { reason: String },
}

/// Network errors.
#[derive(Debug, Error)]
pub enum NetError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Request/response channel for replies.
pub type ResponseChannel = request_response::ResponseChannel<protocol::Resp>;

/// Network handle for sending commands and receiving events.
pub struct NetworkHandle {
    pub commands: Sender<NetworkCommand>,
    pub events: Receiver<NetworkEvent>,
    pub local_peer_id: PeerId,
}

/// Spawn the network task and return a handle for sending commands and receiving events.
pub async fn spawn_network(config: NetConfig) -> Result<NetworkHandle, NetError> {
    let chain_id = config.chain_id;
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(|e| anyhow::anyhow!("transport error: {e}"))?
        .with_behaviour(move |id| behaviour::build_behaviour(id, &chain_id))
        .map_err(|e| anyhow::anyhow!("behaviour error: {e}"))?
        .with_swarm_config(|cfg| cfg.with_max_negotiating_inbound_streams(1024))
        .build();
    let peer_id = *swarm.local_peer_id();
    let cover_traffic = config.cover_traffic;

    for addr in &config.listen {
        Swarm::listen_on(&mut swarm, addr.clone())
            .map_err(|e| anyhow::anyhow!("listen error: {e}"))?;
    }
    for peer in &config.peers {
        Swarm::dial(&mut swarm, peer.clone()).map_err(|e| anyhow::anyhow!("dial error: {e}"))?;
    }

    // Bootstrap Kademlia DHT if we have initial peers.
    if !config.peers.is_empty() {
        info!(
            "bootstrapping Kademlia DHT with {} initial peer(s)",
            config.peers.len()
        );
        let _ = swarm.behaviour_mut().kad.bootstrap();
    }

    let (cmd_tx, cmd_rx) = async_channel::bounded(2048);  // Increased from 64 to handle bursts of block broadcasts
    let (evt_tx, evt_rx) = async_channel::bounded(8192);
    info!("spawning network task with 30s heartbeat enabled");
    tokio::spawn(async move {
        run_swarm(swarm, cmd_rx, evt_tx, chain_id, cover_traffic).await;
        tracing::error!("network task exited unexpectedly");
    });

    Ok(NetworkHandle {
        commands: cmd_tx,
        events: evt_rx,
        local_peer_id: peer_id,
    })
}

/// Main swarm event loop with optional cover traffic.
async fn run_swarm(
    mut swarm: Swarm<Behaviour>,
    cmd_rx: Receiver<NetworkCommand>,
    evt_tx: Sender<NetworkEvent>,
    chain_id: [u8; 4],
    cover_traffic: bool,
) {
    use rand::Rng;

    // Heartbeat interval: log connected peer count every 30 seconds.
    let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(30));
    // Skip the immediate first tick
    heartbeat_interval.tick().await;
    tracing::debug!("heartbeat interval initialized, first tick in 30s");

    // Cover traffic: randomized timing for better privacy
    // Randomize between 30-90 seconds (avg 60s) to prevent timing analysis
    let next_cover_traffic_delay = || -> Duration {
        if cover_traffic {
            let base_secs = 60;
            let jitter_range = 30; // +/- 30 seconds
            let jitter: i64 = rand::thread_rng().gen_range(-(jitter_range as i64)..=(jitter_range as i64));
            Duration::from_secs((base_secs + jitter) as u64)
        } else {
            Duration::from_secs(u64::MAX) // Never fire if disabled
        }
    };

    use tokio::pin;

    let cover_traffic_sleep = if cover_traffic {
        tokio::time::sleep(next_cover_traffic_delay())
    } else {
        tokio::time::sleep(Duration::from_secs(u64::MAX))
    };
    pin!(cover_traffic_sleep);

    loop {
        tracing::trace!("loop iteration, cmd_rx len: {}", cmd_rx.len());

        // tokio::select! fairly distributes processing across all branches,
        // preventing both command starvation and swarm event starvation
        select! {
            _ = heartbeat_interval.tick() => {
                let connected_peers = swarm.connected_peers().count();
                let cmd_queue_len = cmd_rx.len();
                info!("total peers connected: {}, cmd_queue_len: {}", connected_peers, cmd_queue_len);
                tracing::debug!("heartbeat fired, next in 30s");
            }
            _ = &mut cover_traffic_sleep, if cover_traffic => {
                let delay_secs = next_cover_traffic_delay().as_secs();
                tracing::debug!("sending cover traffic, next in ~{} seconds", delay_secs);
                gossip::send_cover_traffic(&mut swarm, chain_id);
                cover_traffic_sleep.set(tokio::time::sleep(next_cover_traffic_delay()));
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Ok(command) => {
                        tracing::info!("network event loop: received command from cmd_rx (queue len: {})", cmd_rx.len());
                        apply_command(&mut swarm, command, chain_id, &evt_tx).await
                    },
                    Err(e) => {
                        tracing::warn!("cmd_rx closed: {:?}, exiting loop", e);
                        break
                    },
                }
            }
            swarm_event = swarm.select_next_some() => {
                if handle_swarm_event(&mut swarm, swarm_event, &evt_tx).await.is_err() {
                    // Best-effort logging, do not crash the loop.
                }
            }
        }
    }
}

/// Check if a multiaddress contains a public (non-private) IP address.
/// Returns false for localhost, private networks (10.x, 172.16-31.x, 192.168.x), and link-local addresses.
fn is_public_addr(addr: &Multiaddr) -> bool {
    for component in addr.iter() {
        match component {
            Protocol::Ip4(ip) => {
                // Reject localhost
                if ip.is_loopback() {
                    return false;
                }
                // Reject private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
                if ip.is_private() {
                    return false;
                }
                // Reject link-local (169.254.0.0/16)
                if ip.octets()[0] == 169 && ip.octets()[1] == 254 {
                    return false;
                }
                return true;
            }
            Protocol::Ip6(ip) => {
                // Reject localhost (::1)
                if ip.is_loopback() {
                    return false;
                }
                // Reject unique local addresses (fc00::/7)
                if (ip.segments()[0] & 0xfe00) == 0xfc00 {
                    return false;
                }
                // Reject link-local addresses (fe80::/10)
                if (ip.segments()[0] & 0xffc0) == 0xfe80 {
                    return false;
                }
                // Reject multicast addresses (ff00::/8)
                if ip.is_multicast() {
                    return false;
                }
                return true;
            }
            _ => continue,
        }
    }
    // If no IP found, consider it non-public
    false
}

/// Handle swarm events and emit network events.
async fn handle_swarm_event(
    swarm: &mut Swarm<Behaviour>,
    event: SwarmEvent<behaviour::BehaviourEvent>,
    evt_tx: &Sender<NetworkEvent>,
) -> Result<(), NetError> {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            send_event_with_timeout(evt_tx, NetworkEvent::NewListen(address)).await;
        }
        SwarmEvent::Behaviour(behaviour_event) => match behaviour_event {
            behaviour::BehaviourEvent::Ping(ping::Event {
                peer,
                connection,
                result,
            }) => {
                if result.is_ok() {
                    info!("ping ok from {peer} on connection {connection:?}");
                    send_event_with_timeout(evt_tx, NetworkEvent::PeerConnected(peer)).await;
                }
            }
            behaviour::BehaviourEvent::Gossipsub(ev) => {
                if let libp2p::gossipsub::Event::Message {
                    propagation_source,
                    message,
                    ..
                } = ev
                {
                    gossip::handle_gossip_message(propagation_source, &message.data, evt_tx).await;
                }
            }
            behaviour::BehaviourEvent::Kad(kad_event) => {
                kad::handle_kad_event(kad_event, evt_tx).await;
            }
            behaviour::BehaviourEvent::RequestResponse(event) => match event {
                request_response::Event::Message { peer, message } => match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        let _ = evt_tx
                            .send(NetworkEvent::Request {
                                peer,
                                req: request,
                                channel,
                            })
                            .await;
                    }
                    request_response::Message::Response { response, .. } => {
                        let _ = evt_tx
                            .send(NetworkEvent::Response {
                                peer,
                                resp: response,
                            })
                            .await;
                    }
                },
                request_response::Event::OutboundFailure { peer, error, .. } => {
                    tracing::warn!("request failed for {peer:?}: {error}");
                }
                request_response::Event::InboundFailure { peer, error, .. } => {
                    tracing::warn!("inbound request failed for {peer:?}: {error}");
                }
                request_response::Event::ResponseSent { peer, .. } => {
                    tracing::debug!("response sent to {peer:?}");
                }
            },
            behaviour::BehaviourEvent::Identify(identify_event) => {
                if let identify::Event::Received { peer_id, info, .. } = identify_event {
                    info!(
                        "identify: received from {peer_id}, listen addrs: {}",
                        info.listen_addrs.len()
                    );
                    for addr in &info.listen_addrs {
                        info!("identify: peer {peer_id} listening on {addr}");

                        // Add address to Kademlia DHT for routing
                        swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                    }

                    // Automatically dial discovered peers if not already connected
                    // Only dial public addresses to avoid connecting to private/internal IPs
                    for addr in info.listen_addrs {
                        if !is_public_addr(&addr) {
                            tracing::debug!("identify: skipping private address {addr} for peer {peer_id}");
                            continue;
                        }

                        let full_addr = addr.with(libp2p::multiaddr::Protocol::P2p(peer_id));
                        if !swarm.is_connected(&peer_id) {
                            info!("identify: auto-dialing discovered peer at {full_addr}");
                            if let Err(err) = swarm.dial(full_addr.clone()) {
                                tracing::warn!("identify: failed to auto-dial {full_addr}: {err:?}");
                            }
                        }
                    }
                }
            }
        },
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            send_event_with_timeout(evt_tx, NetworkEvent::PeerDisconnected(peer_id)).await;
        }
        other => {
            tracing::trace!("unhandled swarm event: {:?}", other);
        }
    }
    Ok(())
}

/// Apply a network command to the swarm.
async fn apply_command(
    swarm: &mut Swarm<Behaviour>,
    command: NetworkCommand,
    chain_id: [u8; 4],
    evt_tx: &async_channel::Sender<NetworkEvent>,
) {
    match command {
        NetworkCommand::Dial(addr) => {
            if let Err(err) = Swarm::dial(swarm, addr.clone()) {
                tracing::warn!("dial error {addr}: {err:?}");
            }
        }
        NetworkCommand::PublishTx { txid } => {
            gossip::publish_tx(swarm, chain_id, txid);
        }
        NetworkCommand::PublishFullTx { tx } => {
            gossip::publish_full_tx(swarm, chain_id, tx);
        }
        NetworkCommand::PublishBlock { header } => {
            gossip::publish_block(swarm, header);
        }
        NetworkCommand::PublishFullBlock { block } => {
            tracing::info!("network thread: received PublishFullBlock command for height {}", block.header.height);
            if !gossip::publish_full_block(swarm, block) {
                send_event_with_timeout(
                    evt_tx,
                    NetworkEvent::BroadcastFailed {
                        reason: "No peers connected to broadcast block".to_string(),
                    },
                )
                .await;
            }
        }
        NetworkCommand::SendRequest { peer, req } => {
            swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer, req);
        }
        NetworkCommand::SendResponse { channel, resp } => {
            let _ = swarm
                .behaviour_mut()
                .request_response
                .send_response(channel, resp);
        }
    }
}

async fn send_event_with_timeout(
    evt_tx: &async_channel::Sender<NetworkEvent>,
    event: NetworkEvent,
) {
    let timeout = Duration::from_millis(200);
    match tokio::time::timeout(timeout, evt_tx.send(event)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::warn!("failed to send network event: {err:?}");
        }
        Err(_) => {
            tracing::warn!("dropping network event after 200ms send timeout");
        }
    }
}

/// Build a block inventory message from a block header.
pub fn build_inv_block(header: &BlockHeader) -> protocol::GossipMsg {
    protocol::GossipMsg::InvBlock {
        header: header.clone(),
    }
}

/// Get the block ID from a block header.
pub fn inv_block_id(header: &BlockHeader) -> Hash32 {
    block_header_id(header)
}
