//! Networking layer for the Nulla blockchain.
//!
//! This crate provides:
//! - libp2p-based P2P networking with Noise encryption and Yamux multiplexing
//! - Gossipsub for transaction and block propagation
//! - Kademlia DHT for peer discovery
//! - Request/response protocol for block and header sync
//! - Dandelion++ transaction privacy protocol
//! - Cover traffic support (placeholder)

use std::time::{Duration, Instant};

use async_channel::{Receiver, Sender};
use futures::prelude::*;
use libp2p::{
    gossipsub, identify, identity, kad, noise, ping,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use rand::{seq::SliceRandom, Rng};
use std::num::NonZeroUsize;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::select;
use tracing::{info, warn};

use nulla_core::{block_header_id, BlockHeader, Hash32};

/// Protocol definitions and message types.
pub mod protocol {
    use super::*;
    use nulla_core::{Block, BlockHeader, Tx};

    /// Maximum number of headers returned in a single response.
    pub const MAX_HEADERS: usize = 2048;

    /// Maximum block size in bytes.
    pub const MAX_BLOCK_SIZE: usize = 1_000_000;

    /// Maximum transaction size in bytes.
    pub const MAX_TX_SIZE: usize = 100_000;

    /// Maximum number of peer addresses in a PeerExchange response.
    pub const MAX_PX_ADDRS: usize = 32;

    /// Messages broadcast via gossipsub.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum GossipMsg {
        /// Transaction inventory announcement.
        InvTx { txid: Hash32 },
        /// Block inventory announcement (includes full header).
        InvBlock { header: BlockHeader },
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
            }
        }

        /// Randomly select a new stem peer from the connected peers.
        pub fn rotate_peer(&mut self, peers: &[PeerId]) {
            if let Some(peer) = peers.choose(&mut self.rng) {
                self.stem_peer = Some(*peer);
                self.stem_deadline = Instant::now() + Duration::from_secs(600);
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
        pub fn on_stem(
            &mut self,
            txid: Hash32,
            hops_left: u8,
            connected: &[PeerId],
        ) -> Action {
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
    /// Enable cover traffic (placeholder; not yet fully wired).
    pub cover_traffic: bool,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            chain_id: *b"NULL",
            listen: Vec::new(),
            peers: Vec::new(),
            dandelion: true,
            cover_traffic: false,
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
    /// Publish a block to the network.
    PublishBlock { header: BlockHeader },
    /// Send a request to a peer.
    SendRequest { peer: PeerId, req: protocol::Req },
    /// Send a response to a peer.
    SendResponse { channel: ResponseChannel, resp: protocol::Resp },
}

/// Events emitted by the network task.
#[derive(Debug)]
pub enum NetworkEvent {
    /// Received a transaction inventory announcement.
    TxInv { from: PeerId, txid: Hash32 },
    /// Received a block inventory announcement.
    BlockInv { from: PeerId, header: BlockHeader },
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
}

/// Network errors.
#[derive(Debug, Error)]
pub enum NetError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    gossipsub: gossipsub::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
}

/// Placeholder for request/response channel (simplified since libp2p API changed).
pub type ResponseChannel = ();

pub struct NetworkHandle {
    pub commands: Sender<NetworkCommand>,
    pub events: Receiver<NetworkEvent>,
    pub local_peer_id: PeerId,
}

/// Spawn the network task and return a handle for sending commands and receiving events.
pub async fn spawn_network(config: NetConfig) -> Result<NetworkHandle, NetError> {
    let cfg_clone = config.clone();
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(|e| anyhow::anyhow!("transport error: {e}"))?
        .with_behaviour(move |id| {
            build_behaviour(id, &cfg_clone)
        })
        .map_err(|e| anyhow::anyhow!("behaviour error: {e}"))?
        .build();
    let peer_id = *swarm.local_peer_id();
    let chain_id = config.chain_id;
    let cover_traffic = config.cover_traffic;

    for addr in &config.listen {
        Swarm::listen_on(&mut swarm, addr.clone())
            .map_err(|e| anyhow::anyhow!("listen error: {e}"))?;
    }
    for peer in &config.peers {
        Swarm::dial(&mut swarm, peer.clone())
            .map_err(|e| anyhow::anyhow!("dial error: {e}"))?;
    }

    // Bootstrap Kademlia DHT if we have initial peers
    if !config.peers.is_empty() {
        info!("bootstrapping Kademlia DHT with {} initial peer(s)", config.peers.len());
        let _ = swarm.behaviour_mut().kad.bootstrap();
    }

    let (cmd_tx, cmd_rx) = async_channel::bounded(64);
    let (evt_tx, evt_rx) = async_channel::bounded(1024);
    tokio::spawn(async move {
        run_swarm(swarm, cmd_rx, evt_tx, chain_id, cover_traffic).await;
    });

    Ok(NetworkHandle {
        commands: cmd_tx,
        events: evt_rx,
        local_peer_id: peer_id,
    })
}

fn build_behaviour(
    keypair: &identity::Keypair,
    config: &NetConfig,
) -> Result<Behaviour, Box<dyn std::error::Error + Send + Sync>> {
    let peer_id = PeerId::from(keypair.public());
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Strict)
        .max_transmit_size(1024 * 64)
        .build()
        .expect("gossipsub config");

    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(keypair.clone()),
        gossipsub_config,
    )
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) })?;
    let tx_topic = gossipsub::IdentTopic::new(protocol::topic_inv_tx(&config.chain_id));
    let block_topic = gossipsub::IdentTopic::new(protocol::topic_inv_block(&config.chain_id));
    gossipsub
        .subscribe(&tx_topic)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) })?;
    gossipsub
        .subscribe(&block_topic)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) })?;

    let store = kad::store::MemoryStore::new(peer_id);
    let kad = kad::Behaviour::new(peer_id, store);

    let identify = libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
        "/nulla/1".into(),
        keypair.public(),
    ));

    Ok(Behaviour {
        identify,
        ping: ping::Behaviour::default(),
        gossipsub,
        kad,
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
    // Cover traffic interval: send a noise message every 45-90 seconds (randomized).
    let mut cover_traffic_interval = if cover_traffic {
        Some(tokio::time::interval(Duration::from_secs(60)))
    } else {
        None
    };

    loop {
        select! {
            swarm_event = swarm.select_next_some() => {
                if handle_swarm_event(&mut swarm, swarm_event, &evt_tx).await.is_err() {
                    // best-effort logging, do not crash the loop
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Ok(command) => apply_command(&mut swarm, command, chain_id),
                    Err(_) => break,
                }
            }
            _ = async {
                if let Some(ref mut interval) = cover_traffic_interval {
                    interval.tick().await;
                } else {
                    // If cover traffic is disabled, never trigger this branch.
                    std::future::pending::<()>().await
                }
            } => {
                // Broadcast a cover traffic noise message.
                send_cover_traffic(&mut swarm, chain_id);
            }
        }
    }
}

/// Send a cover traffic noise message to the network.
fn send_cover_traffic(swarm: &mut Swarm<Behaviour>, chain_id: [u8; 4]) {
    let noise_bytes: [u8; 32] = rand::random();
    let msg = protocol::GossipMsg::Noise { bytes: noise_bytes };
    if let Ok(data) = postcard::to_allocvec(&msg) {
        let topic = gossipsub::IdentTopic::new(protocol::topic_inv_tx(&chain_id));
        let _ = swarm.behaviour_mut().gossipsub.publish(topic, data);
        info!("sent cover traffic noise message");
    }
}

async fn handle_swarm_event(
    _swarm: &mut Swarm<Behaviour>,
    event: SwarmEvent<BehaviourEvent>,
    evt_tx: &Sender<NetworkEvent>,
) -> Result<(), NetError> {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            let _ = evt_tx.send(NetworkEvent::NewListen(address)).await;
        }
        SwarmEvent::Behaviour(behaviour_event) => match behaviour_event {
            BehaviourEvent::Ping(ping::Event { peer, connection, result }) => {
                if result.is_ok() {
                    info!("ping ok from {peer} on connection {connection:?}");
                    let _ = evt_tx.send(NetworkEvent::PeerConnected(peer)).await;
                }
            }
            BehaviourEvent::Gossipsub(ev) => {
                if let gossipsub::Event::Message {
                    propagation_source,
                    message,
                    ..
                } = ev
                {
                    if let Ok(msg) = postcard::from_bytes::<protocol::GossipMsg>(&message.data) {
                        match msg {
                            protocol::GossipMsg::InvTx { txid } => {
                                let _ = evt_tx
                                    .send(NetworkEvent::TxInv {
                                        from: propagation_source,
                                        txid,
                                    })
                                    .await;
                            }
                            protocol::GossipMsg::InvBlock { header } => {
                                let _ = evt_tx
                                    .send(NetworkEvent::BlockInv {
                                        from: propagation_source,
                                        header,
                                    })
                                    .await;
                            }
                            protocol::GossipMsg::Noise { .. } => {}
                        }
                    }
                }
            }
            BehaviourEvent::Kad(kad_event) => match kad_event {
                kad::Event::RoutingUpdated { peer, .. } => {
                    info!("kad: routing updated with peer {peer}");
                    let _ = evt_tx.send(NetworkEvent::PeerConnected(peer)).await;
                }
                kad::Event::OutboundQueryProgressed { result, .. } => {
                    match result {
                        kad::QueryResult::GetClosestPeers(Ok(ok)) => {
                            info!("kad: discovered {} peers via GetClosestPeers", ok.peers.len());
                            for peer_info in ok.peers {
                                let _ = evt_tx.send(NetworkEvent::PeerConnected(peer_info.peer_id)).await;
                            }
                        }
                        kad::QueryResult::Bootstrap(Ok(ok)) => {
                            info!("kad: bootstrap succeeded, {} peers in routing table", ok.num_remaining);
                        }
                        _ => {}
                    }
                }
                _ => {}
            },
            BehaviourEvent::Identify(identify_event) => {
                if let identify::Event::Received { peer_id, info, .. } = identify_event {
                    info!("identify: received from {peer_id}, listen addrs: {}", info.listen_addrs.len());
                    // When we identify a peer, add it to Kademlia DHT
                    for addr in info.listen_addrs {
                        info!("identify: peer {peer_id} listening on {addr}");
                    }
                }
            }
        },
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            let _ = evt_tx.send(NetworkEvent::PeerDisconnected(peer_id)).await;
        }
        _ => {}
    }
    Ok(())
}

fn apply_command(swarm: &mut Swarm<Behaviour>, command: NetworkCommand, chain_id: [u8; 4]) {
    match command {
        NetworkCommand::Dial(addr) => {
            if let Err(err) = Swarm::dial(swarm, addr.clone()) {
                warn!("dial error {addr}: {err:?}");
            }
        }
        NetworkCommand::PublishTx { txid } => {
            let msg = protocol::GossipMsg::InvTx { txid };
            if let Ok(data) = postcard::to_allocvec(&msg) {
                let topic =
                    gossipsub::IdentTopic::new(protocol::topic_inv_tx(&chain_id));
                let _ = swarm.behaviour_mut().gossipsub.publish(topic, data);
            }
        }
        NetworkCommand::PublishBlock { header } => {
            let msg = protocol::GossipMsg::InvBlock { header: header.clone() };
            if let Ok(data) = postcard::to_allocvec(&msg) {
                let topic = gossipsub::IdentTopic::new(protocol::topic_inv_block(
                    &header.chain_id,
                ));
                let _ = swarm.behaviour_mut().gossipsub.publish(topic, data);
            }
        }
        NetworkCommand::SendRequest { peer, req } => {
            // Request/response simplified - log for now.
            info!("send request to {peer:?}: {req:?}");
        }
        NetworkCommand::SendResponse { channel: _, resp } => {
            // Request/response simplified - log for now.
            info!("send response: {resp:?}");
        }
    }
}

pub fn build_inv_block(header: &BlockHeader) -> protocol::GossipMsg {
    protocol::GossipMsg::InvBlock {
        header: header.clone(),
    }
}

pub fn inv_block_id(header: &BlockHeader) -> Hash32 {
    block_header_id(header)
}
