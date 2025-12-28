//! libp2p NetworkBehaviour composition and configuration.

use libp2p::{
    gossipsub, identify, identity, kad, ping, request_response, swarm::NetworkBehaviour, PeerId,
};
use libp2p_swarm::StreamProtocol;
use std::io;

use crate::{protocol, reqresp};

/// Composite network behaviour combining all protocols.
#[derive(NetworkBehaviour)]
pub struct Behaviour {
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub gossipsub: gossipsub::Behaviour,
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    pub request_response: request_response::Behaviour<reqresp::NullaCodec>,
}

/// Build the network behaviour with all required protocols.
pub fn build_behaviour(
    keypair: &identity::Keypair,
    chain_id: &[u8; 4],
) -> Result<Behaviour, Box<dyn std::error::Error + Send + Sync>> {
    let peer_id = PeerId::from(keypair.public());

    // Configure gossipsub for reliable message propagation.
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Strict)
        .max_transmit_size(1024 * 64)
        .build()
        .expect("gossipsub config");

    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(keypair.clone()),
        gossipsub_config,
    )
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
        Box::new(io::Error::new(io::ErrorKind::Other, e))
    })?;

    // Subscribe to transaction and block topics.
    let tx_topic = gossipsub::IdentTopic::new(protocol::topic_inv_tx(chain_id));
    let block_topic = gossipsub::IdentTopic::new(protocol::topic_inv_block(chain_id));
    gossipsub
        .subscribe(&tx_topic)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            Box::new(io::Error::new(io::ErrorKind::Other, e))
        })?;
    gossipsub
        .subscribe(&block_topic)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            Box::new(io::Error::new(io::ErrorKind::Other, e))
        })?;

    // Configure Kademlia DHT for peer discovery.
    let store = kad::store::MemoryStore::new(peer_id);
    let kad = kad::Behaviour::new(peer_id, store);

    // Configure Identify protocol for peer information exchange.
    let identify =
        identify::Behaviour::new(identify::Config::new("/nulla/1".into(), keypair.public()));

    let protocols = std::iter::once((
        StreamProtocol::new(reqresp::PROTOCOL_NAME),
        request_response::ProtocolSupport::Full,
    ));
    let request_response =
        request_response::Behaviour::new(protocols, request_response::Config::default());

    Ok(Behaviour {
        identify,
        ping: ping::Behaviour::default(),
        gossipsub,
        kad,
        request_response,
    })
}
