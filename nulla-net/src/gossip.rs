//! Gossipsub message handling and publishing.

use libp2p::{gossipsub, PeerId, Swarm};
use tracing::info;

use nulla_core::{BlockHeader, Hash32};

use crate::{behaviour::Behaviour, protocol};

/// Publish a transaction inventory announcement to the network.
pub fn publish_tx(swarm: &mut Swarm<Behaviour>, chain_id: [u8; 4], txid: Hash32) {
    let msg = protocol::GossipMsg::InvTx { txid };
    if let Ok(data) = postcard::to_allocvec(&msg) {
        let topic = gossipsub::IdentTopic::new(protocol::topic_inv_tx(&chain_id));
        let _ = swarm.behaviour_mut().gossipsub.publish(topic, data);
    }
}

/// Publish a block inventory announcement to the network.
pub fn publish_block(swarm: &mut Swarm<Behaviour>, header: BlockHeader) {
    let msg = protocol::GossipMsg::InvBlock {
        header: header.clone(),
    };
    if let Ok(data) = postcard::to_allocvec(&msg) {
        let topic = gossipsub::IdentTopic::new(protocol::topic_inv_block(&header.chain_id));
        let _ = swarm.behaviour_mut().gossipsub.publish(topic, data);
    }
}

/// Send a cover traffic noise message to the network.
pub fn send_cover_traffic(swarm: &mut Swarm<Behaviour>, chain_id: [u8; 4]) {
    let noise_bytes: [u8; 32] = rand::random();
    let msg = protocol::GossipMsg::Noise { bytes: noise_bytes };
    if let Ok(data) = postcard::to_allocvec(&msg) {
        let topic = gossipsub::IdentTopic::new(protocol::topic_inv_tx(&chain_id));
        let _ = swarm.behaviour_mut().gossipsub.publish(topic, data);
        info!("sent cover traffic noise message");
    }
}

/// Handle an incoming gossipsub message.
pub async fn handle_gossip_message(
    propagation_source: PeerId,
    data: &[u8],
    evt_tx: &async_channel::Sender<crate::NetworkEvent>,
) {
    if let Ok(msg) = postcard::from_bytes::<protocol::GossipMsg>(data) {
        match msg {
            protocol::GossipMsg::InvTx { txid } => {
                let _ = evt_tx
                    .send(crate::NetworkEvent::TxInv {
                        from: propagation_source,
                        txid,
                    })
                    .await;
            }
            protocol::GossipMsg::InvBlock { header } => {
                let _ = evt_tx
                    .send(crate::NetworkEvent::BlockInv {
                        from: propagation_source,
                        header,
                    })
                    .await;
            }
            protocol::GossipMsg::Noise { .. } => {
                // Ignore cover traffic noise messages.
            }
        }
    }
}
