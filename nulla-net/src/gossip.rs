//! Gossipsub message handling and publishing.

use libp2p::{gossipsub, PeerId, Swarm};
use tracing::info;

use nulla_core::{Block, BlockHeader, Hash32, Tx};

use crate::{behaviour::Behaviour, protocol};

/// Publish a transaction inventory announcement to the network.
pub fn publish_tx(swarm: &mut Swarm<Behaviour>, chain_id: [u8; 4], txid: Hash32) {
    let msg = protocol::GossipMsg::InvTx { txid };
    if let Ok(data) = postcard::to_allocvec(&msg) {
        let topic = gossipsub::IdentTopic::new(protocol::topic_inv_tx(&chain_id));
        let _ = swarm.behaviour_mut().gossipsub.publish(topic, data);
    }
}

/// Publish a full transaction to the network (includes transaction data).
pub fn publish_full_tx(swarm: &mut Swarm<Behaviour>, chain_id: [u8; 4], tx: Tx) {
    let msg = protocol::GossipMsg::FullTx { tx };
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

/// Publish a full block to the network (includes all transactions).
/// Returns true if the block was published successfully, false otherwise.
pub fn publish_full_block(swarm: &mut Swarm<Behaviour>, block: Block) -> bool {
    tracing::info!("publish_full_block called for height {}", block.header.height);
    let peer_count = swarm.connected_peers().count();
    tracing::info!("connected peers: {}", peer_count);

    if peer_count == 0 {
        tracing::warn!("cannot publish block: no peers connected");
        return false;
    }

    let msg = protocol::GossipMsg::FullBlock {
        block: block.clone(),
    };
    tracing::info!("attempting to serialize block height {} for gossipsub", block.header.height);
    if let Ok(data) = postcard::to_allocvec(&msg) {
        tracing::info!("serialized block height {} successfully, size={} bytes", block.header.height, data.len());
        let topic = gossipsub::IdentTopic::new(protocol::topic_inv_block(&block.header.chain_id));
        tracing::info!("publishing to topic: {}", topic);

        // Get mesh peers for this topic to diagnose mesh formation (collect count before mutable borrow)
        let mesh_peer_count = swarm.behaviour().gossipsub.mesh_peers(&topic.hash()).count();
        tracing::info!("mesh peers for topic {}: {} peers in mesh", topic, mesh_peer_count);

        let result = swarm.behaviour_mut().gossipsub.publish(topic.clone(), data);
        match &result {
            Ok(msg_id) => tracing::info!(
                "✓ published block height={} to gossipsub topic {} ({} connected peers, {} mesh peers, msg_id={:?})",
                block.header.height, topic, peer_count, mesh_peer_count, msg_id
            ),
            Err(e) => tracing::error!(
                "✗ FAILED to publish block height={} to gossipsub topic {}: {:?} ({} connected peers, {} mesh peers)",
                block.header.height, topic, e, peer_count, mesh_peer_count
            ),
        }
        result.is_ok()
    } else {
        tracing::warn!("failed to serialize block for gossipsub");
        false
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
                send_event_with_timeout(
                    evt_tx,
                    crate::NetworkEvent::TxInv {
                        from: propagation_source,
                        txid,
                    },
                )
                .await;
            }
            protocol::GossipMsg::FullTx { tx } => {
                send_event_with_timeout(
                    evt_tx,
                    crate::NetworkEvent::FullTx {
                        from: propagation_source,
                        tx,
                    },
                )
                .await;
            }
            protocol::GossipMsg::InvBlock { header } => {
                send_event_with_timeout(
                    evt_tx,
                    crate::NetworkEvent::BlockInv {
                        from: propagation_source,
                        header,
                    },
                )
                .await;
            }
            protocol::GossipMsg::FullBlock { block } => {
                send_event_with_timeout(
                    evt_tx,
                    crate::NetworkEvent::FullBlock {
                        from: propagation_source,
                        block,
                    },
                )
                .await;
            }
            protocol::GossipMsg::Noise { .. } => {
                // Ignore cover traffic noise messages.
            }
        }
    }
}

async fn send_event_with_timeout(
    evt_tx: &async_channel::Sender<crate::NetworkEvent>,
    event: crate::NetworkEvent,
) {
    let timeout = std::time::Duration::from_millis(200);
    match tokio::time::timeout(timeout, evt_tx.send(event)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::warn!("failed to send gossip event: {err:?}");
        }
        Err(_) => {
            tracing::warn!("dropping gossip event after 200ms send timeout");
        }
    }
}
