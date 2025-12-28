//! Kademlia DHT event handling for peer discovery.

use libp2p::kad;
use tracing::info;

use crate::NetworkEvent;

/// Handle a Kademlia DHT event and emit network events for peer discovery.
pub async fn handle_kad_event(kad_event: kad::Event, evt_tx: &async_channel::Sender<NetworkEvent>) {
    match kad_event {
        kad::Event::RoutingUpdated { peer, .. } => {
            info!("kad: routing updated with peer {peer}");
            let _ = evt_tx.send(NetworkEvent::PeerConnected(peer)).await;
        }
        kad::Event::OutboundQueryProgressed { result, .. } => match result {
            kad::QueryResult::GetClosestPeers(Ok(ok)) => {
                info!(
                    "kad: discovered {} peers via GetClosestPeers",
                    ok.peers.len()
                );
                for peer_info in ok.peers {
                    let _ = evt_tx
                        .send(NetworkEvent::PeerConnected(peer_info.peer_id))
                        .await;
                }
            }
            kad::QueryResult::Bootstrap(Ok(ok)) => {
                info!(
                    "kad: bootstrap succeeded, {} peers in routing table",
                    ok.num_remaining
                );
            }
            _ => {}
        },
        _ => {}
    }
}
