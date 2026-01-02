//! Kademlia DHT event handling for peer discovery.

use libp2p::kad;
use tracing::info;

use crate::NetworkEvent;

async fn send_event_with_timeout(
    evt_tx: &async_channel::Sender<NetworkEvent>,
    event: NetworkEvent,
) {
    let timeout = std::time::Duration::from_millis(200);
    match tokio::time::timeout(timeout, evt_tx.send(event)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::warn!("failed to send kad event: {err:?}");
        }
        Err(_) => {
            tracing::warn!("dropping kad event after 200ms send timeout");
        }
    }
}

/// Handle a Kademlia DHT event and emit network events for peer discovery.
pub async fn handle_kad_event(kad_event: kad::Event, evt_tx: &async_channel::Sender<NetworkEvent>) {
    match kad_event {
        kad::Event::RoutingUpdated { peer, .. } => {
            info!("kad: routing updated with peer {peer}");
            send_event_with_timeout(evt_tx, NetworkEvent::PeerConnected(peer)).await;
        }
        kad::Event::OutboundQueryProgressed { result, .. } => match result {
            kad::QueryResult::GetClosestPeers(Ok(ok)) => {
                info!(
                    "kad: discovered {} peers via GetClosestPeers",
                    ok.peers.len()
                );
                for peer_info in ok.peers {
                    send_event_with_timeout(evt_tx, NetworkEvent::PeerConnected(peer_info.peer_id)).await;
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
