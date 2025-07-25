use std::sync::Arc;

use async_trait::async_trait;
use bcr_ebill_core::{
    NodeId, ServiceTraitBounds,
    nostr_contact::{HandshakeStatus, NostrContact, TrustLevel},
};
use bcr_ebill_persistence::nostr::NostrContactStoreApi;
use log::{error, info, warn};

use crate::NotificationJsonTransportApi;

use super::NostrContactProcessorApi;

pub struct NostrContactProcessor {
    transport: Arc<dyn NotificationJsonTransportApi>,
    nostr_contact_store: Arc<dyn NostrContactStoreApi>,
    bitcoin_network: bitcoin::Network,
}

impl NostrContactProcessor {
    pub fn new(
        transport: Arc<dyn NotificationJsonTransportApi>,
        nostr_contact_store: Arc<dyn NostrContactStoreApi>,
        bitcoin_network: bitcoin::Network,
    ) -> Self {
        Self {
            transport,
            nostr_contact_store,
            bitcoin_network,
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NostrContactProcessorApi for NostrContactProcessor {
    async fn ensure_nostr_contact(&self, node_id: &NodeId) {
        // check that the given node id is from the configured network
        if node_id.network() != self.bitcoin_network {
            warn!("Tried to ensure nostr contact for a different network {node_id}");
            return;
        }

        // we already have the contact in the store, no need to resolve it
        if let Ok(Some(_)) = self.nostr_contact_store.by_node_id(node_id).await {
            return;
        }
        // Let's try to get some details and add the contact
        if let Ok(Some(contact)) = self.transport.resolve_contact(node_id).await {
            let relays = contact
                .relays
                .iter()
                .map(|r| r.as_str().to_owned())
                .collect();
            self.upsert_contact(
                node_id,
                &NostrContact {
                    npub: node_id.npub(),
                    name: contact.metadata.name,
                    relays,
                    trust_level: TrustLevel::Participant,
                    handshake_status: HandshakeStatus::None,
                },
            )
            .await;
        } else {
            info!("Could not resolve nostr contact information for node_id {node_id}");
        }
    }
}

impl NostrContactProcessor {
    async fn upsert_contact(&self, node_id: &NodeId, contact: &NostrContact) {
        if let Err(e) = self.nostr_contact_store.upsert(contact).await {
            error!("Failed to save nostr contact information for node_id {node_id}: {e}");
        } else if let Err(e) = self.transport.add_contact_subscription(node_id).await {
            error!("Failed to add nostr contact subscription for contact node_id {node_id}: {e}");
        }
    }
}

impl ServiceTraitBounds for NostrContactProcessor {}
