use async_trait::async_trait;
use bcr_ebill_core::{
    ServiceTraitBounds, blockchain::bill::block::NodeId, contact::BillParticipant,
};
use log::info;

#[cfg(test)]
use mockall::automock;
use nostr::{nips::nip01::Metadata, types::RelayUrl};

use crate::{Result, event::EventEnvelope};

#[cfg(test)]
impl ServiceTraitBounds for MockNotificationJsonTransportApi {}

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait NotificationJsonTransportApi: ServiceTraitBounds {
    /// Returns the senders public key for this instance.
    fn get_sender_key(&self) -> String;
    /// Sends a json event to the given recipient.
    async fn send(&self, recipient: &BillParticipant, event: EventEnvelope) -> Result<()>;
    /// Resolves a nostr contact by node id.
    async fn resolve_contact(&self, node_id: &str) -> Result<Option<NostrContactData>>;
}

/// A dummy transport that logs all events that are sent as json.
pub struct LoggingNotificationJsonTransport;

impl ServiceTraitBounds for LoggingNotificationJsonTransport {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationJsonTransportApi for LoggingNotificationJsonTransport {
    fn get_sender_key(&self) -> String {
        "logging_key".to_string()
    }
    async fn send(&self, recipient: &BillParticipant, event: EventEnvelope) -> Result<()> {
        info!(
            "Sending json event: {:?}({}) with payload: {:?} to peer: {}",
            event.event_type,
            event.version,
            event.data,
            recipient.node_id()
        );
        Ok(())
    }

    async fn resolve_contact(&self, _node_id: &str) -> Result<Option<NostrContactData>> {
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct NostrContactData {
    pub metadata: Metadata,
    pub relays: Vec<RelayUrl>,
}
