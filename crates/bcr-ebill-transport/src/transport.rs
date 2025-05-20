use async_trait::async_trait;
use bcr_ebill_core::{
    ServiceTraitBounds,
    blockchain::{BlockchainType, bill::block::NodeId},
    contact::BillParticipant,
    util::BcrKeys,
};
use log::info;

#[cfg(test)]
use mockall::automock;

use nostr::{
    event::{Tag, TagStandard},
    nips::{nip01::Metadata, nip73::ExternalContentId},
    types::RelayUrl,
};

use crate::{Result, event::EventEnvelope};

#[cfg(test)]
impl ServiceTraitBounds for MockNotificationJsonTransportApi {}

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait NotificationJsonTransportApi: ServiceTraitBounds {
    /// Returns the senders public key for this instance.
    fn get_sender_key(&self) -> String;
    /// Sends a private json event to the given recipient.
    async fn send_private_event(
        &self,
        recipient: &BillParticipant,
        event: EventEnvelope,
    ) -> Result<()>;
    /// Sends a public json chain event to our Nostr relays. The id is the chain id
    /// eg. bill_id or company_id etc. The id will be published as a tag on the Nostr
    /// event.
    async fn send_public_chain_event(
        &self,
        id: &str,
        blockchain: BlockchainType,
        keys: BcrKeys,
        event: EventEnvelope,
    ) -> Result<()>;
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
    async fn send_private_event(
        &self,
        recipient: &BillParticipant,
        event: EventEnvelope,
    ) -> Result<()> {
        info!(
            "Sending json event: {:?}({}) with payload: {:?} to peer: {}",
            event.event_type,
            event.version,
            event.data,
            recipient.node_id()
        );
        Ok(())
    }

    async fn send_public_chain_event(
        &self,
        id: &str,
        blockchain: BlockchainType,
        _keys: BcrKeys,
        event: EventEnvelope,
    ) -> Result<()> {
        info!(
            "Sending public {} chain json event: {:?}({}) with id {} and payload: {:?}",
            blockchain, event.event_type, event.version, id, event.data
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

pub fn bcr_nostr_tag(id: &str, blockchain: BlockchainType) -> Tag {
    TagStandard::ExternalContent {
        content: ExternalContentId::BlockchainAddress {
            chain: "bitcredit".to_string(),
            address: id.to_string(),
            chain_id: Some(blockchain.to_string()),
        },
        hint: None,
        uppercase: false,
    }
    .into()
}
