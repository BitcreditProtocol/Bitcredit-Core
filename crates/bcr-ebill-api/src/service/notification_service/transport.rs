use async_trait::async_trait;
use bcr_ebill_core::{
    NodeId, ServiceTraitBounds, blockchain::BlockchainType, contact::BillParticipant, util::BcrKeys,
};

#[cfg(test)]
use mockall::automock;

use nostr::Event;

use super::{NostrContactData, Result, event::EventEnvelope};

#[cfg(test)]
impl ServiceTraitBounds for MockNotificationJsonTransportApi {}

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait NotificationJsonTransportApi: ServiceTraitBounds {
    /// Returns the senders node id for this instance.
    fn get_sender_node_id(&self) -> NodeId;
    /// Sends a private json event to the given recipient.
    async fn send_private_event(
        &self,
        recipient: &BillParticipant,
        event: EventEnvelope,
    ) -> Result<()>;
    /// Sends a public json chain event to our Nostr relays. The id is the chain id
    /// eg. bill_id or company_id etc. The id will be published as a tag on the Nostr
    /// event. This will return the sent event so we can add it to the local store.
    async fn send_public_chain_event(
        &self,
        id: &str,
        blockchain: BlockchainType,
        block_time: u64,
        keys: BcrKeys,
        event: EventEnvelope,
        previous_event: Option<Event>,
        root_event: Option<Event>,
    ) -> Result<Event>;
    /// Resolves a nostr contact by node id.
    async fn resolve_contact(&self, node_id: &NodeId) -> Result<Option<NostrContactData>>;
    /// Given an id and chain type, tries to resolve the public chain events.
    async fn resolve_public_chain(
        &self,
        id: &str,
        chain_type: BlockchainType,
    ) -> Result<Vec<Event>>;
    /// Adds a new Nostr subscription on the primary client for an added contact
    async fn add_contact_subscription(&self, contact: &NodeId) -> Result<()>;
}
