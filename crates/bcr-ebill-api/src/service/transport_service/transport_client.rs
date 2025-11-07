use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    ServiceTraitBounds, blockchain::BlockchainType, contact::BillParticipant,
    protocol::EventEnvelope, timestamp::Timestamp, util::BcrKeys,
};

#[cfg(test)]
use mockall::automock;

use nostr::{Event, Filter, types::RelayUrl};

use super::{NostrContactData, Result};

#[cfg(test)]
impl ServiceTraitBounds for MockTransportClientApi {}

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait TransportClientApi: ServiceTraitBounds {
    /// Returns the senders node id for this instance.
    fn get_sender_node_id(&self) -> NodeId;
    /// Returns the senders keys for this instance.
    fn get_sender_keys(&self) -> BcrKeys;
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
        block_time: Timestamp,
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
    /// Resolves all private messages matching the filter
    async fn resolve_private_events(&self, filter: Filter) -> Result<Vec<Event>>;

    /// Publishes the metadata (contact info) via the Nostr client
    async fn publish_metadata(&self, data: &nostr::nips::nip01::Metadata) -> Result<()>;

    /// Publishes the relay list via the Nostr client
    async fn publish_relay_list(&self, relays: Vec<RelayUrl>) -> Result<()>;

    /// Opens the connection(s) to the underlying network. This can be called multiple times and
    /// will only open the connection once.
    async fn connect(&self) -> Result<()>;
}
