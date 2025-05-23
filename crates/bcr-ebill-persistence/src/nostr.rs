use super::Result;
use async_trait::async_trait;
use bcr_ebill_core::{
    BoxedFuture, ServiceTraitBounds,
    blockchain::BlockchainType,
    nostr_contact::{HandshakeStatus, NostrContact, TrustLevel},
};
use nostr::{event::Event, key::PublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Allows storing and retrieving time based offsets for subscriptions
/// to Nostr relays. It will also store the event ids that have been
/// received and processed already.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait NostrEventOffsetStoreApi: ServiceTraitBounds {
    /// Returns the current timestamp offset of our nostr subscription
    /// Will return 0 if there are no events in the store yet, otherwise
    /// the highest timestamp of all events processed.
    /// there is still a possibility that we get events delivered that are
    /// older than the current offset just because they were not processed
    /// or the faked timestamp on the GiftWrap event was higher than the
    /// current offset.
    async fn current_offset(&self, node_id: &str) -> Result<u64>;

    /// Returns whether the given event id has been processed already. This
    /// will return true if we never tried to process the event independent
    /// of whether it was successful or not.
    async fn is_processed(&self, event_id: &str) -> Result<bool>;

    /// Stores the given event data in the store.
    async fn add_event(&self, data: NostrEventOffset) -> Result<()>;
}

/// A simple struct to store the event id and the time it was received.
#[derive(Debug, Clone)]
pub struct NostrEventOffset {
    /// The nostr event id
    pub event_id: String,
    /// The timestamp of the inner GiftWrap event. The highest timestamp
    /// of all events will be used when we restart the relay subscription.
    pub time: u64,
    /// Whether the event has been processed successfully on our side
    pub success: bool,
    /// The node id for which this event was processed
    pub node_id: String,
}

/// A dumb retry queue for Nostr messages that failed to be sent.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait NostrQueuedMessageStoreApi: ServiceTraitBounds {
    /// Adds a new retry message
    async fn add_message(&self, message: NostrQueuedMessage, max_retries: i32) -> Result<()>;
    /// Selects all messages that are ready to be retried
    async fn get_retry_messages(&self, limit: u64) -> Result<Vec<NostrQueuedMessage>>;
    /// Fail a retry attempt, schedules a new retry or fails the message if
    /// all retries have been exhausted.
    async fn fail_retry(&self, id: &str) -> Result<()>;
    /// Flags a retry as successful
    async fn succeed_retry(&self, id: &str) -> Result<()>;
}

#[derive(Clone, Debug)]
pub struct NostrQueuedMessage {
    pub id: String,
    pub sender_id: String,
    pub node_id: String,
    pub payload: Value,
}

/// Keeps track of our Nostr contacts. We need to communicate with some network participants before
/// we actually can add them as real contacts. This is also used to track the contact handshake
/// process.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait NostrContactStoreApi: ServiceTraitBounds {
    /// Find a Nostr contact by the node id. This is the primary key for the contact.
    async fn by_node_id(&self, node_id: &str) -> Result<Option<NostrContact>>;
    /// Find a Nostr contact by the npub. This is the public Nostr key of the contact.
    async fn by_npub(&self, npub: &PublicKey) -> Result<Option<NostrContact>>;
    /// Creates a new or updates an existing Nostr contact.
    async fn upsert(&self, data: &NostrContact) -> Result<()>;
    /// Delete an Nostr contact. This will remove the contact from the store.
    async fn delete(&self, node_id: &str) -> Result<()>;
    /// Sets a new handshake status for the contact. This is used to track the handshake process.
    async fn set_handshake_status(&self, node_id: &str, status: HandshakeStatus) -> Result<()>;
    /// Sets a new trust level for the contact. This is used to track the trust level of the
    /// contact.
    async fn set_trust_level(&self, node_id: &str, trust_level: TrustLevel) -> Result<()>;
}

/// Allows us to keep track of Nostr chain events and have an archive of signed events that
/// allows us to proof certain Events where published.
pub trait NostrChainEventStoreApi: Send + Sync {
    /// Finds all chain events for the given chain id and type. This will return all valid
    /// events we ever received for a chain id.
    fn find_chain_events(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> BoxedFuture<'_, Result<Vec<NostrChainEvent>>>;

    /// Finds the latest chain events for the given chain id and type. This can be considered the
    /// tip of the current chain state on Nostr. Latest means the blocks with the highest block
    /// height. In split chain scenarios this can return more than one event.
    fn find_latest_block_events(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> BoxedFuture<'_, Result<Vec<NostrChainEvent>>>;

    /// Finds the root (genesis) event for a given chain
    fn find_root_event(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> BoxedFuture<'_, Result<Option<NostrChainEvent>>>;

    /// Finds a message with a specific block hash as extracted from the chain payload.
    fn find_by_block_hash(&self, hash: &str) -> BoxedFuture<'_, Result<Option<NostrChainEvent>>>;

    /// Adds a new chain event to the store.
    fn add_chain_event(&self, event: NostrChainEvent) -> BoxedFuture<'_, Result<()>>;

    /// Finds an event by a specific Nostr event_id
    fn by_event_id(&self, event_id: &str) -> BoxedFuture<'_, Result<Option<NostrChainEvent>>>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NostrChainEvent {
    /// The nostr event id of this event.
    pub event_id: String,
    /// The event id that started the thread.
    pub root_id: String,
    /// The event id this event was appended to.
    pub reply_id: Option<String>,
    /// The npub of the sender of this event.
    pub author: String,
    /// The BCR id of the blockchain.
    pub chain_id: String,
    /// The type of the blockchain.
    pub chain_type: BlockchainType,
    /// The block height of the block contained in this event.
    pub block_height: usize,
    /// The hash of the block contained in this event.
    pub block_hash: String,
    /// The timestamp when we received the event.
    pub received: u64,
    /// The timestamp of the event.
    pub time: u64,
    /// The event as we received it via nostr.
    pub payload: Event,
}
