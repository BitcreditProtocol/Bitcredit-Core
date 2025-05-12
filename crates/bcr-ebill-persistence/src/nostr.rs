use super::Result;
use async_trait::async_trait;
use bcr_ebill_core::nostr_contact::{HandshakeStatus, NostrContact, TrustLevel};
use nostr::key::PublicKey;
use serde_json::Value;

/// Allows storing and retrieving time based offsets for subscriptions
/// to Nostr relays. It will also store the event ids that have been
/// received and processed already.
#[async_trait]
pub trait NostrEventOffsetStoreApi: Send + Sync {
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
#[async_trait]
pub trait NostrQueuedMessageStoreApi: Send + Sync {
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
#[async_trait]
pub trait NostrContactStoreApi: Send + Sync {
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
