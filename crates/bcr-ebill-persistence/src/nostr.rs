use super::Result;
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    application::contact::Contact,
    application::nostr_contact::{HandshakeStatus, NostrContact, NostrPublicKey, TrustLevel},
    protocol::SecretKey,
    protocol::Sha256Hash,
    protocol::Timestamp,
    protocol::blockchain::BlockchainType,
};
use nostr::event::Event;
use serde::{Deserialize, Serialize};

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
    async fn current_offset(&self, node_id: &NodeId) -> Result<Timestamp>;

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
    pub time: Timestamp,
    /// Whether the event has been processed successfully on our side
    pub success: bool,
    /// The node id for which this event was processed
    pub node_id: NodeId,
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
    pub sender_id: NodeId,
    pub node_id: NodeId,
    pub payload: String,
}

/// Manages all Nostr-related persistence including contacts, events, sync status, and retries
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait NostrStoreApi: ServiceTraitBounds {
    /// Find a Nostr contact by the node id. This node ids npub  is the primary key for the contact.
    async fn by_node_id(&self, node_id: &NodeId) -> Result<Option<NostrContact>>;
    /// Find multiple Nostr contacts by their node ids.
    async fn by_node_ids(&self, node_ids: Vec<NodeId>) -> Result<Vec<NostrContact>>;
    /// Get all Nostr contacts from the store.
    async fn get_all(&self) -> Result<Vec<NostrContact>>;
    /// Find a Nostr contact by the npub. This is the public Nostr key of the contact.
    async fn by_npub(&self, npub: &NostrPublicKey) -> Result<Option<NostrContact>>;
    /// Creates a new or updates an existing Nostr contact.
    async fn upsert(&self, data: &NostrContact) -> Result<()>;
    /// Delete an Nostr contact. This will remove the contact from the store.
    async fn delete(&self, node_id: &NodeId) -> Result<()>;
    /// Sets a new handshake status for the contact. This is used to track the handshake process.
    async fn set_handshake_status(&self, node_id: &NodeId, status: HandshakeStatus) -> Result<()>;
    /// Sets a new trust level for the contact. This is used to track the trust level of the
    /// contact.
    async fn set_trust_level(&self, node_id: &NodeId, trust_level: TrustLevel) -> Result<()>;
    /// returns all npubs that have a trust level higher than or equal to the given level.
    async fn get_npubs(&self, min_trust_level: Vec<TrustLevel>) -> Result<Vec<NostrPublicKey>>;
    /// Searches for a contact by name
    async fn search(&self, search_term: &str, levels: Vec<TrustLevel>)
    -> Result<Vec<NostrContact>>;

    // Pending contact share methods
    /// Store a new pending contact share
    async fn add_pending_share(&self, pending_share: PendingContactShare) -> Result<()>;
    /// Get a pending contact share by its unique id
    async fn get_pending_share(&self, id: &str) -> Result<Option<PendingContactShare>>;
    /// Get a pending contact share by the contact's private key (for auto-accept matching)
    async fn get_pending_share_by_private_key(
        &self,
        private_key: &SecretKey,
    ) -> Result<Option<PendingContactShare>>;
    /// List all pending contact shares for a given receiver node id
    async fn list_pending_shares_by_receiver(
        &self,
        receiver_node_id: &NodeId,
    ) -> Result<Vec<PendingContactShare>>;
    /// List all pending contact shares for a given receiver node id filtered by direction
    async fn list_pending_shares_by_receiver_and_direction(
        &self,
        receiver_node_id: &NodeId,
        direction: ShareDirection,
    ) -> Result<Vec<PendingContactShare>>;
    /// Delete a pending contact share (after approval or rejection)
    async fn delete_pending_share(&self, id: &str) -> Result<()>;
    /// Check if a pending share exists for a given node_id and receiver
    async fn pending_share_exists_for_node_and_receiver(
        &self,
        node_id: &NodeId,
        receiver_node_id: &NodeId,
    ) -> Result<bool>;

    // === Relay Sync Status Methods ===
    
    /// Get all relays that need syncing (status = Pending, InProgress, or Failed)
    async fn get_pending_relays(&self) -> Result<Vec<url::Url>>;
    
    /// Get sync status for a specific relay
    async fn get_relay_sync_status(&self, relay: &url::Url) -> Result<Option<RelaySyncStatus>>;
    
    /// Update sync status (Pending, InProgress, Completed, Failed)
    async fn update_relay_sync_status(&self, relay: &url::Url, status: SyncStatus) -> Result<()>;
    
    /// Update sync progress (increment events_synced and update last_synced_timestamp)
    async fn update_relay_sync_progress(&self, relay: &url::Url, timestamp: Timestamp) -> Result<()>;
    
    /// Update last_seen_in_config timestamp (called on every startup)
    async fn update_relay_last_seen(&self, relay: &url::Url, timestamp: Timestamp) -> Result<()>;
    
    // === Relay Sync Retry Queue Methods ===
    
    /// Add a failed event to the retry queue
    async fn add_failed_relay_sync(&self, relay: &url::Url, event: Event) -> Result<()>;
    
    /// Get events pending retry for a specific relay (ordered by created_at, limited)
    async fn get_pending_relay_retries(&self, relay: &url::Url, limit: usize) -> Result<Vec<Event>>;
    
    /// Mark a retry as successful (remove from queue)
    async fn mark_relay_retry_success(&self, relay: &url::Url, event_id: &str) -> Result<()>;
    
    /// Mark a retry as failed (increment retry_count, remove if max exceeded)
    async fn mark_relay_retry_failed(&self, relay: &url::Url, event_id: &str, max_retries: usize) -> Result<()>;
}

/// Direction of a contact share - incoming (we received) or outgoing (we sent)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShareDirection {
    /// We received this contact share from someone else
    Incoming,
    /// We sent this contact share to someone else
    Outgoing,
}

/// A pending contact share that requires user approval before being added to contacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingContactShare {
    /// Unique identifier for this pending share
    pub id: String,
    /// The node id of the contact that was shared
    pub node_id: NodeId,
    /// The decrypted contact data
    pub contact: Contact,
    /// The node id of the sender who shared this contact
    pub sender_node_id: NodeId,
    /// The private key to decrypt the contact data on Nostr
    pub contact_private_key: SecretKey,
    /// The node id that receives this share (identity or company)
    pub receiver_node_id: NodeId,
    /// When this share was received/sent
    pub received_at: Timestamp,
    /// Direction of the share (incoming or outgoing)
    pub direction: ShareDirection,
    /// The initial share ID from the sender. For Incoming shares, this is always present and
    /// contains the pending share ID that the sender created on their side. When sharing back,
    /// we use this as the share_back_pending_id so the sender can auto-accept.
    /// For Outgoing shares, this is None since we are the sender.
    pub initial_share_id: Option<String>,
}

/// Allows us to keep track of Nostr chain events and have an archive of signed events that
/// allows us to proof certain Events where published.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait NostrChainEventStoreApi: ServiceTraitBounds {
    /// Finds all chain events for the given chain id and type. This will return all valid
    /// events we ever received for a chain id.
    async fn find_chain_events(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> Result<Vec<NostrChainEvent>>;

    /// Finds the latest chain events for the given chain id and type. This can be considered the
    /// tip of the current chain state on Nostr. Latest means the blocks with the highest block
    /// height. In split chain scenarios this can return more than one event.
    async fn find_latest_block_events(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> Result<Vec<NostrChainEvent>>;

    /// Finds the root (genesis) event for a given chain
    async fn find_root_event(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> Result<Option<NostrChainEvent>>;

    /// Finds a message with a specific block hash as extracted from the chain payload.
    async fn find_by_block_hash(&self, hash: &Sha256Hash) -> Result<Option<NostrChainEvent>>;

    /// Adds a new chain event to the store.
    async fn add_chain_event(&self, event: NostrChainEvent) -> Result<()>;

    /// Finds an event by a specific Nostr event_id
    async fn by_event_id(&self, event_id: &str) -> Result<Option<NostrChainEvent>>;
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
    pub block_hash: Sha256Hash,
    /// The timestamp when we received the event.
    pub received: Timestamp,
    /// The timestamp of the event.
    pub time: Timestamp,
    /// The event as we received it via nostr.
    pub payload: Event,
    /// We consider this event as part of the valid chain
    pub valid: bool,
}

impl NostrChainEvent {
    /// Returns the block hash of the event. This is the hash of the block
    /// contained in the event.
    pub fn is_root_event(&self) -> bool {
        self.event_id == self.root_id
    }
}

/// Status of relay synchronization
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncStatus {
    /// Needs sync but hasn't started
    Pending,
    /// Currently syncing
    InProgress,
    /// Fully synced
    Completed,
    /// Last sync attempt failed
    Failed,
}

/// Tracks synchronization status for a user relay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelaySyncStatus {
    /// The relay URL
    pub relay_url: url::Url,
    /// Last time this relay was seen in user's config (updated every startup)
    pub last_seen_in_config: Timestamp,
    /// Current sync status
    pub sync_status: SyncStatus,
    /// Number of events successfully synced
    pub events_synced: usize,
    /// Resume point for sync (timestamp of last synced event)
    pub last_synced_timestamp: Option<Timestamp>,
    /// Error message from last sync failure
    pub last_error: Option<String>,
}

/// An event that failed to sync to a relay (for retry queue)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelaySyncRetry {
    /// Unique ID for this retry record
    pub id: String,
    /// The relay that failed to receive this event
    pub relay_url: url::Url,
    /// The event that failed to sync
    pub event: Event,
    /// Number of retry attempts so far
    pub retry_count: usize,
    /// When this record was created
    pub created_at: Timestamp,
    /// When the last retry was attempted
    pub last_retry_at: Option<Timestamp>,
}
