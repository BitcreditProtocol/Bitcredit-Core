use crate::chain_keys::KnownChain;
use crate::transport::extract_event_envelope;
use crate::{
    chain_keys::ChainKeyServiceApi,
    handler::{FileMetadataProcessorApi, NotificationHandlerApi},
    incoming_verification::IncomingPropagationVerifier,
    transport::{
        chain_filter, create_public_chain_event, unwrap_direct_message, unwrap_public_chain_event,
    },
};
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_api::{
    constants::NOSTR_MAX_RELAYS,
    service::{
        contact_service::ContactServiceApi,
        file_server_service::resolve_blossom_servers,
        transport_service::{
            Error, NostrConfig, NostrContactData, Result,
            propagation::RelayQuorumSnapshot,
            transport_client::{PreparedPrivateNostrEvent, TransportClientApi},
        },
    },
};
use bcr_ebill_core::{application::ServiceTraitBounds, protocol::event::EventEnvelope};
use bcr_ebill_core::{
    application::nostr_contact::{NostrContact, TrustLevel},
    protocol::{
        Timestamp,
        blockchain::{BlockchainType, bill::participant::BillParticipant},
        crypto::BcrKeys,
        event::EventType,
    },
};
use bcr_ebill_persistence::{NostrEventOffset, NostrEventOffsetStoreApi, NostrStoreApi};
use bitcoin::base58;
use futures::StreamExt;
use log::{debug, error, info, trace, warn};
use nostr::message::{RelayMessage, SubscriptionId};
use nostr::nips::nip59::UnwrappedGift;
use nostr::{
    event::{Event, EventBuilder, EventId, FinalizeEvent, Kind, Tag},
    filter::{Filter, SingleLetterTag},
    key::{Keys, PublicKey},
    nips::{
        nip01::Metadata,
        nip17::PrivateDirectMessageBuilder,
        nip65::{RelayList, RelayMetadata, extract_relay_list},
    },
    types::url::RelayUrl,
};
use nostr_sdk::{
    authenticator::SignerAuthenticator,
    client::{Client, ClientNotification, ReqTarget, SendEventOutput},
    relay::{RelayNotification, RelayStatus},
};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, atomic::Ordering};
use std::{
    collections::{HashMap, HashSet},
    sync::atomic::AtomicBool,
    time::Duration,
};
use tokio::sync::broadcast;
use tokio::task::JoinSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SortOrder {
    Asc,
    Desc,
}

const BLOSSOM_SERVER_LIST_KIND: Kind = Kind::Custom(10063);
const FILE_METADATA_KIND: Kind = Kind::Custom(1063);
const DM_BACKFILL_LIMIT: usize = 1000;
const DM_RESTORE_MAX_RECIPIENTS: usize = 128;
/// DM catch-up
const DM_CATCHUP_INTERVAL: Duration = Duration::from_secs(5 * 60);
const DM_CATCHUP_PAGE_SIZE: usize = 256;
const DM_CATCHUP_MAX_PAGES_PER_RELAY: usize = 10;
const DM_CATCHUP_SIGNERS_PER_PASS: usize = 4;
const DM_CATCHUP_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const DM_CATCHUP_SCOPE: &str = "giftwrap";

/// Check the output of sending an event to Nostr relays.
/// Logs warnings for individual relay failures and returns an error if no relay
/// accepted the event.
fn check_send_output(output: SendEventOutput, context: &str) -> Result<()> {
    for (relay, error) in &output.failed {
        warn!("{context}: relay {relay} failed: {error}");
    }
    if output.success.is_empty() {
        error!("{context}: all relays failed to accept the event");
        return Err(Error::Network(format!(
            "{context}: all relays failed to accept the event"
        )));
    }
    Ok(())
}

/// A wrapper around nostr_sdk that implements the NotificationJsonTransportApi.
///
/// # Example:
/// ```no_run
/// let config = NostrConfig::new(
///     BcrKeys::new(),
///     vec!["wss://relay.example.com".to_string()],
///     "My Company".to_string(),
/// );
/// let transport = NostrClient::new(&config).await.unwrap();
/// transport.send(&recipient, event).await.unwrap();
/// ```
/// We use the latest GiftWrap and PrivateDirectMessage already with this if I
/// understand the nostr-sdk docs and sources correctly.
/// @see https://nips.nostr.com/59 and https://nips.nostr.com/17
#[derive(Clone)]
pub struct NostrClient {
    client: Client,
    signers: Arc<Mutex<HashMap<NodeId, Arc<Keys>>>>,
    relays: Vec<url::Url>,
    blossom_servers: Vec<url::Url>,
    default_timeout: Duration,
    connected: Arc<AtomicBool>,
    sync_running: Arc<AtomicBool>, // Prevents concurrent sync
    max_relays: Option<usize>,
    relay_ack_threshold: usize,
    nostr_contact_store: Option<Arc<dyn NostrStoreApi>>, // Keep for backwards compatibility
    nostr_store: Option<Arc<dyn NostrStoreApi>>,
    primary_node_id: NodeId,
}

impl NostrClient {
    /// Creates a new nostr client with multiple identities sharing a relay pool
    pub async fn new(
        identities: Vec<(NodeId, BcrKeys)>,
        relays: Vec<url::Url>,
        blossom_servers: Vec<url::Url>,
        default_timeout: Duration,
        max_relays: Option<usize>,
        relay_ack_threshold: usize,
        nostr_store: Option<Arc<dyn NostrStoreApi>>,
    ) -> Result<Self> {
        if identities.is_empty() {
            return Err(Error::Message("At least one identity required".to_string()));
        }
        let primary_node_id = identities[0].0.clone();
        // Use first identity to construct the underlying Client
        let first_keys = &identities[0].1;
        let client = Client::builder()
            .authenticator(SignerAuthenticator::new(
                first_keys.get_nostr_keys().clone(),
            ))
            .build();

        // Add all relays to the shared pool
        for relay in &relays {
            client.add_relay(relay.to_string()).await.map_err(|e| {
                error!("Failed to add relay to Nostr client: {e}");
                Error::Network("Failed to add relay to Nostr client".to_string())
            })?;
        }

        // Build signers HashMap from all identities
        let mut signers = HashMap::new();
        for (node_id, keys) in identities {
            signers.insert(node_id, Arc::new(keys.get_nostr_keys()));
        }

        Ok(Self {
            client,
            signers: Arc::new(Mutex::new(signers)),
            relays,
            blossom_servers,
            default_timeout,
            connected: Arc::new(AtomicBool::new(false)),
            sync_running: Arc::new(AtomicBool::new(false)),
            max_relays,
            relay_ack_threshold: relay_ack_threshold.max(1),
            nostr_contact_store: nostr_store.clone(), // Keep for backwards compatibility
            nostr_store,
            primary_node_id,
        })
    }

    /// Creates a new nostr client with the given config.
    pub async fn default(config: &NostrConfig) -> Result<Self> {
        let identities = vec![(config.node_id.clone(), config.keys.clone())];
        Self::new(
            identities,
            config.relays.clone(),
            config.blossom_servers.clone(),
            config.default_timeout,
            None, // max_relays not available in old config
            config.relay_ack_threshold,
            None, // store not available
        )
        .await
    }

    /// Get the signer for a specific identity
    pub fn get_signer(&self, node_id: &NodeId) -> Result<Arc<Keys>> {
        self.signers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(node_id)
            .cloned()
            .ok_or_else(|| Error::Message(format!("No signer found for node_id: {}", node_id)))
    }

    /// Add a new identity to this client
    pub fn add_identity(&self, node_id: NodeId, keys: BcrKeys) -> Result<()> {
        self.signers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(node_id, Arc::new(keys.get_nostr_keys()));
        Ok(())
    }

    /// Check if this client has a local signer for the given node_id
    pub fn has_local_signer(&self, node_id: &NodeId) -> bool {
        self.signers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(node_id)
    }

    /// Get all node_ids managed by this client
    pub fn get_all_node_ids(&self) -> Vec<NodeId> {
        self.signers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    /// Subscribe to some nostr events with a filter
    pub async fn subscribe(&self, subscription: Filter) -> Result<()> {
        self.client()
            .await?
            .subscribe(subscription)
            .await
            .map_err(|e| {
                error!("Failed to subscribe to Nostr events: {e}");
                Error::Network("Failed to subscribe to Nostr events".to_string())
            })?;
        Ok(())
    }

    /// Returns the latest metadata event for the given npub either from the provided relays or
    /// from this clients relays.
    pub async fn fetch_metadata(&self, npub: PublicKey) -> Result<Option<Metadata>> {
        let filter = Filter::new().author(npub).kind(Kind::Metadata);

        let events = self
            .client()
            .await?
            .fetch_events(filter)
            .timeout(self.default_timeout)
            .await
            .map_err(|e| {
                error!("Failed to fetch Nostr metadata: {e}");
                Error::Network("Failed to fetch Nostr metadata".to_string())
            })?;

        let Some(event) = events.iter().max_by_key(|e| e.created_at) else {
            return Ok(None);
        };

        let metadata = Metadata::try_from(event).map_err(|e| {
            error!("Failed to decode Nostr metadata: {e}");
            Error::Message("Failed to decode Nostr metadata".to_string())
        })?;

        Ok(Some(metadata))
    }

    /// Returns the relays a given npub is reading from or writing to.
    // Relay list content (the actual relay urls) are stored as tags on the event. The event
    // content itself is actually empty. Here we look for tags with a lowercase 'r' (specified
    // as RelayMetadata) and filter for valid ones. Filter standardized filters and parses the
    // matching tags into enum values.
    pub async fn fetch_relay_list(
        &self,
        npub: PublicKey,
        relays: Vec<url::Url>,
    ) -> Result<Vec<RelayUrl>> {
        let filter = Filter::new().author(npub).kind(Kind::RelayList).limit(1);
        let events = self.fetch_events(filter, None, Some(relays)).await?;
        Ok(events
            .first()
            .map(|e| {
                extract_relay_list(e)
                    .map(|(relay_url, _metadata)| relay_url)
                    .collect()
            })
            .unwrap_or_default())
    }

    pub async fn fetch_blossom_server_list(
        &self,
        npub: PublicKey,
        relays: Vec<url::Url>,
    ) -> Result<Vec<url::Url>> {
        let filter = Filter::new()
            .author(npub)
            .kind(BLOSSOM_SERVER_LIST_KIND)
            .limit(1);
        let events = self.fetch_events(filter, None, Some(relays)).await?;
        Ok(events
            .first()
            .map(|event| {
                event
                    .tags
                    .iter()
                    .filter_map(|tag| match tag.as_slice() {
                        [kind, url, ..] if kind == "server" => url::Url::parse(url).ok(),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Returns events that match filter from either the provided relays or from this clients
    /// relays. If a order is provided, the events are sorted accordingly otherwise the default
    /// descending order is used.
    pub async fn fetch_events(
        &self,
        filter: Filter,
        order: Option<SortOrder>,
        relays: Option<Vec<url::Url>>,
    ) -> Result<Vec<Event>> {
        let relays = match relays {
            Some(relays) => relays,
            None => self.relays.clone(),
        };

        let target = ReqTarget::manual(
            to_relay_urls(&relays)?
                .into_iter()
                .map(|relay| (relay, vec![filter.clone()])),
        );

        let events = self
            .client()
            .await?
            .fetch_events(target)
            .timeout(self.default_timeout)
            .await
            .map_err(|e| {
                error!("Failed to fetch Nostr events: {e}");
                Error::Network("Failed to fetch Nostr events".to_string())
            })?;
        let mut events = events.into_iter().collect::<Vec<Event>>();
        if Some(SortOrder::Asc) == order {
            events.reverse();
        }
        Ok(events)
    }

    /// Fetch a historical page from one relay
    /// Only a completed request may return an empty page
    async fn fetch_completed_page(
        &self,
        filter: Filter,
        relay_url: &url::Url,
        timeout: Duration,
    ) -> Result<Vec<Event>> {
        tokio::time::timeout(timeout, async {
            let relay = self
                .client()
                .await?
                .relay(relay_url.as_str())
                .await
                .map_err(|e| Error::Network(e.to_string()))?
                .ok_or_else(|| Error::Network(format!("Unknown relay {relay_url}")))?;
            let id = SubscriptionId::generate();
            let mut notifications = relay.notifications();
            if relay.status() != RelayStatus::Connected {
                return Err(Error::Network(format!(
                    "Relay {relay_url} is not connected"
                )));
            }
            let limit = filter.limit.unwrap_or(10_000);
            let collect = async {
                let mut stream = relay
                    .stream_events(filter)
                    .with_id(id.clone())
                    .await
                    .map_err(|e| Error::Network(e.to_string()))?;

                let mut events = BTreeSet::new();
                while let Some(event) = stream.next().await {
                    events.insert(event.map_err(|e| Error::Network(e.to_string()))?);
                    if events.len() > limit {
                        return Err(Error::Network(format!(
                            "Relay {relay_url} exceeded page size"
                        )));
                    }
                }
                Ok::<Vec<Event>, Error>(events.into_iter().collect())
            };

            let completed = async {
                while let Some(notification) = notifications.next().await {
                    match notification {
                        RelayNotification::Message { message } => {
                            if matches!(
                                message.as_ref(),
                                RelayMessage::EndOfStoredEvents(sub)
                                    if sub.as_ref() == &id
                            ) {
                                return Ok(());
                            }
                        }
                        RelayNotification::RelayStatus { status }
                            if status != RelayStatus::Connected =>
                        {
                            break;
                        }
                        _ => {}
                    }
                }
                Err(Error::Network(format!(
                    "Historical query on {relay_url} ended before EOSE"
                )))
            };
            let (events, ()) = tokio::try_join!(collect, completed)?;
            Ok(events)
        })
        .await
        .map_err(|_| Error::Network(format!("Historical query timed out on {relay_url}")))?
    }

    /// Stream events from specific relays using the provided filter.
    /// Returns a stream that yields events as they arrive from relays.
    /// This is more efficient than fetch_events for large result sets as it doesn't
    /// wait for all relays to respond before returning results.
    pub async fn stream_events_from(
        &self,
        filter: Filter,
        relays: Option<Vec<url::Url>>,
        timeout: Option<Duration>,
    ) -> Result<impl futures::Stream<Item = Event>> {
        let relays = match relays {
            Some(relays) => relays,
            None => self.relays.clone(),
        };

        let target = ReqTarget::manual(
            to_relay_urls(&relays)?
                .into_iter()
                .map(|relay| (relay, vec![filter.clone()])),
        );

        let stream = self
            .client()
            .await?
            .stream_events(target)
            .timeout(timeout.unwrap_or(self.default_timeout))
            .await
            .map_err(|e| {
                error!("Failed to stream Nostr events: {e}");
                Error::Network("Failed to stream Nostr events".to_string())
            })?;

        Ok(stream.filter_map(|(relay, result)| async move {
            match result {
                Ok(event) => Some(event),
                Err(e) => {
                    debug!("Error streaming event from {relay}: {e}");
                    None
                }
            }
        }))
    }

    /// Send an event to specific relays
    pub async fn send_event_to(&self, relays: Vec<url::Url>, event: &Event) -> Result<()> {
        let output = self
            .client()
            .await?
            .send_event(event)
            .to(to_relay_urls(&relays)?)
            .await
            .map_err(|e| {
                error!("Failed to send event to relays: {e}");
                Error::Network(format!("Failed to send event to relays: {e}"))
            })?;
        check_send_output(output, "send_event_to")
    }

    /// Get the default timeout for this client
    pub fn get_default_timeout(&self) -> Duration {
        self.default_timeout
    }

    async fn send_nip17_message(
        &self,
        sender_node_id: &NodeId,
        recipient: &BillParticipant,
        envelope: EventEnvelope,
    ) -> Result<()> {
        let prepared = self
            .prepare_nip17_message(sender_node_id, recipient, envelope)
            .await?;
        let output = self
            .client()
            .await?
            .send_event(&prepared.event)
            .to(to_relay_urls(&prepared.target_relays)?)
            .await
            .map_err(|e| Error::Network(format!("Failed to send NIP-17 message: {e}")))?;
        check_send_output(output, "send_nip17_message")
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    pub async fn client(&self) -> Result<&Client> {
        if !self.is_connected() {
            self.connect().await?;
        }
        Ok(&self.client)
    }

    /// Calculate the complete relay set from user relays + contact relays
    async fn calculate_relay_set(&self) -> Result<HashSet<url::Url>> {
        // Get contacts from store if available
        let contacts = if let Some(store) = &self.nostr_contact_store {
            store.get_all().await.map_err(|e| {
                error!("Failed to fetch contacts for relay calculation: {e}");
                Error::Message("Failed to fetch contacts".to_string())
            })?
        } else {
            vec![]
        };

        Ok(calculate_relay_set_internal(
            &self.relays,
            &contacts,
            self.max_relays,
        ))
    }

    /// Update the client's relay connections to match the target set
    async fn update_relays(&self, target_relays: HashSet<url::Url>) -> Result<()> {
        let client = &self.client;

        // Get current relays
        let current_relays: HashSet<url::Url> = client
            .relays()
            .await
            .keys()
            .map(|url| url.to_owned().into())
            .collect();

        // Add new relays
        for relay in target_relays.iter() {
            if !current_relays.contains(relay) {
                match client.add_relay(relay.to_string()).await {
                    Ok(_) => debug!("Added relay: {}", relay),
                    Err(e) => warn!("Failed to add relay {}: {}", relay, e),
                }
            }
        }

        // Remove old relays (relays not in target set)
        for relay in current_relays.iter() {
            if !target_relays.contains(relay) {
                // Convert url::Url to RelayUrl
                if let Ok(relay_url) = relay.as_str().parse::<RelayUrl>() {
                    match client.remove_relay(relay_url).await {
                        Ok(_) => debug!("Removed relay: {}", relay),
                        Err(e) => warn!("Failed to remove relay {}: {}", relay, e),
                    }
                }
            }
        }

        Ok(())
    }

    /// Public method to refresh relay connections based on current contacts
    pub async fn refresh_relays(&self) -> Result<()> {
        info!("Refreshing relay connections based on contacts");
        let relay_set = self.calculate_relay_set().await?;
        self.update_relays(relay_set).await?;
        info!(
            "Relay refresh complete, connected to {} relays",
            self.client.relays().await.len()
        );
        Ok(())
    }

    pub async fn has_connected_relays(&self) -> bool {
        self.client
            .relays()
            .await
            .values()
            .any(|relay| relay.status() == RelayStatus::Connected)
    }

    async fn prepare_nip17_message(
        &self,
        sender_node_id: &NodeId,
        recipient: &BillParticipant,
        envelope: EventEnvelope,
    ) -> Result<PreparedPrivateNostrEvent> {
        // resolve local signer
        let sender_keys = self.get_signer(sender_node_id)?;
        let receiver_pubkey = recipient.node_id().npub();
        let message = base58::encode(&borsh::to_vec(&envelope)?);
        // build and sign the NIP-17 GiftWrap
        let event = PrivateDirectMessageBuilder::new(receiver_pubkey, message)
            .finalize(sender_keys.as_ref())
            .map_err(|e| Error::Message(format!("Failed to prepare NIP-17 event: {e}")))?;

        let mut target_relays = recipient.nostr_relays();
        if target_relays.is_empty() {
            target_relays = self
                .client
                .relays()
                .await
                .into_values()
                .filter(|relay| relay.capabilities().has_write())
                .map(|relay| {
                    url::Url::parse(relay.url().as_str())
                        .map_err(|e| Error::Message(format!("Invalid Nostr relay URL: {e}")))
                })
                .collect::<Result<Vec<_>>>()?;
        }
        // ensure a deterministic, unique relay list
        target_relays.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        target_relays.dedup();
        // at least one relay
        if target_relays.is_empty() {
            return Err(Error::Network(
                "No writable relays available for NIP-17 event".to_owned(),
            ));
        }
        to_relay_urls(&target_relays)?;

        Ok(PreparedPrivateNostrEvent {
            event,
            target_relays,
        })
    }

    async fn subscribe_named(&self, id: &str, filter: Filter) -> Result<()> {
        self.client
            .subscribe(filter)
            .with_id(SubscriptionId::new(id))
            .await
            .map_err(|e| Error::Network(e.to_string()))?;

        Ok(())
    }
}

impl ServiceTraitBounds for NostrClient {}

fn to_relay_url(url: &url::Url) -> Result<RelayUrl> {
    RelayUrl::parse(url.as_str())
        .map_err(|e| Error::Message(format!("Invalid Nostr relay URL {url}: {e}")))
}

fn to_relay_urls(urls: &[url::Url]) -> Result<Vec<RelayUrl>> {
    urls.iter().map(to_relay_url).collect()
}

#[async_trait]
impl TransportClientApi for NostrClient {
    async fn send_signed_event_to_relay(&self, event: &Event, relay: &url::Url) -> Result<()> {
        let relay_url = to_relay_url(relay)?;
        let client = self.client().await?;
        // if a relay was removed after the event was enqueued, add it back to retry the event
        if client
            .relay(relay_url.clone())
            .await
            .map_err(|e| Error::Network(e.to_string()))?
            .is_none()
        {
            client
                .add_relay(relay_url.clone())
                .await
                .map_err(|e| Error::Network(e.to_string()))?;
            // adding a relay does not automatically connect it
            client
                .connect_relay(relay_url.clone())
                .await
                .map_err(|e| Error::Network(e.to_string()))?;
        }

        // send only to this one relay
        let output = tokio::time::timeout(
            self.default_timeout,
            client.send_event(event).to([relay_url.clone()]),
        )
        .await
        .map_err(|_| Error::Network(format!("Timed out sending event {} to {relay}", event.id)))?
        .map_err(|e| {
            Error::Network(format!("Could not send event {} to {relay}: {e}", event.id))
        })?;
        // ack = success
        if output.success.contains_key(&relay_url) {
            return Ok(());
        }
        if let Some(reason) = output.failed.get(&relay_url) {
            // duplicate is a success - the relay has our event
            if is_duplicate_response(reason) {
                return Ok(());
            }
            return Err(Error::Network(format!(
                "Relay {relay} rejected event {}: {reason}",
                event.id
            )));
        }
        Err(Error::Network(format!(
            "Relay {relay} did not acknowledge event {}",
            event.id
        )))
    }

    async fn prepare_private_event(
        &self,
        sender_node_id: &NodeId,
        recipient: &BillParticipant,
        event: EventEnvelope,
    ) -> Result<PreparedPrivateNostrEvent> {
        self.prepare_nip17_message(sender_node_id, recipient, event)
            .await
    }

    async fn send_private_event(
        &self,
        sender_node_id: &NodeId,
        recipient: &BillParticipant,
        event: EventEnvelope,
    ) -> Result<()> {
        self.send_nip17_message(sender_node_id, recipient, event)
            .await?;
        Ok(())
    }

    async fn build_public_chain_event(
        &self,
        sender_node_id: &NodeId,
        id: &str,
        blockchain: BlockchainType,
        block_time: Timestamp,
        event: EventEnvelope,
        previous_event: Option<Event>,
        root_event: Option<Event>,
    ) -> Result<Event> {
        // Get the keys for this identity to sign with
        let signing_keys = self.get_signer(sender_node_id)?;

        let event_builder = create_public_chain_event(
            id,
            event,
            block_time,
            blockchain,
            previous_event,
            root_event,
        )?;

        event_builder.finalize(signing_keys.as_ref()).map_err(|e| {
            error!("Failed to sign Nostr event: {e}");
            Error::Crypto("Failed to sign Nostr event".to_string())
        })
    }

    fn relay_ack_threshold(&self) -> usize {
        self.relay_ack_threshold
    }

    async fn resolve_contact(&self, node_id: &NodeId) -> Result<Option<NostrContactData>> {
        match self.fetch_metadata(node_id.npub()).await? {
            Some(meta) => {
                let relays = self
                    .fetch_relay_list(node_id.npub(), self.relays.clone())
                    .await?;
                let blossom_servers = self
                    .fetch_blossom_server_list(node_id.npub(), self.relays.clone())
                    .await?;
                Ok(Some(NostrContactData {
                    metadata: meta,
                    relays,
                    blossom_servers,
                }))
            }
            _ => Ok(None),
        }
    }

    async fn resolve_public_chain(
        &self,
        id: &str,
        chain_type: BlockchainType,
    ) -> Result<Vec<nostr::event::Event>> {
        let filter = chain_filter(id, chain_type);
        let events = self
            .fetch_events(filter, Some(SortOrder::Asc), None)
            .await?;
        Ok(events)
    }

    async fn add_contact_subscription(&self, node_id: &NodeId) -> Result<()> {
        debug!("adding nostr subscription for contact {node_id}");
        self.subscribe(Filter::new().author(node_id.npub())).await?;
        Ok(())
    }

    async fn resolve_events(&self, filter: Filter) -> Result<Vec<nostr::event::Event>> {
        Ok(self
            .fetch_events(filter, Some(SortOrder::Asc), None)
            .await?)
    }

    async fn try_decrypt_private_event(
        &self,
        event: &nostr::event::Event,
    ) -> Result<Option<(NodeId, EventEnvelope, nostr::key::PublicKey)>> {
        match event.kind {
            Kind::GiftWrap => {
                let keys_to_try = prioritized_signers_for_event(event, &self.signers);
                for (node_id, nostr_keys) in keys_to_try {
                    if let Some((envelope, sender, _, _)) =
                        unwrap_direct_message(event, &nostr_keys).await
                    {
                        return Ok(Some((node_id, envelope, sender)));
                    }
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    async fn publish_metadata(&self, node_id: &NodeId, data: &Metadata) -> Result<()> {
        // Get the signer for this identity
        let signer = self.get_signer(node_id)?;

        // Build and sign the metadata event with the specific identity
        let event = data.clone().finalize(signer.as_ref()).map_err(|e| {
            error!("Failed to sign metadata event: {e}");
            Error::Crypto("Failed to sign metadata event".to_string())
        })?;

        let output = self.client().await?.send_event(&event).await.map_err(|e| {
            error!("Failed to send user metadata with Nostr client: {e}");
            Error::Network("Failed to send user metadata with Nostr client".to_string())
        })?;
        check_send_output(output, "publish_metadata")
    }

    async fn publish_relay_list(&self, node_id: &NodeId, relays: Vec<RelayUrl>) -> Result<()> {
        // Get the signer for this identity
        let signer = self.get_signer(node_id)?;

        // Build and sign the relay list event with the specific identity
        let relay_list: Vec<(RelayUrl, Option<RelayMetadata>)> =
            relays.into_iter().map(|r| (r, None)).collect();
        let event = RelayList::new(relay_list)
            .finalize(signer.as_ref())
            .map_err(|e| {
                error!("Failed to sign relay list event: {e}");
                Error::Crypto("Failed to sign relay list event".to_string())
            })?;

        let output = self.client().await?.send_event(&event).await.map_err(|e| {
            error!("Failed to send relay list with Nostr client: {e}");
            Error::Network("Failed to send relay list with Nostr client".to_string())
        })?;
        check_send_output(output, "publish_relay_list")
    }

    async fn publish_blossom_server_list(
        &self,
        node_id: &NodeId,
        blossom_servers: Vec<url::Url>,
    ) -> Result<()> {
        let signer = self.get_signer(node_id)?;
        let tags = blossom_servers
            .into_iter()
            .map(|server| Tag::parse(["server", server.as_str()]))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                error!("Failed to build Blossom server list tags: {e}");
                Error::Message("Failed to build Blossom server list tags".to_string())
            })?;
        let event = EventBuilder::new(BLOSSOM_SERVER_LIST_KIND, "")
            .tags(tags)
            .finalize(&*signer)
            .map_err(|e| {
                error!("Failed to sign Blossom server list event: {e}");
                Error::Crypto("Failed to sign Blossom server list event".to_string())
            })?;

        let output = self.client().await?.send_event(&event).await.map_err(|e| {
            error!("Failed to send Blossom server list with Nostr client: {e}");
            Error::Network("Failed to send Blossom server list with Nostr client".to_string())
        })?;
        check_send_output(output, "publish_blossom_server_list")
    }

    async fn publish_file_metadata(
        &self,
        node_id: &NodeId,
        plaintext_hash: &str,
        encrypted_hash: &str,
        server_urls: Vec<url::Url>,
        mime_type: Option<String>,
    ) -> Result<()> {
        if server_urls.is_empty() {
            debug!("Skipping file metadata publish - no server URLs available");
            return Ok(());
        }

        let signer = self.get_signer(node_id)?;

        // Build tags according to NIP-94 adapted conventions:
        // ox = plaintext local hash
        // x = encrypted blob hash
        // url = primary server URL
        // fallback = additional mirror URLs
        // m = MIME type when known
        let mut tags: Vec<Tag> = vec![
            Tag::parse(["ox", plaintext_hash]).map_err(|e| {
                error!("Failed to build ox tag: {e}");
                Error::Message("Failed to build ox tag".to_string())
            })?,
            Tag::parse(["x", encrypted_hash]).map_err(|e| {
                error!("Failed to build x tag: {e}");
                Error::Message("Failed to build x tag".to_string())
            })?,
        ];

        // Add primary URL
        if let Some(primary) = server_urls.first() {
            tags.push(Tag::parse(["url", primary.as_str()]).map_err(|e| {
                error!("Failed to build url tag: {e}");
                Error::Message("Failed to build url tag".to_string())
            })?);
        }

        // Add fallback URLs for additional mirrors
        for url in server_urls.iter().skip(1) {
            tags.push(Tag::parse(["fallback", url.as_str()]).map_err(|e| {
                error!("Failed to build fallback tag: {e}");
                Error::Message("Failed to build fallback tag".to_string())
            })?);
        }

        // Add MIME type if provided
        if let Some(ref mime) = mime_type {
            tags.push(Tag::parse(["m", mime]).map_err(|e| {
                error!("Failed to build m tag: {e}");
                Error::Message("Failed to build m tag".to_string())
            })?);
        }

        let event = EventBuilder::new(FILE_METADATA_KIND, "")
            .tags(tags)
            .finalize(&*signer)
            .map_err(|e| {
                error!("Failed to sign file metadata event: {e}");
                Error::Crypto("Failed to sign file metadata event".to_string())
            })?;

        let output = self.client().await?.send_event(&event).await.map_err(|e| {
            error!("Failed to send file metadata with Nostr client: {e}");
            Error::Network("Failed to send file metadata with Nostr client".to_string())
        })?;
        check_send_output(output, "publish_file_metadata")
    }

    async fn connect(&self) -> Result<()> {
        if self
            .connected
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.client.connect().await;

            // Publish relay list for ALL identities
            let node_ids = self.get_all_node_ids();
            let relay_urls: Vec<RelayUrl> = self
                .relays
                .iter()
                .filter_map(|r| RelayUrl::parse(r.as_str()).ok())
                .collect();
            let blossom_servers = resolve_blossom_servers(&self.blossom_servers, &self.relays);

            for node_id in node_ids {
                if let Err(e) = self.publish_relay_list(&node_id, relay_urls.clone()).await {
                    error!(
                        "Failed to publish relay list for identity {}: {}",
                        node_id, e
                    );
                }
                if let Err(e) = self
                    .publish_blossom_server_list(&node_id, blossom_servers.clone())
                    .await
                {
                    error!(
                        "Failed to publish Blossom server list for identity {}: {}",
                        node_id, e
                    );
                }
            }
        }
        Ok(())
    }

    async fn add_identity(&self, node_id: NodeId, keys: BcrKeys) -> Result<()> {
        // Add the identity to signers
        self.signers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(node_id.clone(), Arc::new(keys.get_nostr_keys()));

        // Subscribe to direct messages for this identity if connected
        if self.is_connected() {
            let kinds = vec![Kind::GiftWrap];
            debug!("Adding subscription for direct messages to identity: {node_id}");
            self.subscribe(
                Filter::new()
                    .pubkey(node_id.npub())
                    .kinds(kinds)
                    .limit(DM_BACKFILL_LIMIT),
            )
            .await?;
            debug!("Adding subscription for public blocks messages from identity: {node_id}");
            self.subscribe(Filter::new().author(node_id.npub()).kind(Kind::TextNote))
                .await?;

            let relay_urls: Vec<RelayUrl> = self
                .relays
                .iter()
                .filter_map(|r| RelayUrl::parse(r.as_str()).ok())
                .collect();
            self.publish_relay_list(&node_id, relay_urls).await?;
            self.publish_blossom_server_list(
                &node_id,
                resolve_blossom_servers(&self.blossom_servers, &self.relays),
            )
            .await?;
        }

        Ok(())
    }

    fn has_local_signer(&self, node_id: &NodeId) -> bool {
        self.signers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(node_id)
    }

    async fn sync_relays(&self) -> Result<()> {
        // Check if already running
        if self
            .sync_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            debug!("Relay sync already in progress, skipping");
            return Ok(());
        }

        // Perform sync (always release lock after)
        let result = async {
            if let Some(nostr_store) = &self.nostr_store {
                // Update last_seen_in_config for all user relays
                for relay in &self.relays {
                    nostr_store
                        .update_relay_last_seen(relay, Timestamp::now())
                        .await
                        .map_err(|e| {
                            Error::Message(format!("Failed to update relay last seen: {}", e))
                        })?;
                }

                // Run sync
                crate::relay_sync::sync_pending_relays(self, &self.relays, nostr_store).await?;
            }
            Ok(())
        }
        .await;

        // Always release the lock
        self.sync_running.store(false, Ordering::SeqCst);

        result
    }

    async fn retry_failed_syncs(&self) -> Result<()> {
        use bcr_ebill_api::constants::{RELAY_SYNC_MAX_RETRIES, RELAY_SYNC_RETRY_BATCH_SIZE};

        if let Some(nostr_store) = &self.nostr_store {
            for relay in &self.relays {
                let failed_events = nostr_store
                    .get_pending_relay_retries(relay, RELAY_SYNC_RETRY_BATCH_SIZE)
                    .await
                    .map_err(|e| Error::Message(format!("Failed to get retry events: {}", e)))?;

                for event in failed_events {
                    match self.send_event_to(vec![relay.clone()], &event).await {
                        Ok(_) => {
                            nostr_store
                                .mark_relay_retry_success(relay, &event.id.to_string())
                                .await
                                .map_err(|e| {
                                    Error::Message(format!("Failed to mark retry success: {}", e))
                                })?;
                        }
                        Err(e) => {
                            warn!("Retry failed for event {} to {}: {}", event.id, relay, e);
                            nostr_store
                                .mark_relay_retry_failed(
                                    relay,
                                    &event.id.to_string(),
                                    RELAY_SYNC_MAX_RETRIES,
                                )
                                .await
                                .map_err(|e| {
                                    Error::Message(format!("Failed to mark retry failure: {}", e))
                                })?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn query_file_metadata_events(
        &self,
        _file_hash: &str,
        nostr_hash: &str,
    ) -> Result<Vec<Event>> {
        let filter = Filter::new()
            .kind(FILE_METADATA_KIND)
            .custom_tag(SingleLetterTag::LOWERCASE_X, nostr_hash)
            .limit(50);

        self.fetch_events(filter, Some(SortOrder::Desc), None).await
    }

    async fn has_connected_write_relay(&self) -> bool {
        self.client.relays().await.values().any(|relay| {
            relay.status() == RelayStatus::Connected && relay.capabilities().has_write()
        })
    }

    async fn has_connected_read_relay(&self) -> bool {
        self.client.relays().await.values().any(|relay| {
            relay.status() == RelayStatus::Connected && relay.capabilities().can_read()
        })
    }

    async fn writable_relay_urls(&self) -> Result<Vec<url::Url>> {
        let relays = self.client.relays().await;
        let mut urls = relays
            .into_values()
            .filter(|relay| relay.capabilities().has_write())
            .map(|relay| {
                url::Url::parse(relay.url().as_str()).map_err(|e| Error::Network(e.to_string()))
            })
            .collect::<Result<Vec<_>>>()?;
        urls.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        urls.dedup();
        if urls.is_empty() {
            return Err(Error::Network("No writable Nostr relays configured".into()));
        }
        Ok(urls)
    }

    async fn event_available_on_relay(&self, event_id: EventId, relay: &url::Url) -> Result<bool> {
        Ok(self
            .fetch_event_from_relay(event_id, relay)
            .await?
            .is_some())
    }

    async fn fetch_event_from_relay(
        &self,
        event_id: EventId,
        relay: &url::Url,
    ) -> Result<Option<Event>> {
        let events = self
            .fetch_events(
                Filter::new().id(event_id).limit(1),
                None,
                Some(vec![relay.clone()]),
            )
            .await?;
        Ok(events
            .into_iter()
            .find(|event| event.id == event_id && event.verify().is_ok()))
    }

    async fn fetch_events_from_relay(
        &self,
        filter: Filter,
        relay: &url::Url,
    ) -> Result<Vec<Event>> {
        self.fetch_completed_page(filter, relay, self.default_timeout)
            .await
    }
}

#[derive(Clone)]
pub struct NostrConsumer {
    client: Arc<NostrClient>,
    event_handlers: Vec<Arc<dyn NotificationHandlerApi>>,
    contact_service: Arc<dyn ContactServiceApi>,
    offset_store: Arc<dyn NostrEventOffsetStoreApi>,
    chain_key_service: Arc<dyn ChainKeyServiceApi>,
    file_metadata_processor: Arc<dyn FileMetadataProcessorApi>,
    incoming_verifier: Option<(Arc<IncomingPropagationVerifier>, RelayQuorumSnapshot)>,
    catchup_hints: Option<broadcast::Sender<KnownChain>>,
    dm_processing_lock: Arc<tokio::sync::Mutex<()>>,
}

impl NostrConsumer {
    pub fn new(
        client: Arc<NostrClient>,
        contact_service: Arc<dyn ContactServiceApi>,
        event_handlers: Vec<Arc<dyn NotificationHandlerApi>>,
        offset_store: Arc<dyn NostrEventOffsetStoreApi>,
        chain_key_service: Arc<dyn ChainKeyServiceApi>,
        file_metadata_processor: Arc<dyn FileMetadataProcessorApi>,
    ) -> Self {
        Self {
            client,
            #[allow(clippy::arc_with_non_send_sync)]
            event_handlers,
            contact_service,
            chain_key_service,
            offset_store,
            file_metadata_processor,
            incoming_verifier: None,
            catchup_hints: None,
            dm_processing_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    pub fn with_incoming_verifier(
        mut self,
        verifier: Arc<IncomingPropagationVerifier>,
        snapshot: RelayQuorumSnapshot,
    ) -> Self {
        self.incoming_verifier = Some((verifier, snapshot));
        self
    }

    pub fn with_catchup_hints(mut self, hints: broadcast::Sender<KnownChain>) -> Self {
        self.catchup_hints = Some(hints);
        self
    }

    pub async fn start(&self) -> Result<JoinSet<()>> {
        // move dependencies into thread scope
        let client = self.client.clone();
        let event_handlers = self.event_handlers.clone();
        let contact_service = self.contact_service.clone();
        let offset_store = self.offset_store.clone();
        let file_metadata_processor = self.file_metadata_processor.clone();
        let incoming_verifier = self.incoming_verifier.clone();
        let incoming_for_chain_events = incoming_verifier.clone();
        let chain_keys_for_catchup = self.chain_key_service.clone();
        let dm_processing_lock = self.dm_processing_lock.clone();
        let dm_catchup_client = self.client.clone();
        let dm_catchup_offsets = self.offset_store.clone();
        let dm_catchup_handlers = self.event_handlers.clone();
        let dm_catchup_lock = self.dm_processing_lock.clone();

        let catchup_hints = self.catchup_hints.as_ref().map(|sender| sender.subscribe());

        let mut tasks = JoinSet::new();

        // Get all local node IDs from the single client
        let local_node_ids: Vec<NodeId> = client
            .signers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();

        // Connect the client if not already connected
        if !client.is_connected()
            && let Err(e) = client.connect().await
        {
            error!("Failed to connect Nostr client: {e}");
        }

        // Get the earliest offset timestamp across all identities
        let mut earliest_offset = Timestamp::now();
        if !local_node_ids.is_empty() {
            for node_id in &local_node_ids {
                let offset = get_offset(&offset_store, node_id).await;
                if offset != Timestamp::zero() && offset < earliest_offset {
                    earliest_offset = offset;
                }
            }
        }

        // Subscribe to private events for ALL local identities (single subscription)
        let local_pubkeys: Vec<PublicKey> = local_node_ids.iter().map(|n| n.npub()).collect();

        // create notifications channel before subscriptions so we don't drop events in-between
        let mut notifications = client.client.notifications();

        client
            .subscribe_named(
                "bitcr-incoming-private",
                Filter::new()
                    .pubkeys(local_pubkeys.clone())
                    .kinds(vec![Kind::GiftWrap])
                    .limit(DM_BACKFILL_LIMIT),
            )
            .await
            .map_err(|e| {
                error!("Failed to subscribe to Nostr dm events: {e}");
                Error::Network("Failed to subscribe to Nostr dm events".to_string())
            })?;

        // Subscribe to public events from contacts and local identities
        let mut contacts = contact_service.get_nostr_npubs().await.unwrap_or_default();
        info!("Found {} contacts to subscribe to", contacts.len());
        contacts.append(&mut local_pubkeys.clone());
        info!("Subscribing to public Nostr events");

        client
            .subscribe_named(
                "bitcr-incoming-public",
                Filter::new()
                    .authors(contacts)
                    .kinds(vec![
                        Kind::TextNote,
                        Kind::RelayList,
                        Kind::Metadata,
                        BLOSSOM_SERVER_LIST_KIND,
                        FILE_METADATA_KIND,
                    ])
                    .since(earliest_offset.into()),
            )
            .await
            .map_err(|e| {
                error!("Failed to subscribe to Nostr public events: {e}");
                Error::Network("Failed to subscribe to Nostr public events".to_string())
            })?;

        // Spawn a SINGLE task for the single client
        tasks.spawn(async move {
            let result: Result<()> = async {
                while let Some(note) = notifications.next().await {
                    let ClientNotification::Event { event, .. } = note else {
                        continue;
                    };

                    // handle private events - e.g. chain invites, notifications
                    if event.kind == Kind::GiftWrap {
                        if let Err(e) = process_private_event(
                            client.as_ref(),
                            event.as_ref(),
                            &offset_store,
                            &event_handlers,
                            dm_processing_lock.as_ref(),
                        )
                        .await
                        {
                            warn!("Private event {} was not fully processed: {e}", event.id);
                        }

                        continue;
                    }

                    // handle public events - e.g. chain events
                    if let Err(e) = process_public_event(
                        event.as_ref(),
                        client.as_ref(),
                        incoming_for_chain_events.as_ref(),
                        &offset_store,
                        file_metadata_processor.as_ref(),
                    )
                    .await
                    {
                        warn!("Public event {} was not fully processed: {e}", event.id,);
                    }
                }

                Ok(())
            }
            .await;

            if let Err(e) = result {
                error!("Nostr notification handler failed: {e}");
            }
        });

        // start incoming events verifier
        if let Some((verifier, snapshot)) = incoming_verifier {
            let catchup_verifier = verifier.clone();

            tasks.spawn(async move {
                verifier.run_loop().await;
            });

            tasks.spawn(async move {
                catchup_verifier
                    .run_catchup_loop(chain_keys_for_catchup, snapshot, catchup_hints)
                    .await;
            });
        }

        // start private message background catch-up loop
        tasks.spawn(async move {
            run_private_catchup_loop(
                dm_catchup_client,
                dm_catchup_offsets,
                dm_catchup_handlers,
                dm_catchup_lock,
            )
            .await;
        });

        Ok(tasks)
    }
}

/// Determines which local identity should receive this event.
/// For private messages: tries to decrypt with each signer, returns the one that succeeds.
/// For public chain events: the recipient is determined by chain key ownership (all identities have access).
/// Returns the NodeId of the recipient identity and its signer.
pub async fn determine_recipient(
    event: &Event,
    client: &NostrClient,
) -> Result<(NodeId, Arc<Keys>)> {
    match event.kind {
        Kind::GiftWrap => {
            let keys_to_try = prioritized_signers_for_event(event, &client.signers);
            for (node_id, nostr_keys) in keys_to_try {
                // Try to unwrap the message with one of our signers
                if unwrap_direct_message(event, &nostr_keys).await.is_some() {
                    let signer = client.get_signer(&node_id)?;
                    return Ok((node_id, signer));
                }
            }
            Err(Error::Message(
                "No local identity could decrypt this message".to_string(),
            ))
        }
        Kind::TextNote | Kind::RelayList | Kind::Metadata => any_local_signer(client),
        kind if kind == BLOSSOM_SERVER_LIST_KIND || kind == FILE_METADATA_KIND => {
            any_local_signer(client)
        }
        _ => Err(Error::Message(format!(
            "Unsupported event kind: {:?}",
            event.kind
        ))),
    }
}

fn any_local_signer(client: &NostrClient) -> Result<(NodeId, Arc<Keys>)> {
    let node_id = client
        .signers
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .keys()
        .next()
        .cloned()
        .ok_or_else(|| Error::Message("No local identities available".to_string()))?;
    let signer = client.get_signer(&node_id)?;
    Ok((node_id, signer))
}

fn prioritized_signers_for_event(
    event: &Event,
    signers: &Arc<Mutex<HashMap<NodeId, Arc<Keys>>>>,
) -> Vec<(NodeId, Arc<Keys>)> {
    // Clone the keys to avoid holding the lock during async operations
    let mut keys_to_try: Vec<(NodeId, Arc<Keys>)> = signers
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|(id, keys)| (id.clone(), keys.clone()))
        .collect();

    if event.kind == Kind::GiftWrap
        && let Some(recipient_pubkey) = event.tags.public_keys().next()
        && let Some(index) = keys_to_try
            .iter()
            .position(|(_, nostr_keys)| nostr_keys.public_key() == recipient_pubkey)
        && index != 0
    {
        let matching_signer = keys_to_try.swap_remove(index);
        keys_to_try.insert(0, matching_signer);
    }

    keys_to_try
}

pub async fn handle_direct_message(
    event: Box<Event>,
    signer: &Keys,
    client_id: &NodeId,
    event_handlers: &[Arc<dyn NotificationHandlerApi>],
) -> Result<()> {
    let Some((envelope, sender, _, _)) = unwrap_direct_message(&event, signer).await else {
        return Err(Error::Message(format!(
            "Could not decrypt GiftWrap event {}",
            event.id
        )));
    };
    debug!(
        "Processing private event {} from {} for {}",
        event.id,
        sender.to_hex(),
        client_id
    );
    handle_event(envelope, client_id, event_handlers, Some(sender), event).await
}

/// process a private GiftWrap event
/// processing is serialized using a lock, because this can be called from multiple jobs
/// Returns true when the event was newly processed
pub(crate) async fn process_private_event(
    client: &NostrClient,
    event: &Event,
    offset_store: &Arc<dyn NostrEventOffsetStoreApi>,
    handlers: &[Arc<dyn NotificationHandlerApi>],
    processing_lock: &tokio::sync::Mutex<()>,
) -> Result<bool> {
    // Check if the event should be processed
    if event.kind != Kind::GiftWrap {
        return Ok(false);
    }
    let _guard = processing_lock.lock().await;
    let processed = offset_store
        .is_processed(&event.id.to_hex())
        .await
        .map_err(|e| Error::Persistence(e.to_string()))?;
    if processed {
        return Ok(false);
    }

    event
        .verify()
        .map_err(|e| Error::Message(format!("Invalid GiftWrap signature: {e}")))?;
    // Determine which identity should receive this event and whether to ignore the event because it's malformed
    let (recipient_node_id, signer) = match determine_recipient(event, client).await {
        Ok(recipient) => recipient,
        Err(e) => {
            if let Some(recipient) = malformed_private_recipient(event, client).await {
                offset_store
                    .ignore_private_event(
                        &event.id.to_hex(),
                        event.created_at.into(),
                        &recipient,
                        "Malformed Bitcredit envelope",
                    )
                    .await
                    .map_err(|err| Error::Persistence(err.to_string()))?;
                warn!("Ignoring malformed private event {}", event.id);
                return Ok(false);
            }
            return Err(e);
        }
    };

    // Process event with the correct identity's signer
    handle_direct_message(
        Box::new(event.clone()),
        signer.as_ref(),
        &recipient_node_id,
        handlers,
    )
    .await?;

    // Add event offset for the recipient identity
    add_offset(
        offset_store,
        event.id,
        event.created_at.into(),
        true,
        &recipient_node_id,
    )
    .await?;
    Ok(true)
}

/// process a public event, such as chain events and file metadata
async fn process_public_event(
    event: &Event,
    client: &NostrClient,
    incoming: Option<&(Arc<IncomingPropagationVerifier>, RelayQuorumSnapshot)>,
    offset_store: &Arc<dyn NostrEventOffsetStoreApi>,
    file_metadata_processor: &dyn FileMetadataProcessorApi,
) -> Result<()> {
    match event.kind {
        kind if kind == BLOSSOM_SERVER_LIST_KIND => {
            debug!("Received blossom server list from: {}", event.pubkey);
            return Ok(());
        }
        Kind::RelayList => {
            debug!("Received relay list from: {}", event.pubkey);
            return Ok(());
        }
        Kind::Metadata => {
            debug!("Received metadata from: {}", event.pubkey);
            return Ok(());
        }
        Kind::TextNote => {}
        kind if kind == FILE_METADATA_KIND => {}
        _ => return Ok(()),
    }

    // Deduplicate by exact event ID, not timestamp
    let processed = offset_store
        .is_processed(&event.id.to_hex())
        .await
        .unwrap_or_else(|e| {
            warn!("Could not check event {} offset: {e}", event.id);
            false
        });

    if processed {
        return Ok(());
    }

    match event.kind {
        Kind::TextNote => {
            // Only chain events are enqueued and recorded as processed
            enqueue_public_chain_event(
                event,
                incoming
                    .map(|(verifier, snapshot)| (verifier.clone(), snapshot.clone()))
                    .as_ref(),
                &client.primary_node_id,
                offset_store,
            )
            .await?;
        }
        kind if kind == FILE_METADATA_KIND => {
            let (node_id, _) = any_local_signer(client)?;
            event
                .verify()
                .map_err(|e| Error::Message(format!("Invalid file metadata signature: {e}")))?;
            file_metadata_processor
                .process_file_metadata(Box::new(event.clone()), &node_id)
                .await?;
            add_offset(
                offset_store,
                event.id,
                event.created_at.into(),
                true,
                &node_id,
            )
            .await?;
        }
        _ => {}
    }
    Ok(())
}

async fn get_offset(db: &Arc<dyn NostrEventOffsetStoreApi>, node_id: &NodeId) -> Timestamp {
    db.current_offset(node_id)
        .await
        .map_err(|e| error!("Could not get event offset: {e}"))
        .ok()
        .unwrap_or(Timestamp::zero())
}

pub async fn add_offset(
    db: &Arc<dyn NostrEventOffsetStoreApi>,
    event_id: EventId,
    time: Timestamp,
    success: bool,
    node_id: &NodeId,
) -> Result<()> {
    // an unsuccessful attempt is not a processed event
    if !success {
        return Ok(());
    }
    db.add_event(NostrEventOffset {
        event_id: event_id.to_hex(),
        time,
        success: true,
        node_id: node_id.clone(),
    })
    .await
    .map_err(|e| Error::Persistence(e.to_string()))
}

async fn record_offset_after_enqueue<F>(
    event: &Event,
    node_id: &NodeId,
    offset_store: &Arc<dyn NostrEventOffsetStoreApi>,
    enqueue: F,
) -> Result<()>
where
    F: std::future::Future<Output = Result<()>>,
{
    // offset is only written once the event has actually been enqueued
    enqueue.await?;
    add_offset(
        offset_store,
        event.id,
        event.created_at.into(),
        true,
        node_id,
    )
    .await
}

async fn enqueue_public_chain_event(
    event: &Event,
    incoming: Option<&(Arc<IncomingPropagationVerifier>, RelayQuorumSnapshot)>,
    primary_node_id: &NodeId,
    offset_store: &Arc<dyn NostrEventOffsetStoreApi>,
) -> Result<bool> {
    if event.kind != Kind::TextNote {
        return Ok(false);
    }
    let Some(public) = unwrap_public_chain_event(event)? else {
        return Ok(false);
    };

    if crate::chain_keys::validate_chain_id(
        &public.id,
        public.chain_type,
        primary_node_id.network(),
    )
    .is_err()
    {
        debug!("Ignoring public event with invalid chain ID");
        return Ok(false);
    }

    if public.chain_type == BlockchainType::Identity && public.id != primary_node_id.to_string() {
        debug!("Ignoring foreign identity chain event");
        return Ok(false);
    }

    let Some((verifier, snapshot)) = incoming else {
        return Err(Error::Message(
            "Incoming chain verifier not configured".into(),
        ));
    };
    let chain_type = public.chain_type.to_string();
    record_offset_after_enqueue(
        event,
        primary_node_id,
        offset_store,
        verifier.enqueue(event.clone(), &chain_type, &public.id, snapshot.clone()),
    )
    .await?;
    debug!(
        "Enqueued public chain event {} for {} {}",
        event.id, chain_type, public.id
    );
    Ok(true)
}

/// Handle extracted event with given handlers
async fn handle_event(
    event: EventEnvelope,
    node_id: &NodeId,
    handlers: &[Arc<dyn NotificationHandlerApi>],
    sender: Option<nostr::key::PublicKey>,
    original_event: Box<nostr::event::Event>,
) -> Result<()> {
    // chain events are handled by the incoming verifier
    if matches!(
        &event.event_type,
        EventType::BillChain | EventType::CompanyChain | EventType::IdentityChain
    ) {
        return Err(Error::Message(
            "Chain events must pass incoming relay verification".into(),
        ));
    }
    let event_type = &event.event_type;
    let mut handled = 0;
    let mut first_error = None;

    for handler in handlers {
        if !handler.handles_event(event_type) {
            continue;
        }
        match handler
            .handle_event(event.clone(), node_id, sender, Some(original_event.clone()))
            .await
        {
            Ok(()) => handled += 1,
            Err(e) => {
                error!("Nostr handler failed for {event_type:?}: {e}");
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
    }

    // one failure means that not all required processing completed
    if let Some(e) = first_error {
        return Err(e);
    }

    if handled == 0 {
        return Err(Error::Message(format!(
            "No successful handler for {event_type:?}"
        )));
    }

    trace!("{event_type:?} handled successfully {handled} times");
    Ok(())
}

// nip-01 defines duplicate: as the way to report an event has already been received
fn is_duplicate_response(reason: &str) -> bool {
    reason
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("duplicate:")
}

//
// PRIVATE DM CATCH UP
//

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct PrivateCatchupStats {
    processed: usize,
    already_processed: usize,
    failed: usize,
    invalid: usize,
    incomplete_scans: usize,
}

impl PrivateCatchupStats {
    fn merge(&mut self, other: Self) {
        self.processed += other.processed;
        self.already_processed += other.already_processed;
        self.failed += other.failed;
        self.invalid += other.invalid;
        self.incomplete_scans += other.incomplete_scans;
    }
}

struct PrivatePage {
    events: Vec<Event>,
    // returned by the relay before validation entries - needed for pagination
    raw_len: usize,
    invalid: usize,
}

async fn run_private_catchup_loop(
    client: Arc<NostrClient>,
    offsets: Arc<dyn NostrEventOffsetStoreApi>,
    handlers: Vec<Arc<dyn NotificationHandlerApi>>,
    lock: Arc<tokio::sync::Mutex<()>>,
) {
    let mut interval = tokio::time::interval(DM_CATCHUP_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut next_signer = 0;
    loop {
        interval.tick().await;
        match catch_up_private_once(
            client.as_ref(),
            &offsets,
            &handlers,
            lock.as_ref(),
            &mut next_signer,
        )
        .await
        {
            Ok(stats) if stats != PrivateCatchupStats::default() => {
                info!(
                    "Private Nostr catch-up: {} processed, {} already processed, {} failed attempts, {} invalid responses, {} incomplete scans",
                    stats.processed,
                    stats.already_processed,
                    stats.failed,
                    stats.invalid,
                    stats.incomplete_scans,
                );
            }
            Ok(_) => {}
            Err(e) => {
                warn!("Private Nostr catch-up failed: {e}");
            }
        }
    }
}

async fn connected_private_relays(client: &NostrClient) -> Result<Vec<url::Url>> {
    let mut relays: Vec<url::Url> = client
        .client()
        .await?
        .relays()
        .await
        .into_values()
        .filter(|relay| relay.status() == RelayStatus::Connected)
        .filter_map(|relay| url::Url::parse(relay.url().as_str()).ok())
        .collect();
    relays.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    relays.dedup();
    Ok(relays)
}

async fn catch_up_private_for_recipient(
    client: &NostrClient,
    recipient: &NodeId,
    relays: &[url::Url],
    offsets: &Arc<dyn NostrEventOffsetStoreApi>,
    handlers: &[Arc<dyn NotificationHandlerApi>],
    lock: &tokio::sync::Mutex<()>,
) -> PrivateCatchupStats {
    let mut stats = PrivateCatchupStats::default();
    for relay in relays {
        stats.merge(
            catch_up_private_on_relay(client, relay, recipient, offsets, handlers, lock).await,
        );
    }
    stats
}

async fn catch_up_private_once(
    client: &NostrClient,
    offsets: &Arc<dyn NostrEventOffsetStoreApi>,
    handlers: &[Arc<dyn NotificationHandlerApi>],
    lock: &tokio::sync::Mutex<()>,
    next_signer: &mut usize,
) -> Result<PrivateCatchupStats> {
    let mut signers = client.get_all_node_ids();
    if signers.is_empty() {
        return Ok(PrivateCatchupStats::default());
    }
    signers.sort_by_key(|id| id.to_string());
    let relays = connected_private_relays(client).await?;
    if relays.is_empty() {
        return Ok(PrivateCatchupStats::default());
    }
    // round robin signers
    let count = signers.len().min(DM_CATCHUP_SIGNERS_PER_PASS);
    let start = *next_signer % signers.len();
    *next_signer = (start + count) % signers.len();

    let mut stats = PrivateCatchupStats::default();
    for index in 0..count {
        let recipient = &signers[(start + index) % signers.len()];
        stats.merge(
            catch_up_private_for_recipient(client, recipient, &relays, offsets, handlers, lock)
                .await,
        );
    }
    Ok(stats)
}

/// Private-history recovery for restoration, incomplete scan is recoverable after reinitiliaztion after restore
pub(crate) async fn catch_up_private_for_restore(
    client: &NostrClient,
    offsets: &Arc<dyn NostrEventOffsetStoreApi>,
    handlers: &[Arc<dyn NotificationHandlerApi>],
    lock: &tokio::sync::Mutex<()>,
) -> Result<()> {
    let relays = connected_private_relays(client).await?;
    if relays.is_empty() {
        warn!(
            "Private Restore found no connected relays - catch-up will retry after reinitialization"
        );
        return Ok(());
    }

    let mut scanned: HashSet<NodeId> = HashSet::new();
    let mut stats = PrivateCatchupStats::default();
    loop {
        // update signer list on every pass, since we can add a signer during procession
        let pending = unscanned_private_recipients(client, &scanned);
        if pending.is_empty() {
            break;
        }
        if scanned.len() >= DM_RESTORE_MAX_RECIPIENTS {
            warn!(
                "Private restoration reached the {}-recipient budget",
                DM_RESTORE_MAX_RECIPIENTS
            );
            stats.incomplete_scans += 1;
            break;
        }

        // high safety budget to not spin forever
        let remaining_budget = DM_RESTORE_MAX_RECIPIENTS - scanned.len();
        for recipient in pending.into_iter().take(remaining_budget) {
            scanned.insert(recipient.clone());
            stats.merge(
                catch_up_private_for_recipient(
                    client, &recipient, &relays, offsets, handlers, lock,
                )
                .await,
            );
        }
    }
    info!(
        "Private restoration: {} recipients scanned, {} processed, {} already processed, {} failed attempts, {} invalid responses, {} incomplete scans",
        scanned.len(),
        stats.processed,
        stats.already_processed,
        stats.failed,
        stats.invalid,
        stats.incomplete_scans,
    );
    if stats.failed > 0 || stats.incomplete_scans > 0 {
        warn!(
            "Private restoration partially complete - remaining history will be retried after reinitialization"
        );
    }
    Ok(())
}

/// recipients that were not scanned yet
fn unscanned_private_recipients(client: &NostrClient, scanned: &HashSet<NodeId>) -> Vec<NodeId> {
    let mut recipients: Vec<NodeId> = client
        .get_all_node_ids()
        .into_iter()
        .filter(|id| !scanned.contains(id))
        .collect();
    recipients.sort_by_key(|id| id.to_string());
    recipients
}
/// catch up and replay private messages from one given relay
async fn catch_up_private_on_relay(
    client: &NostrClient,
    relay: &url::Url,
    recipient: &NodeId,
    offsets: &Arc<dyn NostrEventOffsetStoreApi>,
    handlers: &[Arc<dyn NotificationHandlerApi>],
    lock: &tokio::sync::Mutex<()>,
) -> PrivateCatchupStats {
    catch_up_private_on_relay_with(
        relay,
        recipient,
        offsets,
        |since, until| fetch_private_page(client, relay, recipient, since, until),
        |events| process_private_page(client, events, offsets, handlers, lock),
    )
    .await
}

async fn catch_up_private_on_relay_with<Fetch, FetchFuture, Process, ProcessFuture>(
    relay: &url::Url,
    recipient: &NodeId,
    offsets: &Arc<dyn NostrEventOffsetStoreApi>,
    fetch: Fetch,
    process: Process,
) -> PrivateCatchupStats
where
    Fetch: Fn(Option<u64>, u64) -> FetchFuture,
    FetchFuture: std::future::Future<Output = Result<PrivatePage>>,
    Process: Fn(Vec<Event>) -> ProcessFuture,
    ProcessFuture: std::future::Future<Output = PrivateCatchupStats>,
{
    let mut stats = PrivateCatchupStats::default();
    let saved_until = match offsets
        .get_catchup_until(DM_CATCHUP_SCOPE, &recipient.to_string(), relay)
        .await
    {
        Ok(cursor) => cursor,
        Err(e) => {
            warn!("Cannot load private catch-up cursor for {recipient} on {relay}: {e}");
            stats.incomplete_scans += 1;
            return stats;
        }
    };
    // fast path if there's a cursor already - fetch the newest page immediately, so we don't have to wait for the whole catch up
    if saved_until.is_some() {
        let now = Timestamp::now().inner();
        match fetch(None, now).await {
            Ok(page) => {
                stats.invalid += page.invalid;
                stats.merge(process(page.events).await);
            }
            Err(e) => {
                warn!("Could not refresh newest private events for {recipient} on {relay}: {e}");
                stats.incomplete_scans += 1;
            }
        }
    }
    let mut until = saved_until.unwrap_or_else(|| Timestamp::now().inner());

    for _ in 0..DM_CATCHUP_MAX_PAGES_PER_RELAY {
        let page = match fetch(None, until).await {
            Ok(page) => page,
            Err(e) => {
                warn!("Private catch-up fetch failed for {recipient} on {relay}: {e}");
                stats.incomplete_scans += 1;
                return stats;
            }
        };
        stats.invalid += page.invalid;
        if page.raw_len == 0 {
            save_private_catchup_cursor(offsets, recipient, relay, None, &mut stats).await;
            return stats;
        }
        let oldest = page
            .events
            .iter()
            .map(|event| event.created_at.as_secs())
            .min();

        stats.merge(process(page.events).await);
        // A short nonempty response does not necessarily mean history is exhausted.
        // Continue from the oldest timestamp regardless of page length.

        // No valid timestamp anchor - do not advance the cursor
        let Some(oldest) = oldest else {
            warn!(
                "Full private-event page contained no valid pagination anchor for {recipient} on {relay}"
            );
            stats.incomplete_scans += 1;
            return stats;
        };

        // re-query at the boundary so we don't skip events
        let boundary = match fetch(Some(oldest), oldest).await {
            Ok(page) => page,
            Err(e) => {
                warn!("Private catch-up boundary fetch failed for {recipient} on {relay}: {e}");
                stats.incomplete_scans += 1;
                return stats;
            }
        };

        let boundary_count = boundary.raw_len;
        stats.invalid += boundary.invalid;
        stats.merge(process(boundary.events).await);

        // if a boundary disappears, return because we can't advance
        if boundary_count == 0 {
            warn!(
                "Private catch-up boundary disappeared for {recipient} on {relay}, can't advance safely"
            );
            stats.incomplete_scans += 1;
            return stats;
        }

        match next_private_page_until(oldest, boundary_count) {
            Ok(Some(next)) => {
                if !save_private_catchup_cursor(offsets, recipient, relay, Some(next), &mut stats)
                    .await
                {
                    return stats;
                }
                until = next;
            }
            Ok(None) => {
                // Timestamp zero: catchup sweep completed
                save_private_catchup_cursor(offsets, recipient, relay, None, &mut stats).await;
                return stats;
            }
            Err(e) => {
                warn!("Private catch-up cannot advance safely for {recipient} on {relay}: {e}");
                stats.incomplete_scans += 1;
                return stats;
            }
        }
    }
    debug!(
        "Private historical scan for {recipient} on {relay} paused after {} pages - next pass will resume at until={until}",
        DM_CATCHUP_MAX_PAGES_PER_RELAY,
    );
    stats.incomplete_scans += 1;
    stats
}

fn filter_private_page(
    events: Vec<Event>,
    recipient: &NodeId,
    since: Option<u64>,
    until: u64,
) -> Result<PrivatePage> {
    let raw_len = events.len();
    if raw_len > DM_CATCHUP_PAGE_SIZE {
        return Err(Error::Network(
            "Relay exceeded the requested private-event page size".into(),
        ));
    }
    let recipient_pubkey = recipient.npub();
    let mut accepted = Vec::with_capacity(raw_len);
    let mut invalid = 0;
    for event in events {
        let timestamp = event.created_at.as_secs();
        let valid = event.kind == Kind::GiftWrap
            && event.verify().is_ok()
            && event.tags.public_keys().any(|pk| pk == recipient_pubkey)
            && timestamp <= until
            && since.is_none_or(|lower| timestamp >= lower);
        if valid {
            accepted.push(event);
        } else {
            invalid += 1;
            debug!(
                "Skipping invalid or mismatched GiftWrap response {}",
                event.id
            );
        }
    }
    Ok(PrivatePage {
        events: accepted,
        raw_len,
        invalid,
    })
}

/// fetch a page of private dms for a given recipient
async fn fetch_private_page(
    client: &NostrClient,
    relay: &url::Url,
    recipient: &NodeId,
    since: Option<u64>,
    until: u64,
) -> Result<PrivatePage> {
    let mut filter = Filter::new()
        .pubkey(recipient.npub())
        .kind(Kind::GiftWrap)
        .limit(DM_CATCHUP_PAGE_SIZE)
        .until(nostr::types::Timestamp::from_secs(until));
    if let Some(since) = since {
        filter = filter.since(nostr::types::Timestamp::from_secs(since));
    }
    let events = client
        .fetch_completed_page(
            filter,
            relay,
            DM_CATCHUP_QUERY_TIMEOUT.min(client.default_timeout),
        )
        .await?;
    let page = filter_private_page(events, recipient, since, until)?;
    if page.invalid > 0 {
        warn!(
            "Relay {relay} returned {} invalid or mismatched GiftWrap events for {recipient}",
            page.invalid
        );
    }
    Ok(page)
}

/// avoid same-second pagination loss, handling the unlikely case that everything has the same timestamp
fn next_private_page_until(oldest_timestamp: u64, boundary_count: usize) -> Result<Option<u64>> {
    if boundary_count >= DM_CATCHUP_PAGE_SIZE {
        return Err(Error::Network(
            "Too many GiftWrap events share one timestamp - cannot safely advance pagination"
                .into(),
        ));
    }
    Ok(oldest_timestamp.checked_sub(1))
}

/// process a page of private dms, returning stats of what was processed
async fn process_private_page(
    client: &NostrClient,
    events: Vec<Event>,
    offsets: &Arc<dyn NostrEventOffsetStoreApi>,
    handlers: &[Arc<dyn NotificationHandlerApi>],
    lock: &tokio::sync::Mutex<()>,
) -> PrivateCatchupStats {
    let mut stats = PrivateCatchupStats::default();
    for event in events {
        match process_private_event(client, &event, offsets, handlers, lock).await {
            Ok(true) => stats.processed += 1,
            Ok(false) => {
                stats.already_processed += 1;
            }
            Err(e) => {
                stats.failed += 1;
                warn!("Private-event catch-up could not process {}: {e}", event.id);
            }
        }
    }
    stats
}

/// save a catchup cursor for a given relay
async fn save_private_catchup_cursor(
    offsets: &Arc<dyn NostrEventOffsetStoreApi>,
    recipient: &NodeId,
    relay: &url::Url,
    until: Option<u64>,
    stats: &mut PrivateCatchupStats,
) -> bool {
    if let Err(e) = offsets
        .set_catchup_until(DM_CATCHUP_SCOPE, &recipient.to_string(), relay, until)
        .await
    {
        warn!("Could not save private catch-up cursor for {recipient} on {relay}: {e}");
        stats.incomplete_scans += 1;
        return false;
    }
    true
}

/// Returns a known recipient only when decryption succeeds but the decrypted NIP-17 message has malformed bcr-content
async fn malformed_private_recipient(event: &Event, client: &NostrClient) -> Option<NodeId> {
    for (node_id, signer) in prioritized_signers_for_event(event, &client.signers) {
        let Ok(UnwrappedGift { rumor, .. }) =
            UnwrappedGift::from_gift_wrap_async(signer.as_ref(), event).await
        else {
            continue;
        };
        // unknown rumor kinds are left retryable
        if rumor.kind != Kind::PrivateDirectMessage {
            continue;
        }
        if extract_event_envelope(rumor).is_none() {
            return Some(node_id);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::get_mock_relay;
    use super::PrivateCatchupStats;
    use super::filter_private_page;
    use super::process_private_event;
    use super::record_offset_after_enqueue;
    use super::unscanned_private_recipients;
    use super::{DM_CATCHUP_PAGE_SIZE, next_private_page_until};
    use super::{NostrClient, NostrConfig, NostrConsumer, prioritized_signers_for_event};
    use super::{PrivatePage, catch_up_private_on_relay_with};
    use crate::handler::NotificationHandlerApi;
    use crate::nostr::is_duplicate_response;
    use crate::test_utils::{
        MockContactService, MockFileMetadataProcessor, MockNostrEventOffsetStore, TestEventPayload,
        create_test_event, get_identity_public_data,
    };
    use crate::transport::unwrap_direct_message;
    use crate::transport::{create_public_chain_event, unwrap_public_chain_event};
    use crate::{handler::MockNotificationHandlerApi, test_utils::MockChainKeyService};
    use bcr_common::core::NodeId;
    use bcr_ebill_api::service::transport_service::Error;
    use bcr_ebill_api::service::transport_service::transport_client::TransportClientApi;
    use bcr_ebill_core::protocol::Email;
    use bcr_ebill_core::protocol::Timestamp;
    use bcr_ebill_core::protocol::blockchain::BlockchainType;
    use bcr_ebill_core::protocol::blockchain::bill::participant::BillParticipant;
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use bcr_ebill_core::protocol::event::BillEventType;
    use bcr_ebill_core::protocol::event::{Event, EventType};
    use bcr_ebill_core::protocol::{
        blockchain::bill::participant::BillAnonParticipant, event::EventEnvelope,
    };
    use bcr_ebill_persistence::NostrEventOffset;
    use bcr_ebill_persistence::NostrEventOffsetStoreApi;
    use mockall::predicate;
    use nostr::event::Kind;
    use nostr::filter::Filter;
    use nostr::{
        event::{EventBuilder, FinalizeEvent, FinalizeUnsignedEvent},
        nips::nip59::GiftWrapBuilder,
    };
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };
    use tokio::time;

    #[tokio::test]
    async fn test_connect() {
        let relay = get_mock_relay().await;
        let url = url::Url::parse(&relay.url().await.to_string()).unwrap();
        let keys = BcrKeys::new();
        let config = NostrConfig::new(
            keys.clone(),
            vec![url.to_owned()],
            vec![],
            true,
            NodeId::new(keys.pub_key(), bitcoin::Network::Testnet),
        );
        let client = NostrClient::default(&config)
            .await
            .expect("failed to create nostr client");

        client.connect().await.expect("failed to connect");
        assert!(client.is_connected(), "client should be connected");
    }

    #[tokio::test]
    async fn test_has_connected_relays_reflects_runtime_state() {
        let relay = get_mock_relay().await;
        let url = url::Url::parse(&relay.url().await.to_string()).unwrap();
        let keys = BcrKeys::new();
        let config = NostrConfig::new(
            keys.clone(),
            vec![url],
            vec![],
            true,
            NodeId::new(keys.pub_key(), bitcoin::Network::Testnet),
        );
        let client = NostrClient::default(&config)
            .await
            .expect("failed to create nostr client");

        assert!(
            !client.has_connected_relays().await,
            "no relay should be connected before connect"
        );

        client.connect().await.expect("failed to connect");

        let timeout = Duration::from_secs(3);
        let start = Instant::now();
        while !client.has_connected_relays().await && start.elapsed() < timeout {
            time::sleep(Duration::from_millis(50)).await;
        }

        assert!(
            client.has_connected_relays().await,
            "at least one relay should be connected after connect"
        );
    }

    /// When testing with the mock relay we need to be careful. It is always
    /// listening on the same port and will not start multiple times. If we
    /// share the instance tests will fail with events from other tests.
    #[tokio::test]
    async fn test_send_and_receive_event() {
        let relay = get_mock_relay().await;
        let url = url::Url::parse(&relay.url().await.to_string()).unwrap();

        let keys1 = BcrKeys::new();
        let keys2 = BcrKeys::new();

        // given two clients
        let config1 = NostrConfig::new(
            keys1.clone(),
            vec![url.to_owned()],
            vec![],
            true,
            NodeId::new(keys1.pub_key(), bitcoin::Network::Testnet),
        );
        let client1 = NostrClient::default(&config1)
            .await
            .expect("failed to create nostr client 1");

        client1.connect().await.expect("failed to connect");

        let config2 = NostrConfig::new(
            keys2.clone(),
            vec![url.to_owned()],
            vec![],
            true,
            NodeId::new(keys2.pub_key(), bitcoin::Network::Testnet),
        );
        let client2 = NostrClient::default(&config2)
            .await
            .expect("failed to create nostr client 2");

        client2.connect().await.expect("failed to connect");

        // and a contact we want to send an event to
        let contact = get_identity_public_data(
            &NodeId::new(keys2.pub_key(), bitcoin::Network::Testnet),
            &Email::new("payee@example.com").unwrap(),
            vec![&url],
        );
        let event = create_test_event(&BillEventType::BillSigned);

        // expect a handler that is subscribed to the event type w sent
        let mut handler = MockNotificationHandlerApi::new();
        handler
            .expect_handles_event()
            .with(predicate::eq(&EventType::Bill))
            .returning(|_| true);

        // expect a handler receiving the event we sent
        let expected_event: Event<TestEventPayload> = event.clone();
        handler
            .expect_handle_event()
            .withf(move |e, i, _, _| {
                let expected = expected_event.clone();
                let received: Event<TestEventPayload> =
                    e.clone().try_into().expect("could not convert event");
                let valid_type = received.event_type == expected.event_type;
                let valid_payload = received.data.foo == expected.data.foo;
                let valid_identity = *i == NodeId::new(keys2.pub_key(), bitcoin::Network::Testnet);
                valid_type && valid_payload && valid_identity
            })
            .returning(|_, _, _, _| Ok(()));

        let mut offset_store = MockNostrEventOffsetStore::new();

        // expect the offset store to return the current offset once on start
        offset_store
            .expect_current_offset()
            .returning(|_| Ok(Timestamp::new(1000).unwrap()))
            .once();

        // should also check if the event has been processed already
        offset_store
            .expect_is_processed()
            .withf(|e: &str| !e.is_empty())
            .returning(|_| Ok(false))
            .once();

        // when done processing the event, add it to the offset store
        offset_store
            .expect_add_event()
            .withf(|e: &NostrEventOffset| e.success)
            .returning(|_| Ok(()))
            .once();

        let chain_key_store = MockChainKeyService::new();
        let contact_service = MockContactService::new();

        // we start the consumer
        let consumer = NostrConsumer::new(
            Arc::new(client2),
            Arc::new(contact_service),
            vec![Arc::new(handler)],
            Arc::new(offset_store),
            Arc::new(chain_key_store),
            Arc::new(MockFileMetadataProcessor::new()),
        );

        // run in a local set
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async move {
                let handle = tokio::task::spawn_local(async move {
                    consumer
                        .start()
                        .await
                        .expect("failed to start nostr consumer");
                });
                // and send an event
                let node_id1 = NodeId::new(keys1.pub_key(), bitcoin::Network::Testnet);
                client1
                    .send_private_event(
                        &node_id1,
                        &BillParticipant::Ident(contact),
                        event.try_into().expect("could not convert event"),
                    )
                    .await
                    .expect("failed to send event");

                // give it a little bit of time to process the event
                time::sleep(Duration::from_millis(100)).await;
                handle.abort();
            })
            .await;
    }

    #[tokio::test]
    async fn test_multi_identity_client() {
        let relay = get_mock_relay().await;
        let url = url::Url::parse(&relay.url().await.to_string()).unwrap();

        let keys1 = BcrKeys::new();
        let keys2 = BcrKeys::new();
        let node_id1 = NodeId::new(keys1.pub_key(), bitcoin::Network::Testnet);
        let node_id2 = NodeId::new(keys2.pub_key(), bitcoin::Network::Testnet);

        let identities = vec![
            (node_id1.clone(), keys1.clone()),
            (node_id2.clone(), keys2.clone()),
        ];

        let client = NostrClient::new(
            identities,
            vec![url],
            vec![],
            Duration::from_secs(20),
            None,
            1,
            None,
        )
        .await
        .expect("failed to create multi-identity client");

        // Should be able to get signer for each identity
        assert!(client.get_signer(&node_id1).is_ok());
        assert!(client.get_signer(&node_id2).is_ok());

        // Should fail for unknown identity
        let unknown = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        assert!(client.get_signer(&unknown).is_err());
    }

    #[tokio::test]
    async fn test_send_private_event_with_sender_node_id() {
        let relay = get_mock_relay().await;
        let url = url::Url::parse(&relay.url().await.to_string()).unwrap();

        let keys1 = BcrKeys::new();
        let keys2 = BcrKeys::new();
        let node_id1 = NodeId::new(keys1.pub_key(), bitcoin::Network::Testnet);
        let node_id2 = NodeId::new(keys2.pub_key(), bitcoin::Network::Testnet);

        let identities = vec![
            (node_id1.clone(), keys1.clone()),
            (node_id2.clone(), keys2.clone()),
        ];

        let client = NostrClient::new(
            identities,
            vec![url.clone()],
            vec![],
            Duration::from_secs(20),
            None,
            1,
            None,
        )
        .await
        .expect("failed to create client");

        client.connect().await.expect("failed to connect");

        let recipient = get_identity_public_data(
            &node_id2,
            &Email::new("recipient@example.com").unwrap(),
            vec![&url],
        );
        let event = create_test_event(&BillEventType::BillSigned);

        // NIP-17 now supports multi-identity clients via manual gift wrap construction
        let result = client
            .send_private_event(
                &node_id1,
                &BillParticipant::Ident(recipient),
                event.try_into().unwrap(),
            )
            .await;

        assert!(
            result.is_ok(),
            "NIP-17 should work for multi-identity clients: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_prioritized_signers_for_gift_wrap_uses_tagged_recipient_first() {
        let sender_keys = BcrKeys::new();
        let recipient_keys = BcrKeys::new();
        let other_keys = BcrKeys::new();

        let recipient_node_id = NodeId::new(recipient_keys.pub_key(), bitcoin::Network::Testnet);
        let other_node_id = NodeId::new(other_keys.pub_key(), bitcoin::Network::Testnet);

        let signers = Arc::new(Mutex::new(HashMap::from([
            (other_node_id.clone(), Arc::new(other_keys.get_nostr_keys())),
            (
                recipient_node_id.clone(),
                Arc::new(recipient_keys.get_nostr_keys()),
            ),
        ])));

        let rumor = EventBuilder::new(nostr::event::Kind::TextNote, "test")
            .finalize_unsigned(sender_keys.get_nostr_keys().public_key());
        let event = GiftWrapBuilder::new(recipient_keys.get_nostr_keys().public_key(), rumor)
            .finalize(&sender_keys.get_nostr_keys())
            .expect("failed to build gift wrap event");

        let prioritized = prioritized_signers_for_event(&event, &signers);

        assert_eq!(prioritized.len(), 2);
        assert_eq!(prioritized[0].0, recipient_node_id);
        assert_eq!(prioritized[1].0, other_node_id);
    }

    #[tokio::test]
    async fn test_prioritized_signers_for_gift_wrap_keeps_fallback_when_tagged_recipient_missing() {
        let sender_keys = BcrKeys::new();
        let remote_recipient_keys = BcrKeys::new();
        let first_local_keys = BcrKeys::new();
        let second_local_keys = BcrKeys::new();

        let first_local_node_id =
            NodeId::new(first_local_keys.pub_key(), bitcoin::Network::Testnet);
        let second_local_node_id =
            NodeId::new(second_local_keys.pub_key(), bitcoin::Network::Testnet);

        let signers = Arc::new(Mutex::new(HashMap::from([
            (
                first_local_node_id.clone(),
                Arc::new(first_local_keys.get_nostr_keys()),
            ),
            (
                second_local_node_id.clone(),
                Arc::new(second_local_keys.get_nostr_keys()),
            ),
        ])));

        let rumor = EventBuilder::new(nostr::event::Kind::TextNote, "test")
            .finalize_unsigned(sender_keys.get_nostr_keys().public_key());
        let event =
            GiftWrapBuilder::new(remote_recipient_keys.get_nostr_keys().public_key(), rumor)
                .finalize(&sender_keys.get_nostr_keys())
                .expect("failed to build gift wrap event");

        let prioritized = prioritized_signers_for_event(&event, &signers);

        assert_eq!(prioritized.len(), 2);
        assert!(
            prioritized
                .iter()
                .any(|(node_id, _)| *node_id == first_local_node_id)
        );
        assert!(
            prioritized
                .iter()
                .any(|(node_id, _)| *node_id == second_local_node_id)
        );
        assert!(prioritized.iter().all(|(_, keys)| {
            keys.public_key() != remote_recipient_keys.get_nostr_keys().public_key()
        }));
    }

    #[tokio::test]
    async fn test_publish_and_fetch_blossom_server_list() {
        let relay = get_mock_relay().await;
        let relay_url = url::Url::parse(&relay.url().await.to_string()).unwrap();

        let sender_keys = BcrKeys::new();
        let sender_node_id = NodeId::new(sender_keys.pub_key(), bitcoin::Network::Testnet);
        let sender_config = NostrConfig::new(
            sender_keys.clone(),
            vec![relay_url.clone()],
            vec![],
            true,
            sender_node_id.clone(),
        );
        let sender = NostrClient::default(&sender_config).await.unwrap();
        sender.connect().await.unwrap();

        let receiver_keys = BcrKeys::new();
        let receiver_node_id = NodeId::new(receiver_keys.pub_key(), bitcoin::Network::Testnet);
        let receiver_config = NostrConfig::new(
            receiver_keys,
            vec![relay_url.clone()],
            vec![],
            true,
            receiver_node_id,
        );
        let receiver = NostrClient::default(&receiver_config).await.unwrap();
        receiver.connect().await.unwrap();

        let expected = vec![
            url::Url::parse("https://blossom-one.example.com").unwrap(),
            url::Url::parse("https://blossom-two.example.com").unwrap(),
        ];

        sender
            .publish_blossom_server_list(&sender_node_id, expected.clone())
            .await
            .unwrap();
        time::sleep(Duration::from_millis(100)).await;

        let fetched = receiver
            .fetch_blossom_server_list(sender_node_id.npub(), vec![relay_url])
            .await
            .unwrap();

        assert_eq!(fetched, expected);
    }

    #[tokio::test]
    async fn test_nostr_consumer_single_client_multi_identity() {
        let relay = get_mock_relay().await;
        let url = url::Url::parse(&relay.url().await.to_string()).unwrap();

        // Create two identities
        let keys1 = BcrKeys::new();
        let keys2 = BcrKeys::new();
        let node_id1 = NodeId::new(keys1.pub_key(), bitcoin::Network::Testnet);
        let node_id2 = NodeId::new(keys2.pub_key(), bitcoin::Network::Testnet);

        // Create single client with multiple identities
        let identities = vec![
            (node_id1.clone(), keys1.clone()),
            (node_id2.clone(), keys2.clone()),
        ];

        let client = Arc::new(
            NostrClient::new(
                identities,
                vec![url.clone()],
                vec![],
                Duration::from_secs(20),
                None,
                1,
                None,
            )
            .await
            .expect("failed to create multi-identity client"),
        );

        // Create mock services for NostrConsumer with expectations
        let mut contact_service = MockContactService::new();
        contact_service
            .expect_get_nostr_npubs()
            .returning(|| Ok(vec![]));

        let mut offset_store = MockNostrEventOffsetStore::new();
        // Set expectations for both node IDs
        offset_store
            .expect_current_offset()
            .returning(|_| Ok(Timestamp::zero()));

        let chain_key_service = Arc::new(MockChainKeyService::new());

        // Create NostrConsumer with single client (not Vec of clients)
        let consumer = NostrConsumer::new(
            client,
            Arc::new(contact_service),
            vec![],
            Arc::new(offset_store),
            chain_key_service,
            Arc::new(MockFileMetadataProcessor::new()),
        );

        // Verify consumer can start and subscribe to events for all identities
        let mut tasks = consumer.start().await.expect("failed to start consumer");

        // Clean up tasks
        tasks.abort_all();
    }

    #[tokio::test]
    async fn prepare_private_event_creates_signed_giftwrap_without_sending() {
        let sender_keys = BcrKeys::new();
        let recipient_keys = BcrKeys::new();
        let sender_id = NodeId::new(sender_keys.pub_key(), bitcoin::Network::Testnet);
        let recipient_id = NodeId::new(recipient_keys.pub_key(), bitcoin::Network::Testnet);
        let relay_a = url::Url::parse("wss://relay-a.example").unwrap();
        let relay_b = url::Url::parse("wss://relay-b.example").unwrap();
        let client = NostrClient::new(
            vec![(sender_id.clone(), sender_keys.clone())],
            vec![relay_a.clone(), relay_b.clone()],
            vec![],
            Duration::from_secs(2),
            None,
            1,
            None,
        )
        .await
        .unwrap();
        let recipient = BillParticipant::Anon(BillAnonParticipant {
            node_id: recipient_id,
            nostr_relays: vec![relay_b.clone(), relay_a.clone(), relay_b.clone()],
        });
        let envelope = EventEnvelope {
            event_type: EventType::BillChainInvite,
            version: "1.0".to_owned(),
            data: vec![1, 2, 3, 4],
        };
        assert!(!client.is_connected());
        let prepared = client
            .prepare_private_event(&sender_id, &recipient, envelope.clone())
            .await
            .unwrap();

        // preparing must not initiate a connection
        assert!(!client.is_connected());
        // signed NIP-17 GiftWrap was created
        assert_eq!(prepared.event.kind, Kind::GiftWrap);
        // relays are sorted and deduplicated
        assert_eq!(prepared.target_relays, vec![relay_a, relay_b],);
        // recipient can decrypt the event
        let recipient_nostr_keys = recipient_keys.get_nostr_keys();
        let (decoded, sender, _, _) = unwrap_direct_message(&prepared.event, &recipient_nostr_keys)
            .await
            .expect("recipient must be able to decrypt the GiftWrap");
        assert_eq!(decoded.event_type, envelope.event_type);
        assert_eq!(decoded.version, envelope.version);
        assert_eq!(decoded.data, envelope.data);
        assert_eq!(sender, sender_keys.get_nostr_keys().public_key(),);
    }

    #[tokio::test]
    async fn prepare_private_event_uses_pool_relays_as_fallback() {
        let sender_keys = BcrKeys::new();
        let recipient_keys = BcrKeys::new();
        let sender_id = NodeId::new(sender_keys.pub_key(), bitcoin::Network::Testnet);
        let recipient = BillParticipant::Anon(BillAnonParticipant {
            node_id: NodeId::new(recipient_keys.pub_key(), bitcoin::Network::Testnet),
            nostr_relays: vec![],
        });
        let relay = url::Url::parse("wss://relay.example.com").unwrap();
        let client = NostrClient::new(
            vec![(sender_id.clone(), sender_keys)],
            vec![relay.clone()],
            vec![],
            Duration::from_secs(2),
            None,
            1,
            None,
        )
        .await
        .unwrap();
        let envelope = EventEnvelope {
            event_type: EventType::Bill,
            version: "1.0".to_owned(),
            data: vec![1, 2, 3],
        };
        let prepared = client
            .prepare_private_event(&sender_id, &recipient, envelope)
            .await
            .unwrap();
        assert_eq!(prepared.target_relays, vec![relay]);
        assert!(!client.is_connected());
    }

    #[test]
    fn recognize_explicit_duplicate_responses() {
        assert!(is_duplicate_response("duplicate: already have this event"));
        assert!(is_duplicate_response("  DUPLICATE: already stored"));
        assert!(!is_duplicate_response("invalid: bad signature"));
        assert!(!is_duplicate_response("rate-limited: slow down"));
        assert!(!is_duplicate_response("error: relay unavailable"));
    }

    #[tokio::test]
    async fn signed_event_can_be_sent_and_fetched_from_one_relay() {
        let relay = get_mock_relay().await;
        let relay_url = url::Url::parse(&relay.url().await.to_string()).unwrap();
        let keys = BcrKeys::new();
        let node_id = NodeId::new(keys.pub_key(), bitcoin::Network::Testnet);
        let client = NostrClient::new(
            vec![(node_id, keys.clone())],
            vec![relay_url.clone()],
            vec![],
            Duration::from_secs(5),
            None,
            1,
            None,
        )
        .await
        .unwrap();
        client.connect().await.unwrap();
        let event = EventBuilder::new(Kind::TextNote, "single-relay propagation test")
            .finalize(&keys.get_nostr_keys())
            .unwrap();
        client
            .send_signed_event_to_relay(&event, &relay_url)
            .await
            .unwrap();

        // Successful nonempty page
        let found = client
            .fetch_events_from_relay(Filter::new().id(event.id).limit(1), &relay_url)
            .await
            .unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, event.id);

        // Successful empty page
        let unpublished = EventBuilder::new(Kind::TextNote, "unpublished test event")
            .finalize(&keys.get_nostr_keys())
            .unwrap();
        let empty = client
            .fetch_events_from_relay(Filter::new().id(unpublished.id).limit(1), &relay_url)
            .await
            .unwrap();
        assert!(empty.is_empty());
        // Disconnect an existing relay, not just an unknown URL
        client
            .client()
            .await
            .unwrap()
            .disconnect_relay(relay_url.as_str())
            .await
            .unwrap();
        assert!(
            client
                .fetch_events_from_relay(Filter::new().id(event.id).limit(1), &relay_url,)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn incoming_chain_offset_is_saved_after_enqueue() {
        let event = EventBuilder::new(Kind::TextNote, "test")
            .finalize(&nostr::key::Keys::generate())
            .unwrap();

        let node_id = crate::test_utils::node_id_test();
        let event_id = event.id.to_hex();
        let enqueued = Arc::new(AtomicBool::new(false));
        let check = enqueued.clone();

        let mut offsets = MockNostrEventOffsetStore::new();
        offsets
            .expect_add_event()
            .once()
            .withf(move |offset| {
                check.load(Ordering::SeqCst) && offset.success && offset.event_id == event_id
            })
            .returning(|_| Ok(()));
        let offsets: Arc<dyn NostrEventOffsetStoreApi> = Arc::new(offsets);
        let set = enqueued.clone();
        record_offset_after_enqueue(&event, &node_id, &offsets, async move {
            set.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap();
        assert!(enqueued.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn incoming_chain_enqueue_failure_does_not_save_offset() {
        let event = EventBuilder::new(Kind::TextNote, "test")
            .finalize(&nostr::key::Keys::generate())
            .unwrap();

        let node_id = crate::test_utils::node_id_test();
        let mut offsets = MockNostrEventOffsetStore::new();
        offsets.expect_add_event().never();
        let offsets: Arc<dyn NostrEventOffsetStoreApi> = Arc::new(offsets);
        let result = record_offset_after_enqueue(&event, &node_id, &offsets, async {
            Err(Error::Persistence(
                "simulated incoming store failure".into(),
            ))
        })
        .await;
        assert!(matches!(result, Err(Error::Persistence(_))));
    }

    #[tokio::test]
    async fn incoming_chain_offset_failure_is_reported() {
        let event = EventBuilder::new(Kind::TextNote, "test")
            .finalize(&nostr::key::Keys::generate())
            .unwrap();
        let node_id = crate::test_utils::node_id_test();
        let mut offsets = MockNostrEventOffsetStore::new();
        offsets.expect_add_event().once().returning(|_| {
            Err(bcr_ebill_persistence::Error::InvalidData(
                "offset write failed".into(),
            ))
        });
        let offsets: Arc<dyn NostrEventOffsetStoreApi> = Arc::new(offsets);
        let result =
            record_offset_after_enqueue(&event, &node_id, &offsets, async { Ok(()) }).await;
        assert!(matches!(
            result,
            Err(Error::Persistence(message))
                if message.contains("offset write failed")
        ));
    }

    #[test]
    fn public_chain_event_can_be_identified_without_keys() {
        let chain_id = crate::test_utils::bill_id_test().to_string();
        let envelope = EventEnvelope {
            event_type: EventType::BillChain,
            version: "1.0".into(),
            data: vec![],
        };
        let event = create_public_chain_event(
            &chain_id,
            envelope,
            Timestamp::now(),
            BlockchainType::Bill,
            None,
            None,
        )
        .unwrap()
        .finalize(&nostr::key::Keys::generate())
        .unwrap();
        let parsed = unwrap_public_chain_event(&event).unwrap().unwrap();
        assert_eq!(parsed.id, chain_id);
        assert_eq!(parsed.chain_type, BlockchainType::Bill);
    }

    #[tokio::test]
    async fn foreign_identity_event_is_ignored_before_enqueue() {
        let keys = BcrKeys::new();
        let foreign_keys = BcrKeys::new();
        let network = bitcoin::Network::Testnet;
        let primary_id = NodeId::new(keys.pub_key(), network);
        let foreign_id = NodeId::new(foreign_keys.pub_key(), network);
        let envelope = EventEnvelope {
            event_type: EventType::IdentityChain,
            version: "1.0".into(),
            data: vec![],
        };
        let event = create_public_chain_event(
            &foreign_id.to_string(),
            envelope,
            Timestamp::now(),
            BlockchainType::Identity,
            None,
            None,
        )
        .unwrap()
        .finalize(&foreign_keys.get_nostr_keys())
        .unwrap();
        let offsets: Arc<dyn NostrEventOffsetStoreApi> = Arc::new(MockNostrEventOffsetStore::new());

        // No verifier is configured and no offset writes are expected. The event must be ignored first
        assert!(
            !super::enqueue_public_chain_event(&event, None, &primary_id, &offsets,)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn failed_invite_handler_is_not_hidden_by_logging() {
        let mut logger = MockNotificationHandlerApi::new();
        logger.expect_handles_event().returning(|_| true);
        logger
            .expect_handle_event()
            .once()
            .returning(|_, _, _, _| Ok(()));
        let mut invite_handler = MockNotificationHandlerApi::new();
        invite_handler
            .expect_handles_event()
            .returning(|event_type| event_type == &EventType::BillChainInvite);
        invite_handler
            .expect_handle_event()
            .once()
            .returning(|_, _, _, _| {
                Err(Error::Persistence("simulated key storage failure".into()))
            });
        let handlers: Vec<Arc<dyn NotificationHandlerApi>> =
            vec![Arc::new(logger), Arc::new(invite_handler)];
        let envelope = EventEnvelope {
            event_type: EventType::BillChainInvite,
            version: "1.0".into(),
            data: vec![],
        };
        let original = EventBuilder::new(Kind::TextNote, "test")
            .finalize(&nostr::key::Keys::generate())
            .unwrap();
        let result = super::handle_event(
            envelope,
            &crate::test_utils::node_id_test(),
            &handlers,
            None,
            Box::new(original),
        )
        .await;
        assert!(matches!(result, Err(Error::Persistence(_))));
    }

    #[tokio::test]
    async fn failed_private_event_can_be_replayed_successfully() {
        let sender_keys = BcrKeys::new();
        let recipient_keys = BcrKeys::new();
        let sender_id = NodeId::new(sender_keys.pub_key(), bitcoin::Network::Testnet);
        let recipient_id = NodeId::new(recipient_keys.pub_key(), bitcoin::Network::Testnet);
        let relay = url::Url::parse("wss://relay.example.com").unwrap();
        let sender = NostrClient::new(
            vec![(sender_id.clone(), sender_keys)],
            vec![relay.clone()],
            vec![],
            Duration::from_secs(2),
            None,
            1,
            None,
        )
        .await
        .unwrap();
        let receiver = NostrClient::new(
            vec![(recipient_id.clone(), recipient_keys)],
            vec![relay],
            vec![],
            Duration::from_secs(2),
            None,
            1,
            None,
        )
        .await
        .unwrap();
        let participant = BillParticipant::Anon(BillAnonParticipant {
            node_id: recipient_id,
            nostr_relays: vec![],
        });
        let prepared = sender
            .prepare_private_event(
                &sender_id,
                &participant,
                EventEnvelope {
                    event_type: EventType::BillChainInvite,
                    version: "1.0".into(),
                    data: vec![1, 2, 3],
                },
            )
            .await
            .unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let handler_attempts = attempts.clone();

        let mut handler = MockNotificationHandlerApi::new();
        handler
            .expect_handles_event()
            .returning(|kind| kind == &EventType::BillChainInvite);
        handler
            .expect_handle_event()
            .times(2)
            .returning(move |_, _, _, _| {
                if handler_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(Error::Persistence("temporary key store failure".into()))
                } else {
                    Ok(())
                }
            });

        let handlers: Vec<Arc<dyn NotificationHandlerApi>> = vec![Arc::new(handler)];
        let mut offsets = MockNostrEventOffsetStore::new();
        offsets
            .expect_is_processed()
            .times(2)
            .returning(|_| Ok(false));
        // Only the successful second attempt saves an offset
        offsets
            .expect_add_event()
            .once()
            .withf(|offset| offset.success)
            .returning(|_| Ok(()));
        let offsets: Arc<dyn NostrEventOffsetStoreApi> = Arc::new(offsets);
        let lock = tokio::sync::Mutex::new(());
        let first =
            process_private_event(&receiver, &prepared.event, &offsets, &handlers, &lock).await;
        assert!(matches!(first, Err(Error::Persistence(_))));
        let second = process_private_event(&receiver, &prepared.event, &offsets, &handlers, &lock)
            .await
            .unwrap();
        assert!(second);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn private_catchup_timestamp_boundary_is_safe() {
        assert_eq!(
            next_private_page_until(1000, DM_CATCHUP_PAGE_SIZE - 1,).unwrap(),
            Some(999),
        );
        // more events at timestamp 1000
        assert!(next_private_page_until(1000, DM_CATCHUP_PAGE_SIZE,).is_err());
        assert_eq!(next_private_page_until(0, 1).unwrap(), None,);
    }

    #[test]
    fn private_page_skips_invalid_events_but_keeps_valid_ones() {
        let sender = BcrKeys::new();
        let recipient_keys = BcrKeys::new();
        let recipient = NodeId::new(recipient_keys.pub_key(), bitcoin::Network::Testnet);
        let rumor = EventBuilder::new(Kind::TextNote, "test")
            .finalize_unsigned(sender.get_nostr_keys().public_key());
        let valid = GiftWrapBuilder::new(recipient.npub(), rumor)
            .finalize(&sender.get_nostr_keys())
            .unwrap();
        let mut bad_signature = valid.clone();
        bad_signature.content.push_str("tampered");
        let wrong_kind = EventBuilder::new(Kind::TextNote, "not a gift wrap")
            .finalize(&nostr::key::Keys::generate())
            .unwrap();
        let page = filter_private_page(
            vec![bad_signature, valid.clone(), wrong_kind],
            &recipient,
            None,
            u64::MAX,
        )
        .unwrap();
        assert_eq!(page.raw_len, 3);
        assert_eq!(page.invalid, 2);
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].id, valid.id);
    }

    #[test]
    fn full_invalid_private_page_has_no_safe_pagination_anchor() {
        let recipient_keys = BcrKeys::new();
        let recipient = NodeId::new(recipient_keys.pub_key(), bitcoin::Network::Testnet);
        let wrong_kind = EventBuilder::new(Kind::TextNote, "wrong kind")
            .finalize(&nostr::key::Keys::generate())
            .unwrap();
        let page = filter_private_page(
            vec![wrong_kind; DM_CATCHUP_PAGE_SIZE],
            &recipient,
            None,
            u64::MAX,
        )
        .unwrap();
        assert_eq!(page.raw_len, DM_CATCHUP_PAGE_SIZE);
        assert_eq!(page.invalid, DM_CATCHUP_PAGE_SIZE);
        assert!(page.events.is_empty());
        // A full page without usable events cannot safely determine which older timestamp to request
        let oldest = page.events.iter().map(|e| e.created_at.as_secs()).min();
        assert!(oldest.is_none());
    }

    #[tokio::test]
    async fn private_catchup_resumes_from_saved_until() {
        let keys = BcrKeys::new();
        let recipient = NodeId::new(keys.pub_key(), bitcoin::Network::Testnet);
        let relay = url::Url::parse("wss://r1.example").unwrap();
        let mut store = MockNostrEventOffsetStore::new();
        store
            .expect_get_catchup_until()
            .once()
            .returning(|scope, subject, _relay| {
                assert_eq!(scope, "giftwrap");
                assert!(!subject.is_empty());
                Ok(Some(1000))
            });
        store
            .expect_set_catchup_until()
            .once()
            .returning(|scope, _subject, _relay, next| {
                assert_eq!(scope, "giftwrap");
                assert_eq!(next, None); // Exhausted catchup resets sweep
                Ok(())
            });
        let offsets: Arc<dyn NostrEventOffsetStoreApi> = Arc::new(store);
        let calls = Arc::new(Mutex::new(Vec::<(Option<u64>, u64)>::new()));
        let observed = calls.clone();
        let stats = catch_up_private_on_relay_with(
            &relay,
            &recipient,
            &offsets,
            move |since, until| {
                observed.lock().unwrap().push((since, until));
                async {
                    Ok(PrivatePage {
                        events: vec![],
                        raw_len: 0,
                        invalid: 0,
                    })
                }
            },
            |_events| async { PrivateCatchupStats::default() },
        )
        .await;
        assert_eq!(stats.incomplete_scans, 0);
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2, "newest-page refresh + saved-cursor scan");
        assert_eq!(calls[0].0, None);
        assert!(
            calls[0].1 >= 1000,
            "first fetch refreshes the newest events"
        );
        assert_eq!(calls[1], (None, 1000));
    }

    #[tokio::test]
    async fn private_catchup_does_not_advance_after_boundary_failure() {
        let keys = BcrKeys::new();
        let recipient = NodeId::new(keys.pub_key(), bitcoin::Network::Testnet);
        let relay = url::Url::parse("wss://r1.example").unwrap();
        let anchor = EventBuilder::new(Kind::TextNote, "pagination anchor")
            .finalize(&nostr::key::Keys::generate())
            .unwrap();
        let oldest = anchor.created_at.as_secs();
        let saved_until = oldest + 10;
        let mut store = MockNostrEventOffsetStore::new();
        store
            .expect_get_catchup_until()
            .once()
            .returning(move |_, _, _| Ok(Some(saved_until)));
        // unsafe boundary must leave the previous durable cursor intact
        store.expect_set_catchup_until().never();
        let offsets: Arc<dyn NostrEventOffsetStoreApi> = Arc::new(store);
        let calls = Arc::new(Mutex::new(Vec::<(Option<u64>, u64)>::new()));
        let observed = calls.clone();
        let stats = catch_up_private_on_relay_with(
            &relay,
            &recipient,
            &offsets,
            move |since, until| {
                let call = {
                    let mut requests = observed.lock().unwrap();
                    requests.push((since, until));
                    requests.len()
                };
                let event = anchor.clone();
                async move {
                    match call {
                        1 => Ok(PrivatePage {
                            events: vec![],
                            raw_len: 0,
                            invalid: 0,
                        }),
                        2 => Ok(PrivatePage {
                            events: vec![event],
                            raw_len: DM_CATCHUP_PAGE_SIZE,
                            // full response with one valid anchor
                            invalid: DM_CATCHUP_PAGE_SIZE - 1,
                        }),
                        3 => Err(Error::Network("boundary query failed".into())),
                        _ => panic!("unexpected private catch-up query #{call}"),
                    }
                }
            },
            |events| async move {
                PrivateCatchupStats {
                    processed: events.len(),
                    ..PrivateCatchupStats::default()
                }
            },
        )
        .await;
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[1], (None, saved_until));
        assert_eq!(calls[2], (Some(oldest), oldest));
        assert_eq!(stats.processed, 1, "valid events retain their progress");
        assert_eq!(stats.incomplete_scans, 1);
    }

    #[test]
    fn private_catchup_stats_preserve_partial_success() {
        let mut total = PrivateCatchupStats {
            processed: 3,
            already_processed: 5,
            failed: 1,
            invalid: 0,
            incomplete_scans: 0,
        };
        total.merge(PrivateCatchupStats {
            processed: 2,
            already_processed: 0,
            failed: 1,
            invalid: 2,
            incomplete_scans: 1,
        });
        assert_eq!(total.processed, 5);
        assert_eq!(total.already_processed, 5);
        assert_eq!(total.failed, 2);
        assert_eq!(total.invalid, 2);
        assert_eq!(total.incomplete_scans, 1);
    }

    #[tokio::test]
    async fn restore_recipient_selection_detects_new_company_signers() {
        let primary_keys = BcrKeys::new();
        let company_keys = BcrKeys::new();
        let primary_id = NodeId::new(primary_keys.pub_key(), bitcoin::Network::Testnet);
        let company_id = NodeId::new(company_keys.pub_key(), bitcoin::Network::Testnet);
        let client = NostrClient::new(
            vec![(primary_id.clone(), primary_keys)],
            vec![],
            vec![],
            Duration::from_secs(2),
            None,
            1,
            None,
        )
        .await
        .unwrap();
        let mut scanned = HashSet::new();
        // at first, only primary identity is available
        assert_eq!(
            unscanned_private_recipients(&client, &scanned),
            vec![primary_id.clone()],
        );
        scanned.insert(primary_id);
        // successful company-invite processing
        client
            .add_identity(company_id.clone(), company_keys)
            .unwrap();
        // next iteration must discover the new signer
        assert_eq!(
            unscanned_private_recipients(&client, &scanned),
            vec![company_id.clone()],
        );
        scanned.insert(company_id);
        assert!(unscanned_private_recipients(&client, &scanned).is_empty());
    }

    #[tokio::test]
    async fn chain_events_never_reach_notification_handlers() {
        let mut handler = MockNotificationHandlerApi::new();
        // Chain events must be rejected before being dispatched
        handler.expect_handles_event().never();
        handler.expect_handle_event().never();
        let handlers: Vec<Arc<dyn NotificationHandlerApi>> = vec![Arc::new(handler)];
        let original = EventBuilder::new(Kind::TextNote, "test")
            .finalize(&nostr::key::Keys::generate())
            .unwrap();

        let node_id = crate::test_utils::node_id_test();
        for event_type in [
            EventType::BillChain,
            EventType::CompanyChain,
            EventType::IdentityChain,
        ] {
            let envelope = EventEnvelope {
                event_type,
                version: "1.0".into(),
                data: vec![],
            };
            let result = super::handle_event(
                envelope,
                &node_id,
                &handlers,
                None,
                Box::new(original.clone()),
            )
            .await;
            assert!(matches!(
                result,
                Err(Error::Message(message))
                    if message.contains(
                        "Chain events must pass incoming relay verification"
                    )
            ));
        }
    }

    #[tokio::test]
    async fn private_catchup_short_pages_reach_older_events() {
        // Fetch event at timestamp 1000
        // Confirm the 1000 boundary, save cursor 999
        // Fetch event at timestamp 900
        // Confirm the 900 boundary, save cursor 899
        // Fetch at 899, receive empty history, reset cursor
        let keys = BcrKeys::new();
        let recipient = NodeId::new(keys.pub_key(), bitcoin::Network::Testnet);
        let relay = url::Url::parse("wss://r1.example").unwrap();
        let signer = nostr::key::Keys::generate();
        let event_at = |secs: u64, content: &str| {
            EventBuilder::new(Kind::GiftWrap, content)
                .custom_created_at(nostr::types::Timestamp::from_secs(secs))
                .finalize(&signer)
                .unwrap()
        };
        let newer = event_at(1000, "newer");
        let older = event_at(900, "older");
        let writes = Arc::new(Mutex::new(Vec::<Option<u64>>::new()));
        let writes_for_store = writes.clone();
        let mut store = MockNostrEventOffsetStore::new();
        store
            .expect_get_catchup_until()
            .once()
            .returning(|_, _, _| Ok(None));
        store
            .expect_set_catchup_until()
            .times(3)
            .returning(move |_, _, _, until| {
                writes_for_store.lock().unwrap().push(until);
                Ok(())
            });
        let offsets: Arc<dyn NostrEventOffsetStoreApi> = Arc::new(store);
        let queries = Arc::new(Mutex::new(Vec::<(Option<u64>, u64)>::new()));
        let observed = queries.clone();
        let stats = catch_up_private_on_relay_with(
            &relay,
            &recipient,
            &offsets,
            move |since, until| {
                observed.lock().unwrap().push((since, until));
                let events = match (since, until) {
                    (None, t) if t >= 1000 => vec![newer.clone()],
                    (Some(1000), 1000) => vec![newer.clone()],
                    (None, 999) => vec![older.clone()],
                    (Some(900), 900) => vec![older.clone()],
                    (None, 899) => vec![],
                    _ => panic!("Unexpected private query: {since:?}, {until}"),
                };
                async move {
                    Ok(PrivatePage {
                        raw_len: events.len(),
                        events,
                        invalid: 0,
                    })
                }
            },
            |events| async move {
                PrivateCatchupStats {
                    processed: events.len(),
                    ..PrivateCatchupStats::default()
                }
            },
        )
        .await;
        assert_eq!(stats.processed, 4);
        assert_eq!(stats.incomplete_scans, 0);
        assert_eq!(*writes.lock().unwrap(), vec![Some(999), Some(899), None],);
        let queries = queries.lock().unwrap();
        assert_eq!(queries.len(), 5);
        assert!(queries[0].1 >= 1000);
        assert_eq!(
            &queries[1..],
            &[
                (Some(1000), 1000),
                (None, 999),
                (Some(900), 900),
                (None, 899),
            ],
        );
    }
}

/// Internal relay calculation function (pure function for testing)
fn calculate_relay_set_internal(
    user_relays: &[url::Url],
    contacts: &[NostrContact],
    max_relays: Option<usize>,
) -> HashSet<url::Url> {
    let mut relay_set = HashSet::new();

    // Pass 1: Add all user relays (exempt from limit)
    for relay in user_relays {
        relay_set.insert(relay.clone());
    }

    // Filter and sort contacts by trust level
    let mut eligible_contacts: Vec<&NostrContact> = contacts
        .iter()
        .filter(|c| matches!(c.trust_level, TrustLevel::Trusted | TrustLevel::Participant))
        .collect();

    // Sort: Trusted (0) before Participant (1)
    eligible_contacts.sort_by_key(|c| match c.trust_level {
        TrustLevel::Trusted => 0,
        TrustLevel::Participant => 1,
        _ => 2, // unreachable due to filter
    });

    let contact_relay_limit = NOSTR_MAX_RELAYS.min(max_relays.unwrap_or(NOSTR_MAX_RELAYS));
    let user_relay_count = relay_set.len();

    // Pass 2: Add first relay from each contact (priority order)
    for contact in &eligible_contacts {
        let contact_relays_added = relay_set.len() - user_relay_count;
        if contact_relays_added >= contact_relay_limit {
            break;
        }
        if let Some(first_relay) = contact.relays.first() {
            relay_set.insert(first_relay.clone());
        }
    }

    // Pass 3: Fill remaining slots with additional contact relays
    for contact in &eligible_contacts {
        for relay in contact.relays.iter().skip(1) {
            let contact_relays_added = relay_set.len() - user_relay_count;
            if contact_relays_added >= contact_relay_limit {
                return relay_set;
            }
            relay_set.insert(relay.clone());
        }
    }

    relay_set
}

#[cfg(test)]
mod relay_calculation_tests {
    use super::*;
    use bcr_ebill_core::application::nostr_contact::{HandshakeStatus, NostrContact, TrustLevel};

    fn create_test_contact(trust_level: TrustLevel, relays: Vec<&str>) -> NostrContact {
        use bcr_ebill_core::protocol::crypto::BcrKeys;
        let keys = BcrKeys::new();
        let node_id = NodeId::new(keys.pub_key(), bitcoin::Network::Testnet);
        NostrContact {
            npub: node_id.npub(),
            node_id,
            name: None,
            relays: relays.iter().map(|r| url::Url::parse(r).unwrap()).collect(),
            blossom_servers: vec![],
            trust_level,
            handshake_status: HandshakeStatus::None,
            contact_private_key: None,
            mint_url: None,
        }
    }

    #[test]
    fn test_user_relays_always_included() {
        let user_relays = vec![
            url::Url::parse("wss://relay1.com").unwrap(),
            url::Url::parse("wss://relay2.com").unwrap(),
        ];
        let contacts = vec![];
        let max_relays = Some(1); // Very low limit

        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);

        // User relays should all be present despite low limit
        assert_eq!(result.len(), 2);
        assert!(result.contains(&url::Url::parse("wss://relay1.com").unwrap()));
        assert!(result.contains(&url::Url::parse("wss://relay2.com").unwrap()));
    }

    #[test]
    fn test_trusted_contacts_prioritized() {
        let user_relays = vec![];
        let contacts = vec![
            create_test_contact(TrustLevel::Participant, vec!["wss://participant.com"]),
            create_test_contact(TrustLevel::Trusted, vec!["wss://trusted.com"]),
        ];
        let max_relays = Some(1);

        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);

        // Should only include trusted contact's relay (higher priority)
        assert_eq!(result.len(), 1);
        assert!(result.contains(&url::Url::parse("wss://trusted.com").unwrap()));
    }

    #[test]
    fn test_contact_relays_added_when_user_relays_exceed_limit() {
        let user_relays = vec![
            url::Url::parse("wss://user1.com").unwrap(),
            url::Url::parse("wss://user2.com").unwrap(),
            url::Url::parse("wss://user3.com").unwrap(),
        ];
        let contacts = vec![
            create_test_contact(TrustLevel::Trusted, vec!["wss://contact1.com"]),
            create_test_contact(TrustLevel::Trusted, vec!["wss://contact2.com"]),
        ];
        let max_relays = Some(2); // Lower than user relay count

        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);

        // Should have all 3 user relays + 2 contact relays (user relays exempt from limit)
        assert_eq!(result.len(), 5);
        assert!(result.contains(&url::Url::parse("wss://user1.com").unwrap()));
        assert!(result.contains(&url::Url::parse("wss://user2.com").unwrap()));
        assert!(result.contains(&url::Url::parse("wss://user3.com").unwrap()));
        assert!(result.contains(&url::Url::parse("wss://contact1.com").unwrap()));
        assert!(result.contains(&url::Url::parse("wss://contact2.com").unwrap()));
    }

    #[test]
    fn test_one_relay_per_contact_guaranteed() {
        let user_relays = vec![];
        let contacts = vec![
            create_test_contact(
                TrustLevel::Trusted,
                vec!["wss://contact1-relay1.com", "wss://contact1-relay2.com"],
            ),
            create_test_contact(
                TrustLevel::Trusted,
                vec!["wss://contact2-relay1.com", "wss://contact2-relay2.com"],
            ),
            create_test_contact(TrustLevel::Trusted, vec!["wss://contact3-relay1.com"]),
        ];
        let max_relays = Some(3);

        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);

        // Should have exactly 3 relays (first relay from each contact)
        assert_eq!(result.len(), 3);
        assert!(result.contains(&url::Url::parse("wss://contact1-relay1.com").unwrap()));
        assert!(result.contains(&url::Url::parse("wss://contact2-relay1.com").unwrap()));
        assert!(result.contains(&url::Url::parse("wss://contact3-relay1.com").unwrap()));
    }

    #[test]
    fn test_deduplication_across_contacts() {
        let user_relays = vec![];
        let contacts = vec![
            create_test_contact(
                TrustLevel::Trusted,
                vec!["wss://shared.com", "wss://unique1.com"],
            ),
            create_test_contact(
                TrustLevel::Trusted,
                vec!["wss://shared.com", "wss://unique2.com"],
            ),
        ];
        let max_relays = Some(10);

        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);

        // Should only include shared.com once
        assert_eq!(result.len(), 3);
        assert!(result.contains(&url::Url::parse("wss://shared.com").unwrap()));
        assert!(result.contains(&url::Url::parse("wss://unique1.com").unwrap()));
        assert!(result.contains(&url::Url::parse("wss://unique2.com").unwrap()));
    }

    #[test]
    fn test_banned_contacts_excluded() {
        let user_relays = vec![];
        let contacts = vec![
            create_test_contact(TrustLevel::Banned, vec!["wss://banned.com"]),
            create_test_contact(TrustLevel::Trusted, vec!["wss://trusted.com"]),
        ];
        let max_relays = Some(10);

        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);

        assert_eq!(result.len(), 1);
        assert!(result.contains(&url::Url::parse("wss://trusted.com").unwrap()));
        assert!(!result.contains(&url::Url::parse("wss://banned.com").unwrap()));
    }

    #[test]
    fn test_none_trust_level_excluded() {
        let user_relays = vec![];
        let contacts = vec![
            create_test_contact(TrustLevel::None, vec!["wss://unknown.com"]),
            create_test_contact(TrustLevel::Participant, vec!["wss://participant.com"]),
        ];
        let max_relays = Some(10);

        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);

        assert_eq!(result.len(), 1);
        assert!(result.contains(&url::Url::parse("wss://participant.com").unwrap()));
        assert!(!result.contains(&url::Url::parse("wss://unknown.com").unwrap()));
    }

    #[test]
    fn test_no_limit_when_max_relays_none() {
        let user_relays = vec![url::Url::parse("wss://user.com").unwrap()];
        let contacts = vec![
            create_test_contact(
                TrustLevel::Trusted,
                vec!["wss://relay1.com", "wss://relay2.com"],
            ),
            create_test_contact(
                TrustLevel::Trusted,
                vec!["wss://relay3.com", "wss://relay4.com"],
            ),
        ];
        let max_relays = None;

        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);

        // All relays should be included
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn test_empty_contacts() {
        let user_relays = vec![url::Url::parse("wss://user.com").unwrap()];
        let contacts = vec![];
        let max_relays = Some(50);

        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);

        assert_eq!(result.len(), 1);
        assert!(result.contains(&url::Url::parse("wss://user.com").unwrap()));
    }

    #[test]
    fn test_contact_with_no_relays() {
        let user_relays = vec![];
        let mut contact = create_test_contact(TrustLevel::Trusted, vec![]);
        contact.relays = vec![]; // Explicitly no relays
        let contacts = vec![contact];
        let max_relays = Some(10);

        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);

        // Should handle gracefully
        assert_eq!(result.len(), 0);
    }
}

#[cfg(test)]
mod optimistic_broadcast_tests {
    use super::super::test_utils::get_mock_relay;
    use super::{NostrClient, NostrConfig};
    use bcr_common::core::NodeId;
    use bcr_ebill_api::service::transport_service::transport_client::TransportClientApi;
    use bcr_ebill_core::protocol::crypto::BcrKeys;

    #[tokio::test]
    async fn test_relay_ack_threshold_returns_configured_value() {
        let relay = get_mock_relay().await;
        let url = url::Url::parse(&relay.url().await.to_string()).unwrap();
        let keys = BcrKeys::new();
        let config = NostrConfig::new(
            keys.clone(),
            vec![url],
            vec![],
            true,
            NodeId::new(keys.pub_key(), bitcoin::Network::Testnet),
        )
        .with_relay_ack_threshold(3);
        let client = NostrClient::default(&config)
            .await
            .expect("failed to create nostr client");

        assert_eq!(client.relay_ack_threshold(), 3);
    }
}
