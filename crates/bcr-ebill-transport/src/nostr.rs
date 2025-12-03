use crate::{
    chain_keys::ChainKeyServiceApi,
    handler::NotificationHandlerApi,
    transport::{
        chain_filter, create_nip04_event, create_public_chain_event, decrypt_public_chain_event,
        unwrap_direct_message, unwrap_public_chain_event,
    },
};
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    protocol::Timestamp, protocol::blockchain::BlockchainType,
    protocol::blockchain::bill::participant::BillParticipant, protocol::crypto::BcrKeys,
};
use bitcoin::base58;
use log::{debug, error, info, trace, warn};
use nostr::{Keys, nips::nip65::RelayMetadata, signer::NostrSigner};
use nostr_sdk::{
    Alphabet, Client, ClientOptions, Event, EventBuilder, EventId, Filter, Kind, Metadata,
    PublicKey, RelayPoolNotification, RelayUrl, SingleLetterTag, TagKind, TagStandard, ToBech32,
};
use std::sync::{Arc, Mutex, atomic::Ordering};
use std::{collections::HashMap, sync::atomic::AtomicBool, time::Duration};

use bcr_ebill_api::{
    constants::NOSTR_EVENT_TIME_SLACK,
    service::{
        contact_service::ContactServiceApi,
        transport_service::{
            Error, NostrConfig, NostrContactData, Result, transport_client::TransportClientApi,
        },
    },
};
use bcr_ebill_core::{application::ServiceTraitBounds, protocol::event::EventEnvelope};
use bcr_ebill_persistence::{NostrEventOffset, NostrEventOffsetStoreApi};

use tokio::task::JoinSet;
use tokio_with_wasm::alias as tokio;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SortOrder {
    Asc,
    Desc,
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
    default_timeout: Duration,
    connected: Arc<AtomicBool>,
}

impl NostrClient {
    /// Creates a new nostr client with multiple identities sharing a relay pool
    pub async fn new(
        identities: Vec<(NodeId, BcrKeys)>,
        relays: Vec<url::Url>,
        default_timeout: Duration,
    ) -> Result<Self> {
        if identities.is_empty() {
            return Err(Error::Message("At least one identity required".to_string()));
        }

        // Use first identity to construct the underlying Client
        let first_keys = &identities[0].1;
        let options = ClientOptions::new();
        let client = Client::builder()
            .signer(first_keys.get_nostr_keys().clone())
            .opts(options)
            .build();

        // Add all relays to the shared pool
        for relay in &relays {
            client.add_relay(relay).await.map_err(|e| {
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
            default_timeout,
            connected: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Creates a new nostr client with the given config.
    pub async fn default(config: &NostrConfig) -> Result<Self> {
        let identities = vec![(config.node_id.clone(), config.keys.clone())];
        Self::new(identities, config.relays.clone(), config.default_timeout).await
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

    fn use_nip04(&self) -> bool {
        false
    }

    /// Subscribe to some nostr events with a filter
    pub async fn subscribe(&self, subscription: Filter) -> Result<()> {
        self.client()
            .await?
            .subscribe(subscription, None)
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
        let result = self
            .client()
            .await?
            .fetch_metadata(npub, self.default_timeout.to_owned())
            .await
            .map_err(|e| {
                error!("Failed to fetch Nostr metadata: {e}");
                Error::Network("Failed to fetch Nostr metadata".to_string())
            })?;
        Ok(result)
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
                e.tags
                    .filter_standardized(TagKind::SingleLetter(SingleLetterTag::lowercase(
                        Alphabet::R,
                    )))
                    .filter_map(|f| match f {
                        TagStandard::RelayMetadata { relay_url, .. } => Some(relay_url.clone()),
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
        let events = self
            .client()
            .await?
            .fetch_events_from(
                relays.unwrap_or(self.relays.clone()),
                filter,
                self.default_timeout.to_owned(),
            )
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

    pub async fn send_nip04_message(
        &self,
        sender_node_id: &NodeId,
        recipient: &BillParticipant,
        event: EventEnvelope,
    ) -> Result<()> {
        let signer = self.get_signer(sender_node_id)?;
        let public_key = recipient.node_id().npub();
        let message = base58::encode(&borsh::to_vec(&event)?);
        let event = create_nip04_event(&*signer, &public_key, &message).await?;
        let relays = recipient.nostr_relays();
        if !relays.is_empty() {
            if let Err(e) = self
                .client()
                .await?
                .send_event_builder_to(&relays, event)
                .await
            {
                error!("Error sending Nostr message: {e}")
            };
        } else if let Err(e) = self.client().await?.send_event_builder(event).await {
            error!("Error sending Nostr message: {e}")
        }
        Ok(())
    }

    async fn send_nip17_message(
        &self,
        sender_node_id: &NodeId,
        recipient: &BillParticipant,
        event: EventEnvelope,
    ) -> Result<()> {
        // Get the Keys for the specified sender identity
        let sender_keys = self.get_signer(sender_node_id)?;

        let receiver_pubkey = recipient.node_id().npub();
        let message = base58::encode(&borsh::to_vec(&event)?);

        let event = EventBuilder::private_msg(&*sender_keys, receiver_pubkey, message, [])
            .await
            .map_err(|e| {
                error!("Failed to create NIP-17 event: {e}");
                Error::Message(format!("Failed to create NIP-17 event: {e}"))
            })?;

        let relays = recipient.nostr_relays();
        if !relays.is_empty() {
            if let Err(e) = self.client().await?.send_event_to(&relays, &event).await {
                error!("Error sending NIP-17 message to specific relays: {e}");
                return Err(Error::Network(format!(
                    "Failed to send NIP-17 message: {e}"
                )));
            };
        } else if let Err(e) = self.client().await?.send_event(&event).await {
            error!("Error sending NIP-17 message: {e}");
            return Err(Error::Network(format!(
                "Failed to send NIP-17 message: {e}"
            )));
        }

        Ok(())
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
}

impl ServiceTraitBounds for NostrClient {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl TransportClientApi for NostrClient {
    async fn send_private_event(
        &self,
        sender_node_id: &NodeId,
        recipient: &BillParticipant,
        event: EventEnvelope,
    ) -> Result<()> {
        if self.use_nip04() {
            self.send_nip04_message(sender_node_id, recipient, event)
                .await?;
        } else {
            self.send_nip17_message(sender_node_id, recipient, event)
                .await?;
        }
        Ok(())
    }

    async fn send_public_chain_event(
        &self,
        sender_node_id: &NodeId,
        id: &str,
        blockchain: BlockchainType,
        block_time: Timestamp,
        keys: BcrKeys,
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
            keys,
            previous_event,
            root_event,
        )?;

        // Build unsigned event and sign it with the explicit keys
        let unsigned = event_builder.build(signing_keys.public_key());
        let send_event = unsigned.sign(&*signing_keys).await.map_err(|e| {
            error!("Failed to sign Nostr event: {e}");
            Error::Crypto("Failed to sign Nostr event".to_string())
        })?;

        self.client()
            .await?
            .send_event(&send_event)
            .await
            .map_err(|e| {
                error!("Failed to send Nostr event: {e}");
                Error::Network("Failed to send Nostr event".to_string())
            })?;
        Ok(send_event)
    }

    async fn resolve_contact(&self, node_id: &NodeId) -> Result<Option<NostrContactData>> {
        match self.fetch_metadata(node_id.npub()).await? {
            Some(meta) => {
                let relays = self
                    .fetch_relay_list(node_id.npub(), self.relays.clone())
                    .await?;
                Ok(Some(NostrContactData {
                    metadata: meta,
                    relays,
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
        Ok(self
            .fetch_events(chain_filter(id, chain_type), Some(SortOrder::Asc), None)
            .await?)
    }

    async fn add_contact_subscription(&self, node_id: &NodeId) -> Result<()> {
        debug!("adding nostr subscription for contact {node_id}");
        self.subscribe(Filter::new().author(node_id.npub())).await?;
        Ok(())
    }

    async fn resolve_private_events(&self, filter: Filter) -> Result<Vec<nostr::event::Event>> {
        let kinds = if self.use_nip04() {
            vec![Kind::EncryptedDirectMessage]
        } else {
            vec![Kind::GiftWrap]
        };
        // Subscribe with all public keys from all identities
        let pubkeys: Vec<PublicKey> = self
            .signers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .map(|node_id| node_id.npub())
            .collect();
        let filter = filter.clone().pubkeys(pubkeys).kinds(kinds);
        Ok(self
            .fetch_events(filter, Some(SortOrder::Asc), None)
            .await?)
    }

    async fn publish_metadata(&self, node_id: &NodeId, data: &Metadata) -> Result<()> {
        // Get the signer for this identity
        let signer = self.get_signer(node_id)?;

        // Build and sign the metadata event with the specific identity
        let event = EventBuilder::metadata(data)
            .build(signer.public_key())
            .sign(&*signer)
            .await
            .map_err(|e| {
                error!("Failed to sign metadata event: {e}");
                Error::Crypto("Failed to sign metadata event".to_string())
            })?;

        self.client().await?.send_event(&event).await.map_err(|e| {
            error!("Failed to send user metadata with Nostr client: {e}");
            Error::Network("Failed to send user metadata with Nostr client".to_string())
        })?;
        Ok(())
    }

    async fn publish_relay_list(&self, node_id: &NodeId, relays: Vec<RelayUrl>) -> Result<()> {
        // Get the signer for this identity
        let signer = self.get_signer(node_id)?;

        // Build and sign the relay list event with the specific identity
        let relay_list: Vec<(RelayUrl, Option<RelayMetadata>)> =
            relays.into_iter().map(|r| (r, None)).collect();
        let event = EventBuilder::relay_list(relay_list)
            .build(signer.public_key())
            .sign(&*signer)
            .await
            .map_err(|e| {
                error!("Failed to sign relay list event: {e}");
                Error::Crypto("Failed to sign relay list event".to_string())
            })?;

        self.client().await?.send_event(&event).await.map_err(|e| {
            error!("Failed to send relay list with Nostr client: {e}");
            Error::Network("Failed to send relay list with Nostr client".to_string())
        })?;
        Ok(())
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

            for node_id in node_ids {
                if let Err(e) = self.publish_relay_list(&node_id, relay_urls.clone()).await {
                    error!(
                        "Failed to publish relay list for identity {}: {}",
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
            let kinds = if self.use_nip04() {
                vec![Kind::EncryptedDirectMessage]
            } else {
                vec![Kind::GiftWrap]
            };
            debug!("Adding subscription for direct messages to identity: {node_id}");
            self.subscribe(Filter::new().pubkey(node_id.npub()).kinds(kinds))
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
}

#[derive(Clone)]
pub struct NostrConsumer {
    client: Arc<NostrClient>,
    event_handlers: Vec<Arc<dyn NotificationHandlerApi>>,
    contact_service: Arc<dyn ContactServiceApi>,
    offset_store: Arc<dyn NostrEventOffsetStoreApi>,
    chain_key_service: Arc<dyn ChainKeyServiceApi>,
}

impl NostrConsumer {
    pub fn new(
        client: Arc<NostrClient>,
        contact_service: Arc<dyn ContactServiceApi>,
        event_handlers: Vec<Arc<dyn NotificationHandlerApi>>,
        offset_store: Arc<dyn NostrEventOffsetStoreApi>,
        chain_key_service: Arc<dyn ChainKeyServiceApi>,
    ) -> Self {
        Self {
            client,
            #[allow(clippy::arc_with_non_send_sync)]
            event_handlers,
            contact_service,
            offset_store,
            chain_key_service,
        }
    }

    pub async fn start(&self) -> Result<JoinSet<()>> {
        // move dependencies into thread scope
        let client = self.client.clone();
        let event_handlers = self.event_handlers.clone();
        let contact_service = self.contact_service.clone();
        let offset_store = self.offset_store.clone();
        let chain_key_store = self.chain_key_service.clone();

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
        // If there are no local node IDs, default to zero to fetch all historical events
        let mut earliest_offset = Timestamp::zero();
        if !local_node_ids.is_empty() {
            earliest_offset = Timestamp::now();
            for node_id in &local_node_ids {
                let offset = get_offset(&offset_store, node_id).await;
                if offset < earliest_offset {
                    earliest_offset = offset;
                }
            }
        }

        // Subscribe to private events for ALL local identities (single subscription)
        let local_pubkeys: Vec<PublicKey> = local_node_ids.iter().map(|n| n.npub()).collect();

        client
            .subscribe(
                Filter::new()
                    .pubkeys(local_pubkeys.clone())
                    .kinds(vec![Kind::EncryptedDirectMessage, Kind::GiftWrap])
                    .since(earliest_offset.into()),
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
            .subscribe(
                Filter::new()
                    .authors(contacts)
                    .kinds(vec![Kind::TextNote, Kind::RelayList, Kind::Metadata])
                    .since(earliest_offset.into()),
            )
            .await
            .map_err(|e| {
                error!("Failed to subscribe to Nostr public events: {e}");
                Error::Network("Failed to subscribe to Nostr public events".to_string())
            })?;

        // Spawn a SINGLE task for the single client
        let client_for_task = client.clone();
        tasks.spawn(async move {
            client_for_task
                .client
                .handle_notifications(move |note| {
                    let event_handlers = event_handlers.clone();
                    let offset_store = offset_store.clone();
                    let chain_key_store = chain_key_store.clone();
                    let contact_service = contact_service.clone();
                    let local_node_ids = local_node_ids.clone();
                    let client = client.clone();

                    async move {
                        if let RelayPoolNotification::Event { event, .. } = note
                            && should_process(
                                event.clone(),
                                &local_node_ids,
                                &contact_service,
                                &offset_store,
                            )
                            .await
                        {
                            // Determine which local identity should receive this event
                            match determine_recipient(&event, &client).await {
                                Ok((recipient_node_id, signer)) => {
                                    let (success, time) = process_event(
                                        event.clone(),
                                        signer,
                                        recipient_node_id.clone(),
                                        chain_key_store,
                                        &event_handlers,
                                    )
                                    .await?;
                                    // store the new event offset for the recipient identity
                                    add_offset(
                                        &offset_store,
                                        event.id,
                                        time,
                                        success,
                                        &recipient_node_id,
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    debug!(
                                        "Could not determine recipient for event {}: {e}",
                                        event.id
                                    );
                                }
                            }
                        }
                        Ok(false)
                    }
                })
                .await
                .unwrap_or_else(|e| {
                    error!("Nostr notification handler failed: {e}");
                });
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
) -> Result<(NodeId, Arc<dyn NostrSigner>)> {
    match event.kind {
        Kind::EncryptedDirectMessage | Kind::GiftWrap => {
            // Try to decrypt with each identity's signer
            // Clone the keys to avoid holding the lock during async operations
            let keys_to_try: Vec<(NodeId, Arc<Keys>)> = client
                .signers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .map(|(id, keys)| (id.clone(), keys.clone()))
                .collect();

            for (node_id, nostr_keys) in keys_to_try {
                // Try to unwrap the message with this signer
                // NOTE: We clone the event for each identity attempt because unwrap_direct_message
                // takes ownership. For systems with many identities, this could be inefficient.
                // However, this only happens for encrypted messages that need decryption,
                // and typically only one or two identities will need to be tried before finding
                // the correct recipient.
                if unwrap_direct_message(Box::new(event.clone()), &*nostr_keys)
                    .await
                    .is_some()
                {
                    let signer = client.get_signer(&node_id)?;
                    return Ok((node_id, signer as Arc<dyn NostrSigner>));
                }
            }
            Err(Error::Message(
                "No local identity could decrypt this message".to_string(),
            ))
        }
        Kind::TextNote | Kind::RelayList | Kind::Metadata => {
            // For public events, any local identity can process them
            // Use the first available identity (they all have access to chain keys)
            let signers_lock = client.signers.lock().unwrap_or_else(|e| e.into_inner());
            let (node_id, _) = signers_lock
                .iter()
                .next()
                .ok_or_else(|| Error::Message("No local identities available".to_string()))?;
            let node_id = node_id.clone();
            drop(signers_lock); // Release lock before calling get_signer
            let signer = client.get_signer(&node_id)?;
            Ok((node_id, signer as Arc<dyn NostrSigner>))
        }
        _ => Err(Error::Message(format!(
            "Unsupported event kind: {:?}",
            event.kind
        ))),
    }
}

/// Detects event types and routes them to the correct handler.
pub async fn process_event(
    event: Box<Event>,
    signer: Arc<dyn NostrSigner>,
    client_id: NodeId,
    chain_key_store: Arc<dyn ChainKeyServiceApi>,
    event_handlers: &[Arc<dyn NotificationHandlerApi>],
) -> Result<(bool, Timestamp)> {
    let (success, time) = match event.kind {
        Kind::EncryptedDirectMessage | Kind::GiftWrap => {
            trace!("Received encrypted direct message: {event:?}");
            match handle_direct_message(event.clone(), &signer, &client_id, event_handlers).await {
                Err(e) => {
                    error!("Failed to handle direct message: {e}");
                    (false, Timestamp::zero())
                }
                Ok(_) => (true, event.created_at.into()),
            }
        }
        Kind::TextNote => {
            trace!("Received text note: {event:?}");
            match handle_public_event(event.clone(), &client_id, &chain_key_store, event_handlers)
                .await
            {
                Err(e) => {
                    debug!("Skipping public chain event with missing chain keys: {e}");
                    (false, Timestamp::zero())
                }
                Ok(v) => {
                    if v {
                        (v, event.created_at.into())
                    } else {
                        (false, Timestamp::zero())
                    }
                }
            }
        }
        Kind::RelayList => {
            // we have not subscribed to relaylist events yet
            debug!("Received relay list from: {}", event.pubkey);
            (true, Timestamp::zero())
        }
        Kind::Metadata => {
            // we have not subscribed to metadata events yet
            debug!("Received metadata from: {}", event.pubkey);
            (true, Timestamp::zero())
        }
        _ => (true, Timestamp::zero()),
    };

    Ok((success, time))
}

pub async fn should_process(
    event: Box<Event>,
    local_node_ids: &[NodeId],
    contact_service: &Arc<dyn ContactServiceApi>,
    offset_store: &Arc<dyn NostrEventOffsetStoreApi>,
) -> bool {
    valid_sender(&event.pubkey, local_node_ids, contact_service).await
        && !offset_store
            .is_processed(&event.id.to_hex())
            .await
            .unwrap_or(false)
}

pub async fn handle_direct_message<T: NostrSigner>(
    event: Box<Event>,
    signer: &T,
    client_id: &NodeId,
    event_handlers: &[Arc<dyn NotificationHandlerApi>],
) -> Result<()> {
    if let Some((envelope, sender, _, _)) = unwrap_direct_message(event.clone(), signer).await {
        let sender_npub = sender.to_bech32();
        let sender_pub_key = sender.to_hex();
        debug!(
            "Processing event: {} {} from {sender_npub:?} (hex: {sender_pub_key}) on client {client_id}",
            envelope.event_type, envelope.version
        );
        handle_event(envelope, client_id, event_handlers, Some(sender), event).await?;
    }
    Ok(())
}

async fn handle_public_event(
    event: Box<Event>,
    node_id: &NodeId,
    chain_key_store: &Arc<dyn ChainKeyServiceApi>,
    handlers: &[Arc<dyn NotificationHandlerApi>],
) -> Result<bool> {
    if let Some(encrypted_data) = unwrap_public_chain_event(event.clone())? {
        debug!(
            "Received public chain event: {} {}",
            encrypted_data.chain_type, encrypted_data.id
        );
        if let Ok(Some(chain_keys)) = chain_key_store
            .get_chain_keys(&encrypted_data.id, encrypted_data.chain_type)
            .await
        {
            let decrypted = decrypt_public_chain_event(&encrypted_data.payload, &chain_keys)?;
            debug!("Handling public chain event: {:?}", decrypted.event_type);
            handle_event(
                decrypted.clone(),
                node_id,
                handlers,
                Some(event.pubkey),
                event.clone(),
            )
            .await?;
        }
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn valid_sender(
    npub: &PublicKey,
    local_node_ids: &[NodeId],
    contact_service: &Arc<dyn ContactServiceApi>,
) -> bool {
    if local_node_ids.iter().any(|node_id| node_id.npub() == *npub) {
        return true;
    }
    if let Ok(res) = contact_service.is_known_npub(npub).await {
        res
    } else {
        error!("Could not check if sender is a known contact");
        false
    }
}

async fn get_offset(db: &Arc<dyn NostrEventOffsetStoreApi>, node_id: &NodeId) -> Timestamp {
    let current = db
        .current_offset(node_id)
        .await
        .map_err(|e| error!("Could not get event offset: {e}"))
        .ok()
        .unwrap_or(Timestamp::zero());
    if current.inner() <= NOSTR_EVENT_TIME_SLACK {
        current
    } else {
        current - NOSTR_EVENT_TIME_SLACK
    }
}

pub async fn add_offset(
    db: &Arc<dyn NostrEventOffsetStoreApi>,
    event_id: EventId,
    time: Timestamp,
    success: bool,
    node_id: &NodeId,
) {
    db.add_event(NostrEventOffset {
        event_id: event_id.to_hex(),
        time,
        success,
        node_id: node_id.to_owned(),
    })
    .await
    .map_err(|e| error!("Could not store event offset: {e}"))
    .ok();
}

/// Handle extracted event with given handlers.
async fn handle_event(
    event: EventEnvelope,
    node_id: &NodeId,
    handlers: &[Arc<dyn NotificationHandlerApi>],
    sender: Option<nostr::PublicKey>,
    original_event: Box<nostr::Event>,
) -> Result<()> {
    let event_type = &event.event_type;
    let mut times = 0;
    for handler in handlers.iter() {
        if handler.handles_event(event_type) {
            match handler
                .handle_event(
                    event.to_owned(),
                    node_id,
                    sender,
                    Some(original_event.clone()),
                )
                .await
            {
                Ok(_) => times += 1,
                Err(e) => error!("Nostr event handler failed: {e}"),
            }
        }
    }
    if times < 1 {
        warn!("No handler subscribed for event: {event:?}");
    } else {
        trace!("{event_type:?} event handled successfully {times} times");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use bcr_common::core::NodeId;
    use bcr_ebill_api::service::transport_service::transport_client::TransportClientApi;
    use bcr_ebill_core::protocol::Email;
    use bcr_ebill_core::protocol::Timestamp;
    use bcr_ebill_core::protocol::blockchain::bill::participant::BillParticipant;
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use bcr_ebill_core::protocol::event::BillEventType;
    use bcr_ebill_core::protocol::event::{Event, EventType};
    use bcr_ebill_persistence::NostrEventOffset;
    use mockall::predicate;
    use tokio::time;

    use crate::handler::MockNotificationHandlerApi;
    use crate::test_utils::{
        MockChainKeyService, MockContactService, MockNostrEventOffsetStore, TestEventPayload,
        create_test_event, get_identity_public_data,
    };

    use super::super::test_utils::get_mock_relay;
    use super::{NostrClient, NostrConfig, NostrConsumer};

    #[tokio::test]
    async fn test_connect() {
        let relay = get_mock_relay().await;
        let url = url::Url::parse(&relay.url()).unwrap();
        let keys = BcrKeys::new();
        let config = NostrConfig::new(
            keys.clone(),
            vec![url.to_owned()],
            true,
            NodeId::new(keys.pub_key(), bitcoin::Network::Testnet),
        );
        let client = NostrClient::default(&config)
            .await
            .expect("failed to create nostr client");

        client.connect().await.expect("failed to connect");
        assert!(client.is_connected(), "client should be connected");
    }

    /// When testing with the mock relay we need to be careful. It is always
    /// listening on the same port and will not start multiple times. If we
    /// share the instance tests will fail with events from other tests.
    #[tokio::test]
    async fn test_send_and_receive_event() {
        let relay = get_mock_relay().await;
        let url = url::Url::parse(&relay.url()).unwrap();

        let keys1 = BcrKeys::new();
        let keys2 = BcrKeys::new();

        // given two clients
        let config1 = NostrConfig::new(
            keys1.clone(),
            vec![url.to_owned()],
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

        // expect the receiver to check if the sender contact is known
        let mut contact_service = MockContactService::new();
        contact_service
            .expect_is_known_npub()
            .with(predicate::eq(keys1.get_nostr_keys().public_key()))
            .returning(|_| Ok(true));

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

        // we start the consumer
        let consumer = NostrConsumer::new(
            Arc::new(client2),
            Arc::new(contact_service),
            vec![Arc::new(handler)],
            Arc::new(offset_store),
            Arc::new(chain_key_store),
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
        let url = url::Url::parse(&relay.url()).unwrap();

        let keys1 = BcrKeys::new();
        let keys2 = BcrKeys::new();
        let node_id1 = NodeId::new(keys1.pub_key(), bitcoin::Network::Testnet);
        let node_id2 = NodeId::new(keys2.pub_key(), bitcoin::Network::Testnet);

        let identities = vec![
            (node_id1.clone(), keys1.clone()),
            (node_id2.clone(), keys2.clone()),
        ];

        let client = NostrClient::new(identities, vec![url], Duration::from_secs(20))
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
        let url = url::Url::parse(&relay.url()).unwrap();

        let keys1 = BcrKeys::new();
        let keys2 = BcrKeys::new();
        let node_id1 = NodeId::new(keys1.pub_key(), bitcoin::Network::Testnet);
        let node_id2 = NodeId::new(keys2.pub_key(), bitcoin::Network::Testnet);

        let identities = vec![
            (node_id1.clone(), keys1.clone()),
            (node_id2.clone(), keys2.clone()),
        ];

        let client = NostrClient::new(identities, vec![url.clone()], Duration::from_secs(20))
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
    async fn test_nostr_consumer_single_client_multi_identity() {
        let relay = get_mock_relay().await;
        let url = url::Url::parse(&relay.url()).unwrap();

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
            NostrClient::new(identities, vec![url.clone()], Duration::from_secs(20))
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
        );

        // Verify consumer can start and subscribe to events for all identities
        let mut tasks = consumer.start().await.expect("failed to start consumer");
        assert_eq!(tasks.len(), 1, "Should have single task for single client");

        // Clean up tasks
        tasks.abort_all();
    }
}
