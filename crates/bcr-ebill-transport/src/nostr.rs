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
use nostr::{nips::nip65::RelayMetadata, signer::NostrSigner};
use nostr_sdk::{
    Alphabet, Client, ClientOptions, Event, EventBuilder, EventId, Filter, Kind, Metadata,
    PublicKey, RelayPoolNotification, RelayUrl, SingleLetterTag, TagKind, TagStandard, ToBech32,
};
use std::sync::{Arc, atomic::Ordering};
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
    pub(crate) signers: HashMap<NodeId, Arc<dyn NostrSigner>>,
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
            signers.insert(node_id, Arc::new(keys.get_nostr_keys()) as Arc<dyn NostrSigner>);
        }
        
        Ok(Self {
            client,
            signers,
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
    pub fn get_signer(&self, node_id: &NodeId) -> Result<Arc<dyn NostrSigner>> {
        self.signers
            .get(node_id)
            .cloned()
            .ok_or_else(|| Error::Message(format!("No signer found for node_id: {}", node_id)))
    }

    /// Add a new identity to this client
    pub async fn add_identity(&mut self, node_id: NodeId, keys: BcrKeys) -> Result<()> {
        self.signers.insert(node_id, Arc::new(keys.get_nostr_keys()) as Arc<dyn NostrSigner>);
        Ok(())
    }

    pub async fn publish_relay_list(&self, relays: Vec<url::Url>) -> Result<()> {
        let urls = relays
            .iter()
            .filter_map(|r| RelayUrl::parse(r.as_str()).ok().map(|u| (u, None)))
            .collect();
        self.update_relay_list(urls).await.map_err(|e| {
            error!("Failed to update relay list: {e}");
            Error::Network("Failed to update relay list".to_string())
        })?;
        Ok(())
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

    /// Updates our relay list on all our configured write relays.
    async fn update_relay_list(
        &self,
        relays: Vec<(RelayUrl, Option<RelayMetadata>)>,
    ) -> Result<()> {
        let event = EventBuilder::relay_list(relays);
        self.client()
            .await?
            .send_event_builder(event)
            .await
            .map_err(|e| {
                error!("Failed to send Nostr relay list: {e}");
                Error::Network("Failed to send Nostr relay list".to_string())
            })?;
        Ok(())
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
        recipient: &BillParticipant,
        event: EventEnvelope,
    ) -> Result<()> {
        let public_key = recipient.node_id().npub();
        let message = base58::encode(&borsh::to_vec(&event)?);
        // TODO: This will be updated in Task 2 to accept sender_node_id parameter
        let first_signer = self.signers.values().next()
            .ok_or_else(|| Error::Message("No signers available".to_string()))?
            .clone();
        let event = create_nip04_event(&first_signer, &public_key, &message).await?;
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
        recipient: &BillParticipant,
        event: EventEnvelope,
    ) -> Result<()> {
        let public_key = recipient.node_id().npub();
        let message = base58::encode(&borsh::to_vec(&event)?);
        let relays = recipient.nostr_relays();
        if !relays.is_empty() {
            if let Err(e) = self
                .client()
                .await?
                .send_private_msg_to(&relays, public_key, message, None)
                .await
            {
                error!("Error sending Nostr message: {e}")
            };
        } else if let Err(e) = self
            .client()
            .await?
            .send_private_msg(public_key, message, None)
            .await
        {
            error!("Error sending Nostr message: {e}")
        }
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
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
    fn get_sender_node_id(&self) -> NodeId {
        // TODO: This method will be removed in Task 2 - multi-identity clients don't have a single node_id
        panic!("get_sender_node_id() is deprecated - use explicit node_id parameters instead")
    }

    fn get_sender_keys(&self) -> BcrKeys {
        // TODO: This method will be removed in Task 2 - multi-identity clients don't have single keys
        panic!("get_sender_keys() is deprecated - use explicit node_id parameters instead")
    }

    async fn send_private_event(
        &self,
        recipient: &BillParticipant,
        event: EventEnvelope,
    ) -> Result<()> {
        if self.use_nip04() {
            self.send_nip04_message(recipient, event).await?;
        } else {
            self.send_nip17_message(recipient, event).await?;
        }
        Ok(())
    }

    async fn send_public_chain_event(
        &self,
        id: &str,
        blockchain: BlockchainType,
        block_time: Timestamp,
        keys: BcrKeys,
        event: EventEnvelope,
        previous_event: Option<Event>,
        root_event: Option<Event>,
    ) -> Result<Event> {
        let event = create_public_chain_event(
            id,
            event,
            block_time,
            blockchain,
            keys,
            previous_event,
            root_event,
        )?;
        let send_event = self
            .client()
            .await?
            .sign_event_builder(event)
            .await
            .map_err(|e| {
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
        let pubkeys: Vec<PublicKey> = self.signers.keys()
            .map(|node_id| node_id.npub())
            .collect();
        let filter = filter
            .clone()
            .pubkeys(pubkeys)
            .kinds(kinds);
        Ok(self
            .fetch_events(filter, Some(SortOrder::Asc), None)
            .await?)
    }

    async fn publish_metadata(&self, data: &Metadata) -> Result<()> {
        self.client().await?.set_metadata(data).await.map_err(|e| {
            error!("Failed to send user metadata with Nostr client: {e}");
            Error::Network("Failed to send user metadata with Nostr client".to_string())
        })?;
        Ok(())
    }

    async fn publish_relay_list(&self, relays: Vec<RelayUrl>) -> Result<()> {
        self.update_relay_list(relays.into_iter().map(|r| (r, None)).collect())
            .await
            .map_err(|e| {
                error!("Failed to send relay list with Nostr client: {e}");
                Error::Network("Failed to send relay list with Nostr client".to_string())
            })?;
        Ok(())
    }

    async fn connect(&self) -> Result<()> {
        if !self.connected.load(Ordering::Relaxed) {
            self.connected.store(true, Ordering::Relaxed);
            self.client.connect().await;
            self.publish_relay_list(self.relays.clone()).await?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct NostrConsumer {
    clients: HashMap<NodeId, Arc<NostrClient>>,
    event_handlers: Vec<Arc<dyn NotificationHandlerApi>>,
    contact_service: Arc<dyn ContactServiceApi>,
    offset_store: Arc<dyn NostrEventOffsetStoreApi>,
    chain_key_service: Arc<dyn ChainKeyServiceApi>,
}

impl NostrConsumer {
    pub fn new(
        clients: Vec<Arc<NostrClient>>,
        contact_service: Arc<dyn ContactServiceApi>,
        event_handlers: Vec<Arc<dyn NotificationHandlerApi>>,
        offset_store: Arc<dyn NostrEventOffsetStoreApi>,
        chain_key_service: Arc<dyn ChainKeyServiceApi>,
    ) -> Self {
        let clients = clients
            .into_iter()
            .map(|c| {
                // TODO: This will be refactored in Task 3 - multi-identity clients don't have a single node_id
                let node_id = c.signers.keys().next()
                    .expect("No signers available")
                    .clone();
                (node_id, c)
            })
            .collect::<HashMap<NodeId, Arc<NostrClient>>>();
        Self {
            clients,
            #[allow(clippy::arc_with_non_send_sync)]
            event_handlers,
            contact_service,
            offset_store,
            chain_key_service,
        }
    }

    pub async fn start(&self) -> Result<JoinSet<()>> {
        // move dependencies into thread scope
        let clients = self.clients.clone();
        let event_handlers = self.event_handlers.clone();
        let contact_service = self.contact_service.clone();
        let offset_store = self.offset_store.clone();
        let chain_key_store = self.chain_key_service.clone();

        let mut tasks = JoinSet::new();
        let local_node_ids = clients.keys().cloned().collect::<Vec<NodeId>>();

        for (node_id, node_client) in clients.into_iter() {
            if !node_client.is_connected()
                && let Err(e) = node_client.connect().await
            {
                error!("Failed to connect Nostr client for node {node_id} with: {e}");
            }
            let current_client = node_client.clone();
            let event_handlers = event_handlers.clone();
            let offset_store = offset_store.clone();
            let chain_key_store = chain_key_store.clone();
            let client_id = node_id;
            let contact_service = contact_service.clone();
            let local_node_ids = local_node_ids.clone();

            // Spawn a task for each client
            tasks.spawn(async move {
                // continue where we left off
                let offset_ts = get_offset(&offset_store, &client_id).await;

                // subscribe to private events
                // TODO: This will be refactored in Task 3 for multi-identity support
                let first_pubkey = current_client.signers.keys().next()
                    .expect("No signers available")
                    .npub();
                current_client
                    .subscribe(
                        Filter::new()
                            .pubkey(first_pubkey)
                            .kinds(vec![Kind::EncryptedDirectMessage, Kind::GiftWrap])
                            .since(offset_ts.into()),
                    )
                    .await
                    .expect("Failed to subscribe to Nostr dm events");

                // we only need one client to subscribe to public events
                // TODO: is_primary will be removed in Task 11
                if true {  // Temporarily always subscribe
                    let mut contacts = contact_service.get_nostr_npubs().await.unwrap_or_default();
                    info!("Found {} contacts to subscribe to", contacts.len());
                    // we also subscribe to our own local public keys
                    let mut local_npubs =
                        local_node_ids.iter().map(|n| n.npub()).collect::<Vec<_>>();
                    contacts.append(&mut local_npubs);
                    info!("Subscribing to public Nostr events for client {client_id}");
                    current_client
                        .subscribe(
                            Filter::new()
                                .authors(contacts)
                                .kinds(vec![Kind::TextNote, Kind::RelayList, Kind::Metadata])
                                .since(offset_ts.into()),
                        )
                        .await
                        .expect("Failed to subscribe to Nostr public events");
                }

                // TODO: This will be refactored in Task 3
                let first_signer = current_client.signers.values().next()
                    .expect("No signers available")
                    .clone();

                current_client
                    .client
                    .handle_notifications(move |note| {
                        let event_handlers = event_handlers.clone();
                        let offset_store = offset_store.clone();
                        let chain_key_store = chain_key_store.clone();
                        let client_id = client_id.clone();
                        let contact_service = contact_service.clone();
                        let local_node_ids = local_node_ids.clone();
                        let first_signer = first_signer.clone();

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
                                let (success, time) = process_event(
                                    event.clone(),
                                    first_signer,
                                    client_id.clone(),
                                    chain_key_store,
                                    &event_handlers,
                                )
                                .await?;
                                // store the new event offset
                                add_offset(&offset_store, event.id, time, success, &client_id)
                                    .await;
                            }
                            Ok(false)
                        }
                    })
                    .await
                    .expect("Nostr notification handler failed");
            });
        }

        Ok(tasks)
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
            vec![Arc::new(client2)],
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
                client1
                    .send_private_event(
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
}
