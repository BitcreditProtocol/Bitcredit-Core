use async_trait::async_trait;
use bcr_ebill_core::{
    blockchain::{BlockchainType, bill::block::NodeId},
    contact::BillParticipant,
    util::{
        base58_decode, base58_encode,
        crypto::{self, decrypt_ecies, encrypt_ecies},
    },
};
use bcr_ebill_transport::{
    bcr_nostr_tag, event::EventEnvelope, handler::NotificationHandlerApi,
    transport::NostrContactData,
};
use log::{error, info, trace, warn};
use nostr::nips::nip73::ExternalContentId;
use nostr_sdk::{
    Alphabet, Client, Event, EventBuilder, EventId, Filter, Kind, Metadata, Options, PublicKey,
    RelayPoolNotification, RelayUrl, SecretKey, SingleLetterTag, Tag, TagKind, TagStandard,
    Timestamp, ToBech32, UnsignedEvent,
    nips::{nip04, nip59::UnwrappedGift},
};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::util::BcrKeys;
use crate::{constants::NOSTR_EVENT_TIME_SLACK, service::contact_service::ContactServiceApi};
use bcr_ebill_core::ServiceTraitBounds;
use bcr_ebill_persistence::{NostrEventOffset, NostrEventOffsetStoreApi};
use bcr_ebill_transport::{Error, NotificationJsonTransportApi, Result};

use tokio::task::spawn;
use tokio_with_wasm::alias as tokio;

#[derive(Clone, Debug)]
pub struct NostrConfig {
    pub keys: BcrKeys,
    pub relays: Vec<String>,
    pub name: String,
    pub default_timeout: Duration,
}

impl NostrConfig {
    pub fn new(keys: BcrKeys, relays: Vec<String>, name: String) -> Self {
        assert!(!relays.is_empty());
        Self {
            keys,
            relays,
            name,
            default_timeout: Duration::from_secs(20),
        }
    }

    #[allow(dead_code)]
    pub fn get_npub(&self) -> String {
        self.keys.get_nostr_npub()
    }

    pub fn get_relay(&self) -> String {
        self.relays[0].clone()
    }
}

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
#[derive(Clone, Debug)]
pub struct NostrClient {
    pub keys: BcrKeys,
    pub client: Client,
    config: NostrConfig,
}

impl NostrClient {
    pub async fn new(config: &NostrConfig) -> Result<Self> {
        let keys = config.keys.clone();
        let options = Options::new();
        let client = Client::builder()
            .signer(keys.get_nostr_keys().clone())
            .opts(options)
            .build();
        for relay in &config.relays {
            client.add_relay(relay).await.map_err(|e| {
                error!("Failed to add relay to Nostr client: {e}");
                Error::Network("Failed to add relay to Nostr client".to_string())
            })?;
        }
        client.connect().await;
        let metadata = Metadata::new()
            .name(&config.name)
            .display_name(&config.name);
        client.set_metadata(&metadata).await.map_err(|e| {
            error!("Failed to set and send user metadata with Nostr client: {e}");
            Error::Network("Failed to send user metadata with Nostr client".to_string())
        })?;

        let client = Self {
            keys,
            client,
            config: config.clone(),
        };

        client
            .update_relay_list(config.relays.clone())
            .await
            .map_err(|e| {
                error!("Failed to update relay list: {e}");
                Error::Network("Failed to update relay list".to_string())
            })?;

        Ok(client)
    }

    pub fn get_node_id(&self) -> String {
        self.keys.get_public_key()
    }

    pub fn get_nostr_keys(&self) -> nostr_sdk::Keys {
        self.keys.get_nostr_keys()
    }

    fn use_nip04(&self) -> bool {
        true
    }

    /// Subscribe to some nostr events with a filter
    pub async fn subscribe(&self, subscription: Filter) -> Result<()> {
        self.client
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
            .client
            .fetch_metadata(npub, self.config.default_timeout.to_owned())
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
        relays: Vec<String>,
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
    async fn update_relay_list(&self, relays: Vec<String>) -> Result<()> {
        let event = EventBuilder::relay_list(
            relays
                .iter()
                .filter_map(|r| RelayUrl::parse(r.as_str()).ok().map(|u| (u, None))),
        );
        self.client.send_event_builder(event).await.map_err(|e| {
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
        relays: Option<Vec<String>>,
    ) -> Result<Vec<Event>> {
        let events = self
            .client
            .fetch_events_from(
                relays.unwrap_or(self.config.relays.clone()),
                filter,
                self.config.default_timeout.to_owned(),
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

    pub async fn unwrap_envelope(
        &self,
        note: RelayPoolNotification,
    ) -> Option<(EventEnvelope, PublicKey, EventId, Timestamp)> {
        if self.use_nip04() {
            self.unwrap_nip04_envelope(note).await
        } else {
            self.unwrap_nip17_envelope(note).await
        }
    }

    /// Unwrap envelope from private direct message
    async fn unwrap_nip17_envelope(
        &self,
        note: RelayPoolNotification,
    ) -> Option<(EventEnvelope, PublicKey, EventId, Timestamp)> {
        let mut result: Option<(EventEnvelope, PublicKey, EventId, Timestamp)> = None;
        if let RelayPoolNotification::Event { event, .. } = note {
            if event.kind == Kind::GiftWrap {
                result = match self.client.unwrap_gift_wrap(&event).await {
                    Ok(UnwrappedGift { rumor, sender }) => extract_event_envelope(rumor)
                        .map(|e| (e, sender, event.id, event.created_at)),
                    Err(e) => {
                        error!("Unwrapping gift wrap failed: {e}");
                        None
                    }
                }
            }
        }
        result
    }

    /// Unwrap envelope from private direct message
    async fn unwrap_nip04_envelope(
        &self,
        note: RelayPoolNotification,
    ) -> Option<(EventEnvelope, PublicKey, EventId, Timestamp)> {
        let mut result: Option<(EventEnvelope, PublicKey, EventId, Timestamp)> = None;
        if let RelayPoolNotification::Event { event, .. } = note {
            if event.kind == Kind::EncryptedDirectMessage {
                match nip04::decrypt(
                    self.keys.get_nostr_keys().secret_key(),
                    &event.pubkey,
                    &event.content,
                ) {
                    Ok(decrypted) => {
                        result = extract_text_envelope(&decrypted)
                            .map(|e| (e, event.pubkey, event.id, event.created_at));
                    }
                    Err(e) => {
                        error!("Decrypting event failed: {e}");
                    }
                }
            } else {
                info!(
                    "Received event with kind {} but expected EncryptedDirectMessage",
                    event.kind
                );
            }
        }
        result
    }

    pub async fn send_nip04_message(
        &self,
        recipient: &BillParticipant,
        event: EventEnvelope,
    ) -> bcr_ebill_transport::Result<()> {
        if let Ok(npub) = crypto::get_nostr_npub_as_hex_from_node_id(&recipient.node_id()) {
            let public_key = PublicKey::from_str(&npub).map_err(|e| {
                error!("Failed to parse Nostr npub when sending a notification: {e}");
                Error::Crypto("Failed to parse Nostr npub".to_string())
            })?;
            let message = serde_json::to_string(&event)?;
            let event =
                create_nip04_event(self.get_nostr_keys().secret_key(), &public_key, &message)?;
            let relays = recipient.nostr_relays();
            if !relays.is_empty() {
                if let Err(e) = self.client.send_event_builder_to(&relays, event).await {
                    error!("Error sending Nostr message: {e}")
                };
            } else if let Err(e) = self.client.send_event_builder(event).await {
                error!("Error sending Nostr message: {e}")
            }
        } else {
            error!(
                "Try to send Nostr message but Nostr npub not found in contact {}",
                recipient.node_id()
            );
        }
        Ok(())
    }

    async fn send_nip17_message(
        &self,
        recipient: &BillParticipant,
        event: EventEnvelope,
    ) -> bcr_ebill_transport::Result<()> {
        if let Ok(npub) = crypto::get_nostr_npub_as_hex_from_node_id(&recipient.node_id()) {
            let public_key = PublicKey::from_str(&npub).map_err(|e| {
                error!("Failed to parse Nostr npub when sending a notification: {e}");
                Error::Crypto("Failed to parse Nostr npub".to_string())
            })?;
            let message = serde_json::to_string(&event)?;
            let relays = recipient.nostr_relays();
            if !relays.is_empty() {
                if let Err(e) = self
                    .client
                    .send_private_msg_to(&relays, public_key, message, None)
                    .await
                {
                    error!("Error sending Nostr message: {e}")
                };
            } else if let Err(e) = self
                .client
                .send_private_msg(public_key, message, None)
                .await
            {
                error!("Error sending Nostr message: {e}")
            }
        } else {
            error!(
                "Try to send Nostr message but Nostr npub not found in contact {}",
                recipient.node_id()
            );
        }
        Ok(())
    }
}

impl ServiceTraitBounds for NostrClient {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationJsonTransportApi for NostrClient {
    fn get_sender_key(&self) -> String {
        self.get_node_id()
    }

    async fn send_private_event(
        &self,
        recipient: &BillParticipant,
        event: EventEnvelope,
    ) -> bcr_ebill_transport::Result<()> {
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
        keys: BcrKeys,
        event: EventEnvelope,
    ) -> Result<()> {
        let event = create_public_chain_event(id, event, blockchain, keys)?;
        self.client.send_event_builder(event).await.map_err(|e| {
            error!("Failed to send Nostr event: {e}");
            Error::Network("Failed to send Nostr event".to_string())
        })?;
        Ok(())
    }

    async fn resolve_contact(
        &self,
        node_id: &str,
    ) -> Result<Option<bcr_ebill_transport::transport::NostrContactData>> {
        if let Ok(npub) = crypto::get_nostr_npub_as_hex_from_node_id(node_id) {
            let public_key = PublicKey::from_str(&npub).map_err(|e| {
                error!("Failed to parse Nostr npub when sending a notification: {e}");
                Error::Crypto("Failed to parse Nostr npub".to_string())
            })?;
            match self.fetch_metadata(public_key).await? {
                Some(meta) => {
                    let relays = self
                        .fetch_relay_list(public_key, self.config.relays.clone())
                        .await?;
                    Ok(Some(NostrContactData {
                        metadata: meta,
                        relays,
                    }))
                }
                _ => Ok(None),
            }
        } else {
            error!("Try to resolve Nostr contact but node_id {node_id} was invalid");
            Ok(None)
        }
    }
}

#[derive(Clone)]
pub struct NostrConsumer {
    clients: HashMap<PublicKey, Arc<NostrClient>>,
    event_handlers: Arc<Vec<Box<dyn NotificationHandlerApi>>>,
    contact_service: Arc<dyn ContactServiceApi>,
    offset_store: Arc<dyn NostrEventOffsetStoreApi>,
}

impl NostrConsumer {
    #[allow(dead_code)]
    pub fn new(
        clients: Vec<Arc<NostrClient>>,
        contact_service: Arc<dyn ContactServiceApi>,
        event_handlers: Vec<Box<dyn NotificationHandlerApi>>,
        offset_store: Arc<dyn NostrEventOffsetStoreApi>,
    ) -> Self {
        let clients = clients
            .into_iter()
            .map(|c| (c.get_nostr_keys().public_key(), c))
            .collect::<HashMap<PublicKey, Arc<NostrClient>>>();
        Self {
            clients,
            #[allow(clippy::arc_with_non_send_sync)]
            event_handlers: Arc::new(event_handlers),
            contact_service,
            offset_store,
        }
    }

    #[allow(dead_code)]
    pub async fn start(&self) -> Result<()> {
        // move dependencies into thread scope
        let clients = self.clients.clone();
        let event_handlers = self.event_handlers.clone();
        let contact_service = self.contact_service.clone();
        let offset_store = self.offset_store.clone();

        let mut tasks = Vec::new();
        let local_node_ids = clients.keys().cloned().collect::<Vec<PublicKey>>();

        for (node_id, node_client) in clients.into_iter() {
            let current_client = node_client.clone();
            let event_handlers = event_handlers.clone();
            let offset_store = offset_store.clone();
            let client_id = node_id.to_hex();
            let contact_service = contact_service.clone();
            let local_node_ids = local_node_ids.clone();

            // Spawn a task for each client
            let task = spawn(async move {
                // continue where we left off
                let offset_ts = get_offset(&offset_store, &client_id).await;
                let public_key = current_client.keys.get_nostr_keys().public_key();
                let filter = Filter::new()
                    .pubkey(public_key)
                    .kind(Kind::EncryptedDirectMessage)
                    .since(offset_ts);

                // subscribe only to private messages sent to our pubkey
                current_client
                    .subscribe(filter)
                    .await
                    .expect("Failed to subscribe to Nostr events");

                let inner = current_client.clone();
                current_client
                    .client
                    .handle_notifications(move |note| {
                        let client = inner.clone();
                        let event_handlers = event_handlers.clone();
                        let offset_store = offset_store.clone();
                        let client_id = client_id.clone();
                        let contact_service = contact_service.clone();
                        let local_node_ids = local_node_ids.clone();

                        async move {
                            if let Some((envelope, sender, event_id, time)) =
                                client.unwrap_envelope(note).await
                            {
                                if !offset_store.is_processed(&event_id.to_hex()).await? {
                                    let sender_npub = sender.to_bech32();
                                    let sender_node_id = sender.to_hex();
                                    trace!("Received event: {envelope:?} from {sender_npub:?} (hex: {sender_node_id}) on client {client_id}");
                                    // We use hex here, so we can compare it with our node_ids
                                    if valid_sender(&sender, &local_node_ids, &contact_service).await {
                                        trace!("Processing event: {envelope:?}");
                                        handle_event(envelope, &client_id, &event_handlers).await?;
                                    }

                                    // store the new event offset
                                    add_offset(&offset_store, event_id, time, true, &client_id).await;
                                }
                            };
                            Ok(false)
                        }
                    })
                    .await
                    .expect("Nostr notification handler failed");
            });

            tasks.push(task);
        }

        // Wait for all tasks to complete (they would run indefinitely unless interrupted)
        for task in tasks {
            if let Err(e) = task.await {
                error!("Nostr client task failed: {e}");
            }
        }

        Ok(())
    }
}

async fn valid_sender(
    node_id: &PublicKey,
    local_node_ids: &[PublicKey],
    contact_service: &Arc<dyn ContactServiceApi>,
) -> bool {
    if local_node_ids.contains(node_id) {
        return true;
    }
    if let Ok(res) = contact_service.is_known_npub(node_id).await {
        res
    } else {
        error!("Could not check if sender is a known contact");
        false
    }
}

async fn get_offset(db: &Arc<dyn NostrEventOffsetStoreApi>, node_id: &str) -> Timestamp {
    let current = db
        .current_offset(node_id)
        .await
        .map_err(|e| error!("Could not get event offset: {e}"))
        .ok()
        .unwrap_or(0);
    let ts = if current <= NOSTR_EVENT_TIME_SLACK {
        current
    } else {
        current - NOSTR_EVENT_TIME_SLACK
    };
    Timestamp::from_secs(ts)
}

async fn add_offset(
    db: &Arc<dyn NostrEventOffsetStoreApi>,
    event_id: EventId,
    time: Timestamp,
    success: bool,
    node_id: &str,
) {
    db.add_event(NostrEventOffset {
        event_id: event_id.to_hex(),
        time: time.as_u64(),
        success,
        node_id: node_id.to_string(),
    })
    .await
    .map_err(|e| error!("Could not store event offset: {e}"))
    .ok();
}

fn extract_text_envelope(message: &str) -> Option<EventEnvelope> {
    match serde_json::from_str::<EventEnvelope>(message) {
        Ok(envelope) => Some(envelope),
        Err(e) => {
            error!("Json deserializing event envelope failed: {e}");
            None
        }
    }
}

fn extract_event_envelope(rumor: UnsignedEvent) -> Option<EventEnvelope> {
    if rumor.kind == Kind::PrivateDirectMessage {
        match serde_json::from_str::<EventEnvelope>(rumor.content.as_str()) {
            Ok(envelope) => Some(envelope),
            Err(e) => {
                error!("Json deserializing event envelope failed: {e}");
                None
            }
        }
    } else {
        None
    }
}

fn create_nip04_event(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    message: &str,
) -> Result<EventBuilder> {
    Ok(EventBuilder::new(
        Kind::EncryptedDirectMessage,
        nip04::encrypt(secret_key, public_key, message).map_err(|e| {
            error!("Failed to encrypt direct private message: {e}");
            Error::Crypto("Failed to encrypt direct private message".to_string())
        })?,
    )
    .tag(Tag::public_key(*public_key)))
}

/// Takes an event envelope and creates a public chain event with appropriate tags and encypted
/// base58 encoded payload.
fn create_public_chain_event(
    id: &str,
    event: EventEnvelope,
    blockchain: BlockchainType,
    keys: BcrKeys,
) -> Result<EventBuilder> {
    let payload = base58_encode(&encrypt_ecies(
        &serde_json::to_vec(&event)?,
        &keys.get_public_key(),
    )?);
    let event = EventBuilder::new(Kind::TextNote, payload).tag(bcr_nostr_tag(id, blockchain));
    Ok(event)
}

#[allow(dead_code)]
/// Unwraps a Nostr chain event with its metadata. Will return the encrypted payload and
/// the metadata if the event matches a public chain event. Otherwise it returns None.
fn unwrap_public_chain_event(event: Box<Event>) -> Result<Option<EncryptedPublicEventData>> {
    let data: Vec<EncryptedPublicEventData> = event
        .tags
        .filter_standardized(TagKind::SingleLetter(SingleLetterTag::lowercase(
            Alphabet::I,
        )))
        .filter_map(|t| match t {
            TagStandard::ExternalContent {
                content:
                    ExternalContentId::BlockchainAddress {
                        address, chain_id, ..
                    },
                ..
            } => chain_id.as_ref().map(|id| EncryptedPublicEventData {
                id: address.to_owned(),
                chain_type: BlockchainType::try_from(id.as_ref()).unwrap(),
                payload: event.content.clone(),
            }),
            _ => None,
        })
        .collect();
    Ok(data.first().cloned())
}

#[allow(dead_code)]
/// Given a encrypted payload and a private key, decrypts the payload and returns the
/// its content as an EventEnvelope.
fn decrypt_public_chain_event(data: &str, keys: &BcrKeys) -> Result<EventEnvelope> {
    let decrypted = decrypt_ecies(&base58_decode(data)?, &keys.get_private_key_string())?;
    let payload = serde_json::from_slice::<EventEnvelope>(&decrypted)?;
    Ok(payload)
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct EncryptedPublicEventData {
    pub id: String,
    pub chain_type: BlockchainType,
    pub payload: String,
}

/// Handle extracted event with given handlers.
async fn handle_event(
    event: EventEnvelope,
    node_id: &str,
    handlers: &Arc<Vec<Box<dyn NotificationHandlerApi>>>,
) -> Result<()> {
    let event_type = &event.event_type;
    let mut times = 0;
    for handler in handlers.iter() {
        if handler.handles_event(event_type) {
            match handler.handle_event(event.to_owned(), node_id).await {
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

    use bcr_ebill_core::contact::BillParticipant;
    use bcr_ebill_core::{ServiceTraitBounds, notification::BillEventType};
    use bcr_ebill_transport::handler::NotificationHandlerApi;
    use bcr_ebill_transport::{Event, EventEnvelope, EventType};
    use mockall::predicate;
    use tokio::time;

    use super::super::test_utils::get_mock_relay;
    use super::{NostrClient, NostrConfig, NostrConsumer};
    use crate::persistence::nostr::NostrEventOffset;
    use crate::service::{
        contact_service::MockContactServiceApi,
        notification_service::{NotificationJsonTransportApi, test_utils::*},
    };
    use crate::tests::tests::MockNostrEventOffsetStoreApiMock;
    use crate::util::BcrKeys;
    use mockall::mock;

    impl ServiceTraitBounds for MockNotificationHandler {}
    mock! {
        pub NotificationHandler {}
        #[async_trait::async_trait]
        impl NotificationHandlerApi for NotificationHandler {
            async fn handle_event(&self, event: EventEnvelope, identity: &str) -> bcr_ebill_transport::Result<()>;
            fn handles_event(&self, event_type: &EventType) -> bool;
        }
    }

    /// When testing with the mock relay we need to be careful. It is always
    /// listening on the same port and will not start multiple times. If we
    /// share the instance tests will fail with events from other tests.
    #[tokio::test]
    async fn test_send_and_receive_event() {
        let relay = get_mock_relay().await;
        let url = relay.url();

        let keys1 = BcrKeys::new();
        let keys2 = BcrKeys::new();

        // given two clients
        let config1 = NostrConfig::new(
            keys1.clone(),
            vec![url.to_string()],
            "BcrDamus1".to_string(),
        );
        let client1 = NostrClient::new(&config1)
            .await
            .expect("failed to create nostr client 1");

        let config2 = NostrConfig::new(
            keys2.clone(),
            vec![url.to_string()],
            "BcrDamus2".to_string(),
        );
        let client2 = NostrClient::new(&config2)
            .await
            .expect("failed to create nostr client 2");

        // and a contact we want to send an event to
        let contact =
            get_identity_public_data(&keys2.get_public_key(), "payee@example.com", vec![&url]);
        let event = create_test_event(&BillEventType::BillSigned);

        // expect the receiver to check if the sender contact is known
        let mut contact_service = MockContactServiceApi::new();
        contact_service
            .expect_is_known_npub()
            .with(predicate::eq(keys1.get_nostr_keys().public_key()))
            .returning(|_| Ok(true));

        // expect a handler that is subscribed to the event type w sent
        let mut handler = MockNotificationHandler::new();
        handler
            .expect_handles_event()
            .with(predicate::eq(&EventType::Bill))
            .returning(|_| true);

        // expect a handler receiving the event we sent
        let expected_event: Event<TestEventPayload> = event.clone();
        handler
            .expect_handle_event()
            .withf(move |e, i| {
                let expected = expected_event.clone();
                let received: Event<TestEventPayload> =
                    e.clone().try_into().expect("could not convert event");
                let valid_type = received.event_type == expected.event_type;
                let valid_payload = received.data.foo == expected.data.foo;
                let valid_identity = i == keys2.get_public_key();
                valid_type && valid_payload && valid_identity
            })
            .returning(|_, _| Ok(()));

        let mut offset_store = MockNostrEventOffsetStoreApiMock::new();

        // expect the offset store to return the current offset once on start
        offset_store
            .expect_current_offset()
            .returning(|_| Ok(1000))
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

        // we start the consumer
        let consumer = NostrConsumer::new(
            vec![Arc::new(client2)],
            Arc::new(contact_service),
            vec![Box::new(handler)],
            Arc::new(offset_store),
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
}
