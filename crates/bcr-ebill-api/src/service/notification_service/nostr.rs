use async_trait::async_trait;
use bcr_ebill_core::{blockchain::BlockchainType, contact::BillParticipant, util::crypto};
use bcr_ebill_transport::{
    chain_keys::ChainKeyServiceApi,
    event::EventEnvelope,
    handler::NotificationHandlerApi,
    transport::{
        NostrContactData, chain_filter, create_nip04_event, create_public_chain_event,
        decrypt_public_chain_event, unwrap_direct_message, unwrap_public_chain_event,
    },
};
use log::{error, info, trace, warn};
use nostr::signer::NostrSigner;
use nostr_sdk::{
    Alphabet, Client, Event, EventBuilder, EventId, Filter, Kind, Metadata, Options, PublicKey,
    RelayPoolNotification, RelayUrl, SingleLetterTag, TagKind, TagStandard, Timestamp, ToBech32,
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
    pub is_primary: bool,
}

impl NostrConfig {
    pub fn new(keys: BcrKeys, relays: Vec<String>, name: String, is_primary: bool) -> Self {
        assert!(!relays.is_empty());
        Self {
            keys,
            relays,
            name,
            default_timeout: Duration::from_secs(20),
            is_primary,
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
#[derive(Clone)]
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

    pub fn is_primary(&self) -> bool {
        self.config.is_primary
    }

    fn use_nip04(&self) -> bool {
        true
    }

    // We create the client with a private key so this should never fail.
    async fn get_signer(&self) -> Arc<dyn NostrSigner> {
        self.client
            .signer()
            .await
            .expect("Unable to get Nostr signer for active client")
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
            let event = create_nip04_event(&self.get_signer().await, &public_key, &message).await?;
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
        block_time: u64,
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
        let send_event = self.client.sign_event_builder(event).await.map_err(|e| {
            error!("Failed to sign Nostr event: {e}");
            Error::Crypto("Failed to sign Nostr event".to_string())
        })?;
        self.client.send_event(&send_event).await.map_err(|e| {
            error!("Failed to send Nostr event: {e}");
            Error::Network("Failed to send Nostr event".to_string())
        })?;
        Ok(send_event)
    }

    async fn resolve_contact(
        &self,
        node_id: &str,
    ) -> Result<Option<bcr_ebill_transport::transport::NostrContactData>> {
        if let Ok(public_key) = crypto::get_npub_from_node_id(node_id) {
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

    async fn resolve_public_chain(
        &self,
        id: &str,
        chain_type: BlockchainType,
    ) -> Result<Vec<nostr::event::Event>> {
        Ok(self
            .fetch_events(chain_filter(id, chain_type), Some(SortOrder::Asc), None)
            .await?)
    }
}

#[derive(Clone)]
pub struct NostrConsumer {
    clients: HashMap<PublicKey, Arc<NostrClient>>,
    event_handlers: Arc<Vec<Box<dyn NotificationHandlerApi>>>,
    contact_service: Arc<dyn ContactServiceApi>,
    offset_store: Arc<dyn NostrEventOffsetStoreApi>,
    chain_key_service: Arc<dyn ChainKeyServiceApi>,
}

impl NostrConsumer {
    pub fn new(
        clients: Vec<Arc<NostrClient>>,
        contact_service: Arc<dyn ContactServiceApi>,
        event_handlers: Vec<Box<dyn NotificationHandlerApi>>,
        offset_store: Arc<dyn NostrEventOffsetStoreApi>,
        chain_key_service: Arc<dyn ChainKeyServiceApi>,
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
            chain_key_service,
        }
    }

    pub async fn start(&self) -> Result<()> {
        // move dependencies into thread scope
        let clients = self.clients.clone();
        let event_handlers = self.event_handlers.clone();
        let contact_service = self.contact_service.clone();
        let offset_store = self.offset_store.clone();
        let chain_key_store = self.chain_key_service.clone();

        let mut tasks = Vec::new();
        let local_node_ids = clients.keys().cloned().collect::<Vec<PublicKey>>();

        for (node_id, node_client) in clients.into_iter() {
            let current_client = node_client.clone();
            let event_handlers = event_handlers.clone();
            let offset_store = offset_store.clone();
            let chain_key_store = chain_key_store.clone();
            let client_id = node_id.to_hex();
            let contact_service = contact_service.clone();
            let local_node_ids = local_node_ids.clone();

            // Spawn a task for each client
            let task = spawn(async move {
                // continue where we left off
                let offset_ts = get_offset(&offset_store, &client_id).await;

                // subscribe to private events
                current_client
                    .subscribe(
                        Filter::new()
                            .pubkey(current_client.keys.get_nostr_keys().public_key())
                            .kinds(vec![Kind::EncryptedDirectMessage, Kind::GiftWrap])
                            .since(offset_ts),
                    )
                    .await
                    .expect("Failed to subscribe to Nostr dm events");

                // we only need one client to subscribe to public events
                if current_client.is_primary() {
                    let contacts = contact_service.get_nostr_npubs().await.unwrap_or_default();
                    info!("Found {} contacts to subscribe to", contacts.len());
                    if !contacts.is_empty() {
                        info!("Subscribing to public Nostr events for client {client_id}");
                        current_client
                            .subscribe(
                                Filter::new()
                                    .authors(contacts)
                                    .kinds(vec![Kind::TextNote, Kind::RelayList, Kind::Metadata])
                                    .since(offset_ts),
                            )
                            .await
                            .expect("Failed to subscribe to Nostr public events");
                    }
                }

                let signer = current_client.get_signer().await;

                current_client
                    .client
                    .handle_notifications(move |note| {
                        let event_handlers = event_handlers.clone();
                        let offset_store = offset_store.clone();
                        let chain_key_store = chain_key_store.clone();
                        let client_id = client_id.clone();
                        let contact_service = contact_service.clone();
                        let local_node_ids = local_node_ids.clone();
                        let signer = signer.clone();

                        async move {
                            if let RelayPoolNotification::Event { event, .. } = note {
                                if should_process(
                                    event.clone(),
                                    &local_node_ids,
                                    &contact_service,
                                    &offset_store,
                                )
                                .await
                                {
                                    let (success, time) = match event.kind {
                                        Kind::EncryptedDirectMessage | Kind::GiftWrap => {
                                            trace!("Received encrypted direct message: {event:?}");
                                            match handle_direct_message(
                                                event.clone(),
                                                &signer,
                                                &client_id,
                                                &event_handlers,
                                            )
                                            .await
                                            {
                                                Err(e) => {
                                                    error!("Failed to handle direct message: {e}");
                                                    (false, 0u64)
                                                }
                                                Ok(_) => (true, event.created_at.as_u64()),
                                            }
                                        }
                                        Kind::TextNote => {
                                            trace!("Received text note: {event:?}");
                                            match handle_public_event(
                                                event.clone(),
                                                &client_id,
                                                &chain_key_store,
                                                &event_handlers,
                                            )
                                            .await
                                            {
                                                Err(e) => {
                                                    error!(
                                                        "Failed to handle public chain event: {e}"
                                                    );
                                                    (false, 0u64)
                                                }
                                                Ok(v) => {
                                                    if v {
                                                        (v, event.created_at.as_u64())
                                                    } else {
                                                        (false, 0u64)
                                                    }
                                                }
                                            }
                                        }
                                        Kind::RelayList => {
                                            // we have not subscribed to relaylist events yet
                                            info!("Received relay list: {event:?}");
                                            (true, 0u64)
                                        }
                                        Kind::Metadata => {
                                            // we have not subscribed to metadata events yet
                                            info!("Received metadata: {event:?}");
                                            (true, 0u64)
                                        }
                                        _ => (true, 0u64),
                                    };
                                    // store the new event offset
                                    add_offset(&offset_store, event.id, time, success, &client_id)
                                        .await;
                                }
                            }
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

async fn should_process(
    event: Box<Event>,
    local_node_ids: &[PublicKey],
    contact_service: &Arc<dyn ContactServiceApi>,
    offset_store: &Arc<dyn NostrEventOffsetStoreApi>,
) -> bool {
    valid_sender(&event.pubkey, local_node_ids, contact_service).await
        && !offset_store
            .is_processed(&event.id.to_hex())
            .await
            .unwrap_or(false)
}

async fn handle_direct_message<T: NostrSigner>(
    event: Box<Event>,
    signer: &T,
    client_id: &str,
    event_handlers: &Arc<Vec<Box<dyn NotificationHandlerApi>>>,
) -> Result<()> {
    if let Some((envelope, sender, _, _)) = unwrap_direct_message(event.clone(), signer).await {
        let sender_npub = sender.to_bech32();
        let sender_node_id = sender.to_hex();
        trace!(
            "Processing event: {envelope:?} from {sender_npub:?} (hex: {sender_node_id}) on client {client_id}"
        );
        handle_event(envelope, client_id, event_handlers, event).await?;
    }
    Ok(())
}

async fn handle_public_event(
    event: Box<Event>,
    node_id: &str,
    chain_key_store: &Arc<dyn ChainKeyServiceApi>,
    handlers: &Arc<Vec<Box<dyn NotificationHandlerApi>>>,
) -> Result<bool> {
    if let Some(encrypted_data) = unwrap_public_chain_event(event.clone())? {
        if let Ok(Some(chain_keys)) = chain_key_store
            .get_chain_keys(&encrypted_data.id, encrypted_data.chain_type)
            .await
        {
            let decrypted = decrypt_public_chain_event(&encrypted_data.payload, &chain_keys)?;
            trace!("Handling public chain event: {decrypted:?}");
            handle_event(decrypted.clone(), node_id, handlers, event.clone()).await?;
        }
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn valid_sender(
    npub: &PublicKey,
    local_node_ids: &[PublicKey],
    contact_service: &Arc<dyn ContactServiceApi>,
) -> bool {
    if local_node_ids.contains(npub) {
        return true;
    }
    if let Ok(res) = contact_service.is_known_npub(npub).await {
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
    time: u64,
    success: bool,
    node_id: &str,
) {
    db.add_event(NostrEventOffset {
        event_id: event_id.to_hex(),
        time,
        success,
        node_id: node_id.to_string(),
    })
    .await
    .map_err(|e| error!("Could not store event offset: {e}"))
    .ok();
}

/// Handle extracted event with given handlers.
async fn handle_event(
    event: EventEnvelope,
    node_id: &str,
    handlers: &Arc<Vec<Box<dyn NotificationHandlerApi>>>,
    original_event: Box<nostr::Event>,
) -> Result<()> {
    let event_type = &event.event_type;
    let mut times = 0;
    for handler in handlers.iter() {
        if handler.handles_event(event_type) {
            match handler
                .handle_event(event.to_owned(), node_id, original_event.clone())
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
    use crate::tests::tests::{MockChainKeyService, MockNostrEventOffsetStoreApiMock};
    use crate::util::BcrKeys;
    use mockall::mock;

    impl ServiceTraitBounds for MockNotificationHandler {}
    mock! {
        pub NotificationHandler {}
        #[async_trait::async_trait]
        impl NotificationHandlerApi for NotificationHandler {
            async fn handle_event(&self, event: EventEnvelope, identity: &str, original_event: Box<nostr::Event>) -> bcr_ebill_transport::Result<()>;
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
            true,
        );
        let client1 = NostrClient::new(&config1)
            .await
            .expect("failed to create nostr client 1");

        let config2 = NostrConfig::new(
            keys2.clone(),
            vec![url.to_string()],
            "BcrDamus2".to_string(),
            true,
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
            .withf(move |e, i, _| {
                let expected = expected_event.clone();
                let received: Event<TestEventPayload> =
                    e.clone().try_into().expect("could not convert event");
                let valid_type = received.event_type == expected.event_type;
                let valid_payload = received.data.foo == expected.data.foo;
                let valid_identity = i == keys2.get_public_key();
                valid_type && valid_payload && valid_identity
            })
            .returning(|_, _, _| Ok(()));

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

        let chain_key_store = MockChainKeyService::new();

        // we start the consumer
        let consumer = NostrConsumer::new(
            vec![Arc::new(client2)],
            Arc::new(contact_service),
            vec![Box::new(handler)],
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
}
