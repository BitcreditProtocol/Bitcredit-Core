use std::collections::HashMap;
use std::sync::Arc;

use crate::nostr::NostrClient;
use bcr_common::core::NodeId;
use bcr_ebill_api::service::transport_service::NostrConfig;
use bcr_ebill_api::service::transport_service::transport_client::TransportClientApi;
use bcr_ebill_api::util::validate_node_id_network;
use bcr_ebill_core::application::ServiceTraitBounds;
use bcr_ebill_core::application::company::Company;
use bcr_ebill_core::application::nostr_contact::TrustLevel;
use bcr_ebill_core::protocol::Address;
use bcr_ebill_core::protocol::City;
use bcr_ebill_core::protocol::Country;
use bcr_ebill_core::protocol::Name;
use bcr_ebill_core::protocol::Sha256Hash;
use bcr_ebill_core::protocol::blockchain::BlockchainType;
use bcr_ebill_core::protocol::blockchain::bill::{
    block::ContactType,
    participant::{BillAnonParticipant, BillIdentParticipant, BillParticipant},
};
use bcr_ebill_core::protocol::crypto::BcrKeys;
use bcr_ebill_core::protocol::event::{BillChainEventPayload, Event, EventEnvelope};
use bcr_ebill_persistence::ContactStoreApi;
use bcr_ebill_persistence::nostr::{
    NostrChainEvent, NostrChainEventStoreApi, NostrContactStoreApi, NostrQueuedMessage,
    NostrQueuedMessageStoreApi,
};
use bitcoin::base58;
use log::{debug, error, warn};
use tokio::sync::Mutex;
use tokio_with_wasm::alias as tokio;

use bcr_ebill_api::get_config;
use bcr_ebill_api::service::transport_service::{Error, Result};
use bcr_ebill_core::protocol::PostalAddress;

/// Transport implementation for Nostr
pub struct NostrTransportService {
    notification_transport: Mutex<HashMap<NodeId, Arc<dyn TransportClientApi>>>,
    contact_store: Arc<dyn ContactStoreApi>,
    nostr_contact_store: Arc<dyn NostrContactStoreApi>,
    queued_message_store: Arc<dyn NostrQueuedMessageStoreApi>,
    chain_event_store: Arc<dyn NostrChainEventStoreApi>,
    nostr_relays: Vec<url::Url>,
}

impl ServiceTraitBounds for NostrTransportService {}

impl NostrTransportService {
    // the number of times we want to retry sending a block message
    const NOSTR_MAX_RETRIES: i32 = 10;

    pub fn new(
        notification_transport: Vec<Arc<dyn TransportClientApi>>,
        contact_store: Arc<dyn ContactStoreApi>,
        nostr_contact_store: Arc<dyn NostrContactStoreApi>,
        queued_message_store: Arc<dyn NostrQueuedMessageStoreApi>,
        chain_event_store: Arc<dyn NostrChainEventStoreApi>,
        nostr_relays: Vec<url::Url>,
    ) -> Self {
        let transports: Mutex<HashMap<NodeId, Arc<dyn TransportClientApi>>> = Mutex::new(
            notification_transport
                .into_iter()
                .map(|t| (t.get_sender_node_id(), t))
                .collect(),
        );
        Self {
            notification_transport: transports,
            contact_store,
            nostr_contact_store,
            queued_message_store,
            chain_event_store,
            nostr_relays,
        }
    }

    pub(crate) async fn get_node_transport(
        &self,
        node_id: &NodeId,
    ) -> Option<Arc<dyn TransportClientApi>> {
        let transports = self.notification_transport.lock().await;
        transports.get(node_id).cloned()
    }

    pub(crate) async fn get_first_transport(&self) -> Option<Arc<dyn TransportClientApi>> {
        let transports = self.notification_transport.lock().await;
        transports.values().next().cloned()
    }

    pub(crate) async fn get_local_identity(&self, node_id: &NodeId) -> Option<BillParticipant> {
        if self.get_node_transport(node_id).await.is_some() {
            Some(BillParticipant::Ident(BillIdentParticipant {
                // we create an ident, but it doesn't matter, since we just need the node id and nostr relay
                t: ContactType::Person,
                node_id: node_id.to_owned(),
                email: None,
                name: Name::new("default name").expect("is a valid name"),
                postal_address: PostalAddress {
                    country: Country::AT,
                    city: City::new("default city").expect("is valid city"),
                    zip: None,
                    address: Address::new("default address").expect("is valid address"),
                },
                nostr_relays: self.nostr_relays.clone(),
            }))
        } else {
            None
        }
    }

    pub(crate) async fn resolve_identity(&self, node_id: &NodeId) -> Option<BillParticipant> {
        match self.get_local_identity(node_id).await {
            Some(id) => Some(id),
            None => {
                if let Some(identity) = self.resolve_node_contact(node_id).await {
                    Some(identity)
                } else if let Ok(Some(nostr)) = self.nostr_contact_store.by_node_id(node_id).await
                    && nostr.trust_level != TrustLevel::None
                {
                    // we have no contact but a nostr contact of a participant
                    Some(BillParticipant::Anon(BillAnonParticipant {
                        node_id: node_id.to_owned(),
                        nostr_relays: nostr.relays,
                    }))
                } else {
                    None
                }
            }
        }
    }

    pub(crate) async fn resolve_node_contact(&self, node_id: &NodeId) -> Option<BillParticipant> {
        if validate_node_id_network(node_id).is_err() {
            return None;
        }
        if let Ok(Some(identity)) = self.contact_store.get(node_id).await {
            identity.try_into().ok()
        } else {
            None
        }
    }

    pub(crate) async fn add_company_client(
        &self,
        _company: &Company,
        keys: &BcrKeys,
    ) -> Result<()> {
        let config = get_config();
        let node_id = NodeId::new(keys.pub_key(), get_config().bitcoin_network());

        let mut transports = self.notification_transport.lock().await;
        if transports.contains_key(&node_id) {
            debug!("transport for node {node_id} already present");
            return Ok(());
        }

        let nostr_config = NostrConfig::new(
            keys.clone(),
            config.nostr_config.relays.clone(),
            false,
            node_id.clone(),
        );

        if let Ok(client) = NostrClient::default(&nostr_config).await {
            debug!("adding nostr client for {}", &nostr_config.get_npub());
            client.connect().await?;
            transports.insert(node_id, Arc::new(client));
        }
        Ok(())
    }

    pub(crate) async fn send_all_bill_events(
        &self,
        sender: &NodeId,
        events: &HashMap<NodeId, Event<BillChainEventPayload>>,
    ) -> Result<()> {
        if let Some(node) = self.get_node_transport(sender).await {
            for (node_id, event_to_process) in events.iter() {
                if let Some(identity) = self.resolve_identity(node_id).await {
                    if let Err(e) = node
                        .send_private_event(sender, &identity, event_to_process.clone().try_into()?)
                        .await
                    {
                        error!(
                            "Failed to send block notification, will add it to retry queue: {e}"
                        );
                        self.queue_retry_message(
                            sender,
                            node_id,
                            base58::encode(
                                &borsh::to_vec(event_to_process)
                                    .map_err(|e| Error::Message(e.to_string()))?,
                            ),
                        )
                        .await?;
                    }
                } else {
                    warn!("Failed to find recipient in contacts for node_id: {node_id}");
                }
            }
        } else {
            warn!("No transport node found for sender node_id: {sender}");
        }
        Ok(())
    }

    pub(crate) async fn send_private_event(
        &self,
        sender: &NodeId,
        recipient: &NodeId,
        relays: &[url::Url],
        message: EventEnvelope,
    ) -> Result<()> {
        if let Some(transport) = self.get_node_transport(sender).await {
            let recipient = BillParticipant::Anon(BillAnonParticipant {
                node_id: recipient.to_owned(),
                nostr_relays: relays.to_vec(),
            });
            transport.send_private_event(sender, &recipient, message).await?;
        } else {
            warn!("No transport node found for sender node_id: {sender}");
            return Err(Error::Network(
                "No transport found for node {sender}".to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn queue_retry_message(
        &self,
        sender: &NodeId,
        recipient: &NodeId,
        payload: String,
    ) -> Result<()> {
        let queue_message = NostrQueuedMessage {
            id: uuid::Uuid::new_v4().to_string(),
            sender_id: sender.to_owned(),
            node_id: recipient.to_owned(),
            payload,
        };
        if let Err(e) = self
            .queued_message_store
            .add_message(queue_message, Self::NOSTR_MAX_RETRIES)
            .await
        {
            error!("Failed to add send nostr event to retry queue: {e}");
        }
        Ok(())
    }

    pub(crate) async fn find_root_and_previous_event(
        &self,
        previous_hash: &Sha256Hash,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> Result<(Option<NostrChainEvent>, Option<NostrChainEvent>)> {
        // find potential previous block event
        let previous_event = self
            .chain_event_store
            .find_by_block_hash(previous_hash)
            .await
            .map_err(|_| Error::Persistence("failed to read from chain events".to_owned()))?;

        // if there is a previous and it is not the root event, also get the root event
        let root_event = if previous_event.clone().is_some_and(|f| !f.is_root_event()) {
            self.chain_event_store
                .find_root_event(chain_id, chain_type)
                .await
                .map_err(|_| Error::Persistence("failed to read from chain events".to_owned()))?
        } else {
            previous_event.clone()
        };
        Ok((previous_event, root_event))
    }

    // sends all required bill chain events like public bill data and bill invites
    pub(crate) async fn add_chain_event(
        &self,
        event: &nostr::event::Event,
        root: &Option<NostrChainEvent>,
        previous: &Option<NostrChainEvent>,
        chain_id: &str,
        chain_type: BlockchainType,
        block_height: usize,
        block_hash: &Sha256Hash,
    ) -> Result<()> {
        self.chain_event_store
            .add_chain_event(NostrChainEvent {
                event_id: event.id.to_string(),
                root_id: root
                    .clone()
                    .map(|e| e.event_id.to_string())
                    .unwrap_or(event.id.to_string()),
                reply_id: previous.clone().map(|e| e.event_id.to_string()),
                author: event.pubkey.to_string(),
                chain_id: chain_id.to_string(),
                chain_type,
                block_height,
                block_hash: block_hash.to_owned(),
                received: event.created_at.into(),
                time: event.created_at.into(),
                payload: event.clone(),
                valid: true,
            })
            .await
            .map_err(|_| Error::Persistence("failed to write to chain events".to_owned()))?;
        Ok(())
    }

    pub(crate) async fn send_retry_messages(&self) -> Result<()> {
        let mut failed_ids = vec![];
        while let Ok(Some(queued_message)) = self
            .queued_message_store
            .get_retry_messages(1)
            .await
            .map(|r| r.first().cloned())
        {
            if let Ok(message) =
                borsh::from_slice::<EventEnvelope>(&base58::decode(&queued_message.payload)?)
            {
                if let Err(e) = self
                    .send_retry_message(
                        &queued_message.sender_id,
                        &queued_message.node_id,
                        message.clone(),
                    )
                    .await
                {
                    error!("Failed to send retry message: {e}");
                    failed_ids.push(queued_message.id.clone());
                } else if let Err(e) = self
                    .queued_message_store
                    .succeed_retry(&queued_message.id)
                    .await
                {
                    error!("Failed to mark retry message as sent: {e}");
                }
            }
        }

        for failed in failed_ids {
            if let Err(e) = self.queued_message_store.fail_retry(&failed).await {
                error!("Failed to store failed retry attemt: {e}");
            }
        }
        Ok(())
    }

    async fn send_retry_message(
        &self,
        sender: &NodeId,
        node_id: &NodeId,
        message: EventEnvelope,
    ) -> Result<()> {
        if let (Some(node), Some(identity)) = (
            self.get_node_transport(sender).await,
            self.resolve_node_contact(node_id).await,
        ) {
            node.send_private_event(sender, &identity, message).await?;
        }
        Ok(())
    }

    pub(crate) async fn connect(&self) {
        let transports = self.notification_transport.lock().await;
        for (_, transport) in transports.iter() {
            if let Err(e) = transport.connect().await {
                error!(
                    "Failed to connect to transport for node id {}: {e}",
                    transport.get_sender_node_id()
                );
            }
        }
    }
}
