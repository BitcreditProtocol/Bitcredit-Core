use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use crate::handler::{
    BillChainEventProcessorApi, CompanyChainEventProcessorApi, IdentityChainEventProcessorApi,
    NostrContactProcessorApi,
};
use crate::nostr::NostrClient;
use async_trait::async_trait;
use bcr_ebill_api::external::email::EmailClientApi;
use bcr_ebill_api::service::notification_service::transport::NotificationJsonTransportApi;
use bcr_ebill_api::service::notification_service::{NostrConfig, NostrContactData};
use bcr_ebill_core::address::Address;
use bcr_ebill_core::bill::BillId;
use bcr_ebill_core::blockchain::BlockchainType;
use bcr_ebill_core::city::City;
use bcr_ebill_core::company::Company;
use bcr_ebill_core::contact::{BillAnonParticipant, BillParticipant, ContactType};
use bcr_ebill_core::country::Country;
use bcr_ebill_core::email::Email;
use bcr_ebill_core::hash::Sha256Hash;
use bcr_ebill_core::name::Name;
use bcr_ebill_core::nostr_contact::TrustLevel;
use bcr_ebill_core::protocol::{
    BillChainEvent, BillChainEventPayload, CompanyChainEvent, ContactShareEvent, Event,
    EventEnvelope, IdentityChainEvent,
};
use bcr_ebill_core::sum::Sum;
use bcr_ebill_core::util::BcrKeys;
use bcr_ebill_persistence::ContactStoreApi;
use bcr_ebill_persistence::nostr::{
    NostrChainEvent, NostrChainEventStoreApi, NostrContactStoreApi, NostrQueuedMessage,
    NostrQueuedMessageStoreApi,
};
use bcr_ebill_persistence::notification::EmailNotificationStoreApi;
use log::{debug, error, warn};
use serde_json::Value;
use tokio::sync::Mutex;
use tokio::task::spawn;
use tokio_with_wasm::alias as tokio;

use bcr_ebill_api::data::{
    bill::BitcreditBill,
    contact::BillIdentParticipant,
    notification::{Notification, NotificationType},
};
use bcr_ebill_api::data::{validate_bill_id_network, validate_node_id_network};
use bcr_ebill_api::get_config;
use bcr_ebill_api::persistence::notification::{NotificationFilter, NotificationStoreApi};
use bcr_ebill_api::service::notification_service::{Error, NotificationServiceApi, Result};
use bcr_ebill_core::notification::{ActionType, BillEventType};
use bcr_ebill_core::{NodeId, PostalAddress, ServiceTraitBounds};

/// A default implementation of the NotificationServiceApi that can
/// send events via json and email transports.
#[allow(dead_code)]
pub struct NotificationService {
    notification_transport: Mutex<HashMap<NodeId, Arc<dyn NotificationJsonTransportApi>>>,
    notification_store: Arc<dyn NotificationStoreApi>,
    email_notification_store: Arc<dyn EmailNotificationStoreApi>,
    contact_store: Arc<dyn ContactStoreApi>,
    nostr_contact_store: Arc<dyn NostrContactStoreApi>,
    queued_message_store: Arc<dyn NostrQueuedMessageStoreApi>,
    chain_event_store: Arc<dyn NostrChainEventStoreApi>,
    email_client: Arc<dyn EmailClientApi>,
    bill_chain_event_processor: Arc<dyn BillChainEventProcessorApi>,
    company_chain_event_processor: Arc<dyn CompanyChainEventProcessorApi>,
    identity_chain_event_processor: Arc<dyn IdentityChainEventProcessorApi>,
    nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
    nostr_relays: Vec<url::Url>,
}

impl ServiceTraitBounds for NotificationService {}

impl NotificationService {
    // the number of times we want to retry sending a block message
    const NOSTR_MAX_RETRIES: i32 = 10;

    pub fn new(
        notification_transport: Vec<Arc<dyn NotificationJsonTransportApi>>,
        notification_store: Arc<dyn NotificationStoreApi>,
        email_notification_store: Arc<dyn EmailNotificationStoreApi>,
        contact_store: Arc<dyn ContactStoreApi>,
        nostr_contact_store: Arc<dyn NostrContactStoreApi>,
        queued_message_store: Arc<dyn NostrQueuedMessageStoreApi>,
        chain_event_store: Arc<dyn NostrChainEventStoreApi>,
        email_client: Arc<dyn EmailClientApi>,
        bill_chain_event_processor: Arc<dyn BillChainEventProcessorApi>,
        company_chain_event_processor: Arc<dyn CompanyChainEventProcessorApi>,
        identity_chain_event_processor: Arc<dyn IdentityChainEventProcessorApi>,
        nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
        nostr_relays: Vec<url::Url>,
    ) -> Self {
        let transports: Mutex<HashMap<NodeId, Arc<dyn NotificationJsonTransportApi>>> = Mutex::new(
            notification_transport
                .into_iter()
                .map(|t| (t.get_sender_node_id(), t))
                .collect(),
        );
        Self {
            notification_transport: transports,
            notification_store,
            email_notification_store,
            contact_store,
            nostr_contact_store,
            queued_message_store,
            chain_event_store,
            email_client,
            bill_chain_event_processor,
            company_chain_event_processor,
            identity_chain_event_processor,
            nostr_contact_processor,
            nostr_relays,
        }
    }

    async fn get_node_transport(
        &self,
        node_id: &NodeId,
    ) -> Option<Arc<dyn NotificationJsonTransportApi>> {
        let transports = self.notification_transport.lock().await;
        transports.get(node_id).cloned()
    }

    async fn get_local_identity(&self, node_id: &NodeId) -> Option<BillParticipant> {
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

    async fn resolve_identity(&self, node_id: &NodeId) -> Option<BillParticipant> {
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
                        email: None,
                        nostr_relays: nostr.relays,
                    }))
                } else {
                    None
                }
            }
        }
    }

    async fn resolve_node_contact(&self, node_id: &NodeId) -> Option<BillParticipant> {
        if validate_node_id_network(node_id).is_err() {
            return None;
        }
        if let Ok(Some(identity)) = self.contact_store.get(node_id).await {
            identity.try_into().ok()
        } else {
            None
        }
    }

    async fn add_company_client(&self, _company: &Company, keys: &BcrKeys) -> Result<()> {
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

        if let Ok(client) = NostrClient::new(&nostr_config).await {
            debug!("adding nostr client for {}", &nostr_config.get_npub());
            client.connect().await?;
            transports.insert(node_id, Arc::new(client));
        }
        Ok(())
    }

    async fn send_all_bill_events(
        &self,
        sender: &NodeId,
        events: &HashMap<NodeId, Event<BillChainEventPayload>>,
    ) -> Result<()> {
        if let Some(node) = self.get_node_transport(sender).await {
            for (node_id, event_to_process) in events.iter() {
                if let Some(identity) = self.resolve_identity(node_id).await {
                    if let Err(e) = node
                        .send_private_event(&identity, event_to_process.clone().try_into()?)
                        .await
                    {
                        error!(
                            "Failed to send block notification, will add it to retry queue: {e}"
                        );
                        self.queue_retry_message(
                            sender,
                            node_id,
                            serde_json::to_value(event_to_process)?,
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

    async fn send_private_event(
        &self,
        sender: &NodeId,
        recipient: &NodeId,
        relays: &[url::Url],
        message: EventEnvelope,
    ) -> Result<()> {
        if let Some(transport) = self.get_node_transport(sender).await {
            let recipient = BillParticipant::Anon(BillAnonParticipant {
                node_id: recipient.to_owned(),
                email: None,
                nostr_relays: relays.to_vec(),
            });
            transport.send_private_event(&recipient, message).await?;
        } else {
            warn!("No transport node found for sender node_id: {sender}");
            return Err(Error::Network(
                "No transport found for node {sender}".to_string(),
            ));
        }
        Ok(())
    }

    async fn queue_retry_message(
        &self,
        sender: &NodeId,
        recipient: &NodeId,
        payload: Value,
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

    async fn find_root_and_previous_event(
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
    async fn send_bill_chain_events(&self, events: &BillChainEvent) -> Result<()> {
        if let Some(node) = self.get_node_transport(&events.sender()).await {
            if let Some(block_event) = events.generate_blockchain_message() {
                let (previous_event, root_event) = self
                    .find_root_and_previous_event(
                        &block_event.data.block.previous_hash,
                        &block_event.data.bill_id.to_string(),
                        BlockchainType::Bill,
                    )
                    .await?;

                // now send the event
                let event = node
                    .send_public_chain_event(
                        &block_event.data.bill_id.to_string(),
                        BlockchainType::Bill,
                        block_event.data.block.timestamp,
                        events.bill_keys.clone().try_into()?,
                        block_event.clone().try_into()?,
                        previous_event.clone().map(|e| e.payload),
                        root_event.clone().map(|e| e.payload),
                    )
                    .await?;

                self.add_chain_event(
                    &event,
                    &root_event,
                    &previous_event,
                    &block_event.data.bill_id.to_string(),
                    BlockchainType::Bill,
                    block_event.data.block.id.inner() as usize,
                    &block_event.data.block.hash,
                )
                .await?;
            }

            let invites = events.generate_bill_invite_events();
            if !invites.is_empty() {
                for (recipient, event) in invites {
                    if let Some(identity) = self.resolve_identity(&recipient).await {
                        node.send_private_event(&identity, event.try_into()?)
                            .await?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn add_chain_event(
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
                received: event.created_at.as_u64(),
                time: event.created_at.as_u64(),
                payload: event.clone(),
                valid: true,
            })
            .await
            .map_err(|_| Error::Persistence("failed to write to chain events".to_owned()))?;
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
            node.send_private_event(&identity, message).await?;
        }
        Ok(())
    }

    /// Attempts to send an email notification for an event to the receiver
    /// if the receiver does not have email notifications enabled, the relay
    /// ignores the request and returns a quick 200 OK.
    async fn send_email_notification(
        &self,
        sender: &NodeId,
        receiver: &NodeId,
        event: &Event<BillChainEventPayload>,
    ) {
        if let Some(node) = self.get_node_transport(sender).await {
            if let Some(identity) = self.resolve_identity(receiver).await {
                // TODO(multi-relay): don't default to first, but to notification relay of receiver
                if let Some(nostr_relay) = identity.nostr_relays().first() {
                    // send asynchronously and don't fail on error
                    let email_client = self.email_client.clone();
                    let relay_clone = nostr_relay.clone();
                    let rcv_clone = receiver.clone();
                    let private_key = node.get_sender_keys().get_nostr_keys().secret_key().clone();
                    let evt_clone = event.clone();
                    spawn(async move {
                        if let Err(e) = email_client
                            .send_bill_notification(
                                &relay_clone,
                                evt_clone.data.event_type.to_owned(),
                                &evt_clone.data.bill_id,
                                &rcv_clone,
                                &private_key,
                            )
                            .await
                        {
                            warn!("Failed to send email notification: {e}");
                        }
                    });
                }
            } else {
                warn!("Failed to find recipient in contacts for node_id: {receiver}");
            }
        } else {
            warn!("No transport node found for sender node_id: {sender}");
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationServiceApi for NotificationService {
    async fn connect(&self) {
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

    async fn ensure_nostr_contact(&self, node_id: &NodeId) {
        self.nostr_contact_processor
            .ensure_nostr_contact(node_id)
            .await;
    }

    /// Adds a new transport client for a company if it does not already exist
    async fn add_company_transport(&self, company: &Company, keys: &BcrKeys) -> Result<()> {
        self.add_company_client(company, keys).await
    }
    /// Sent when an identity chain is created or updated
    async fn send_identity_chain_events(&self, events: IdentityChainEvent) -> Result<()> {
        debug!(
            "sending identity chain events for node: {}",
            events.identity.node_id
        );
        if let Some(node) = self.get_node_transport(&events.sender()).await {
            if let Some(event) = events.generate_blockchain_message() {
                let (previous_event, root_event) = self
                    .find_root_and_previous_event(
                        &event.data.block.previous_hash,
                        &event.data.node_id.to_string(),
                        BlockchainType::Identity,
                    )
                    .await?;
                // send the event
                let nostr_event = node
                    .send_public_chain_event(
                        &event.data.node_id.to_string(),
                        BlockchainType::Identity,
                        event.data.block.timestamp,
                        events.keys.clone(),
                        event.clone().try_into()?,
                        previous_event.clone().map(|e| e.payload),
                        root_event.clone().map(|e| e.payload),
                    )
                    .await?;
                // and store the event locally
                self.add_chain_event(
                    &nostr_event,
                    &root_event,
                    &previous_event,
                    &event.data.node_id.to_string(),
                    BlockchainType::Identity,
                    event.data.block.id.inner() as usize,
                    &event.data.block.hash,
                )
                .await?;
            }
        } else {
            error!(
                "could not find transport instance for sender node {}",
                events.sender()
            );
        }

        Ok(())
    }

    /// Sent when a company chain is created or updated
    async fn send_company_chain_events(&self, events: CompanyChainEvent) -> Result<()> {
        debug!(
            "sending company chain events for company id: {}",
            events.company.id
        );
        if let Some(node) = self.get_node_transport(&events.sender()).await {
            if let Some(event) = events.generate_blockchain_message() {
                let (previous_event, root_event) = self
                    .find_root_and_previous_event(
                        &event.data.block.previous_hash,
                        &event.data.node_id.to_string(),
                        BlockchainType::Company,
                    )
                    .await?;
                // send the event
                let nostr_event = node
                    .send_public_chain_event(
                        &event.data.node_id.to_string(),
                        BlockchainType::Company,
                        event.data.block.timestamp,
                        events.keys.clone().try_into()?,
                        event.clone().try_into()?,
                        previous_event.clone().map(|e| e.payload),
                        root_event.clone().map(|e| e.payload),
                    )
                    .await?;
                // and store the event locally
                self.add_chain_event(
                    &nostr_event,
                    &root_event,
                    &previous_event,
                    &event.data.node_id.to_string(),
                    BlockchainType::Company,
                    event.data.block.id.inner() as usize,
                    &event.data.block.hash,
                )
                .await?;
            }

            // handle potential invite for new signatory
            if let Some((recipient, invite)) = events.generate_company_invite_message()
                && let Some(identity) = self.resolve_identity(&recipient).await
            {
                node.send_private_event(&identity, invite.try_into()?)
                    .await?;
            }
        } else {
            error!(
                "could not find transport instance for sender node {}",
                events.sender()
            );
        }

        Ok(())
    }

    async fn send_bill_is_signed_event(&self, event: &BillChainEvent) -> Result<()> {
        let event_type = BillEventType::BillSigned;
        let sender = event.sender();
        let drawer = &event.bill.drawer.node_id;
        let drawee = &event.bill.drawee.node_id;
        let payee = &event.bill.payee.node_id();

        let all_events = event.generate_action_messages(
            HashMap::from_iter(vec![
                (
                    event.bill.drawee.node_id.clone(),
                    (event_type.clone(), ActionType::AcceptBill),
                ),
                (
                    event.bill.payee.node_id().clone(),
                    (event_type, ActionType::CheckBill),
                ),
            ]),
            None,
            None,
        );

        self.send_bill_chain_events(event).await?;
        self.send_all_bill_events(&sender, &all_events).await?;
        // send email(s)
        if drawer != drawee && drawer != payee {
            // if we're drawer, but neither drawee, nor payee, send mail to both
            if let Some(payee_event) = all_events.get(payee) {
                self.send_email_notification(&event.sender(), payee, payee_event)
                    .await;
            }

            if let Some(drawee_event) = all_events.get(drawee) {
                self.send_email_notification(&event.sender(), drawee, drawee_event)
                    .await;
            }
        } else if drawer == drawee {
            // if we're drawer & drawee, send mail to payee only

            if let Some(payee_event) = all_events.get(payee) {
                self.send_email_notification(&event.sender(), payee, payee_event)
                    .await;
            }
        } else if drawer == payee {
            // if we're drawer & payee, send mail to drawee only
            if let Some(drawee_event) = all_events.get(drawee) {
                self.send_email_notification(&event.sender(), drawee, drawee_event)
                    .await;
            }
        }

        Ok(())
    }

    async fn send_bill_is_accepted_event(&self, event: &BillChainEvent) -> Result<()> {
        let payee = event.bill.payee.node_id();
        let all_events = event.generate_action_messages(
            HashMap::from_iter(vec![(
                payee.clone(),
                (BillEventType::BillAccepted, ActionType::CheckBill),
            )]),
            None,
            None,
        );
        self.send_bill_chain_events(event).await?;
        self.send_all_bill_events(&event.sender(), &all_events)
            .await?;
        // Only send email to payee
        if let Some(payee_event) = all_events.get(&payee) {
            self.send_email_notification(&event.sender(), &payee, payee_event)
                .await;
        }
        Ok(())
    }

    async fn send_request_to_accept_event(&self, event: &BillChainEvent) -> Result<()> {
        let drawee = &event.bill.drawee.node_id;
        let all_events = event.generate_action_messages(
            HashMap::from_iter(vec![(
                drawee.clone(),
                (
                    BillEventType::BillAcceptanceRequested,
                    ActionType::AcceptBill,
                ),
            )]),
            None,
            None,
        );
        self.send_bill_chain_events(event).await?;
        self.send_all_bill_events(&event.sender(), &all_events)
            .await?;
        // Only send email to drawee
        if let Some(drawee_event) = all_events.get(drawee) {
            self.send_email_notification(&event.sender(), drawee, drawee_event)
                .await;
        }
        Ok(())
    }

    async fn send_request_to_pay_event(&self, event: &BillChainEvent) -> Result<()> {
        let drawee = &event.bill.drawee.node_id;
        let all_events = event.generate_action_messages(
            HashMap::from_iter(vec![(
                drawee.clone(),
                (BillEventType::BillPaymentRequested, ActionType::PayBill),
            )]),
            None,
            None,
        );
        self.send_bill_chain_events(event).await?;
        self.send_all_bill_events(&event.sender(), &all_events)
            .await?;
        // Only send email to drawee
        if let Some(drawee_event) = all_events.get(drawee) {
            self.send_email_notification(&event.sender(), drawee, drawee_event)
                .await;
        }
        Ok(())
    }

    async fn send_bill_is_paid_event(&self, event: &BillChainEvent) -> Result<()> {
        let sender = event.sender();
        let holder = event.bill.endorsee.as_ref().unwrap_or(&event.bill.payee);
        let all_events = event.generate_action_messages(
            HashMap::from_iter(vec![(
                holder.node_id(),
                (BillEventType::BillPaid, ActionType::CheckBill),
            )]),
            None,
            None,
        );
        self.send_bill_chain_events(event).await?;
        self.send_all_bill_events(&sender, &all_events).await?;
        // Only send email to holder and only if we are drawee
        if let Some(holder_event) = all_events.get(&holder.node_id())
            && sender == event.bill.drawee.node_id
        {
            self.send_email_notification(&sender, &holder.node_id(), holder_event)
                .await;
        }
        Ok(())
    }

    async fn send_bill_is_endorsed_event(&self, event: &BillChainEvent) -> Result<()> {
        let endorsee = event.bill.endorsee.as_ref().unwrap().node_id();
        let all_events = event.generate_action_messages(
            HashMap::from_iter(vec![(
                endorsee.clone(),
                (BillEventType::BillEndorsed, ActionType::CheckBill),
            )]),
            None,
            None,
        );
        self.send_bill_chain_events(event).await?;
        self.send_all_bill_events(&event.sender(), &all_events)
            .await?;
        // Only send email to endorsee
        if let Some(endorsee_event) = all_events.get(&endorsee) {
            self.send_email_notification(&event.sender(), &endorsee, endorsee_event)
                .await;
        }
        Ok(())
    }

    async fn send_offer_to_sell_event(
        &self,
        event: &BillChainEvent,
        buyer: &BillParticipant,
    ) -> Result<()> {
        let all_events = event.generate_action_messages(
            HashMap::from_iter(vec![(
                buyer.node_id().clone(),
                (BillEventType::BillSellOffered, ActionType::CheckBill),
            )]),
            None,
            None,
        );
        self.send_bill_chain_events(event).await?;
        self.send_all_bill_events(&event.sender(), &all_events)
            .await?;
        // Only send email to buyer
        if let Some(buyer_event) = all_events.get(&buyer.node_id()) {
            self.send_email_notification(&event.sender(), &buyer.node_id(), buyer_event)
                .await;
        }
        Ok(())
    }

    async fn send_bill_is_sold_event(
        &self,
        event: &BillChainEvent,
        buyer: &BillParticipant,
    ) -> Result<()> {
        let all_events = event.generate_action_messages(
            HashMap::from_iter(vec![(
                buyer.node_id().clone(),
                (BillEventType::BillSold, ActionType::CheckBill),
            )]),
            None,
            None,
        );
        self.send_bill_chain_events(event).await?;
        self.send_all_bill_events(&event.sender(), &all_events)
            .await?;
        // Only send email to buyer
        if let Some(buyer_event) = all_events.get(&buyer.node_id()) {
            self.send_email_notification(&event.sender(), &buyer.node_id(), buyer_event)
                .await;
        }
        Ok(())
    }

    async fn send_bill_recourse_paid_event(
        &self,
        event: &BillChainEvent,
        recoursee: &BillIdentParticipant,
    ) -> Result<()> {
        let all_events = event.generate_action_messages(
            HashMap::from_iter(vec![(
                recoursee.node_id.clone(),
                (BillEventType::BillRecoursePaid, ActionType::CheckBill),
            )]),
            None,
            None,
        );
        self.send_bill_chain_events(event).await?;
        self.send_all_bill_events(&event.sender(), &all_events)
            .await?;
        // Only send email to recoursee
        if let Some(recoursee_event) = all_events.get(&recoursee.node_id) {
            self.send_email_notification(&event.sender(), &recoursee.node_id, recoursee_event)
                .await;
        }
        Ok(())
    }

    async fn send_request_to_mint_event(
        &self,
        sender_node_id: &NodeId,
        mint: &BillParticipant,
        bill: &BitcreditBill,
    ) -> Result<()> {
        let event = Event::new_bill(BillChainEventPayload {
            event_type: BillEventType::BillMintingRequested,
            bill_id: bill.id.clone(),
            action_type: Some(ActionType::CheckBill),
            sum: Some(bill.sum.clone()),
        });
        if let Some(node) = self.get_node_transport(sender_node_id).await {
            node.send_private_event(mint, event.clone().try_into()?)
                .await?;
        }
        // Only send email to mint
        self.send_email_notification(sender_node_id, &mint.node_id(), &event)
            .await;
        Ok(())
    }

    async fn send_request_to_action_rejected_event(
        &self,
        event: &BillChainEvent,
        rejected_action: ActionType,
    ) -> Result<()> {
        if let Some(event_type) = rejected_action.get_rejected_event_type() {
            let holder = event.bill.endorsee.as_ref().unwrap_or(&event.bill.payee);
            let all_events = event.generate_action_messages(
                HashMap::new(),
                Some(event_type),
                Some(rejected_action),
            );

            self.send_bill_chain_events(event).await?;
            self.send_all_bill_events(&event.sender(), &all_events)
                .await?;
            // Only send email to holder (=requester)
            if let Some(holder_event) = all_events.get(&holder.node_id()) {
                self.send_email_notification(&event.sender(), &holder.node_id(), holder_event)
                    .await;
            }
        }
        Ok(())
    }

    async fn send_request_to_action_timed_out_event(
        &self,
        sender_node_id: &NodeId,
        bill_id: &BillId,
        sum: Option<Sum>,
        timed_out_action: ActionType,
        recipients: Vec<BillParticipant>,
        holder: &NodeId,
        drawee: &NodeId,
        recoursee: &Option<NodeId>,
    ) -> Result<()> {
        if let Some(node) = self.get_node_transport(sender_node_id).await
            && let Some(event_type) = timed_out_action.get_timeout_event_type()
        {
            // only send to a recipient once
            let unique: HashMap<NodeId, BillParticipant> =
                HashMap::from_iter(recipients.iter().map(|r| (r.node_id().clone(), r.clone())));

            let payload = BillChainEventPayload {
                event_type,
                bill_id: bill_id.to_owned(),
                action_type: Some(ActionType::CheckBill),
                sum,
            };
            for (_, recipient) in unique {
                let event = Event::new_bill(payload.clone());
                node.send_private_event(&recipient, event.clone().try_into()?)
                    .await?;

                // Only send email to holder, and only if we are drawee, or recoursee
                if let Some(r) = recoursee {
                    if sender_node_id == r {
                        self.send_email_notification(sender_node_id, holder, &event)
                            .await;
                    }
                } else if sender_node_id == drawee {
                    self.send_email_notification(sender_node_id, holder, &event)
                        .await;
                }
            }
        }
        Ok(())
    }

    async fn send_recourse_action_event(
        &self,
        event: &BillChainEvent,
        action: ActionType,
        recoursee: &BillIdentParticipant,
    ) -> Result<()> {
        if let Some(event_type) = action.get_recourse_event_type() {
            let all_events = event.generate_action_messages(
                HashMap::from_iter(vec![(
                    recoursee.node_id.clone(),
                    (event_type.clone(), action.clone()),
                )]),
                Some(BillEventType::BillBlock),
                None,
            );
            self.send_bill_chain_events(event).await?;
            self.send_all_bill_events(&event.sender(), &all_events)
                .await?;
            // Only send email to recoursee
            if let Some(recoursee_event) = all_events.get(&recoursee.node_id) {
                self.send_email_notification(&event.sender(), &recoursee.node_id, recoursee_event)
                    .await;
            }
        }
        Ok(())
    }

    async fn get_client_notifications(
        &self,
        filter: NotificationFilter,
    ) -> Result<Vec<Notification>> {
        for node_id in filter.node_ids.iter() {
            validate_node_id_network(node_id)?;
        }
        let result = self.notification_store.list(filter).await.map_err(|e| {
            error!("Failed to get client notifications: {e}");
            Error::Persistence("Failed to get client notifications".to_string())
        })?;
        Ok(result)
    }

    async fn mark_notification_as_done(&self, notification_id: &str) -> Result<()> {
        let _ = self
            .notification_store
            .mark_as_done(notification_id)
            .await
            .map_err(|e| {
                error!("Failed to mark notification as done: {e}");
                Error::Persistence("Failed to mark notification as done".to_string())
            })?;
        Ok(())
    }

    async fn get_active_bill_notification(&self, bill_id: &BillId) -> Option<Notification> {
        validate_bill_id_network(bill_id).ok()?;
        self.notification_store
            .get_latest_by_reference(&bill_id.to_string(), NotificationType::Bill)
            .await
            .unwrap_or_default()
    }

    async fn get_active_bill_notifications(
        &self,
        bill_ids: &[BillId],
    ) -> HashMap<BillId, Notification> {
        let ids: Vec<String> = bill_ids.iter().map(|bill_id| bill_id.to_string()).collect();
        let refs = self
            .notification_store
            .get_latest_by_references(&ids, NotificationType::Bill)
            .await
            .unwrap_or_default();
        refs.into_iter()
            .filter_map(|(key, value)| match BillId::from_str(&key) {
                Ok(bill_id) => Some((bill_id, value)),
                Err(_) => None,
            })
            .collect()
    }

    async fn get_active_notification_status_for_node_ids(
        &self,
        node_ids: &[NodeId],
    ) -> Result<HashMap<NodeId, bool>> {
        Ok(self
            .notification_store
            .get_active_status_for_node_ids(node_ids)
            .await
            .unwrap_or_default())
    }

    async fn check_bill_notification_sent(
        &self,
        bill_id: &BillId,
        block_height: i32,
        action: ActionType,
    ) -> Result<bool> {
        validate_bill_id_network(bill_id)?;
        Ok(self
            .notification_store
            .bill_notification_sent(bill_id, block_height, action)
            .await
            .map_err(|e| {
                error!("Failed to check if bill notification was already sent: {e}");
                Error::Persistence(
                    "Failed to check if bill notification was already sent".to_string(),
                )
            })?)
    }

    /// Stores that a notification was sent for the given bill id and action
    async fn mark_bill_notification_sent(
        &self,
        bill_id: &BillId,
        block_height: i32,
        action: ActionType,
    ) -> Result<()> {
        validate_bill_id_network(bill_id)?;
        self.notification_store
            .set_bill_notification_sent(bill_id, block_height, action)
            .await
            .map_err(|e| {
                error!("Failed to mark bill notification as sent: {e}");
                Error::Persistence("Failed to mark bill notification as sent".to_string())
            })?;
        Ok(())
    }

    async fn send_retry_messages(&self) -> Result<()> {
        let mut failed_ids = vec![];
        while let Ok(Some(queued_message)) = self
            .queued_message_store
            .get_retry_messages(1)
            .await
            .map(|r| r.first().cloned())
        {
            if let Ok(message) = serde_json::from_value::<EventEnvelope>(queued_message.payload) {
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

    async fn resolve_contact(&self, node_id: &NodeId) -> Result<Option<NostrContactData>> {
        validate_node_id_network(node_id)?;
        let transports = self.notification_transport.lock().await;
        // take any transport - doesn't matter
        if let Some((_node, transport)) = transports.iter().nth(0) {
            let res = transport.resolve_contact(node_id).await?;
            Ok(res)
        } else {
            Ok(None)
        }
    }

    async fn publish_contact(&self, node_id: &NodeId, data: &NostrContactData) -> Result<()> {
        let transports = self.notification_transport.lock().await;
        if let Some(transport) = transports.get(node_id) {
            transport.publish_metadata(&data.metadata).await?;
            transport.publish_relay_list(data.relays.clone()).await?;
        }
        Ok(())
    }

    async fn register_email_notifications(
        &self,
        relay_url: &url::Url,
        email: &Email,
        node_id: &NodeId,
        caller_keys: &BcrKeys,
    ) -> Result<()> {
        let challenge = self.email_client.start(relay_url, node_id).await?;

        let preferences_link = self
            .email_client
            .register(
                relay_url,
                email,
                caller_keys.get_nostr_keys().secret_key(),
                &challenge,
            )
            .await?;
        self.email_notification_store
            .add_email_preferences_link_for_node_id(&preferences_link, node_id)
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;
        Ok(())
    }

    async fn get_email_notifications_preferences_link(&self, node_id: &NodeId) -> Result<url::Url> {
        match self
            .email_notification_store
            .get_email_preferences_link_for_node_id(node_id)
            .await
        {
            Ok(Some(link)) => Ok(link),
            Ok(None) => Err(Error::NotFound),
            Err(e) => Err(Error::Persistence(e.to_string())),
        }
    }

    async fn resync_bill_chain(&self, bill_id: &BillId) -> Result<()> {
        self.bill_chain_event_processor
            .resync_chain(bill_id)
            .await?;
        Ok(())
    }

    async fn resync_company_chain(&self, company_id: &NodeId) -> Result<()> {
        self.company_chain_event_processor
            .resync_chain(company_id)
            .await?;
        Ok(())
    }

    async fn resync_identity_chain(&self) -> Result<()> {
        self.identity_chain_event_processor.resync_chain().await?;
        Ok(())
    }

    /// Shares derived keys for private contact information via DM.
    async fn share_contact_details_keys(
        &self,
        recipient: &NodeId,
        contact_id: &NodeId,
        keys: &BcrKeys,
    ) -> Result<()> {
        let relays = match self.nostr_contact_store.by_node_id(recipient).await {
            Ok(Some(contact)) => contact.relays,
            _ => self
                .resolve_contact(recipient)
                .await?
                .map(|c| c.relays.iter().map(|r| r.to_owned().into()).collect())
                .unwrap_or_default(),
        };
        if relays.is_empty() {
            error!("No relays found for contact {recipient}");
            return Err(Error::NotFound);
        }
        let event = Event::new_contact_share(ContactShareEvent {
            node_id: contact_id.to_owned(),
            private_key: keys.get_private_key(),
        });

        self.send_private_event(contact_id, recipient, &relays, event.try_into()?)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bcr_ebill_core::bill::BillKeys;
    use bcr_ebill_core::blockchain::bill::block::{
        BillAcceptBlockData, BillOfferToSellBlockData, BillParticipantBlockData,
        BillRecourseBlockData, BillRecourseReasonBlockData, BillRequestToAcceptBlockData,
        BillRequestToPayBlockData,
    };
    use bcr_ebill_core::blockchain::bill::{BillBlock, BillBlockchain};
    use bcr_ebill_core::blockchain::{Blockchain, BlockchainType};
    use bcr_ebill_core::constants::{
        ACCEPT_DEADLINE_SECONDS, DAY_IN_SECS, PAYMENT_DEADLINE_SECONDS,
    };
    use bcr_ebill_core::contact::Contact;
    use bcr_ebill_core::protocol::{ChainInvite, EventType};
    use bcr_ebill_core::sum::Currency;
    use bcr_ebill_core::util::{BcrKeys, date::now};
    use mockall::predicate::eq;
    use std::sync::Arc;

    use crate::handler::{
        MockBillChainEventProcessorApi, MockCompanyChainEventProcessorApi,
        MockIdentityChainEventProcessorApi, MockNostrContactProcessorApi,
    };
    use crate::test_utils::{
        MockContactStore, MockEmailClient, MockEmailNotificationStore, MockNostrChainEventStore,
        MockNostrContactStore, MockNostrQueuedMessageStore, MockNotificationJsonTransport,
        MockNotificationStore, bill_id_test, empty_address, get_baseline_identity,
        get_genesis_chain, init_test_cfg, node_id_test, node_id_test_other, node_id_test_other2,
        private_key_test,
    };

    use super::super::test_utils::{get_identity_public_data, get_test_bitcredit_bill};
    use super::*;

    fn check_chain_payload(event: &EventEnvelope, bill_event_type: BillEventType) -> bool {
        let valid_event_type = event.event_type == EventType::Bill;
        let event: bcr_ebill_core::protocol::Result<Event<BillChainEventPayload>> =
            event.clone().try_into();
        if let Ok(event) = event {
            valid_event_type && event.data.event_type == bill_event_type
        } else {
            false
        }
    }

    fn get_test_nostr_event() -> nostr::event::Event {
        let keys = nostr::key::Keys::generate();
        let sig = [0u8; 64];
        let id = [0u8; 32];
        nostr::event::Event::new(
            nostr::event::EventId::from_byte_array(id),
            keys.public_key(),
            nostr::Timestamp::from_secs(now().timestamp() as u64),
            nostr::event::Kind::TextNote,
            nostr::event::Tags::default(),
            "test".to_string(),
            nostr::secp256k1::schnorr::Signature::from_slice(&sig).unwrap(),
        )
    }

    #[tokio::test]
    async fn test_connect() {
        init_test_cfg();
        let mut mock_transport = MockNotificationJsonTransport::new();

        // get node_id
        mock_transport
            .expect_get_sender_node_id()
            .returning(node_id_test);

        // call connect on the inner transport
        mock_transport.expect_connect().returning(|| Ok(()));

        let service = NotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(MockContactStore::new()),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        service.connect().await;
    }

    #[tokio::test]
    async fn test_send_request_to_action_rejected_event() {
        init_test_cfg();
        let payer = get_identity_public_data(
            &node_id_test(),
            &Email::new("drawee@example.com").unwrap(),
            vec![],
        );
        let payee = get_identity_public_data(
            &node_id_test_other(),
            &Email::new("payee@example.com").unwrap(),
            vec![],
        );
        let buyer = get_identity_public_data(
            &node_id_test_other2(),
            &Email::new("buyer@example.com").unwrap(),
            vec![],
        );
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let mut chain = get_genesis_chain(Some(bill.clone()));
        let timestamp = now().timestamp() as u64;
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_offer_to_sell(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillOfferToSellBlockData {
                seller: BillParticipantBlockData::Ident(payee.clone().into()),
                buyer: BillParticipantBlockData::Ident(buyer.clone().into()),
                sum: Sum::new_sat(100).expect("sat works"),
                signatory: None,
                payment_address: "Address".to_string(),
                signing_timestamp: timestamp,
                signing_address: Some(empty_address()),
                buying_deadline_timestamp: timestamp + 2 * DAY_IN_SECS,
            },
            &keys,
            None,
            &keys,
            timestamp,
        )
        .unwrap();

        chain.try_add_block(block);

        let event = BillChainEvent::new(
            &bill,
            &chain,
            &BillKeys {
                private_key: private_key_test(),
                public_key: node_id_test().pub_key(),
            },
            true,
            &node_id_test(),
        )
        .unwrap();

        let mut mock_contact_store = MockContactStore::new();

        mock_contact_store
            .expect_get()
            .returning(move |_| Ok(Some(as_contact(&buyer))));
        mock_contact_store
            .expect_get()
            .returning(move |_| Ok(Some(as_contact(&payer))));
        mock_contact_store
            .expect_get()
            .returning(move |_| Ok(Some(as_contact(&payee))));

        let mut mock = MockNotificationJsonTransport::new();

        // get node_id
        mock.expect_get_sender_node_id().returning(node_id_test);

        // expect to send payment rejected event to all recipients
        mock.expect_send_private_event()
            .withf(|_, e| check_chain_payload(e, BillEventType::BillPaymentRejected))
            .returning(|_, _| Ok(()))
            .times(3);

        // expect to send acceptance rejected event to all recipients
        mock.expect_send_private_event()
            .withf(|_, e| check_chain_payload(e, BillEventType::BillAcceptanceRejected))
            .returning(|_, _| Ok(()))
            .times(3);

        // expect to send buying rejected event to all recipients
        mock.expect_send_private_event()
            .withf(|_, e| check_chain_payload(e, BillEventType::BillBuyingRejected))
            .returning(|_, _| Ok(()))
            .times(3);

        // expect to send recourse rejected event to all recipients
        mock.expect_send_private_event()
            .withf(|_, e| check_chain_payload(e, BillEventType::BillRecourseRejected))
            .returning(|_, _| Ok(()))
            .times(3);

        let previous_hash = chain.get_latest_block().previous_hash.to_owned();
        let mut mock_event_store = MockNostrChainEventStore::new();
        // lookup parent event
        mock_event_store
            .expect_find_by_block_hash()
            .with(eq(previous_hash.to_owned()))
            .returning(|_| Ok(None));

        // sends the public chain event for each of the events
        mock.expect_send_public_chain_event()
            .returning(|_, _, _, _, _, _, _| Ok(get_test_nostr_event()))
            .times(4);

        // afterwards we store the block event we have sent
        mock_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()))
            .times(4);

        // this is only required for the test as it contains an invite block so it tries to send an
        // invite to new participants as well and the test data doesn't have them all.
        mock.expect_send_private_event()
            .withf(|_, e| e.event_type == EventType::BillChainInvite)
            .returning(|_, _| Ok(()));

        let service = NotificationService::new(
            vec![Arc::new(mock)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(mock_contact_store),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(mock_event_store),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        service
            .send_request_to_action_rejected_event(&event, ActionType::PayBill)
            .await
            .expect("failed to send event");

        service
            .send_request_to_action_rejected_event(&event, ActionType::AcceptBill)
            .await
            .expect("failed to send event");

        service
            .send_request_to_action_rejected_event(&event, ActionType::BuyBill)
            .await
            .expect("failed to send event");

        service
            .send_request_to_action_rejected_event(&event, ActionType::RecourseBill)
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_send_request_to_action_rejected_does_not_send_non_rejectable_action() {
        init_test_cfg();
        let payer = get_identity_public_data(
            &node_id_test(),
            &Email::new("drawee@example.com").unwrap(),
            vec![],
        );
        let payee = get_identity_public_data(
            &node_id_test_other(),
            &Email::new("payee@example.com").unwrap(),
            vec![],
        );
        let buyer = get_identity_public_data(
            &node_id_test_other2(),
            &Email::new("buyer@example.com").unwrap(),
            vec![],
        );
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let mut chain = get_genesis_chain(Some(bill.clone()));
        let timestamp = now().timestamp() as u64;
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_offer_to_sell(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillOfferToSellBlockData {
                seller: BillParticipantBlockData::Ident(payee.clone().into()),
                buyer: BillParticipantBlockData::Ident(buyer.clone().into()),
                sum: Sum::new_sat(100).expect("sat works"),
                signatory: None,
                payment_address: "Address".to_string(),
                signing_timestamp: timestamp,
                signing_address: Some(empty_address()),
                buying_deadline_timestamp: timestamp + 2 * DAY_IN_SECS,
            },
            &keys,
            None,
            &keys,
            timestamp,
        )
        .unwrap();

        chain.try_add_block(block);

        let event = BillChainEvent::new(
            &bill,
            &chain,
            &BillKeys {
                private_key: private_key_test(),
                public_key: node_id_test().pub_key(),
            },
            true,
            &node_id_test(),
        )
        .unwrap();

        let mut mock_contact_store = MockContactStore::new();

        // no participant should receive events
        mock_contact_store.expect_get().never();

        let mut mock = MockNotificationJsonTransport::new();
        mock.expect_get_sender_node_id().returning(node_id_test);

        // expect to not send rejected event for non rejectable actions
        mock.expect_send_private_event().never();

        let service = NotificationService::new(
            vec![Arc::new(mock)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(mock_contact_store),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        service
            .send_request_to_action_rejected_event(&event, ActionType::CheckBill)
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_send_request_to_action_timed_out_event() {
        init_test_cfg();
        let recipients = vec![
            BillParticipant::Ident(get_identity_public_data(
                &node_id_test(),
                &Email::new("part1@example.com").unwrap(),
                vec![],
            )),
            BillParticipant::Ident(get_identity_public_data(
                &node_id_test_other(),
                &Email::new("part2@example.com").unwrap(),
                vec![],
            )),
            BillParticipant::Ident(get_identity_public_data(
                &node_id_test_other2(),
                &Email::new("part3@example.com").unwrap(),
                vec![],
            )),
        ];

        let mut mock = MockNotificationJsonTransport::new();

        // resolves node_id
        mock.expect_get_sender_node_id().returning(node_id_test);
        mock.expect_get_sender_keys()
            .returning(|| BcrKeys::from_private_key(&private_key_test()).unwrap());

        // expect to send payment timeout event to all recipients
        mock.expect_send_private_event()
            .withf(|_, e| check_chain_payload(e, BillEventType::BillPaymentTimeout))
            .returning(|_, _| Ok(()))
            .times(3);

        // expect to send acceptance timeout event to all recipients
        mock.expect_send_private_event()
            .withf(|_, e| check_chain_payload(e, BillEventType::BillAcceptanceTimeout))
            .returning(|_, _| Ok(()))
            .times(3);

        let service = NotificationService::new(
            vec![Arc::new(mock)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(MockContactStore::new()),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        service
            .send_request_to_action_timed_out_event(
                &node_id_test(),
                &bill_id_test(),
                Some(Sum::new_sat(100).expect("sat works")),
                ActionType::PayBill,
                recipients.clone(),
                &node_id_test(),
                &node_id_test(),
                &None,
            )
            .await
            .expect("failed to send event");

        service
            .send_request_to_action_timed_out_event(
                &node_id_test(),
                &bill_id_test(),
                Some(Sum::new_sat(100).expect("sat works")),
                ActionType::AcceptBill,
                recipients.clone(),
                &node_id_test(),
                &node_id_test(),
                &None,
            )
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_send_request_to_action_timed_out_does_not_send_non_timeout_action() {
        init_test_cfg();
        let recipients = vec![
            BillParticipant::Ident(get_identity_public_data(
                &node_id_test(),
                &Email::new("part1@example.com").unwrap(),
                vec![],
            )),
            BillParticipant::Ident(get_identity_public_data(
                &node_id_test_other(),
                &Email::new("part2@example.com").unwrap(),
                vec![],
            )),
            BillParticipant::Ident(get_identity_public_data(
                &node_id_test_other2(),
                &Email::new("part3@example.com").unwrap(),
                vec![],
            )),
        ];

        let mut mock = MockNotificationJsonTransport::new();
        mock.expect_get_sender_node_id().returning(node_id_test);

        // expect to never send timeout event on non expiring events
        mock.expect_send_private_event().never();

        let service = NotificationService::new(
            vec![Arc::new(mock)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(MockContactStore::new()),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        service
            .send_request_to_action_timed_out_event(
                &node_id_test(),
                &bill_id_test(),
                Some(Sum::new_sat(100).expect("sat works")),
                ActionType::CheckBill,
                recipients.clone(),
                &node_id_test(),
                &node_id_test(),
                &None,
            )
            .await
            .expect("failed to send event");
    }

    fn as_contact(id: &BillIdentParticipant) -> Contact {
        Contact {
            t: id.t.clone(),
            node_id: id.node_id.clone(),
            name: id.name.to_owned(),
            email: id.email.clone(),
            postal_address: Some(id.postal_address.clone()),
            nostr_relays: id.nostr_relays.clone(),
            identification_number: None,
            avatar_file: None,
            proof_document_file: None,
            date_of_birth_or_registration: None,
            country_of_birth_or_registration: None,
            city_of_birth_or_registration: None,
            is_logical: false,
        }
    }

    #[tokio::test]
    async fn test_send_recourse_action_event() {
        init_test_cfg();
        let payer = get_identity_public_data(
            &node_id_test(),
            &Email::new("drawee@example.com").unwrap(),
            vec![],
        );
        let payee = get_identity_public_data(
            &node_id_test_other(),
            &Email::new("payee@example.com").unwrap(),
            vec![],
        );
        let buyer = get_identity_public_data(
            &node_id_test_other2(),
            &Email::new("buyer@example.com").unwrap(),
            vec![],
        );
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let mut chain = get_genesis_chain(Some(bill.clone()));
        let timestamp = now().timestamp() as u64;
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_offer_to_sell(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillOfferToSellBlockData {
                seller: BillParticipantBlockData::Ident(payee.clone().into()),
                buyer: BillParticipantBlockData::Ident(buyer.clone().into()),
                sum: Sum::new_sat(100).expect("sat works"),
                signatory: None,
                payment_address: "Address".to_string(),
                signing_timestamp: timestamp,
                signing_address: Some(empty_address()),
                buying_deadline_timestamp: timestamp + 2 * DAY_IN_SECS,
            },
            &keys,
            None,
            &keys,
            timestamp,
        )
        .unwrap();

        chain.try_add_block(block);

        let event = BillChainEvent::new(
            &bill,
            &chain,
            &BillKeys {
                private_key: private_key_test(),
                public_key: node_id_test().pub_key(),
            },
            true,
            &node_id_test(),
        )
        .unwrap();

        let mut mock_contact_store = MockContactStore::new();

        let buyer_clone = buyer.clone();
        // participants should receive events
        mock_contact_store
            .expect_get()
            .returning(move |_| Ok(Some(as_contact(&buyer_clone))));
        mock_contact_store
            .expect_get()
            .returning(move |_| Ok(Some(as_contact(&payee))));
        mock_contact_store
            .expect_get()
            .returning(move |_| Ok(Some(as_contact(&payer))));

        let mut mock = MockNotificationJsonTransport::new();

        // resolve node_id
        mock.expect_get_sender_node_id().returning(node_id_test);

        // expect to send payment recourse event to all recipients
        mock.expect_send_private_event()
            .withf(|_, e| check_chain_payload(e, BillEventType::BillPaymentRecourse))
            .returning(|_, _| Ok(()))
            .times(1);
        mock.expect_send_private_event()
            .withf(|_, e| check_chain_payload(e, BillEventType::BillBlock))
            .returning(|_, _| Ok(()))
            .times(2);

        // expect to send acceptance recourse event to all recipients
        mock.expect_send_private_event()
            .withf(|_, e| check_chain_payload(e, BillEventType::BillAcceptanceRecourse))
            .returning(|_, _| Ok(()))
            .times(1);
        mock.expect_send_private_event()
            .withf(|_, e| check_chain_payload(e, BillEventType::BillBlock))
            .returning(|_, _| Ok(()))
            .times(2);

        mock.expect_send_public_chain_event()
            .returning(|_, _, _, _, _, _, _| Ok(get_test_nostr_event()))
            .times(2);

        mock.expect_send_private_event()
            .withf(move |_, e| {
                let r: bcr_ebill_core::protocol::Result<Event<ChainInvite>> = e.clone().try_into();
                r.is_ok()
            })
            .returning(|_, _| Ok(()));

        let event_store = setup_event_store_expectations(
            &chain.get_latest_block().previous_hash.to_owned(),
            &bill.id,
        );

        let service = NotificationService::new(
            vec![Arc::new(mock)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(mock_contact_store),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(event_store),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        service
            .send_recourse_action_event(&event, ActionType::PayBill, &buyer)
            .await
            .expect("failed to send event");

        service
            .send_recourse_action_event(&event, ActionType::AcceptBill, &buyer)
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_send_recourse_action_event_does_not_send_non_recurse_action() {
        init_test_cfg();
        let payer = get_identity_public_data(
            &node_id_test(),
            &Email::new("drawee@example.com").unwrap(),
            vec![],
        );
        let payee = get_identity_public_data(
            &node_id_test_other(),
            &Email::new("payee@example.com").unwrap(),
            vec![],
        );
        let buyer = get_identity_public_data(
            &node_id_test_other2(),
            &Email::new("buyer@example.com").unwrap(),
            vec![],
        );
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let mut chain = get_genesis_chain(Some(bill.clone()));
        let timestamp = now().timestamp() as u64;
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_offer_to_sell(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillOfferToSellBlockData {
                seller: BillParticipantBlockData::Ident(payee.clone().into()),
                buyer: BillParticipantBlockData::Ident(buyer.clone().into()),
                sum: Sum::new_sat(100).expect("sat works"),
                signatory: None,
                payment_address: "Address".to_string(),
                signing_timestamp: timestamp,
                signing_address: Some(empty_address()),
                buying_deadline_timestamp: timestamp + 2 * DAY_IN_SECS,
            },
            &keys,
            None,
            &keys,
            timestamp,
        )
        .unwrap();

        chain.try_add_block(block);

        let event = BillChainEvent::new(
            &bill,
            &chain,
            &BillKeys {
                private_key: private_key_test(),
                public_key: node_id_test().pub_key(),
            },
            true,
            &node_id_test(),
        )
        .unwrap();

        let mut mock = MockNotificationJsonTransport::new();
        mock.expect_get_sender_node_id().returning(node_id_test);

        // expect not to send non recourse event
        mock.expect_send_private_event().never();

        let service = NotificationService::new(
            vec![Arc::new(mock)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(MockContactStore::new()),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        service
            .send_recourse_action_event(&event, ActionType::CheckBill, &payer)
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_failed_to_send_is_added_to_retry_queue() {
        init_test_cfg();
        // given a payer and payee with a new bill
        let payer = get_identity_public_data(
            &node_id_test(),
            &Email::new("drawee@example.com").unwrap(),
            vec![],
        );
        let payee = get_identity_public_data(
            &node_id_test_other(),
            &Email::new("payee@example.com").unwrap(),
            vec![],
        );
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let chain = get_genesis_chain(Some(bill.clone()));

        let mut mock_contact_store = MockContactStore::new();
        mock_contact_store
            .expect_get()
            .returning(move |_| Ok(Some(as_contact(&payer))));
        mock_contact_store
            .expect_get()
            .returning(move |_| Ok(Some(as_contact(&payee))));

        let mut mock = MockNotificationJsonTransport::new();
        mock.expect_get_sender_node_id().returning(node_id_test);

        mock.expect_send_private_event()
            .withf(move |_, e| {
                let r: bcr_ebill_core::protocol::Result<Event<ChainInvite>> = e.clone().try_into();
                r.is_ok()
            })
            .returning(|_, _| Ok(()));

        mock.expect_send_public_chain_event()
            .returning(|_, _, _, _, _, _, _| Ok(get_test_nostr_event()));

        let mock_event_store = setup_event_store_expectations(
            &chain.get_latest_block().previous_hash.to_owned(),
            &bill.id,
        );

        mock.expect_send_private_event()
            .returning(|_, _| Ok(()))
            .once();

        mock.expect_send_private_event()
            .withf(move |_, e| {
                let r: bcr_ebill_core::protocol::Result<Event<ChainInvite>> = e.clone().try_into();
                r.is_err()
            })
            .returning(|_, _| Err(Error::Network("Failed to send".to_string())));

        let mut queue_mock = MockNostrQueuedMessageStore::new();
        queue_mock
            .expect_add_message()
            .returning(|_, _| Ok(()))
            .once();

        let service = NotificationService::new(
            vec![Arc::new(mock)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(mock_contact_store),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(queue_mock),
            Arc::new(mock_event_store),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        let event = BillChainEvent::new(
            &bill,
            &chain,
            &BillKeys {
                private_key: private_key_test(),
                public_key: node_id_test().pub_key(),
            },
            true,
            &node_id_test(),
        )
        .unwrap();

        service
            .send_bill_is_signed_event(&event)
            .await
            .expect("failed to send event");
    }

    fn setup_event_store_expectations(
        previous_hash: &Sha256Hash,
        bill_id: &BillId,
    ) -> MockNostrChainEventStore {
        let mut mock_event_store = MockNostrChainEventStore::new();
        // lookup parent event
        mock_event_store
            .expect_find_by_block_hash()
            .with(eq(previous_hash.to_owned()))
            .returning(|_| Ok(None));

        // if no parent we don't need to lookup the root event
        mock_event_store
            .expect_find_root_event()
            .with(eq(bill_id.to_string()), eq(BlockchainType::Bill))
            .returning(|_, _| Ok(None))
            .never();

        // afterwards we store the event we have sent
        mock_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()));
        mock_event_store
    }

    fn setup_chain_expectation(
        participants: Vec<(BillIdentParticipant, BillEventType, Option<ActionType>)>,
        bill: &BitcreditBill,
        chain: &BillBlockchain,
        new_blocks: bool,
    ) -> (NotificationService, BillChainEvent) {
        let mut mock_email_client = MockEmailClient::new();
        mock_email_client
            .expect_send_bill_notification()
            .returning(|_, _, _, _, _| Ok(()));
        let mut mock_contact_store = MockContactStore::new();
        let mut mock = MockNotificationJsonTransport::new();
        for p in participants.into_iter() {
            let clone1 = p.clone();
            mock_contact_store
                .expect_get()
                .with(eq(clone1.0.node_id.clone()))
                .returning(move |_| Ok(Some(as_contact(&clone1.0))));

            mock.expect_get_sender_node_id().returning(node_id_test);
            mock.expect_get_sender_keys()
                .returning(|| BcrKeys::from_private_key(&private_key_test()).unwrap());

            let clone2 = p.clone();
            mock.expect_send_private_event()
                .withf(move |r, e| {
                    let part = clone2.clone();
                    let valid_node_id = r.node_id() == part.0.node_id;
                    let event_result: bcr_ebill_core::protocol::Result<
                        Event<BillChainEventPayload>,
                    > = e.clone().try_into();
                    if let Ok(event) = event_result {
                        let valid_event_type = event.data.event_type == part.1;
                        valid_node_id && valid_event_type && event.data.action_type == part.2
                    } else {
                        false
                    }
                })
                .returning(|_, _| Ok(()));

            mock.expect_send_private_event()
                .withf(move |_, e| {
                    let r: bcr_ebill_core::protocol::Result<Event<ChainInvite>> =
                        e.clone().try_into();
                    r.is_ok()
                })
                .returning(|_, _| Ok(()));
        }
        let mut mock_event_store: MockNostrChainEventStore = MockNostrChainEventStore::new();
        if new_blocks {
            mock.expect_send_public_chain_event()
                .returning(|_, _, _, _, _, _, _| Ok(get_test_nostr_event()))
                .once();
            mock_event_store = setup_event_store_expectations(
                &chain.get_latest_block().previous_hash.to_owned(),
                &bill.id,
            );
        } else {
            mock.expect_send_public_chain_event()
                .returning(|_, _, _, _, _, _, _| Ok(get_test_nostr_event()))
                .never();
        }

        let service = NotificationService::new(
            vec![Arc::new(mock)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(mock_contact_store),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(mock_event_store),
            Arc::new(mock_email_client),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        (
            service,
            BillChainEvent::new(
                bill,
                chain,
                &BillKeys {
                    private_key: private_key_test(),
                    public_key: node_id_test().pub_key(),
                },
                new_blocks,
                &node_id_test(),
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn test_send_bill_is_signed_event() {
        init_test_cfg();
        // given a payer and payee with a new bill
        let payer = get_identity_public_data(
            &node_id_test(),
            &Email::new("drawee@example.com").unwrap(),
            vec![],
        );
        let payee = get_identity_public_data(
            &node_id_test_other(),
            &Email::new("payee@example.com").unwrap(),
            vec![],
        );
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let chain = get_genesis_chain(Some(bill.clone()));
        let (service, event) = setup_chain_expectation(
            vec![
                (
                    payer,
                    BillEventType::BillSigned,
                    Some(ActionType::AcceptBill),
                ),
                (
                    payee,
                    BillEventType::BillSigned,
                    Some(ActionType::CheckBill),
                ),
            ],
            &bill,
            &chain,
            true,
        );
        service
            .send_bill_is_signed_event(&event)
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_send_bill_is_accepted_event() {
        init_test_cfg();
        let payer = get_identity_public_data(
            &node_id_test(),
            &Email::new("drawee@example.com").unwrap(),
            vec![],
        );
        let payee = get_identity_public_data(
            &node_id_test_other(),
            &Email::new("payee@example.com").unwrap(),
            vec![],
        );
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let mut chain = get_genesis_chain(Some(bill.clone()));
        let timestamp = now().timestamp() as u64;
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_accept(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillAcceptBlockData {
                accepter: payer.clone().into(),
                signatory: None,
                signing_timestamp: timestamp,
                signing_address: empty_address(),
            },
            &keys,
            None,
            &keys,
            timestamp,
        )
        .unwrap();

        chain.try_add_block(block);

        let (service, event) = setup_chain_expectation(
            vec![
                (
                    payee,
                    BillEventType::BillAccepted,
                    Some(ActionType::CheckBill),
                ),
                (payer, BillEventType::BillBlock, None),
            ],
            &bill,
            &chain,
            true,
        );

        service
            .send_bill_is_accepted_event(&event)
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_send_request_to_accept_event() {
        init_test_cfg();
        let payer = get_identity_public_data(
            &node_id_test(),
            &Email::new("drawee@example.com").unwrap(),
            vec![],
        );
        let payee = get_identity_public_data(
            &node_id_test_other(),
            &Email::new("payee@example.com").unwrap(),
            vec![],
        );
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let mut chain = get_genesis_chain(Some(bill.clone()));
        let timestamp = now().timestamp() as u64;
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_request_to_accept(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payee.clone().into()),
                signatory: None,
                signing_timestamp: timestamp,
                signing_address: Some(empty_address()),
                acceptance_deadline_timestamp: timestamp + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &keys,
            None,
            &keys,
            timestamp,
        )
        .unwrap();

        chain.try_add_block(block);

        let (service, event) = setup_chain_expectation(
            vec![
                (payee, BillEventType::BillBlock, None),
                (
                    payer,
                    BillEventType::BillAcceptanceRequested,
                    Some(ActionType::AcceptBill),
                ),
            ],
            &bill,
            &chain,
            true,
        );

        service
            .send_request_to_accept_event(&event)
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_send_request_to_pay_event() {
        init_test_cfg();
        let payer = get_identity_public_data(
            &node_id_test(),
            &Email::new("drawee@example.com").unwrap(),
            vec![],
        );
        let payee = get_identity_public_data(
            &node_id_test_other(),
            &Email::new("payee@example.com").unwrap(),
            vec![],
        );
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let mut chain = get_genesis_chain(Some(bill.clone()));
        let timestamp = now().timestamp() as u64;
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_request_to_pay(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillRequestToPayBlockData {
                requester: BillParticipantBlockData::Ident(payee.clone().into()),
                currency: Currency::sat(),
                signatory: None,
                signing_timestamp: timestamp,
                signing_address: Some(empty_address()),
                payment_deadline_timestamp: timestamp + 2 * PAYMENT_DEADLINE_SECONDS,
            },
            &keys,
            None,
            &keys,
            timestamp,
        )
        .unwrap();

        chain.try_add_block(block);

        let (service, event) = setup_chain_expectation(
            vec![
                (payee, BillEventType::BillBlock, None),
                (
                    payer,
                    BillEventType::BillPaymentRequested,
                    Some(ActionType::PayBill),
                ),
            ],
            &bill,
            &chain,
            true,
        );

        service
            .send_request_to_pay_event(&event)
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_send_bill_is_paid_event() {
        init_test_cfg();
        let payer = get_identity_public_data(
            &node_id_test(),
            &Email::new("drawee@example.com").unwrap(),
            vec![],
        );
        let payee = get_identity_public_data(
            &node_id_test_other(),
            &Email::new("payee@example.com").unwrap(),
            vec![],
        );
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let chain = get_genesis_chain(Some(bill.clone()));
        let (service, event) = setup_chain_expectation(
            vec![
                (payee, BillEventType::BillPaid, Some(ActionType::CheckBill)),
                (payer, BillEventType::BillBlock, None),
            ],
            &bill,
            &chain,
            false,
        );

        service
            .send_bill_is_paid_event(&event)
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_send_bill_is_endorsed_event() {
        init_test_cfg();
        let payer = get_identity_public_data(
            &node_id_test(),
            &Email::new("drawee@example.com").unwrap(),
            vec![],
        );
        let payee = get_identity_public_data(
            &node_id_test_other(),
            &Email::new("payee@example.com").unwrap(),
            vec![],
        );
        let endorsee = get_identity_public_data(
            &node_id_test_other2(),
            &Email::new("endorsee@example.com").unwrap(),
            vec![],
        );
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, Some(&endorsee));
        let chain = get_genesis_chain(Some(bill.clone()));

        let (service, event) = setup_chain_expectation(
            vec![
                (payee, BillEventType::BillBlock, None),
                (payer, BillEventType::BillBlock, None),
                (
                    endorsee,
                    BillEventType::BillAcceptanceRequested,
                    Some(ActionType::AcceptBill),
                ),
            ],
            &bill,
            &chain,
            false,
        );

        service
            .send_bill_is_endorsed_event(&event)
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_send_offer_to_sell_event() {
        init_test_cfg();
        let payer = get_identity_public_data(
            &node_id_test(),
            &Email::new("drawee@example.com").unwrap(),
            vec![],
        );
        let payee = get_identity_public_data(
            &node_id_test_other(),
            &Email::new("payee@example.com").unwrap(),
            vec![],
        );
        let buyer = get_identity_public_data(
            &node_id_test_other2(),
            &Email::new("buyer@example.com").unwrap(),
            vec![],
        );
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let mut chain = get_genesis_chain(Some(bill.clone()));
        let timestamp = now().timestamp() as u64;
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_offer_to_sell(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillOfferToSellBlockData {
                seller: BillParticipantBlockData::Ident(payee.clone().into()),
                buyer: BillParticipantBlockData::Ident(buyer.clone().into()),
                sum: Sum::new_sat(100).expect("sat works"),
                signatory: None,
                payment_address: "Address".to_string(),
                signing_timestamp: timestamp,
                signing_address: Some(empty_address()),
                buying_deadline_timestamp: timestamp + 2 * DAY_IN_SECS,
            },
            &keys,
            None,
            &keys,
            timestamp,
        )
        .unwrap();

        chain.try_add_block(block);

        let (service, event) = setup_chain_expectation(
            vec![
                (payee, BillEventType::BillBlock, None),
                (payer, BillEventType::BillBlock, None),
                (
                    buyer.clone(),
                    BillEventType::BillSellOffered,
                    Some(ActionType::CheckBill),
                ),
            ],
            &bill,
            &chain,
            true,
        );

        service
            .send_offer_to_sell_event(&event, &BillParticipant::Ident(buyer))
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_send_bill_is_sold_event() {
        init_test_cfg();
        let payer = get_identity_public_data(
            &node_id_test(),
            &Email::new("drawee@example.com").unwrap(),
            vec![],
        );
        let payee = get_identity_public_data(
            &node_id_test_other(),
            &Email::new("payee@example.com").unwrap(),
            vec![],
        );
        let buyer = get_identity_public_data(
            &node_id_test_other2(),
            &Email::new("buyer@example.com").unwrap(),
            vec![],
        );
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let mut chain = get_genesis_chain(Some(bill.clone()));
        let timestamp = now().timestamp() as u64;
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_offer_to_sell(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillOfferToSellBlockData {
                seller: BillParticipantBlockData::Ident(payee.clone().into()),
                buyer: BillParticipantBlockData::Ident(buyer.clone().into()),
                sum: Sum::new_sat(100).expect("sat works"),
                signatory: None,
                payment_address: "Address".to_string(),
                signing_timestamp: timestamp,
                signing_address: Some(empty_address()),
                buying_deadline_timestamp: timestamp + 2 * DAY_IN_SECS,
            },
            &keys,
            None,
            &keys,
            timestamp,
        )
        .unwrap();

        chain.try_add_block(block);

        let (service, event) = setup_chain_expectation(
            vec![
                (payee, BillEventType::BillBlock, None),
                (payer, BillEventType::BillBlock, None),
                (
                    buyer.clone(),
                    BillEventType::BillSold,
                    Some(ActionType::CheckBill),
                ),
            ],
            &bill,
            &chain,
            true,
        );

        service
            .send_bill_is_sold_event(&event, &BillParticipant::Ident(buyer))
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_send_bill_recourse_paid_event() {
        init_test_cfg();
        let payer = get_identity_public_data(
            &node_id_test(),
            &Email::new("drawee@example.com").unwrap(),
            vec![],
        );
        let payee = get_identity_public_data(
            &node_id_test_other(),
            &Email::new("payee@example.com").unwrap(),
            vec![],
        );
        let recoursee = get_identity_public_data(
            &node_id_test_other2(),
            &Email::new("recoursee@example.com").unwrap(),
            vec![],
        );
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let mut chain = get_genesis_chain(Some(bill.clone()));
        let timestamp = now().timestamp() as u64;
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_recourse(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillRecourseBlockData {
                recourser: BillParticipant::Ident(payee.clone()).into(),
                recoursee: recoursee.clone().into(),
                sum: Sum::new_sat(100).expect("sat works"),
                recourse_reason: BillRecourseReasonBlockData::Pay,
                signatory: None,
                signing_timestamp: timestamp,
                signing_address: Some(empty_address()),
            },
            &keys,
            None,
            &keys,
            timestamp,
        )
        .unwrap();

        chain.try_add_block(block);

        let (service, event) = setup_chain_expectation(
            vec![
                (payee, BillEventType::BillBlock, None),
                (payer, BillEventType::BillBlock, None),
                (
                    recoursee.clone(),
                    BillEventType::BillRecoursePaid,
                    Some(ActionType::CheckBill),
                ),
            ],
            &bill,
            &chain,
            true,
        );

        service
            .send_bill_recourse_paid_event(&event, &recoursee)
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_send_request_to_mint_event() {
        init_test_cfg();
        let payer = get_identity_public_data(
            &node_id_test(),
            &Email::new("drawee@example.com").unwrap(),
            vec![],
        );
        let payee = get_identity_public_data(
            &node_id_test_other(),
            &Email::new("payee@example.com").unwrap(),
            vec![],
        );
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let mut chain = get_genesis_chain(Some(bill.clone()));
        let timestamp = now().timestamp() as u64;
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_accept(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillAcceptBlockData {
                accepter: payer.clone().into(),
                signatory: None,
                signing_timestamp: timestamp,
                signing_address: empty_address(),
            },
            &keys,
            None,
            &keys,
            timestamp,
        )
        .unwrap();

        chain.try_add_block(block);

        let (service, _event) = setup_chain_expectation(
            vec![(
                payee.clone(),
                BillEventType::BillMintingRequested,
                Some(ActionType::CheckBill),
            )],
            &bill,
            &chain,
            false,
        );

        service
            .send_request_to_mint_event(
                &node_id_test(),
                &BillParticipant::Ident(payee.clone()),
                &bill,
            )
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn get_client_notifications() {
        init_test_cfg();
        let mut mock_store = MockNotificationStore::new();
        let result =
            Notification::new_bill_notification(&bill_id_test(), &node_id_test(), "desc", None);
        let returning = result.clone();
        let filter = NotificationFilter {
            active: Some(true),
            ..Default::default()
        };
        mock_store
            .expect_list()
            .with(eq(filter.clone()))
            .returning(move |_| Ok(vec![returning.clone()]));

        let mut mock_transport = MockNotificationJsonTransport::new();
        mock_transport
            .expect_get_sender_node_id()
            .returning(node_id_test);

        let service = NotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(mock_store),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(MockContactStore::new()),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        let res = service
            .get_client_notifications(filter)
            .await
            .expect("could not get notifications");
        assert!(!res.is_empty());
        assert_eq!(res[0].id, result.id);
    }

    #[tokio::test]
    async fn wrong_network_failures() {
        init_test_cfg();
        let mainnet_node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Bitcoin);
        let mainnet_bill_id = BillId::new(BcrKeys::new().pub_key(), bitcoin::Network::Bitcoin);
        let filter = NotificationFilter {
            node_ids: vec![mainnet_node_id.clone()],
            ..Default::default()
        };

        let mut mock_transport = MockNotificationJsonTransport::new();
        mock_transport
            .expect_get_sender_node_id()
            .returning(node_id_test);

        let service = NotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(MockContactStore::new()),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        assert!(service.get_client_notifications(filter).await.is_err());
        assert!(service.resolve_contact(&mainnet_node_id).await.is_err());
        assert!(
            service
                .check_bill_notification_sent(&mainnet_bill_id, 0, ActionType::CheckBill)
                .await
                .is_err()
        );
        assert!(
            service
                .mark_bill_notification_sent(&mainnet_bill_id, 0, ActionType::CheckBill)
                .await
                .is_err()
        );
        assert!(
            service
                .get_active_bill_notification(&mainnet_bill_id)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn get_mark_notification_done() {
        init_test_cfg();
        let mut mock_store = MockNotificationStore::new();
        mock_store
            .expect_mark_as_done()
            .with(eq("notification_id"))
            .returning(|_| Ok(()));

        let mut mock_transport = MockNotificationJsonTransport::new();
        mock_transport
            .expect_get_sender_node_id()
            .returning(node_id_test);

        let service = NotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(mock_store),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(MockContactStore::new()),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        service
            .mark_notification_as_done("notification_id")
            .await
            .expect("could not mark notification as done");
    }

    #[tokio::test]
    async fn test_send_retry_messages_success() {
        init_test_cfg();
        let node_id = node_id_test_other();
        let message_id = "test_message_id";
        let sender_id = node_id_test();
        let payload = serde_json::to_value(EventEnvelope {
            version: "1.0".to_string(),
            event_type: EventType::Bill,
            data: "".to_owned(),
        })
        .unwrap();
        let queued_message = NostrQueuedMessage {
            id: message_id.to_string(),
            sender_id: sender_id.to_owned(),
            node_id: node_id.to_owned(),
            payload: payload.clone(),
        };

        let identity =
            get_identity_public_data(&node_id, &Email::new("test@example.com").unwrap(), vec![]);

        // Set up mocks
        let mut mock_contact_store = MockContactStore::new();
        mock_contact_store
            .expect_get()
            .returning(move |_| Ok(Some(as_contact(&identity))));

        let mut mock_transport = MockNotificationJsonTransport::new();
        mock_transport
            .expect_get_sender_node_id()
            .returning(node_id_test);
        mock_transport
            .expect_send_private_event()
            .returning(|_, _| Ok(()));

        let mut mock_queue = MockNostrQueuedMessageStore::new();
        mock_queue
            .expect_get_retry_messages()
            .with(eq(1))
            .returning(move |_| Ok(vec![queued_message.clone()]))
            .once();
        mock_queue
            .expect_get_retry_messages()
            .with(eq(1))
            .returning(|_| Ok(vec![]));
        mock_queue
            .expect_succeed_retry()
            .with(eq(message_id))
            .returning(|_| Ok(()));

        let service = NotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(mock_contact_store),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(mock_queue),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        let result = service.send_retry_messages().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_email_notification() {
        init_test_cfg();
        let node_id = node_id_test_other();
        let identity = get_identity_public_data(
            &node_id,
            &Email::new("test@example.com").unwrap(),
            vec![&url::Url::parse("ws://test.relay").unwrap()],
        );
        // Set up mocks
        let mut mock_contact_store = MockContactStore::new();
        mock_contact_store
            .expect_get()
            .returning(move |_| Ok(Some(as_contact(&identity))));

        let mut mock_transport = MockNotificationJsonTransport::new();
        mock_transport
            .expect_get_sender_node_id()
            .returning(node_id_test);
        mock_transport
            .expect_send_private_event()
            .returning(|_, _| Ok(()));
        mock_transport
            .expect_get_sender_keys()
            .returning(|| BcrKeys::from_private_key(&private_key_test()).unwrap());

        let mut mock_email_client = MockEmailClient::new();
        mock_email_client
            .expect_send_bill_notification()
            .returning(|_, _, _, _, _| Ok(()))
            .times(1);

        let service = NotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(mock_contact_store),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(mock_email_client),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );
        let event = Event::new(
            EventType::Bill,
            BillChainEventPayload {
                event_type: BillEventType::BillAccepted,
                bill_id: bill_id_test(),
                action_type: Some(ActionType::CheckBill),
                sum: None,
            },
        );
        service
            .send_email_notification(&node_id_test(), &node_id_test_other(), &event)
            .await;
    }

    #[tokio::test]
    async fn test_send_retry_messages_with_send_failure() {
        init_test_cfg();
        let node_id = node_id_test_other();
        let message_id = "test_message_id";
        let sender_id = node_id_test();
        let payload = serde_json::to_value(EventEnvelope {
            version: "1.0".to_string(),
            event_type: EventType::Bill,
            data: "".to_owned(),
        })
        .unwrap();

        let queued_message = NostrQueuedMessage {
            id: message_id.to_string(),
            sender_id: sender_id.to_owned(),
            node_id: node_id.to_owned(),
            payload: payload.clone(),
        };

        let identity =
            get_identity_public_data(&node_id, &Email::new("test@example.com").unwrap(), vec![]);

        // Set up mocks
        let mut mock_contact_store = MockContactStore::new();
        mock_contact_store
            .expect_get()
            .returning(move |_| Ok(Some(as_contact(&identity))));

        let mut mock_transport = MockNotificationJsonTransport::new();
        mock_transport
            .expect_get_sender_node_id()
            .returning(node_id_test);

        mock_transport
            .expect_send_private_event()
            .returning(|_, _| Err(Error::Network("Failed to send".to_string())));

        let mut mock_queue = MockNostrQueuedMessageStore::new();
        mock_queue
            .expect_get_retry_messages()
            .with(eq(1))
            .returning(move |_| Ok(vec![queued_message.clone()]))
            .once();
        mock_queue
            .expect_get_retry_messages()
            .with(eq(1))
            .returning(|_| Ok(vec![]));
        mock_queue
            .expect_fail_retry()
            .with(eq(message_id))
            .returning(|_| Ok(()));

        let service = NotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(mock_contact_store),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(mock_queue),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        let result = service.send_retry_messages().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_retry_messages_with_multiple_messages() {
        init_test_cfg();
        let node_id1 = node_id_test_other();
        let sender_id = node_id_test();
        let node_id2 = node_id_test_other2();
        let message_id1 = "test_message_id_1";
        let message_id2 = "test_message_id_2";

        let payload1 = serde_json::to_value(EventEnvelope {
            version: "1.0".to_string(),
            event_type: EventType::Bill,
            data: "".to_owned(),
        })
        .unwrap();

        let payload2 = serde_json::to_value(EventEnvelope {
            version: "1.0".to_string(),
            event_type: EventType::Bill,
            data: "".to_owned(),
        })
        .unwrap();

        let queued_message1 = NostrQueuedMessage {
            id: message_id1.to_string(),
            sender_id: sender_id.to_owned(),
            node_id: node_id1.to_owned(),
            payload: payload1.clone(),
        };

        let queued_message2 = NostrQueuedMessage {
            id: message_id2.to_string(),
            sender_id: sender_id.to_owned(),
            node_id: node_id2.to_owned(),
            payload: payload2.clone(),
        };

        let identity1 =
            get_identity_public_data(&node_id1, &Email::new("test1@example.com").unwrap(), vec![]);
        let identity2 =
            get_identity_public_data(&node_id2, &Email::new("test2@example.com").unwrap(), vec![]);

        // Set up mocks
        let mut mock_contact_store = MockContactStore::new();
        mock_contact_store
            .expect_get()
            .returning(move |_| Ok(Some(as_contact(&identity1))));
        mock_contact_store
            .expect_get()
            .returning(move |_| Ok(Some(as_contact(&identity2))));

        let mut mock_transport = MockNotificationJsonTransport::new();

        mock_transport
            .expect_get_sender_node_id()
            .returning(node_id_test);

        // First message succeeds, second fails
        mock_transport
            .expect_send_private_event()
            .returning(|_, _| Ok(()))
            .times(1);
        mock_transport
            .expect_send_private_event()
            .returning(|_, _| Err(Error::Network("Failed to send".to_string())))
            .times(1);

        let mut mock_queue = MockNostrQueuedMessageStore::new();
        // Return first message, then second message
        mock_queue
            .expect_get_retry_messages()
            .with(eq(1))
            .returning(move |_| Ok(vec![queued_message1.clone()]))
            .times(1);
        mock_queue
            .expect_get_retry_messages()
            .with(eq(1))
            .returning(move |_| Ok(vec![queued_message2.clone()]))
            .times(1);
        mock_queue
            .expect_get_retry_messages()
            .with(eq(1))
            .returning(|_| Ok(vec![]))
            .times(1);

        mock_queue
            .expect_succeed_retry()
            .with(eq(message_id1))
            .returning(|_| Ok(()));
        mock_queue
            .expect_fail_retry()
            .with(eq(message_id2))
            .returning(|_| Ok(()));

        let service = NotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(mock_contact_store),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(mock_queue),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        let result = service.send_retry_messages().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_retry_messages_with_invalid_payload() {
        init_test_cfg();
        let node_id = node_id_test_other();
        let message_id = "test_message_id";
        let sender = node_id_test();
        // Invalid payload that can't be deserialized to EventEnvelope
        let invalid_payload = serde_json::json!({ "invalid": "data" });

        let queued_message = NostrQueuedMessage {
            id: message_id.to_string(),
            sender_id: sender.to_owned(),
            node_id: node_id.to_owned(),
            payload: invalid_payload,
        };

        let mut mock_queue = MockNostrQueuedMessageStore::new();
        mock_queue
            .expect_get_retry_messages()
            .with(eq(1))
            .returning(move |_| Ok(vec![queued_message.clone()]))
            .times(1);
        mock_queue
            .expect_get_retry_messages()
            .with(eq(1))
            .returning(|_| Ok(vec![]))
            .times(1);

        let mut mock_transport = MockNotificationJsonTransport::new();
        mock_transport
            .expect_get_sender_node_id()
            .returning(node_id_test);

        let service = NotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(MockContactStore::new()),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(mock_queue),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        let result = service.send_retry_messages().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_retry_messages_with_fail_retry_error() {
        init_test_cfg();
        let node_id = node_id_test_other();
        let message_id = "test_message_id";
        let sender = node_id_test();
        let payload = serde_json::to_value(EventEnvelope {
            version: "1.0".to_string(),
            event_type: EventType::Bill,
            data: "".to_owned(),
        })
        .unwrap();

        let queued_message = NostrQueuedMessage {
            id: message_id.to_string(),
            sender_id: sender.to_owned(),
            node_id: node_id.to_owned(),
            payload: payload.clone(),
        };

        let identity =
            get_identity_public_data(&node_id, &Email::new("test@example.com").unwrap(), vec![]);

        // Set up mocks
        let mut mock_contact_store = MockContactStore::new();
        mock_contact_store
            .expect_get()
            .returning(move |_| Ok(Some(as_contact(&identity))));

        let mut mock_transport = MockNotificationJsonTransport::new();
        mock_transport
            .expect_get_sender_node_id()
            .returning(node_id_test);
        mock_transport
            .expect_send_private_event()
            .returning(|_, _| Err(Error::Network("Failed to send".to_string())));

        let mut mock_queue = MockNostrQueuedMessageStore::new();
        mock_queue
            .expect_get_retry_messages()
            .with(eq(1))
            .returning(move |_| Ok(vec![queued_message.clone()]))
            .times(1);
        mock_queue
            .expect_get_retry_messages()
            .with(eq(1))
            .returning(|_| Ok(vec![]))
            .times(1);

        mock_queue
            .expect_fail_retry()
            .with(eq(message_id))
            .returning(|_| {
                Err(bcr_ebill_persistence::Error::InsertFailed(
                    "Failed to update retry status".to_string(),
                ))
            });

        let service = NotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(mock_contact_store),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(mock_queue),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        let result = service.send_retry_messages().await;
        assert!(result.is_ok()); // Should still return Ok despite the internal error
    }

    #[tokio::test]
    async fn test_send_retry_messages_with_succeed_retry_error() {
        init_test_cfg();
        let node_id = node_id_test_other();
        let message_id = "test_message_id";
        let sender = node_id_test();
        let payload = serde_json::to_value(EventEnvelope {
            version: "1.0".to_string(),
            event_type: EventType::Bill,
            data: "".to_owned(),
        })
        .unwrap();

        let queued_message = NostrQueuedMessage {
            id: message_id.to_string(),
            sender_id: sender.to_owned(),
            node_id: node_id.to_owned(),
            payload: payload.clone(),
        };

        let identity =
            get_identity_public_data(&node_id, &Email::new("test@example.com").unwrap(), vec![]);

        // Set up mocks
        let mut mock_contact_store = MockContactStore::new();
        mock_contact_store
            .expect_get()
            .returning(move |_| Ok(Some(as_contact(&identity))));

        let mut mock_transport = MockNotificationJsonTransport::new();
        mock_transport
            .expect_get_sender_node_id()
            .returning(node_id_test);
        mock_transport
            .expect_send_private_event()
            .returning(|_, _| Ok(()));

        let mut mock_queue = MockNostrQueuedMessageStore::new();
        mock_queue
            .expect_get_retry_messages()
            .with(eq(1))
            .returning(move |_| Ok(vec![queued_message.clone()]))
            .times(1);
        mock_queue
            .expect_get_retry_messages()
            .with(eq(1))
            .returning(|_| Ok(vec![]))
            .times(1);

        mock_queue
            .expect_succeed_retry()
            .with(eq(message_id))
            .returning(|_| {
                Err(bcr_ebill_persistence::Error::InsertFailed(
                    "Failed to update retry status".to_string(),
                ))
            });

        let service = NotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(mock_contact_store),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(mock_queue),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        let result = service.send_retry_messages().await;
        assert!(result.is_ok()); // Should still return Ok despite the internal error
    }

    #[tokio::test]
    async fn test_send_retry_messages_with_no_messages() {
        init_test_cfg();
        let mut mock_queue = MockNostrQueuedMessageStore::new();
        mock_queue
            .expect_get_retry_messages()
            .with(eq(1))
            .returning(|_| Ok(vec![]))
            .times(1);
        let mut mock_transport = MockNotificationJsonTransport::new();
        mock_transport
            .expect_get_sender_node_id()
            .returning(node_id_test);

        let service = NotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockEmailNotificationStore::new()),
            Arc::new(MockContactStore::new()),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(mock_queue),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        let result = service.send_retry_messages().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_register_email_notifications() {
        init_test_cfg();
        let mut mock_email_notification_store = MockEmailNotificationStore::new();
        mock_email_notification_store
            .expect_add_email_preferences_link_for_node_id()
            .returning(|_, _| Ok(()))
            .times(1);
        let mut mock_email_client = MockEmailClient::new();
        mock_email_client
            .expect_start()
            .returning(|_, _| Ok("challenge".to_string()));
        mock_email_client
            .expect_register()
            .returning(|_, _, _, _| Ok(url::Url::parse("http://bit.cr/").unwrap()));
        let mut mock_transport = MockNotificationJsonTransport::new();
        mock_transport
            .expect_get_sender_node_id()
            .returning(node_id_test);

        let service = NotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(mock_email_notification_store),
            Arc::new(MockContactStore::new()),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(mock_email_client),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        let result = service
            .register_email_notifications(
                &url::Url::parse("ws://test.relay").unwrap(),
                &Email::new("test@example.com").unwrap(),
                &node_id_test(),
                &BcrKeys::new(),
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_email_notifications_preferences_link() {
        init_test_cfg();
        let mut mock_email_notification_store = MockEmailNotificationStore::new();
        mock_email_notification_store
            .expect_get_email_preferences_link_for_node_id()
            .returning(|_| Ok(Some(url::Url::parse("http://bit.cr/").unwrap())))
            .times(1);
        let mut mock_transport = MockNotificationJsonTransport::new();
        mock_transport
            .expect_get_sender_node_id()
            .returning(node_id_test);

        let service = NotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(mock_email_notification_store),
            Arc::new(MockContactStore::new()),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );

        let result = service
            .get_email_notifications_preferences_link(&node_id_test())
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.as_ref().unwrap(),
            &url::Url::parse("http://bit.cr/").unwrap()
        );
    }

    #[tokio::test]
    async fn test_get_email_notifications_preferences_link_no_entry() {
        init_test_cfg();
        let mut mock_email_notification_store = MockEmailNotificationStore::new();
        mock_email_notification_store
            .expect_get_email_preferences_link_for_node_id()
            .returning(|_| Ok(None))
            .times(1);
        let mut mock_transport = MockNotificationJsonTransport::new();
        mock_transport
            .expect_get_sender_node_id()
            .returning(node_id_test);

        let service = NotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStore::new()),
            Arc::new(mock_email_notification_store),
            Arc::new(MockContactStore::new()),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockEmailClient::new()),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
        );
        let result = service
            .get_email_notifications_preferences_link(&node_id_test())
            .await;
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::NotFound)));
    }
}
