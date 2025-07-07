use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bcr_ebill_core::bill::BillId;
use bcr_ebill_core::blockchain::BlockchainType;
use bcr_ebill_core::contact::{BillAnonParticipant, BillParticipant, ContactType};
use bcr_ebill_persistence::nostr::{
    NostrChainEvent, NostrChainEventStoreApi, NostrQueuedMessage, NostrQueuedMessageStoreApi,
};
use bcr_ebill_transport::event::company_events::CompanyChainEvent;
use bcr_ebill_transport::event::identity_events::IdentityChainEvent;
use bcr_ebill_transport::transport::NostrContactData;
use bcr_ebill_transport::{BillChainEvent, BillChainEventPayload, Error, Event, EventEnvelope};
use log::{error, info, warn};

use super::NotificationJsonTransportApi;
use super::{NotificationServiceApi, Result};
use crate::data::{
    bill::BitcreditBill,
    contact::BillIdentParticipant,
    notification::{Notification, NotificationType},
};
use crate::data::{validate_bill_id_network, validate_node_id_network};
use crate::persistence::notification::{NotificationFilter, NotificationStoreApi};
use crate::service::contact_service::ContactServiceApi;
use bcr_ebill_core::notification::{ActionType, BillEventType};
use bcr_ebill_core::{NodeId, PostalAddress, ServiceTraitBounds};

/// A default implementation of the NotificationServiceApi that can
/// send events via json and email transports.
#[allow(dead_code)]
pub struct DefaultNotificationService {
    notification_transport: HashMap<NodeId, Arc<dyn NotificationJsonTransportApi>>,
    notification_store: Arc<dyn NotificationStoreApi>,
    contact_service: Arc<dyn ContactServiceApi>,
    queued_message_store: Arc<dyn NostrQueuedMessageStoreApi>,
    chain_event_store: Arc<dyn NostrChainEventStoreApi>,
    nostr_relays: Vec<String>,
}

impl ServiceTraitBounds for DefaultNotificationService {}

impl DefaultNotificationService {
    // the number of times we want to retry sending a block message
    const NOSTR_MAX_RETRIES: i32 = 10;

    pub fn new(
        notification_transport: Vec<Arc<dyn NotificationJsonTransportApi>>,
        notification_store: Arc<dyn NotificationStoreApi>,
        contact_service: Arc<dyn ContactServiceApi>,
        queued_message_store: Arc<dyn NostrQueuedMessageStoreApi>,
        chain_event_store: Arc<dyn NostrChainEventStoreApi>,
        nostr_relays: Vec<String>,
    ) -> Self {
        Self {
            notification_transport: notification_transport
                .into_iter()
                .map(|t| (t.get_sender_node_id(), t))
                .collect(),
            notification_store,
            contact_service,
            queued_message_store,
            chain_event_store,
            nostr_relays,
        }
    }

    fn get_local_identity(&self, node_id: &NodeId) -> Option<BillParticipant> {
        if self.notification_transport.contains_key(node_id) {
            Some(BillParticipant::Ident(BillIdentParticipant {
                // we create an ident, but it doesn't matter, since we just need the node id and nostr relay
                t: ContactType::Person,
                node_id: node_id.to_owned(),
                email: None,
                name: String::new(),
                postal_address: PostalAddress::default(),
                nostr_relays: self.nostr_relays.clone(),
            }))
        } else {
            None
        }
    }

    async fn resolve_identity(&self, node_id: &NodeId) -> Option<BillParticipant> {
        match self.get_local_identity(node_id) {
            Some(id) => Some(id),
            None => {
                if let Ok(Some(identity)) =
                    self.contact_service.get_identity_by_node_id(node_id).await
                {
                    Some(identity)
                } else if let Ok(Some(nostr)) = self
                    .contact_service
                    .get_nostr_contact_by_node_id(node_id)
                    .await
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

    async fn send_all_bill_events(
        &self,
        sender: &NodeId,
        events: HashMap<NodeId, Event<BillChainEventPayload>>,
    ) -> Result<()> {
        if let Some(node) = self.notification_transport.get(sender) {
            for (node_id, event_to_process) in events.into_iter() {
                if let Some(identity) = self.resolve_identity(&node_id).await {
                    if let Err(e) = node
                        .send_private_event(&identity, event_to_process.clone().try_into()?)
                        .await
                    {
                        error!(
                            "Failed to send block notification, will add it to retry queue: {e}"
                        );
                        let queue_message = NostrQueuedMessage {
                            id: uuid::Uuid::new_v4().to_string(),
                            sender_id: sender.to_owned(),
                            node_id: node_id.to_owned(),
                            payload: serde_json::to_value(event_to_process)?,
                        };
                        if let Err(e) = self
                            .queued_message_store
                            .add_message(queue_message, Self::NOSTR_MAX_RETRIES)
                            .await
                        {
                            error!("Failed to add block notification to retry queue: {e}");
                        }
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

    async fn find_root_and_previous_event(
        &self,
        previous_hash: &str,
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
        if let Some(node) = self.notification_transport.get(&events.sender()) {
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
                    block_event.data.block.id as usize,
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
        block_hash: &str,
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
        if let Some(node) = self.notification_transport.get(sender) {
            if let Ok(Some(identity)) = self.contact_service.get_identity_by_node_id(node_id).await
            {
                node.send_private_event(&identity, message).await?;
            }
        }
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationServiceApi for DefaultNotificationService {
    /// Sent when an identity chain is created or updated
    async fn send_identity_chain_events(&self, events: IdentityChainEvent) -> Result<()> {
        info!("sending identity chain events with {events:#?}");
        if let Some(node) = self.notification_transport.get(&events.sender()) {
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
                    event.data.block.id as usize,
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
        info!("sending company chain events with {events:#?}");
        if let Some(node) = self.notification_transport.get(&events.sender()) {
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
                    event.data.block.id as usize,
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

    async fn send_bill_is_signed_event(&self, event: &BillChainEvent) -> Result<()> {
        let event_type = BillEventType::BillSigned;

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
        self.send_all_bill_events(&event.sender(), all_events)
            .await?;
        Ok(())
    }

    async fn send_bill_is_accepted_event(&self, event: &BillChainEvent) -> Result<()> {
        let all_events = event.generate_action_messages(
            HashMap::from_iter(vec![(
                event.bill.payee.node_id().clone(),
                (BillEventType::BillAccepted, ActionType::CheckBill),
            )]),
            None,
            None,
        );
        self.send_bill_chain_events(event).await?;
        self.send_all_bill_events(&event.sender(), all_events)
            .await?;
        Ok(())
    }

    async fn send_request_to_accept_event(&self, event: &BillChainEvent) -> Result<()> {
        let all_events = event.generate_action_messages(
            HashMap::from_iter(vec![(
                event.bill.drawee.node_id.clone(),
                (
                    BillEventType::BillAcceptanceRequested,
                    ActionType::AcceptBill,
                ),
            )]),
            None,
            None,
        );
        self.send_bill_chain_events(event).await?;
        self.send_all_bill_events(&event.sender(), all_events)
            .await?;
        Ok(())
    }

    async fn send_request_to_pay_event(&self, event: &BillChainEvent) -> Result<()> {
        let all_events = event.generate_action_messages(
            HashMap::from_iter(vec![(
                event.bill.drawee.node_id.clone(),
                (BillEventType::BillPaymentRequested, ActionType::PayBill),
            )]),
            None,
            None,
        );
        self.send_bill_chain_events(event).await?;
        self.send_all_bill_events(&event.sender(), all_events)
            .await?;
        Ok(())
    }

    async fn send_bill_is_paid_event(&self, event: &BillChainEvent) -> Result<()> {
        let all_events = event.generate_action_messages(
            HashMap::from_iter(vec![(
                event.bill.payee.node_id().clone(),
                (BillEventType::BillPaid, ActionType::CheckBill),
            )]),
            None,
            None,
        );
        self.send_bill_chain_events(event).await?;
        self.send_all_bill_events(&event.sender(), all_events)
            .await?;
        Ok(())
    }

    async fn send_bill_is_endorsed_event(&self, bill: &BillChainEvent) -> Result<()> {
        let all_events = bill.generate_action_messages(
            HashMap::from_iter(vec![(
                bill.bill.endorsee.as_ref().unwrap().node_id().clone(),
                (BillEventType::BillEndorsed, ActionType::CheckBill),
            )]),
            None,
            None,
        );
        self.send_bill_chain_events(bill).await?;
        self.send_all_bill_events(&bill.sender(), all_events)
            .await?;
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
        self.send_all_bill_events(&event.sender(), all_events)
            .await?;
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
        self.send_all_bill_events(&event.sender(), all_events)
            .await?;
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
        self.send_all_bill_events(&event.sender(), all_events)
            .await?;
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
            sum: Some(bill.sum),
        });
        if let Some(node) = self.notification_transport.get(sender_node_id) {
            node.send_private_event(mint, event.try_into()?).await?;
        }
        Ok(())
    }

    async fn send_request_to_action_rejected_event(
        &self,
        event: &BillChainEvent,
        rejected_action: ActionType,
    ) -> Result<()> {
        if let Some(event_type) = rejected_action.get_rejected_event_type() {
            let all_events = event.generate_action_messages(
                HashMap::new(),
                Some(event_type),
                Some(rejected_action),
            );

            self.send_all_bill_events(&event.sender(), all_events)
                .await?;
        }
        Ok(())
    }

    async fn send_request_to_action_timed_out_event(
        &self,
        sender_node_id: &NodeId,
        bill_id: &BillId,
        sum: Option<u64>,
        timed_out_action: ActionType,
        recipients: Vec<BillParticipant>,
    ) -> Result<()> {
        if let Some(node) = self.notification_transport.get(sender_node_id) {
            if let Some(event_type) = timed_out_action.get_timeout_event_type() {
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
                    node.send_private_event(&recipient, event.try_into()?)
                        .await?;
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
            self.send_all_bill_events(&event.sender(), all_events)
                .await?;
        }
        Ok(())
    }

    async fn send_new_quote_event(&self, _bill: &BitcreditBill) -> Result<()> {
        // @TODO: How do we know the quoting participants
        Ok(())
    }

    async fn send_quote_is_approved_event(&self, _bill: &BitcreditBill) -> Result<()> {
        // @TODO: How do we address a mint ???
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
        // take any transport - doesn't matter
        if let Some((_node, transport)) = self.notification_transport.iter().next() {
            let res = transport.resolve_contact(node_id).await?;
            Ok(res)
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {

    use bcr_ebill_core::PostalAddress;
    use bcr_ebill_core::bill::BillKeys;
    use bcr_ebill_core::blockchain::bill::block::{
        BillAcceptBlockData, BillOfferToSellBlockData, BillParticipantBlockData,
        BillRecourseBlockData, BillRecourseReasonBlockData, BillRequestToAcceptBlockData,
        BillRequestToPayBlockData,
    };
    use bcr_ebill_core::blockchain::bill::{BillBlock, BillBlockchain};
    use bcr_ebill_core::blockchain::{Blockchain, BlockchainType};
    use bcr_ebill_core::nostr_contact::{
        HandshakeStatus, NostrContact, NostrPublicKey, TrustLevel,
    };
    use bcr_ebill_core::util::{BcrKeys, date::now};
    use bcr_ebill_transport::event::blockchain_event::ChainInvite;
    use bcr_ebill_transport::{EventEnvelope, EventType, PushApi};
    use mockall::{mock, predicate::eq};
    use std::sync::Arc;

    use crate::service::bill_service::test_utils::{get_baseline_identity, get_genesis_chain};
    use crate::service::contact_service::MockContactServiceApi;
    use crate::service::notification_service::create_nostr_consumer;
    use async_broadcast::Receiver;
    use serde_json::Value;

    impl ServiceTraitBounds for MockNotificationJsonTransport {}
    mock! {
        pub NotificationJsonTransport {}
        #[async_trait]
        impl NotificationJsonTransportApi for NotificationJsonTransport {
            fn get_sender_node_id(&self) -> NodeId;
            async fn send_private_event(&self, recipient: &BillParticipant, event: EventEnvelope) -> bcr_ebill_transport::Result<()>;
            async fn send_public_chain_event(
                &self,
                id: &str,
                blockchain: BlockchainType,
                block_time: u64,
                keys: BcrKeys,
                event: EventEnvelope,
                previous_event: Option<nostr::event::Event>,
                root_event: Option<nostr::event::Event>) -> bcr_ebill_transport::Result<nostr::event::Event>;
            async fn resolve_contact(&self, node_id: &NodeId) -> Result<Option<bcr_ebill_transport::transport::NostrContactData>>;
            async fn resolve_public_chain(&self, id: &str, chain_type: BlockchainType) -> Result<Vec<nostr::event::Event>>;
        }
    }

    mock! {
        pub PushService {}

        impl ServiceTraitBounds for PushService {}

        #[async_trait]
        impl PushApi for PushService {
            async fn send(&self, value: Value);
            async fn subscribe(&self) -> Receiver<Value>;
        }
    }

    use super::super::test_utils::{
        get_identity_public_data, get_mock_nostr_client, get_test_bitcredit_bill,
    };
    use super::*;
    use crate::tests::tests::{
        MockBillChainStoreApiMock, MockBillStoreApiMock, MockChainKeyService,
        MockNostrChainEventStore, MockNostrContactStore, MockNostrEventOffsetStoreApiMock,
        MockNostrQueuedMessageStore, MockNotificationStoreApiMock, TEST_NODE_ID_SECP_AS_NPUB_HEX,
        bill_id_test, node_id_test, node_id_test_other, node_id_test_other2, private_key_test,
    };

    fn check_chain_payload(event: &EventEnvelope, bill_event_type: BillEventType) -> bool {
        let valid_event_type = event.event_type == EventType::Bill;
        let event: Result<Event<BillChainEventPayload>> = event.clone().try_into();
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
    async fn test_send_request_to_action_rejected_event() {
        let payer = get_identity_public_data(&node_id_test(), "drawee@example.com", vec![]);
        let payee = get_identity_public_data(&node_id_test_other(), "payee@example.com", vec![]);
        let buyer = get_identity_public_data(&node_id_test_other2(), "buyer@example.com", vec![]);
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
                sum: 100,
                currency: "USD".to_string(),
                signatory: None,
                payment_address: "Address".to_string(),
                signing_timestamp: timestamp,
                signing_address: Some(PostalAddress::default()),
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

        let mut mock_contact_service = MockContactServiceApi::new();

        // every participant should receive events
        mock_contact_service
            .expect_get_identity_by_node_id()
            .with(eq(node_id_test_other2()))
            .returning(move |_| Ok(Some(BillParticipant::Ident(buyer.clone()))));
        mock_contact_service
            .expect_get_identity_by_node_id()
            .with(eq(node_id_test()))
            .returning(move |_| Ok(Some(BillParticipant::Ident(payer.clone()))));
        mock_contact_service
            .expect_get_identity_by_node_id()
            .with(eq(node_id_test_other()))
            .returning(move |_| Ok(Some(BillParticipant::Ident(payee.clone()))));

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

        let service = DefaultNotificationService::new(
            vec![Arc::new(mock)],
            Arc::new(MockNotificationStoreApiMock::new()),
            Arc::new(mock_contact_service),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            vec!["ws://test.relay".into()],
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
        let payer = get_identity_public_data(&node_id_test(), "drawee@example.com", vec![]);
        let payee = get_identity_public_data(&node_id_test_other(), "payee@example.com", vec![]);
        let buyer = get_identity_public_data(&node_id_test_other2(), "buyer@example.com", vec![]);
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
                sum: 100,
                currency: "USD".to_string(),
                signatory: None,
                payment_address: "Address".to_string(),
                signing_timestamp: timestamp,
                signing_address: Some(PostalAddress::default()),
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

        let mut mock_contact_service = MockContactServiceApi::new();

        // no participant should receive events
        mock_contact_service
            .expect_get_identity_by_node_id()
            .never();

        let mut mock = MockNotificationJsonTransport::new();
        mock.expect_get_sender_node_id().returning(node_id_test);

        // expect to not send rejected event for non rejectable actions
        mock.expect_send_private_event().never();

        let service = DefaultNotificationService::new(
            vec![Arc::new(mock)],
            Arc::new(MockNotificationStoreApiMock::new()),
            Arc::new(mock_contact_service),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            vec!["ws://test.relay".into()],
        );

        service
            .send_request_to_action_rejected_event(&event, ActionType::CheckBill)
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_send_request_to_action_timed_out_event() {
        let recipients = vec![
            BillParticipant::Ident(get_identity_public_data(
                &node_id_test(),
                "part1@example.com",
                vec![],
            )),
            BillParticipant::Ident(get_identity_public_data(
                &node_id_test_other(),
                "part2@example.com",
                vec![],
            )),
            BillParticipant::Ident(get_identity_public_data(
                &node_id_test_other2(),
                "part3@example.com",
                vec![],
            )),
        ];

        let mut mock = MockNotificationJsonTransport::new();

        // resolves node_id
        mock.expect_get_sender_node_id().returning(node_id_test);

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

        let service = DefaultNotificationService::new(
            vec![Arc::new(mock)],
            Arc::new(MockNotificationStoreApiMock::new()),
            Arc::new(MockContactServiceApi::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            vec!["ws://test.relay".into()],
        );

        service
            .send_request_to_action_timed_out_event(
                &node_id_test(),
                &bill_id_test(),
                Some(100),
                ActionType::PayBill,
                recipients.clone(),
            )
            .await
            .expect("failed to send event");

        service
            .send_request_to_action_timed_out_event(
                &node_id_test(),
                &bill_id_test(),
                Some(100),
                ActionType::AcceptBill,
                recipients.clone(),
            )
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_send_request_to_action_timed_out_does_not_send_non_timeout_action() {
        let recipients = vec![
            BillParticipant::Ident(get_identity_public_data(
                &node_id_test(),
                "part1@example.com",
                vec![],
            )),
            BillParticipant::Ident(get_identity_public_data(
                &node_id_test_other(),
                "part2@example.com",
                vec![],
            )),
            BillParticipant::Ident(get_identity_public_data(
                &node_id_test_other2(),
                "part3@example.com",
                vec![],
            )),
        ];

        let mut mock = MockNotificationJsonTransport::new();
        mock.expect_get_sender_node_id().returning(node_id_test);

        // expect to never send timeout event on non expiring events
        mock.expect_send_private_event().never();

        let service = DefaultNotificationService::new(
            vec![Arc::new(mock)],
            Arc::new(MockNotificationStoreApiMock::new()),
            Arc::new(MockContactServiceApi::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            vec!["ws://test.relay".into()],
        );

        service
            .send_request_to_action_timed_out_event(
                &node_id_test(),
                &bill_id_test(),
                Some(100),
                ActionType::CheckBill,
                recipients.clone(),
            )
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_send_recourse_action_event() {
        let payer = get_identity_public_data(&node_id_test(), "drawee@example.com", vec![]);
        let payee = get_identity_public_data(&node_id_test_other(), "payee@example.com", vec![]);
        let buyer = get_identity_public_data(&node_id_test_other2(), "buyer@example.com", vec![]);
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
                sum: 100,
                currency: "USD".to_string(),
                signatory: None,
                payment_address: "Address".to_string(),
                signing_timestamp: timestamp,
                signing_address: Some(PostalAddress::default()),
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

        let mut mock_contact_service = MockContactServiceApi::new();

        let buyer_clone = buyer.clone();
        // participants should receive events
        mock_contact_service
            .expect_get_identity_by_node_id()
            .returning(move |_| Ok(Some(BillParticipant::Ident(buyer_clone.clone()))));
        mock_contact_service
            .expect_get_identity_by_node_id()
            .returning(move |_| Ok(Some(BillParticipant::Ident(payee.clone()))));
        mock_contact_service
            .expect_get_identity_by_node_id()
            .returning(move |_| Ok(Some(BillParticipant::Ident(payer.clone()))));

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
                let r: Result<Event<ChainInvite>> = e.clone().try_into();
                r.is_ok()
            })
            .returning(|_, _| Ok(()));

        let event_store = setup_event_store_expectations(
            chain.get_latest_block().previous_hash.to_owned().as_str(),
            &bill.id,
        );

        let service = DefaultNotificationService::new(
            vec![Arc::new(mock)],
            Arc::new(MockNotificationStoreApiMock::new()),
            Arc::new(mock_contact_service),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(event_store),
            vec!["ws://test.relay".into()],
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
        let payer = get_identity_public_data(&node_id_test(), "drawee@example.com", vec![]);
        let payee = get_identity_public_data(&node_id_test_other(), "payee@example.com", vec![]);
        let buyer = get_identity_public_data(&node_id_test_other2(), "buyer@example.com", vec![]);
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
                sum: 100,
                currency: "USD".to_string(),
                signatory: None,
                payment_address: "Address".to_string(),
                signing_timestamp: timestamp,
                signing_address: Some(PostalAddress::default()),
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

        let mut mock_contact_service = MockContactServiceApi::new();

        // participants should receive events
        mock_contact_service
            .expect_get_identity_by_node_id()
            .never();

        let mut mock = MockNotificationJsonTransport::new();
        mock.expect_get_sender_node_id().returning(node_id_test);

        // expect not to send non recourse event
        mock.expect_send_private_event().never();

        let service = DefaultNotificationService::new(
            vec![Arc::new(mock)],
            Arc::new(MockNotificationStoreApiMock::new()),
            Arc::new(MockContactServiceApi::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            vec!["ws://test.relay".into()],
        );

        service
            .send_recourse_action_event(&event, ActionType::CheckBill, &payer)
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_failed_to_send_is_added_to_retry_queue() {
        // given a payer and payee with a new bill
        let payer = get_identity_public_data(&node_id_test(), "drawee@example.com", vec![]);
        let payee = get_identity_public_data(&node_id_test_other(), "payee@example.com", vec![]);
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let chain = get_genesis_chain(Some(bill.clone()));

        let mut mock_contact_service = MockContactServiceApi::new();
        mock_contact_service
            .expect_get_identity_by_node_id()
            .with(eq(payer.node_id.clone()))
            .returning(move |_| Ok(Some(BillParticipant::Ident(payer.clone()))));

        mock_contact_service
            .expect_get_identity_by_node_id()
            .with(eq(payee.node_id.clone()))
            .returning(move |_| Ok(Some(BillParticipant::Ident(payee.clone()))));

        let mut mock = MockNotificationJsonTransport::new();
        mock.expect_get_sender_node_id().returning(node_id_test);

        mock.expect_send_private_event()
            .withf(move |_, e| {
                let r: Result<Event<ChainInvite>> = e.clone().try_into();
                r.is_ok()
            })
            .returning(|_, _| Ok(()));

        mock.expect_send_public_chain_event()
            .returning(|_, _, _, _, _, _, _| Ok(get_test_nostr_event()));

        let mock_event_store = setup_event_store_expectations(
            chain.get_latest_block().previous_hash.to_owned().as_str(),
            &bill.id,
        );

        mock.expect_send_private_event()
            .returning(|_, _| Ok(()))
            .once();

        mock.expect_send_private_event()
            .withf(move |_, e| {
                let r: Result<Event<ChainInvite>> = e.clone().try_into();
                r.is_err()
            })
            .returning(|_, _| Err(Error::Network("Failed to send".to_string())));

        let mut queue_mock = MockNostrQueuedMessageStore::new();
        queue_mock
            .expect_add_message()
            .returning(|_, _| Ok(()))
            .once();

        let service = DefaultNotificationService::new(
            vec![Arc::new(mock)],
            Arc::new(MockNotificationStoreApiMock::new()),
            Arc::new(mock_contact_service),
            Arc::new(queue_mock),
            Arc::new(mock_event_store),
            vec!["ws://test.relay".into()],
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
        previous_hash: &str,
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
    ) -> (DefaultNotificationService, BillChainEvent) {
        let mut mock_contact_service = MockContactServiceApi::new();
        let mut mock = MockNotificationJsonTransport::new();
        for p in participants.into_iter() {
            let clone1 = p.clone();
            mock_contact_service
                .expect_get_identity_by_node_id()
                .with(eq(p.0.node_id.clone()))
                .returning(move |_| Ok(Some(BillParticipant::Ident(clone1.0.clone()))));

            mock.expect_get_sender_node_id().returning(node_id_test);

            let clone2 = p.clone();
            mock.expect_send_private_event()
                .withf(move |r, e| {
                    let part = clone2.clone();
                    let valid_node_id = r.node_id() == part.0.node_id;
                    let event_result: Result<Event<BillChainEventPayload>> = e.clone().try_into();
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
                    let r: Result<Event<ChainInvite>> = e.clone().try_into();
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
                chain.get_latest_block().previous_hash.to_owned().as_str(),
                &bill.id,
            );
        } else {
            mock.expect_send_public_chain_event()
                .returning(|_, _, _, _, _, _, _| Ok(get_test_nostr_event()))
                .never();
        }

        let service = DefaultNotificationService::new(
            vec![Arc::new(mock)],
            Arc::new(MockNotificationStoreApiMock::new()),
            Arc::new(mock_contact_service),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(mock_event_store),
            vec!["ws://test.relay".into()],
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
        // given a payer and payee with a new bill
        let payer = get_identity_public_data(&node_id_test(), "drawee@example.com", vec![]);
        let payee = get_identity_public_data(&node_id_test_other(), "payee@example.com", vec![]);
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
        let payer = get_identity_public_data(&node_id_test(), "drawee@example.com", vec![]);
        let payee = get_identity_public_data(&node_id_test_other(), "payee@example.com", vec![]);
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
                signing_address: PostalAddress::default(),
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
        let payer = get_identity_public_data(&node_id_test(), "drawee@example.com", vec![]);
        let payee = get_identity_public_data(&node_id_test_other(), "payee@example.com", vec![]);
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
                signing_address: Some(PostalAddress::default()),
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
        let payer = get_identity_public_data(&node_id_test(), "drawee@example.com", vec![]);
        let payee = get_identity_public_data(&node_id_test_other(), "payee@example.com", vec![]);
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let mut chain = get_genesis_chain(Some(bill.clone()));
        let timestamp = now().timestamp() as u64;
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_request_to_pay(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillRequestToPayBlockData {
                requester: BillParticipantBlockData::Ident(payee.clone().into()),
                currency: "USD".to_string(),
                signatory: None,
                signing_timestamp: timestamp,
                signing_address: Some(PostalAddress::default()),
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
        let payer = get_identity_public_data(&node_id_test(), "drawee@example.com", vec![]);
        let payee = get_identity_public_data(&node_id_test_other(), "payee@example.com", vec![]);
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
        let payer = get_identity_public_data(&node_id_test(), "drawee@example.com", vec![]);
        let payee = get_identity_public_data(&node_id_test_other(), "payee@example.com", vec![]);
        let endorsee =
            get_identity_public_data(&node_id_test_other2(), "endorsee@example.com", vec![]);
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
        let payer = get_identity_public_data(&node_id_test(), "drawee@example.com", vec![]);
        let payee = get_identity_public_data(&node_id_test_other(), "payee@example.com", vec![]);
        let buyer = get_identity_public_data(&node_id_test_other2(), "buyer@example.com", vec![]);
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
                sum: 100,
                currency: "USD".to_string(),
                signatory: None,
                payment_address: "Address".to_string(),
                signing_timestamp: timestamp,
                signing_address: Some(PostalAddress::default()),
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
        let payer = get_identity_public_data(&node_id_test(), "drawee@example.com", vec![]);
        let payee = get_identity_public_data(&node_id_test_other(), "payee@example.com", vec![]);
        let buyer = get_identity_public_data(&node_id_test_other2(), "buyer@example.com", vec![]);
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
                sum: 100,
                currency: "USD".to_string(),
                signatory: None,
                payment_address: "Address".to_string(),
                signing_timestamp: timestamp,
                signing_address: Some(PostalAddress::default()),
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
        let payer = get_identity_public_data(&node_id_test(), "drawee@example.com", vec![]);
        let payee = get_identity_public_data(&node_id_test_other(), "payee@example.com", vec![]);
        let recoursee =
            get_identity_public_data(&node_id_test_other2(), "recoursee@example.com", vec![]);
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let mut chain = get_genesis_chain(Some(bill.clone()));
        let timestamp = now().timestamp() as u64;
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_recourse(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillRecourseBlockData {
                recourser: payee.clone().into(),
                recoursee: recoursee.clone().into(),
                sum: 100,
                currency: "sat".to_string(),
                recourse_reason: BillRecourseReasonBlockData::Pay,
                signatory: None,
                signing_timestamp: timestamp,
                signing_address: PostalAddress::default(),
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
        let bill = get_test_bill();
        let endorsee = bill.endorsee.clone().unwrap();

        // should send minting requested to endorsee (mint)
        let service = setup_service_expectation(
            &endorsee.node_id(),
            BillEventType::BillMintingRequested,
            ActionType::CheckBill,
        );

        service
            .send_request_to_mint_event(&node_id_test(), &endorsee, &bill)
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn get_client_notifications() {
        let mut mock_store = MockNotificationStoreApiMock::new();
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

        let service = DefaultNotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(mock_store),
            Arc::new(MockContactServiceApi::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            vec!["ws://test.relay".into()],
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

        let service = DefaultNotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStoreApiMock::new()),
            Arc::new(MockContactServiceApi::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            vec!["ws://test.relay".into()],
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
        let mut mock_store = MockNotificationStoreApiMock::new();
        mock_store
            .expect_mark_as_done()
            .with(eq("notification_id"))
            .returning(|_| Ok(()));

        let mut mock_transport = MockNotificationJsonTransport::new();
        mock_transport
            .expect_get_sender_node_id()
            .returning(node_id_test);

        let service = DefaultNotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(mock_store),
            Arc::new(MockContactServiceApi::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            vec!["ws://test.relay".into()],
        );

        service
            .mark_notification_as_done("notification_id")
            .await
            .expect("could not mark notification as done");
    }

    fn setup_service_expectation(
        node_id: &NodeId,
        event_type: BillEventType,
        action_type: ActionType,
    ) -> DefaultNotificationService {
        let node_id = node_id.to_owned();
        let mut mock = MockNotificationJsonTransport::new();
        mock.expect_get_sender_node_id().returning(node_id_test);
        mock.expect_send_private_event()
            .withf(move |r, e| {
                let valid_node_id = r.node_id() == node_id;
                let event: Event<BillChainEventPayload> = e.clone().try_into().unwrap();
                valid_node_id
                    && event.data.event_type == event_type
                    && event.data.action_type == Some(action_type.clone())
            })
            .returning(|_, _| Ok(()));
        DefaultNotificationService::new(
            vec![Arc::new(mock)],
            Arc::new(MockNotificationStoreApiMock::new()),
            Arc::new(MockContactServiceApi::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            vec!["ws://test.relay".into()],
        )
    }

    fn get_test_bill() -> BitcreditBill {
        get_test_bitcredit_bill(
            &bill_id_test(),
            &get_identity_public_data(&node_id_test(), "drawee@example.com", vec![]),
            &get_identity_public_data(&node_id_test_other(), "payee@example.com", vec![]),
            Some(&get_identity_public_data(
                &node_id_test_other(),
                "drawer@example.com",
                vec![],
            )),
            Some(&get_identity_public_data(
                &node_id_test_other2(),
                "endorsee@example.com",
                vec![],
            )),
        )
    }

    #[tokio::test]
    async fn test_create_nostr_consumer() {
        let clients = vec![Arc::new(get_mock_nostr_client().await)];
        let contact_service = Arc::new(MockContactServiceApi::new());
        let store = Arc::new(MockNostrEventOffsetStoreApiMock::new());
        let notification_store = Arc::new(MockNotificationStoreApiMock::new());
        let push_service = Arc::new(MockPushService::new());
        let bill_store = Arc::new(MockBillStoreApiMock::new());
        let bill_blockchain_store = Arc::new(MockBillChainStoreApiMock::new());
        let mut nostr_contact_store = MockNostrContactStore::new();
        nostr_contact_store.expect_by_node_id().returning(|_| {
            Ok(Some(NostrContact {
                npub: NostrPublicKey::from_hex(TEST_NODE_ID_SECP_AS_NPUB_HEX).unwrap(),
                name: None,
                relays: Vec::default(),
                trust_level: TrustLevel::Participant,
                handshake_status: HandshakeStatus::None,
            }))
        });
        let chain_key_store = Arc::new(MockChainKeyService::new());
        let chain_event_store = Arc::new(MockNostrChainEventStore::new());
        let _ = create_nostr_consumer(
            clients,
            contact_service,
            store,
            notification_store,
            push_service,
            bill_blockchain_store,
            bill_store,
            Arc::new(nostr_contact_store),
            chain_key_store,
            chain_event_store,
        )
        .await;
    }

    #[tokio::test]
    async fn test_send_retry_messages_success() {
        let node_id = node_id_test_other();
        let message_id = "test_message_id";
        let sender_id = node_id_test();
        let payload = serde_json::to_value(EventEnvelope {
            version: "1.0".to_string(),
            event_type: EventType::Bill,
            data: serde_json::Value::Null,
        })
        .unwrap();
        let queued_message = NostrQueuedMessage {
            id: message_id.to_string(),
            sender_id: sender_id.to_owned(),
            node_id: node_id.to_owned(),
            payload: payload.clone(),
        };

        let identity = get_identity_public_data(&node_id, "test@example.com", vec![]);

        // Set up mocks
        let mut mock_contact_service = MockContactServiceApi::new();
        mock_contact_service
            .expect_get_identity_by_node_id()
            .with(eq(node_id))
            .returning(move |_| Ok(Some(BillParticipant::Ident(identity.clone()))));

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

        let service = DefaultNotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStoreApiMock::new()),
            Arc::new(mock_contact_service),
            Arc::new(mock_queue),
            Arc::new(MockNostrChainEventStore::new()),
            vec!["ws://test.relay".into()],
        );

        let result = service.send_retry_messages().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_retry_messages_with_send_failure() {
        let node_id = node_id_test_other();
        let message_id = "test_message_id";
        let sender_id = node_id_test();
        let payload = serde_json::to_value(EventEnvelope {
            version: "1.0".to_string(),
            event_type: EventType::Bill,
            data: serde_json::Value::Null,
        })
        .unwrap();

        let queued_message = NostrQueuedMessage {
            id: message_id.to_string(),
            sender_id: sender_id.to_owned(),
            node_id: node_id.to_owned(),
            payload: payload.clone(),
        };

        let identity = get_identity_public_data(&node_id, "test@example.com", vec![]);

        // Set up mocks
        let mut mock_contact_service = MockContactServiceApi::new();
        mock_contact_service
            .expect_get_identity_by_node_id()
            .with(eq(node_id))
            .returning(move |_| Ok(Some(BillParticipant::Ident(identity.clone()))));

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

        let service = DefaultNotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStoreApiMock::new()),
            Arc::new(mock_contact_service),
            Arc::new(mock_queue),
            Arc::new(MockNostrChainEventStore::new()),
            vec!["ws://test.relay".into()],
        );

        let result = service.send_retry_messages().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_retry_messages_with_multiple_messages() {
        let node_id1 = node_id_test_other();
        let sender_id = node_id_test();
        let node_id2 = node_id_test_other2();
        let message_id1 = "test_message_id_1";
        let message_id2 = "test_message_id_2";

        let payload1 = serde_json::to_value(EventEnvelope {
            version: "1.0".to_string(),
            event_type: EventType::Bill,
            data: serde_json::Value::Null,
        })
        .unwrap();

        let payload2 = serde_json::to_value(EventEnvelope {
            version: "1.0".to_string(),
            event_type: EventType::Bill,
            data: serde_json::Value::Null,
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

        let identity1 = get_identity_public_data(&node_id1, "test1@example.com", vec![]);
        let identity2 = get_identity_public_data(&node_id2, "test2@example.com", vec![]);

        // Set up mocks
        let mut mock_contact_service = MockContactServiceApi::new();
        mock_contact_service
            .expect_get_identity_by_node_id()
            .with(eq(node_id1))
            .returning(move |_| Ok(Some(BillParticipant::Ident(identity1.clone()))));
        mock_contact_service
            .expect_get_identity_by_node_id()
            .with(eq(node_id2))
            .returning(move |_| Ok(Some(BillParticipant::Ident(identity2.clone()))));

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

        let service = DefaultNotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStoreApiMock::new()),
            Arc::new(mock_contact_service),
            Arc::new(mock_queue),
            Arc::new(MockNostrChainEventStore::new()),
            vec!["ws://test.relay".into()],
        );

        let result = service.send_retry_messages().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_retry_messages_with_invalid_payload() {
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

        let service = DefaultNotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStoreApiMock::new()),
            Arc::new(MockContactServiceApi::new()),
            Arc::new(mock_queue),
            Arc::new(MockNostrChainEventStore::new()),
            vec!["ws://test.relay".into()],
        );

        let result = service.send_retry_messages().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_retry_messages_with_fail_retry_error() {
        let node_id = node_id_test_other();
        let message_id = "test_message_id";
        let sender = node_id_test();
        let payload = serde_json::to_value(EventEnvelope {
            version: "1.0".to_string(),
            event_type: EventType::Bill,
            data: serde_json::Value::Null,
        })
        .unwrap();

        let queued_message = NostrQueuedMessage {
            id: message_id.to_string(),
            sender_id: sender.to_owned(),
            node_id: node_id.to_owned(),
            payload: payload.clone(),
        };

        let identity = get_identity_public_data(&node_id, "test@example.com", vec![]);

        // Set up mocks
        let mut mock_contact_service = MockContactServiceApi::new();
        mock_contact_service
            .expect_get_identity_by_node_id()
            .with(eq(node_id))
            .returning(move |_| Ok(Some(BillParticipant::Ident(identity.clone()))));

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

        let service = DefaultNotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStoreApiMock::new()),
            Arc::new(mock_contact_service),
            Arc::new(mock_queue),
            Arc::new(MockNostrChainEventStore::new()),
            vec!["ws://test.relay".into()],
        );

        let result = service.send_retry_messages().await;
        assert!(result.is_ok()); // Should still return Ok despite the internal error
    }

    #[tokio::test]
    async fn test_send_retry_messages_with_succeed_retry_error() {
        let node_id = node_id_test_other();
        let message_id = "test_message_id";
        let sender = node_id_test();
        let payload = serde_json::to_value(EventEnvelope {
            version: "1.0".to_string(),
            event_type: EventType::Bill,
            data: serde_json::Value::Null,
        })
        .unwrap();

        let queued_message = NostrQueuedMessage {
            id: message_id.to_string(),
            sender_id: sender.to_owned(),
            node_id: node_id.to_owned(),
            payload: payload.clone(),
        };

        let identity = get_identity_public_data(&node_id, "test@example.com", vec![]);

        // Set up mocks
        let mut mock_contact_service = MockContactServiceApi::new();
        mock_contact_service
            .expect_get_identity_by_node_id()
            .with(eq(node_id))
            .returning(move |_| Ok(Some(BillParticipant::Ident(identity.clone()))));

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

        let service = DefaultNotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStoreApiMock::new()),
            Arc::new(mock_contact_service),
            Arc::new(mock_queue),
            Arc::new(MockNostrChainEventStore::new()),
            vec!["ws://test.relay".into()],
        );

        let result = service.send_retry_messages().await;
        assert!(result.is_ok()); // Should still return Ok despite the internal error
    }

    #[tokio::test]
    async fn test_send_retry_messages_with_no_messages() {
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

        let service = DefaultNotificationService::new(
            vec![Arc::new(mock_transport)],
            Arc::new(MockNotificationStoreApiMock::new()),
            Arc::new(MockContactServiceApi::new()),
            Arc::new(mock_queue),
            Arc::new(MockNostrChainEventStore::new()),
            vec!["ws://test.relay".into()],
        );

        let result = service.send_retry_messages().await;
        assert!(result.is_ok());
    }
}
