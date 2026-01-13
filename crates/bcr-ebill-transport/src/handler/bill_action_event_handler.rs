use super::BillChainEventProcessorApi;
use super::NotificationHandlerApi;
use crate::EventType;
use crate::PushApi;
use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_api::service::transport_service::{Error, Result};
use bcr_ebill_core::application::ServiceTraitBounds;
use bcr_ebill_core::application::notification::{Notification, NotificationType};
use bcr_ebill_core::protocol::event::BillChainEventPayload;
use bcr_ebill_core::protocol::event::BillEventType;
use bcr_ebill_core::protocol::event::Event;
use bcr_ebill_core::protocol::event::EventEnvelope;
use bcr_ebill_persistence::NotificationStoreApi;
use log::{debug, error, trace, warn};
use std::sync::Arc;

#[derive(Clone)]
pub struct BillActionEventHandler {
    notification_store: Arc<dyn NotificationStoreApi>,
    push_service: Arc<dyn PushApi>,
    processor: Arc<dyn BillChainEventProcessorApi>,
}

impl BillActionEventHandler {
    pub fn new(
        notification_store: Arc<dyn NotificationStoreApi>,
        push_service: Arc<dyn PushApi>,
        processor: Arc<dyn BillChainEventProcessorApi>,
    ) -> Self {
        Self {
            notification_store,
            push_service,
            processor,
        }
    }

    async fn create_notification(
        &self,
        event: &BillChainEventPayload,
        node_id: &NodeId,
        npub: nostr::PublicKey,
        event_id: Option<String>,
    ) -> Result<()> {
        trace!("creating notification {event:?} for {node_id}");
        // no action no notification required
        if event.action_type.is_none() {
            return Ok(());
        }

        // we don't have this chain or the sender is not part of the chain so skip event
        if !self
            .validate_chain_event_and_sender(&event.bill_id, npub)
            .await
        {
            return Ok(());
        }

        // Check for deduplication based on event_id
        if let Some(ref eid) = event_id
            && let Ok(true) = self
                .notification_store
                .notification_exists_for_event_id(eid, node_id)
                .await
        {
            trace!("Notification already exists for event_id {eid}, skipping");
            return Ok(());
        }

        // create notification
        let mut notification = Notification::new_bill_notification(
            &event.bill_id,
            node_id,
            &event_description(&event.event_type),
            Some(serde_json::to_value(event)?),
        );
        notification.event_id = event_id;

        // mark Bill event as done if any active one exists
        match self
            .notification_store
            .get_latest_by_reference(&event.bill_id.to_string(), NotificationType::Bill)
            .await
        {
            Ok(Some(currently_active)) => {
                if let Err(e) = self
                    .notification_store
                    .mark_as_done(&currently_active.id)
                    .await
                {
                    error!("Failed to mark currently active notification as done: {e}");
                }
            }
            Err(e) => error!("Failed to get latest notification by reference: {e}"),
            Ok(None) => {}
        }
        // save new notification to database
        self.notification_store
            .add(notification.clone())
            .await
            .map_err(|e| {
                error!("Failed to save new notification to database: {e}");
                Error::Persistence("Failed to save new notification to database".to_string())
            })?;

        // send push notification to connected clients
        match serde_json::to_value(notification) {
            Ok(notification) => {
                trace!("sending notification {notification:?} for {node_id}");
                self.push_service.send(notification).await;
            }
            Err(e) => {
                error!("Failed to serialize notification for push service: {e}");
            }
        }
        Ok(())
    }

    async fn validate_chain_event_and_sender(
        &self,
        bill_id: &BillId,
        npub: nostr::PublicKey,
    ) -> bool {
        if let Ok(valid) = self
            .processor
            .validate_chain_event_and_sender(bill_id, npub)
            .await
        {
            return valid;
        }
        false
    }
}

impl ServiceTraitBounds for BillActionEventHandler {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationHandlerApi for BillActionEventHandler {
    fn handles_event(&self, event_type: &EventType) -> bool {
        event_type == &EventType::Bill
    }

    async fn handle_event(
        &self,
        event: EventEnvelope,
        node_id: &NodeId,
        sender: Option<nostr::PublicKey>,
        evt: Option<Box<nostr::Event>>,
    ) -> Result<()> {
        debug!("incoming bill chain event for {node_id} in action event handler");
        let event_id = evt.as_ref().map(|e| e.id.to_string());
        if let Ok(decoded) = Event::<BillChainEventPayload>::try_from(event.clone()) {
            if let Err(e) = self
                .create_notification(
                    &decoded.data,
                    node_id,
                    sender.ok_or(Error::Network(
                        "No original event for notification handler".to_string(),
                    ))?,
                    event_id,
                )
                .await
            {
                error!("Failed to create notification for bill event: {e}");
            }
        } else {
            warn!("Could not decode event to BillChainEventPayload {event:?}");
        }
        Ok(())
    }
}

// generates a human readable description for an event
fn event_description(event_type: &BillEventType) -> String {
    match event_type {
        BillEventType::BillSigned => "bill_signed".to_string(),
        BillEventType::BillAccepted => "bill_accepted".to_string(),
        BillEventType::BillAcceptanceRequested => "bill_should_be_accepted".to_string(),
        BillEventType::BillAcceptanceRejected => "bill_acceptance_rejected".to_string(),
        BillEventType::BillAcceptanceTimeout => "bill_acceptance_timed_out".to_string(),
        BillEventType::BillAcceptanceRecourse => "bill_recourse_acceptance_required".to_string(),
        BillEventType::BillPaymentRequested => "bill_payment_required".to_string(),
        BillEventType::BillPaymentRejected => "bill_payment_rejected".to_string(),
        BillEventType::BillPaymentTimeout => "bill_payment_timed_out".to_string(),
        BillEventType::BillPaymentRecourse => "bill_recourse_payment_required".to_string(),
        BillEventType::BillRecourseRejected => "Bill_recourse_rejected".to_string(),
        BillEventType::BillRecourseTimeout => "Bill_recourse_timed_out".to_string(),
        BillEventType::BillSellOffered => "bill_request_to_buy".to_string(),
        BillEventType::BillBuyingRejected => "bill_buying_rejected".to_string(),
        BillEventType::BillPaid => "bill_paid".to_string(),
        BillEventType::BillRecoursePaid => "bill_recourse_paid".to_string(),
        BillEventType::BillEndorsed => "bill_endorsed".to_string(),
        BillEventType::BillSold => "bill_sold".to_string(),
        BillEventType::BillMintingRequested => "requested_to_mint".to_string(),
        BillEventType::BillNewQuote => "new_quote".to_string(),
        BillEventType::BillQuoteApproved => "quote_approved".to_string(),
        BillEventType::BillBlock => "".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bcr_ebill_core::{protocol::PublicKey, protocol::Sum, protocol::event::ActionType};
    use mockall::predicate::{always, eq};

    use crate::handler::{
        MockBillChainEventProcessorApi,
        test_utils::{MockNotificationStore, MockPushService, get_test_nostr_event},
    };

    use super::*;

    #[tokio::test]
    async fn test_create_event_handler() {
        let (notification_store, push_service, chain_store) = create_mocks();
        BillActionEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(chain_store),
        );
    }

    #[tokio::test]
    async fn test_fails_to_add_notification_for_unknown_chain() {
        let (mut notification_store, mut push_service, mut chain_processor) = create_mocks();

        // no bill chain
        chain_processor
            .expect_validate_chain_event_and_sender()
            .with(eq(bill_id_test()), always())
            .returning(|_, _| Ok(false));

        // not look for currently active notification
        notification_store.expect_get_latest_by_reference().never();

        // not store new notification
        notification_store.expect_add().never();

        // not send push notification
        push_service.expect_send().never();

        let handler = BillActionEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(chain_processor),
        );

        let event = Event::new(
            EventType::Bill,
            BillChainEventPayload {
                bill_id: bill_id_test(),
                event_type: BillEventType::BillBlock,
                sum: Some(Sum::new_sat(100).expect("sat works")),
                action_type: Some(ActionType::CheckBill),
            },
        );

        handler
            .handle_event(
                event.try_into().expect("Envelope from event"),
                &node_id_test(),
                Some(get_test_nostr_event().pubkey),
                Some(Box::new(get_test_nostr_event())),
            )
            .await
            .expect("Event should be handled");
    }

    #[tokio::test]
    async fn test_creates_no_notification_for_non_action_event() {
        let (mut notification_store, mut push_service, chain_processor) = create_mocks();

        // look for currently active notification
        notification_store.expect_get_latest_by_reference().never();

        // store new notification
        notification_store.expect_add().never();

        // send push notification
        push_service.expect_send().never();

        let handler = BillActionEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(chain_processor),
        );
        let event = Event::new(
            EventType::Bill,
            BillChainEventPayload {
                bill_id: bill_id_test(),
                event_type: BillEventType::BillBlock,
                sum: None,
                action_type: None,
            },
        );

        handler
            .handle_event(
                event.try_into().expect("Envelope from event"),
                &node_id_test(),
                Some(get_test_nostr_event().pubkey),
                Some(Box::new(get_test_nostr_event())),
            )
            .await
            .expect("Event should be handled");
    }

    #[tokio::test]
    async fn test_creates_notification_for_simple_action_event() {
        let (mut notification_store, mut push_service, mut chain_processor) = create_mocks();

        // given bill chain valid
        chain_processor
            .expect_validate_chain_event_and_sender()
            .with(eq(bill_id_test()), always())
            .returning(|_, _| Ok(true));

        // check for deduplication
        notification_store
            .expect_notification_exists_for_event_id()
            .with(always(), eq(node_id_test()))
            .times(1)
            .returning(|_, _| Ok(false));

        // look for currently active notification
        notification_store
            .expect_get_latest_by_reference()
            .with(eq(bill_id_test().to_string()), eq(NotificationType::Bill))
            .times(1)
            .returning(|_, _| Ok(None));

        // store new notification
        notification_store.expect_add().times(1).returning(|_| {
            Ok(Notification::new_bill_notification(
                &bill_id_test(),
                &node_id_test(),
                "description",
                None,
            ))
        });

        // send push notification
        push_service.expect_send().times(1).returning(|_| ());

        let handler = BillActionEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(chain_processor),
        );
        let event = Event::new(
            EventType::Bill,
            BillChainEventPayload {
                bill_id: bill_id_test(),
                event_type: BillEventType::BillSigned,
                sum: Some(Sum::new_sat(500).expect("sat works")),
                action_type: Some(ActionType::CheckBill),
            },
        );

        handler
            .handle_event(
                event.try_into().expect("Envelope from event"),
                &node_id_test(),
                Some(get_test_nostr_event().pubkey),
                Some(Box::new(get_test_nostr_event())),
            )
            .await
            .expect("Event should be handled");
    }

    // bitcrt285psGq4Lz4fEQwfM3We5HPznJq8p1YvRaddszFaU5dY
    pub fn bill_id_test() -> BillId {
        BillId::new(
            PublicKey::from_str(
                "026423b7d36d05b8d50a89a1b4ef2a06c88bcd2c5e650f25e122fa682d3b39686c",
            )
            .unwrap(),
            bitcoin::Network::Testnet,
        )
    }

    pub fn node_id_test() -> NodeId {
        NodeId::from_str("bitcrt02295fb5f4eeb2f21e01eaf3a2d9a3be10f39db870d28f02146130317973a40ac0")
            .unwrap()
    }

    fn create_mocks() -> (
        MockNotificationStore,
        MockPushService,
        MockBillChainEventProcessorApi,
    ) {
        (
            MockNotificationStore::new(),
            MockPushService::new(),
            MockBillChainEventProcessorApi::new(),
        )
    }

    #[tokio::test]
    async fn test_deduplicates_notification_for_same_event_id() {
        let (mut notification_store, mut push_service, mut chain_processor) = create_mocks();

        // given bill chain valid
        chain_processor
            .expect_validate_chain_event_and_sender()
            .with(eq(bill_id_test()), always())
            .returning(|_, _| Ok(true));

        // check for deduplication - return true to indicate notification already exists
        notification_store
            .expect_notification_exists_for_event_id()
            .with(always(), eq(node_id_test()))
            .times(1)
            .returning(|_, _| Ok(true));

        // should NOT look for currently active notification
        notification_store.expect_get_latest_by_reference().never();

        // should NOT store new notification
        notification_store.expect_add().never();

        // should NOT send push notification
        push_service.expect_send().never();

        let handler = BillActionEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(chain_processor),
        );
        let event = Event::new(
            EventType::Bill,
            BillChainEventPayload {
                bill_id: bill_id_test(),
                event_type: BillEventType::BillSigned,
                sum: Some(Sum::new_sat(500).expect("sat works")),
                action_type: Some(ActionType::CheckBill),
            },
        );

        let nostr_event = get_test_nostr_event();
        handler
            .handle_event(
                event.try_into().expect("Envelope from event"),
                &node_id_test(),
                Some(nostr_event.pubkey),
                Some(Box::new(nostr_event)),
            )
            .await
            .expect("Event should be handled");
    }
}
