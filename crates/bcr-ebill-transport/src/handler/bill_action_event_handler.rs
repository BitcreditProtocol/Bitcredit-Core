use super::BillChainEventProcessorApi;
use super::NotificationHandlerApi;
use crate::BillChainEventPayload;
use crate::EventType;
use crate::{Error, Event, EventEnvelope, PushApi, Result};
use async_trait::async_trait;
use bcr_ebill_core::ServiceTraitBounds;
use bcr_ebill_core::notification::BillEventType;
use bcr_ebill_core::notification::{Notification, NotificationType};
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
        node_id: &str,
    ) -> Result<()> {
        trace!("creating notification {event:?} for {node_id}");
        // no action no notification required
        if event.action_type.is_none() {
            return Ok(());
        }
        // create notification
        let notification = Notification::new_bill_notification(
            &event.bill_id,
            node_id,
            &event_description(&event.event_type),
            Some(serde_json::to_value(event)?),
        );
        // mark Bill event as done if any active one exists
        match self
            .notification_store
            .get_latest_by_reference(&event.bill_id, NotificationType::Bill)
            .await
        {
            Ok(Some(currently_active)) => {
                if let Err(e) = self
                    .notification_store
                    .mark_as_done(&currently_active.id)
                    .await
                {
                    error!(
                        "Failed to mark currently active notification as done: {}",
                        e
                    );
                }
            }
            Err(e) => error!("Failed to get latest notification by reference: {}", e),
            Ok(None) => {}
        }
        // save new notification to database
        self.notification_store
            .add(notification.clone())
            .await
            .map_err(|e| {
                error!("Failed to save new notification to database: {}", e);
                Error::Persistence("Failed to save new notification to database".to_string())
            })?;

        // send push notification to connected clients
        match serde_json::to_value(notification) {
            Ok(notification) => {
                trace!("sending notification {notification:?} for {node_id}");
                self.push_service.send(notification).await;
            }
            Err(e) => {
                error!("Failed to serialize notification for push service: {}", e);
            }
        }
        Ok(())
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
        node_id: &str,
        _: Box<nostr::Event>,
    ) -> Result<()> {
        debug!("incoming bill chain event for {node_id}");
        if let Ok(decoded) = Event::<BillChainEventPayload>::try_from(event.clone()) {
            if !decoded.data.blocks.is_empty() {
                if let Err(e) = self
                    .processor
                    .process_chain_data(
                        &decoded.data.bill_id,
                        decoded.data.blocks.clone(),
                        decoded.data.keys.clone(),
                    )
                    .await
                {
                    error!("Failed to process chain data: {}", e);
                    return Ok(());
                }
            }
            if let Err(e) = self.create_notification(&decoded.data, node_id).await {
                error!("Failed to create notification for bill event: {}", e);
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
    use bcr_ebill_core::{
        OptionalPostalAddress, PostalAddress,
        bill::BillKeys,
        bill::BitcreditBill,
        blockchain::{
            Blockchain,
            bill::{
                BillBlock, BillBlockchain,
                block::{
                    BillEndorseBlockData, BillIssueBlockData, BillParticipantBlockData,
                    BillRejectBlockData,
                },
            },
        },
        contact::{BillIdentParticipant, BillParticipant, ContactType},
        identity::{Identity, IdentityType, IdentityWithAll},
        notification::ActionType,
        util::BcrKeys,
    };
    use mockall::predicate::{always, eq};

    use crate::handler::{
        MockBillChainEventProcessorApi,
        test_utils::{MockNotificationStore, MockPushService, get_test_nostr_event},
    };

    use super::*;

    #[tokio::test]
    async fn test_create_event_handler() {
        let (notification_store, push_service, bill_chain_event_processor) = create_mocks();
        BillActionEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_event_processor),
        );
    }

    #[tokio::test]
    async fn test_creates_new_chain_for_new_chain_event() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let mut payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        payee.node_id = OTHER_TEST_PUB_KEY_SECP.to_owned();
        let drawer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bill = get_test_bitcredit_bill(TEST_BILL_ID, &payer, &payee, Some(&drawer), None);
        let chain = get_genesis_chain(Some(bill.clone()));
        let keys = get_bill_keys();

        let (notification_store, push_service, mut bill_chain_event_processor) = create_mocks();

        bill_chain_event_processor
            .expect_process_chain_data()
            .with(eq(TEST_BILL_ID), always(), always())
            .returning(|_, _, _| Ok(()));

        let handler = BillActionEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_event_processor),
        );
        let event = Event::new(
            EventType::Bill,
            BillChainEventPayload {
                bill_id: TEST_BILL_ID.to_string(),
                event_type: BillEventType::BillBlock,
                blocks: chain.blocks().clone(),
                keys: Some(keys.clone()),
                sum: Some(0),
                action_type: None,
            },
        );

        handler
            .handle_event(
                event.try_into().expect("Envelope from event"),
                "node_id",
                Box::new(get_test_nostr_event()),
            )
            .await
            .expect("Event should be handled");
    }

    #[tokio::test]
    async fn test_fails_to_create_new_chain_for_new_chain_event_if_block_validation_fails() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let mut payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        payee.node_id = OTHER_TEST_PUB_KEY_SECP.to_owned();
        let drawer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bill = get_test_bitcredit_bill(TEST_BILL_ID, &payer, &payee, Some(&drawer), None);
        let mut chain = get_genesis_chain(Some(bill.clone()));
        let keys = get_bill_keys();

        // reject to pay without a request to accept will fail
        let block = BillBlock::create_block_for_reject_to_pay(
            TEST_BILL_ID.to_string(),
            chain.get_latest_block(),
            &BillRejectBlockData {
                rejecter: payer.clone().into(),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1000,
                signing_address: empty_address(),
            },
            &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
            None,
            &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();
        assert!(chain.try_add_block(block));

        let (notification_store, push_service, mut bill_chain_event_processor) = create_mocks();

        bill_chain_event_processor
            .expect_process_chain_data()
            .with(eq(TEST_BILL_ID), always(), always())
            .returning(|_, _, _| Ok(()));

        let handler = BillActionEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_event_processor),
        );
        let event = Event::new(
            EventType::Bill,
            BillChainEventPayload {
                bill_id: TEST_BILL_ID.to_string(),
                event_type: BillEventType::BillBlock,
                blocks: chain.blocks().clone(),
                keys: Some(keys.clone()),
                sum: Some(0),
                action_type: None,
            },
        );

        handler
            .handle_event(
                event.try_into().expect("Envelope from event"),
                "node_id",
                Box::new(get_test_nostr_event()),
            )
            .await
            .expect("Event should be handled");
    }

    #[tokio::test]
    async fn test_fails_to_create_new_chain_for_new_chain_event_if_block_signing_check_fails() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        // drawer has a different key than signer, signing check will fail
        let mut drawer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        drawer.node_id = BcrKeys::new().get_public_key();
        let bill = get_test_bitcredit_bill(TEST_BILL_ID, &payer, &payee, Some(&drawer), None);
        let chain = get_genesis_chain(Some(bill.clone()));
        let keys = get_bill_keys();

        let (notification_store, push_service, mut bill_chain_event_processor) = create_mocks();

        bill_chain_event_processor
            .expect_process_chain_data()
            .with(eq(TEST_BILL_ID), always(), always())
            .returning(|_, _, _| Ok(()));

        let handler = BillActionEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_event_processor),
        );
        let event = Event::new(
            EventType::Bill,
            BillChainEventPayload {
                bill_id: TEST_BILL_ID.to_string(),
                event_type: BillEventType::BillBlock,
                blocks: chain.blocks().clone(),
                keys: Some(keys.clone()),
                sum: Some(0),
                action_type: None,
            },
        );

        handler
            .handle_event(
                event.try_into().expect("Envelope from event"),
                "node_id",
                Box::new(get_test_nostr_event()),
            )
            .await
            .expect("Event should be handled");
    }

    #[tokio::test]
    async fn test_adds_block_for_existing_chain_event() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let mut endorsee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        endorsee.node_id = OTHER_TEST_PUB_KEY_SECP.to_owned();
        let bill = get_test_bitcredit_bill(TEST_BILL_ID, &payer, &payee, None, None);
        let chain = get_genesis_chain(Some(bill.clone()));
        let block = BillBlock::create_block_for_endorse(
            TEST_BILL_ID.to_string(),
            chain.get_latest_block(),
            &BillEndorseBlockData {
                endorsee: BillParticipantBlockData::Ident(endorsee.clone().into()),
                // endorsed by payee
                endorser: BillParticipantBlockData::Ident(
                    BillIdentParticipant::new(get_baseline_identity().identity)
                        .unwrap()
                        .into(),
                ),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1000,
                signing_address: Some(empty_address()),
            },
            &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
            None,
            &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();

        let (notification_store, push_service, mut bill_chain_event_processor) = create_mocks();

        bill_chain_event_processor
            .expect_process_chain_data()
            .with(eq(TEST_BILL_ID), always(), always())
            .returning(|_, _, _| Ok(()));

        let handler = BillActionEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_event_processor),
        );
        let event = Event::new(
            EventType::Bill,
            BillChainEventPayload {
                bill_id: TEST_BILL_ID.to_string(),
                event_type: BillEventType::BillBlock,
                blocks: vec![block.clone()],
                keys: None,
                sum: Some(0),
                action_type: None,
            },
        );

        handler
            .handle_event(
                event.try_into().expect("Envelope from event"),
                "node_id",
                Box::new(get_test_nostr_event()),
            )
            .await
            .expect("Event should be handled");
    }

    #[tokio::test]
    async fn test_fails_to_add_block_for_invalid_bill_action() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bill = get_test_bitcredit_bill(TEST_BILL_ID, &payer, &payee, None, None);
        let chain = get_genesis_chain(Some(bill.clone()));

        // reject to pay without a request to accept will fail
        let block = BillBlock::create_block_for_reject_to_pay(
            TEST_BILL_ID.to_string(),
            chain.get_latest_block(),
            &BillRejectBlockData {
                rejecter: payer.clone().into(),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1000,
                signing_address: empty_address(),
            },
            &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
            None,
            &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();

        let (notification_store, push_service, mut bill_chain_event_processor) = create_mocks();

        bill_chain_event_processor
            .expect_process_chain_data()
            .with(eq(TEST_BILL_ID), always(), always())
            .returning(|_, _, _| Ok(()));

        let handler = BillActionEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_event_processor),
        );

        let event = Event::new(
            EventType::Bill,
            BillChainEventPayload {
                bill_id: TEST_BILL_ID.to_string(),
                event_type: BillEventType::BillBlock,
                blocks: vec![block.clone()],
                keys: None,
                sum: Some(0),
                action_type: None,
            },
        );

        handler
            .handle_event(
                event.try_into().expect("Envelope from event"),
                "node_id",
                Box::new(get_test_nostr_event()),
            )
            .await
            .expect("Event should be handled");
    }

    #[tokio::test]
    async fn test_fails_to_add_block_for_invalidly_signed_blocks() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let endorsee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        // endorser is different than block signer - signature won't be able to be validated
        let mut endorser = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        endorser.node_id = BcrKeys::new().get_public_key();
        let bill = get_test_bitcredit_bill(TEST_BILL_ID, &payer, &payee, None, None);
        let chain = get_genesis_chain(Some(bill.clone()));

        let block = BillBlock::create_block_for_endorse(
            TEST_BILL_ID.to_string(),
            chain.get_latest_block(),
            &BillEndorseBlockData {
                endorsee: BillParticipantBlockData::Ident(endorsee.clone().into()),
                // endorsed by payee
                endorser: BillParticipantBlockData::Ident(endorser.clone().into()),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1000,
                signing_address: Some(empty_address()),
            },
            &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
            None,
            &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();

        let (notification_store, push_service, mut bill_chain_event_processor) = create_mocks();

        bill_chain_event_processor
            .expect_process_chain_data()
            .with(eq(TEST_BILL_ID), always(), always())
            .returning(|_, _, _| Ok(()));

        let handler = BillActionEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_event_processor),
        );
        let event = Event::new(
            EventType::Bill,
            BillChainEventPayload {
                bill_id: TEST_BILL_ID.to_string(),
                event_type: BillEventType::BillBlock,
                blocks: vec![block.clone()],
                keys: None,
                sum: Some(0),
                action_type: None,
            },
        );

        handler
            .handle_event(
                event.try_into().expect("Envelope from event"),
                "node_id",
                Box::new(get_test_nostr_event()),
            )
            .await
            .expect("Event should be handled");
    }

    #[tokio::test]
    async fn test_fails_to_add_block_for_unknown_chain() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let endorsee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bill = get_test_bitcredit_bill(TEST_BILL_ID, &payer, &payee, None, None);
        let chain = get_genesis_chain(Some(bill.clone()));

        let block = BillBlock::create_block_for_endorse(
            TEST_BILL_ID.to_string(),
            chain.get_latest_block(),
            &BillEndorseBlockData {
                endorsee: BillParticipantBlockData::Ident(endorsee.clone().into()),
                // endorsed by payee
                endorser: BillParticipantBlockData::Ident(
                    BillIdentParticipant::new(get_baseline_identity().identity)
                        .unwrap()
                        .into(),
                ),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1000,
                signing_address: Some(empty_address()),
            },
            &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
            None,
            &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();

        let (notification_store, push_service, mut bill_chain_event_processor) = create_mocks();

        bill_chain_event_processor
            .expect_process_chain_data()
            .with(eq(TEST_BILL_ID), always(), always())
            .returning(|_, _, _| Ok(()));

        let handler = BillActionEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_event_processor),
        );
        let event = Event::new(
            EventType::Bill,
            BillChainEventPayload {
                bill_id: TEST_BILL_ID.to_string(),
                event_type: BillEventType::BillBlock,
                blocks: vec![block.clone()],
                keys: None,
                sum: Some(0),
                action_type: None,
            },
        );

        handler
            .handle_event(
                event.try_into().expect("Envelope from event"),
                "node_id",
                Box::new(get_test_nostr_event()),
            )
            .await
            .expect("Event should be handled");
    }

    #[tokio::test]
    async fn test_creates_no_notification_for_non_action_event() {
        let (mut notification_store, mut push_service, bill_chain_event_processor) = create_mocks();

        // look for currently active notification
        notification_store.expect_get_latest_by_reference().never();

        // store new notification
        notification_store.expect_add().never();

        // send push notification
        push_service.expect_send().never();

        let handler = BillActionEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_event_processor),
        );
        let event = Event::new(
            EventType::Bill,
            BillChainEventPayload {
                bill_id: "bill_id".to_string(),
                event_type: BillEventType::BillBlock,
                blocks: vec![],
                keys: None,
                sum: None,
                action_type: None,
            },
        );

        handler
            .handle_event(
                event.try_into().expect("Envelope from event"),
                "node_id",
                Box::new(get_test_nostr_event()),
            )
            .await
            .expect("Event should be handled");
    }

    #[tokio::test]
    async fn test_creates_notification_for_simple_action_event() {
        let (mut notification_store, mut push_service, bill_chain_event_processor) = create_mocks();

        // look for currently active notification
        notification_store
            .expect_get_latest_by_reference()
            .with(eq("bill_id"), eq(NotificationType::Bill))
            .times(1)
            .returning(|_, _| Ok(None));

        // store new notification
        notification_store.expect_add().times(1).returning(|_| {
            Ok(Notification::new_bill_notification(
                "bill_id",
                "node_id",
                "description",
                None,
            ))
        });

        // send push notification
        push_service.expect_send().times(1).returning(|_| ());

        let handler = BillActionEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_event_processor),
        );
        let event = Event::new(
            EventType::Bill,
            BillChainEventPayload {
                bill_id: "bill_id".to_string(),
                event_type: BillEventType::BillSigned,
                blocks: vec![],
                keys: None,
                sum: Some(0),
                action_type: Some(ActionType::CheckBill),
            },
        );

        handler
            .handle_event(
                event.try_into().expect("Envelope from event"),
                "node_id",
                Box::new(get_test_nostr_event()),
            )
            .await
            .expect("Event should be handled");
    }
    pub fn get_test_bitcredit_bill(
        id: &str,
        payer: &BillIdentParticipant,
        payee: &BillIdentParticipant,
        drawer: Option<&BillIdentParticipant>,
        endorsee: Option<&BillIdentParticipant>,
    ) -> BitcreditBill {
        let mut bill = empty_bitcredit_bill();
        bill.id = id.to_owned();
        bill.payee = BillParticipant::Ident(payee.clone());
        bill.drawee = payer.clone();
        if let Some(drawer) = drawer {
            bill.drawer = drawer.clone();
        }
        bill.endorsee = endorsee.map(|e| BillParticipant::Ident(e.to_owned()));
        bill
    }
    fn get_genesis_chain(bill: Option<BitcreditBill>) -> BillBlockchain {
        let bill = bill.unwrap_or(get_baseline_bill("some id"));
        BillBlockchain::new(
            &BillIssueBlockData::from(bill, None, 1731593928),
            get_baseline_identity().key_pair,
            None,
            BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
            1731593928,
        )
        .unwrap()
    }
    fn get_baseline_bill(bill_id: &str) -> BitcreditBill {
        let mut bill = empty_bitcredit_bill();
        let keys = BcrKeys::new();

        bill.maturity_date = "2099-10-15".to_string();
        let mut payee = empty_bill_identified_participant();
        payee.name = "payee".to_owned();
        payee.node_id = keys.get_public_key();
        bill.payee = BillParticipant::Ident(payee);
        bill.drawee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        bill.id = bill_id.to_owned();
        bill
    }
    fn empty_bitcredit_bill() -> BitcreditBill {
        BitcreditBill {
            id: "".to_string(),
            country_of_issuing: "AT".to_string(),
            city_of_issuing: "Vienna".to_string(),
            drawee: empty_bill_identified_participant(),
            drawer: empty_bill_identified_participant(),
            payee: BillParticipant::Ident(empty_bill_identified_participant()),
            endorsee: None,
            currency: "sat".to_string(),
            sum: 500,
            maturity_date: "2099-11-12".to_string(),
            issue_date: "2099-08-12".to_string(),
            city_of_payment: "Vienna".to_string(),
            country_of_payment: "AT".to_string(),
            language: "DE".to_string(),
            files: vec![],
        }
    }

    pub fn get_bill_keys() -> BillKeys {
        BillKeys {
            private_key: TEST_PRIVATE_KEY_SECP.to_owned(),
            public_key: TEST_PUB_KEY_SECP.to_owned(),
        }
    }

    fn get_baseline_identity() -> IdentityWithAll {
        let keys = BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap();
        let mut identity = empty_identity();
        identity.name = "drawer".to_owned();
        identity.node_id = keys.get_public_key();
        identity.postal_address.country = Some("AT".to_owned());
        identity.postal_address.city = Some("Vienna".to_owned());
        identity.postal_address.address = Some("Hayekweg 5".to_owned());
        IdentityWithAll {
            identity,
            key_pair: keys,
        }
    }
    fn empty_bill_identified_participant() -> BillIdentParticipant {
        BillIdentParticipant {
            t: ContactType::Person,
            node_id: "".to_string(),
            name: "some name".to_string(),
            postal_address: empty_address(),
            email: None,
            nostr_relays: vec![],
        }
    }
    fn empty_address() -> PostalAddress {
        PostalAddress {
            country: "AT".to_string(),
            city: "Vienna".to_string(),
            zip: None,
            address: "Some address".to_string(),
        }
    }
    fn empty_identity() -> Identity {
        Identity {
            t: IdentityType::Ident,
            node_id: "".to_string(),
            name: "some name".to_string(),
            email: Some("some@example.com".to_string()),
            postal_address: empty_optional_address(),
            date_of_birth: None,
            country_of_birth: None,
            city_of_birth: None,
            identification_number: None,
            nostr_relays: vec![],
            profile_picture_file: None,
            identity_document_file: None,
        }
    }

    pub fn empty_optional_address() -> OptionalPostalAddress {
        OptionalPostalAddress {
            country: None,
            city: None,
            zip: None,
            address: None,
        }
    }

    const TEST_PRIVATE_KEY_SECP: &str =
        "d1ff7427912d3b81743d3b67ffa1e65df2156d3dab257316cbc8d0f35eeeabe9";

    pub const TEST_PUB_KEY_SECP: &str =
        "02295fb5f4eeb2f21e01eaf3a2d9a3be10f39db870d28f02146130317973a40ac0";

    pub const OTHER_TEST_PUB_KEY_SECP: &str =
        "03f9f94d1fdc2090d46f3524807e3f58618c36988e69577d70d5d4d1e9e9645a4f";

    pub const TEST_BILL_ID: &str = "KmtMUia3ezhshD9EyzvpT62DUPLr66M5LESy6j8ErCtv1USUDtoTA8JkXnCCGEtZxp41aKne5wVcCjoaFbjDqD4aFk";

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
}
