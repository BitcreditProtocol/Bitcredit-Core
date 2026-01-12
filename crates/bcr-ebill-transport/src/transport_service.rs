use async_trait::async_trait;
use std::collections::HashMap;

use bcr_common::core::NodeId;
use bcr_ebill_api::service::transport_service::{
    BlockTransportServiceApi, ContactTransportServiceApi, NotificationTransportServiceApi,
    TransportServiceApi,
};
use bcr_ebill_core::protocol::blockchain::bill::BitcreditBill;
use bcr_ebill_core::protocol::blockchain::bill::participant::{
    BillIdentParticipant, BillParticipant,
};
use bcr_ebill_core::protocol::event::{BillChainEvent, BillChainEventPayload, Event};

use super::nostr_transport::NostrTransportService;
use bcr_ebill_api::service::transport_service::Result;
use bcr_ebill_core::application::ServiceTraitBounds;
use bcr_ebill_core::protocol::event::{ActionType, BillEventType};
use std::sync::Arc;

pub struct TransportService {
    nostr_transport: Arc<NostrTransportService>,
    notification_transport_service: Arc<dyn NotificationTransportServiceApi>,
    contact_transport_service: Arc<dyn ContactTransportServiceApi>,
    block_transport_service: Arc<dyn BlockTransportServiceApi>,
}

impl TransportService {
    pub fn new(
        nostr_transport: Arc<NostrTransportService>,
        notification_transport_service: Arc<dyn NotificationTransportServiceApi>,
        contact_transport_service: Arc<dyn ContactTransportServiceApi>,
        block_transport_service: Arc<dyn BlockTransportServiceApi>,
    ) -> Self {
        Self {
            nostr_transport,
            notification_transport_service,
            contact_transport_service,
            block_transport_service,
        }
    }
}

impl ServiceTraitBounds for TransportService {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl TransportServiceApi for TransportService {
    fn block_transport(&self) -> &Arc<dyn BlockTransportServiceApi> {
        &self.block_transport_service
    }

    fn contact_transport(&self) -> &Arc<dyn ContactTransportServiceApi> {
        &self.contact_transport_service
    }

    #[doc = " Returns the notification service"]
    fn notification_transport(&self) -> &Arc<dyn NotificationTransportServiceApi> {
        &self.notification_transport_service
    }

    async fn connect(&self) {
        self.nostr_transport.connect().await;
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

        self.block_transport_service
            .send_bill_chain_events(event.clone())
            .await?;
        self.nostr_transport
            .send_all_bill_events(&sender, &all_events)
            .await?;
        // send email(s)
        if drawer != drawee && drawer != payee {
            // if we're drawer, but neither drawee, nor payee, send mail to both
            if let Some(payee_event) = all_events.get(payee) {
                self.notification_transport_service
                    .send_email_notification(&event.sender(), payee, payee_event)
                    .await;
            }

            if let Some(drawee_event) = all_events.get(drawee) {
                self.notification_transport_service
                    .send_email_notification(&event.sender(), drawee, drawee_event)
                    .await;
            }
        } else if drawer == drawee {
            // if we're drawer & drawee, send mail to payee only

            if let Some(payee_event) = all_events.get(payee) {
                self.notification_transport_service
                    .send_email_notification(&event.sender(), payee, payee_event)
                    .await;
            }
        } else if drawer == payee {
            // if we're drawer & payee, send mail to drawee only
            if let Some(drawee_event) = all_events.get(drawee) {
                self.notification_transport_service
                    .send_email_notification(&event.sender(), drawee, drawee_event)
                    .await;
            }
        }

        Ok(())
    }

    async fn send_bill_is_accepted_event(&self, event: &BillChainEvent) -> Result<()> {
        let payee = event.bill.payee.node_id();
        let drawer = &event.bill.drawer.node_id;

        // Build recipients: payee and drawer (avoiding duplicates)
        let mut recipients = vec![(
            payee.clone(),
            (BillEventType::BillAccepted, ActionType::CheckBill),
        )];

        // Add drawer only if different from payee
        if drawer != &payee {
            recipients.push((
                drawer.clone(),
                (BillEventType::BillAccepted, ActionType::CheckBill),
            ));
        }

        let all_events = event.generate_action_messages(HashMap::from_iter(recipients), None, None);
        self.block_transport_service
            .send_bill_chain_events(event.clone())
            .await?;
        self.nostr_transport
            .send_all_bill_events(&event.sender(), &all_events)
            .await?;
        // Only send email to payee
        if let Some(payee_event) = all_events.get(&payee) {
            self.notification_transport_service
                .send_email_notification(&event.sender(), &payee, payee_event)
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
        self.block_transport_service
            .send_bill_chain_events(event.clone())
            .await?;
        self.nostr_transport
            .send_all_bill_events(&event.sender(), &all_events)
            .await?;
        // Only send email to drawee
        if let Some(drawee_event) = all_events.get(drawee) {
            self.notification_transport_service
                .send_email_notification(&event.sender(), drawee, drawee_event)
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
        self.block_transport_service
            .send_bill_chain_events(event.clone())
            .await?;
        self.nostr_transport
            .send_all_bill_events(&event.sender(), &all_events)
            .await?;
        // Only send email to drawee
        if let Some(drawee_event) = all_events.get(drawee) {
            self.notification_transport_service
                .send_email_notification(&event.sender(), drawee, drawee_event)
                .await;
        }
        Ok(())
    }

    async fn send_bill_is_paid_event(&self, event: &BillChainEvent) -> Result<()> {
        let sender = event.sender();
        let payee = event.bill.payee.node_id();
        let drawer = &event.bill.drawer.node_id;

        // Build recipients: payee and drawer (avoiding duplicates)
        let mut recipients = vec![(
            payee.clone(),
            (BillEventType::BillPaid, ActionType::CheckBill),
        )];

        // Add drawer only if different from payee
        if drawer != &payee {
            recipients.push((
                drawer.clone(),
                (BillEventType::BillPaid, ActionType::CheckBill),
            ));
        }

        let all_events = event.generate_action_messages(HashMap::from_iter(recipients), None, None);
        self.block_transport_service
            .send_bill_chain_events(event.clone())
            .await?;
        self.nostr_transport
            .send_all_bill_events(&sender, &all_events)
            .await?;
        // Only send email to holder and only if we are drawee
        let holder = event.bill.endorsee.as_ref().unwrap_or(&event.bill.payee);
        if let Some(holder_event) = all_events.get(&holder.node_id())
            && sender == event.bill.drawee.node_id
        {
            self.notification_transport_service
                .send_email_notification(&sender, &holder.node_id(), holder_event)
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
        self.block_transport_service
            .send_bill_chain_events(event.clone())
            .await?;
        self.nostr_transport
            .send_all_bill_events(&event.sender(), &all_events)
            .await?;
        // Only send email to endorsee
        if let Some(endorsee_event) = all_events.get(&endorsee) {
            self.notification_transport_service
                .send_email_notification(&event.sender(), &endorsee, endorsee_event)
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
        self.block_transport_service
            .send_bill_chain_events(event.clone())
            .await?;
        self.nostr_transport
            .send_all_bill_events(&event.sender(), &all_events)
            .await?;
        // Only send email to buyer
        if let Some(buyer_event) = all_events.get(&buyer.node_id()) {
            self.notification_transport_service
                .send_email_notification(&event.sender(), &buyer.node_id(), buyer_event)
                .await;
        }
        Ok(())
    }

    async fn send_bill_is_sold_event(
        &self,
        event: &BillChainEvent,
        buyer: &BillParticipant,
    ) -> Result<()> {
        let seller = event.bill.endorsee.as_ref().unwrap_or(&event.bill.payee);

        // Build recipients: buyer and seller (avoiding duplicates)
        let mut recipients = vec![(
            buyer.node_id().clone(),
            (BillEventType::BillSold, ActionType::CheckBill),
        )];

        // Add seller only if different from buyer
        if buyer.node_id() != seller.node_id() {
            recipients.push((
                seller.node_id(),
                (BillEventType::BillSold, ActionType::CheckBill),
            ));
        }

        let all_events = event.generate_action_messages(HashMap::from_iter(recipients), None, None);
        self.block_transport_service
            .send_bill_chain_events(event.clone())
            .await?;
        self.nostr_transport
            .send_all_bill_events(&event.sender(), &all_events)
            .await?;
        // Only send email to buyer
        if let Some(buyer_event) = all_events.get(&buyer.node_id()) {
            self.notification_transport_service
                .send_email_notification(&event.sender(), &buyer.node_id(), buyer_event)
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
        self.block_transport_service
            .send_bill_chain_events(event.clone())
            .await?;
        self.nostr_transport
            .send_all_bill_events(&event.sender(), &all_events)
            .await?;
        // Only send email to recoursee
        if let Some(recoursee_event) = all_events.get(&recoursee.node_id) {
            self.notification_transport_service
                .send_email_notification(&event.sender(), &recoursee.node_id, recoursee_event)
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
        let node = self.nostr_transport.get_node_transport(sender_node_id);
        node.send_private_event(sender_node_id, mint, event.clone().try_into()?)
            .await?;
        // Only send email to mint
        self.notification_transport_service
            .send_email_notification(sender_node_id, &mint.node_id(), &event)
            .await;
        Ok(())
    }

    async fn send_request_to_action_rejected_event(
        &self,
        event: &BillChainEvent,
        rejected_action: ActionType,
    ) -> Result<()> {
        if let Some(event_type) = rejected_action.get_rejected_event_type() {
            let drawee = &event.bill.drawee.node_id;

            // Build recipients: everyone in bill chain except payer (drawee)
            let recipients: HashMap<NodeId, (BillEventType, ActionType)> = event
                .get_all_participant_node_ids()
                .into_iter()
                .filter(|node_id| node_id != drawee)
                .map(|node_id| (node_id, (event_type.clone(), ActionType::CheckBill)))
                .collect();

            let all_events = event.generate_action_messages(recipients, None, None);

            self.block_transport_service
                .send_bill_chain_events(event.clone())
                .await?;
            self.nostr_transport
                .send_all_bill_events(&event.sender(), &all_events)
                .await?;
            // Only send email to holder (=requester)
            let holder = event.bill.endorsee.as_ref().unwrap_or(&event.bill.payee);
            if let Some(holder_event) = all_events.get(&holder.node_id()) {
                self.notification_transport_service
                    .send_email_notification(&event.sender(), &holder.node_id(), holder_event)
                    .await;
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
                None,
                None,
            );
            self.block_transport_service
                .send_bill_chain_events(event.clone())
                .await?;
            self.nostr_transport
                .send_all_bill_events(&event.sender(), &all_events)
                .await?;
            // Only send email to recoursee
            if let Some(recoursee_event) = all_events.get(&recoursee.node_id) {
                self.notification_transport_service
                    .send_email_notification(&event.sender(), &recoursee.node_id, recoursee_event)
                    .await;
            }
        }
        Ok(())
    }

    async fn send_retry_messages(&self) -> Result<()> {
        self.nostr_transport.send_retry_messages().await
    }

    async fn sync_relays(&self) -> Result<()> {
        self.nostr_transport
            .get_first_transport()
            .sync_relays()
            .await
    }

    async fn retry_failed_syncs(&self) -> Result<()> {
        self.nostr_transport
            .get_first_transport()
            .retry_failed_syncs()
            .await
    }
}

#[cfg(test)]
mod tests {
    use crate::Error;
    use crate::test_utils::{
        MockBlockTransportService, MockContactTransportService, MockNotificationTransportService,
        get_nostr_transport, signed_identity_proof_test,
    };
    use bcr_ebill_core::application::contact::Contact;
    use bcr_ebill_core::protocol::Timestamp;
    use bcr_ebill_core::protocol::blockchain::Blockchain;
    use bcr_ebill_core::protocol::blockchain::bill::block::{
        BillAcceptBlockData, BillOfferToSellBlockData, BillParticipantBlockData,
        BillRecourseBlockData, BillRecourseReasonBlockData, BillRequestToAcceptBlockData,
        BillRequestToPayBlockData,
    };
    use bcr_ebill_core::protocol::blockchain::bill::{BillBlock, BillBlockchain};
    use bcr_ebill_core::protocol::constants::{
        ACCEPT_DEADLINE_SECONDS, DAY_IN_SECS, PAYMENT_DEADLINE_SECONDS,
    };
    use bcr_ebill_core::protocol::event::{ChainInvite, EventEnvelope, EventType};
    use bcr_ebill_core::{
        protocol::Email,
        protocol::Result,
        protocol::crypto::BcrKeys,
        protocol::{Currency, Sum},
    };
    use bcr_ebill_persistence::nostr::NostrQueuedMessage;
    use bitcoin::base58;
    use mockall::predicate::eq;
    use std::sync::Arc;

    use crate::test_utils::{
        MockContactStore, MockNostrChainEventStore, MockNostrContactStore,
        MockNostrQueuedMessageStore, MockNotificationJsonTransport, bill_id_test, empty_address,
        get_baseline_identity, get_genesis_chain, init_test_cfg, node_id_test, node_id_test_other,
        node_id_test_other2, private_key_test, valid_payment_address_testnet,
    };

    use super::super::test_utils::{get_identity_public_data, get_test_bitcredit_bill};
    use super::*;

    fn check_chain_payload(event: &EventEnvelope, bill_event_type: BillEventType) -> bool {
        let valid_event_type = event.event_type == EventType::Bill;
        let event: Result<Event<BillChainEventPayload>> = event.clone().try_into();
        if let Ok(event) = event {
            valid_event_type && event.data.event_type == bill_event_type
        } else {
            false
        }
    }

    fn get_mocks() -> (
        MockNotificationJsonTransport,
        MockContactStore,
        MockNostrContactStore,
        MockNostrQueuedMessageStore,
        MockNostrChainEventStore,
        MockNotificationTransportService,
        MockContactTransportService,
        MockBlockTransportService,
    ) {
        let mut mock_transport = MockNotificationJsonTransport::new();
        // Set default expectation for has_local_signer to return false for any node_id
        // Tests can override this expectation as needed
        mock_transport
            .expect_has_local_signer()
            .returning(|_| false);

        (
            mock_transport,
            MockContactStore::new(),
            MockNostrContactStore::new(),
            MockNostrQueuedMessageStore::new(),
            MockNostrChainEventStore::new(),
            MockNotificationTransportService::new(),
            MockContactTransportService::new(),
            MockBlockTransportService::new(),
        )
    }
    fn get_transport(
        mock_transport: MockNotificationJsonTransport,
        contact_store: MockContactStore,
        nostr_contact_store: MockNostrContactStore,
        queued_message_store: MockNostrQueuedMessageStore,
        chain_events: MockNostrChainEventStore,
        mock_notification_transport: MockNotificationTransportService,
        mock_contact_transport: MockContactTransportService,
        mock_block_transport: MockBlockTransportService,
    ) -> TransportService {
        TransportService::new(
            Arc::new(get_nostr_transport(
                mock_transport,
                contact_store,
                nostr_contact_store,
                queued_message_store,
                chain_events,
            )),
            Arc::new(mock_notification_transport),
            Arc::new(mock_contact_transport),
            Arc::new(mock_block_transport),
        )
    }

    fn expect_service<T>(
        expect: impl Fn(
            &mut MockNotificationJsonTransport,
            &mut MockContactStore,
            &mut MockNostrContactStore,
            &mut MockNostrQueuedMessageStore,
            &mut MockNostrChainEventStore,
            &mut MockNotificationTransportService,
            &mut MockContactTransportService,
            &mut MockBlockTransportService,
        ) -> T,
    ) -> (TransportService, T) {
        let (
            mut transport,
            mut contact_store,
            mut nostr_contact_store,
            mut queued_message_store,
            mut chain_events,
            mut notification_transport,
            mut contact_transport,
            mut block_transport,
        ) = get_mocks();

        let value = expect(
            &mut transport,
            &mut contact_store,
            &mut nostr_contact_store,
            &mut queued_message_store,
            &mut chain_events,
            &mut notification_transport,
            &mut contact_transport,
            &mut block_transport,
        );

        (
            get_transport(
                transport,
                contact_store,
                nostr_contact_store,
                queued_message_store,
                chain_events,
                notification_transport,
                contact_transport,
                block_transport,
            ),
            value,
        )
    }

    #[tokio::test]
    async fn test_connect() {
        init_test_cfg();
        let mut mock_transport = MockNotificationJsonTransport::new();

        // call connect on the inner transport
        mock_transport.expect_connect().returning(|| Ok(()));

        let service = NostrTransportService::new(
            Arc::new(mock_transport),
            Arc::new(MockContactStore::new()),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(MockNostrQueuedMessageStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
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
        let timestamp = Timestamp::now();
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_offer_to_sell(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillOfferToSellBlockData {
                seller: BillParticipantBlockData::Ident(payee.clone().into()),
                buyer: BillParticipantBlockData::Ident(buyer.clone().into()),
                sum: Sum::new_sat(100).expect("sat works"),
                signatory: None,
                payment_address: valid_payment_address_testnet(),
                signing_timestamp: timestamp,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
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
            &BcrKeys::from_private_key(&private_key_test()),
            true,
            &node_id_test(),
        )
        .unwrap();

        let (service, _) = expect_service(
            move |transport, contact_store, _, _, _, notification_transport, _, block_transport| {
                let buyer = buyer.clone();
                let payer = payer.clone();
                let payee = payee.clone();
                contact_store
                    .expect_get()
                    .returning(move |_| Ok(Some(as_contact(&buyer))));
                contact_store
                    .expect_get()
                    .returning(move |_| Ok(Some(as_contact(&payer))));
                contact_store
                    .expect_get()
                    .returning(move |_| Ok(Some(as_contact(&payee))));

                // expect to send payment rejected event to all recipients (except payer)
                transport
                    .expect_send_private_event()
                    .withf(|_, _, e| check_chain_payload(e, BillEventType::BillPaymentRejected))
                    .returning(|_, _, _| Ok(()))
                    .times(2);

                // expect to send acceptance rejected event to all recipients (except payer)
                transport
                    .expect_send_private_event()
                    .withf(|_, _, e| check_chain_payload(e, BillEventType::BillAcceptanceRejected))
                    .returning(|_, _, _| Ok(()))
                    .times(2);

                // expect to send buying rejected event to all recipients (except payer)
                transport
                    .expect_send_private_event()
                    .withf(|_, _, e| check_chain_payload(e, BillEventType::BillBuyingRejected))
                    .returning(|_, _, _| Ok(()))
                    .times(2);

                // expect to send recourse rejected event to all recipients (except payer)
                transport
                    .expect_send_private_event()
                    .withf(|_, _, e| check_chain_payload(e, BillEventType::BillRecourseRejected))
                    .returning(|_, _, _| Ok(()))
                    .times(2);

                block_transport
                    .expect_send_bill_chain_events()
                    .returning(|_| Ok(()))
                    .times(4);

                notification_transport
                    .expect_send_email_notification()
                    .returning(|_, _, _| ())
                    .times(4);

                // this is only required for the test as it contains an invite block so it tries to send an
                // invite to new participants as well and the test data doesn't have them all.
                transport
                    .expect_send_private_event()
                    .withf(|_, _, e| e.event_type == EventType::BillChainInvite)
                    .returning(|_, _, _| Ok(()));
            },
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
        let timestamp = Timestamp::now();
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_offer_to_sell(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillOfferToSellBlockData {
                seller: BillParticipantBlockData::Ident(payee.clone().into()),
                buyer: BillParticipantBlockData::Ident(buyer.clone().into()),
                sum: Sum::new_sat(100).expect("sat works"),
                signatory: None,
                payment_address: valid_payment_address_testnet(),
                signing_timestamp: timestamp,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
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
            &BcrKeys::from_private_key(&private_key_test()),
            true,
            &node_id_test(),
        )
        .unwrap();

        let (service, _) = expect_service(|mock, mock_contact_store, _, _, _, _, _, _| {
            // no participant should receive events
            mock_contact_store.expect_get().never();

            // expect to not send rejected event for non rejectable actions
            mock.expect_send_private_event().never();
        });

        service
            .send_request_to_action_rejected_event(&event, ActionType::CheckBill)
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
            mint_url: None,
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
        let timestamp = Timestamp::now();
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_offer_to_sell(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillOfferToSellBlockData {
                seller: BillParticipantBlockData::Ident(payee.clone().into()),
                buyer: BillParticipantBlockData::Ident(buyer.clone().into()),
                sum: Sum::new_sat(100).expect("sat works"),
                signatory: None,
                payment_address: valid_payment_address_testnet(),
                signing_timestamp: timestamp,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
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
            &BcrKeys::from_private_key(&private_key_test()),
            true,
            &node_id_test(),
        )
        .unwrap();

        let (service, _) = expect_service(
            |mock, mock_contact_store, _, _, _, notification_transport, _, block_transport| {
                let buyer = buyer.clone();
                let payer = payer.clone();
                let payee = payee.clone();
                // participants should receive events
                mock_contact_store
                    .expect_get()
                    .returning(move |_| Ok(Some(as_contact(&buyer))));
                mock_contact_store
                    .expect_get()
                    .returning(move |_| Ok(Some(as_contact(&payee))));
                mock_contact_store
                    .expect_get()
                    .returning(move |_| Ok(Some(as_contact(&payer))));

                // expect to send payment recourse event to recoursee only
                mock.expect_send_private_event()
                    .withf(|_, _, e| check_chain_payload(e, BillEventType::BillPaymentRecourse))
                    .returning(|_, _, _| Ok(()))
                    .times(1);

                // expect to send acceptance recourse event to recoursee only
                mock.expect_send_private_event()
                    .withf(|_, _, e| check_chain_payload(e, BillEventType::BillAcceptanceRecourse))
                    .returning(|_, _, _| Ok(()))
                    .times(1);

                block_transport
                    .expect_send_bill_chain_events()
                    .returning(|_| Ok(()))
                    .times(2);

                notification_transport
                    .expect_send_email_notification()
                    .returning(|_, _, _| ())
                    .times(2);

                mock.expect_send_private_event()
                    .withf(move |_, _, e| {
                        let r: bcr_ebill_core::protocol::Result<Event<ChainInvite>> =
                            e.clone().try_into();
                        r.is_ok()
                    })
                    .returning(|_, _, _| Ok(()));
            },
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
        let timestamp = Timestamp::now();
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_offer_to_sell(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillOfferToSellBlockData {
                seller: BillParticipantBlockData::Ident(payee.clone().into()),
                buyer: BillParticipantBlockData::Ident(buyer.clone().into()),
                sum: Sum::new_sat(100).expect("sat works"),
                signatory: None,
                payment_address: valid_payment_address_testnet(),
                signing_timestamp: timestamp,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
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
            &BcrKeys::from_private_key(&private_key_test()),
            true,
            &node_id_test(),
        )
        .unwrap();

        let (service, _) = expect_service(|mock, _, _, _, _, _, _, _| {
            // expect not to send non recourse event
            mock.expect_send_private_event().never();
        });

        service
            .send_recourse_action_event(&event, ActionType::CheckBill, &payer)
            .await
            .expect("failed to send event");
    }

    fn setup_chain_expectation(
        participants: Vec<(BillIdentParticipant, BillEventType, Option<ActionType>)>,
        bill: &BitcreditBill,
        chain: &BillBlockchain,
        new_blocks: bool,
        mock_contact_store: &mut MockContactStore,
        mock: &mut MockNotificationJsonTransport,
        mock_block_transport: &mut MockBlockTransportService,
        mock_notification_transport: &mut MockNotificationTransportService,
    ) -> BillChainEvent {
        mock_notification_transport
            .expect_send_email_notification()
            .returning(|_, _, _| ());

        for p in participants.into_iter() {
            let clone1 = p.clone();
            mock_contact_store
                .expect_get()
                .with(eq(clone1.0.node_id.clone()))
                .returning(move |_| Ok(Some(as_contact(&clone1.0))));

            let clone2 = p.clone();
            mock.expect_send_private_event()
                .withf(move |_, r, e| {
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
                .returning(|_, _, _| Ok(()));

            mock.expect_send_private_event()
                .withf(move |_, _, e| {
                    let r: bcr_ebill_core::protocol::Result<Event<ChainInvite>> =
                        e.clone().try_into();
                    r.is_ok()
                })
                .returning(|_, _, _| Ok(()));
        }
        mock_block_transport
            .expect_send_bill_chain_events()
            .returning(|_| Ok(()))
            .once();

        BillChainEvent::new(
            bill,
            chain,
            &BcrKeys::from_private_key(&private_key_test()),
            new_blocks,
            &node_id_test(),
        )
        .unwrap()
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
        let (service, event) = expect_service(
            |mock, mock_contact_store, _, _, _, notification_transport, _, block_transport| {
                let payer = payer.clone();
                let payee = payee.clone();
                setup_chain_expectation(
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
                    mock_contact_store,
                    mock,
                    block_transport,
                    notification_transport,
                )
            },
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
        let timestamp = Timestamp::now();
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_accept(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillAcceptBlockData {
                accepter: payer.clone().into(),
                signatory: None,
                signing_timestamp: timestamp,
                signing_address: empty_address(),
                signer_identity_proof: signed_identity_proof_test().into(),
            },
            &keys,
            None,
            &keys,
            timestamp,
        )
        .unwrap();

        chain.try_add_block(block);

        let (service, event) = expect_service(
            |mock, mock_contact_store, _, _, _, notification_transport, _, block_transport| {
                let payer = payer.clone();
                let payee = payee.clone();
                setup_chain_expectation(
                    vec![
                        (
                            payee,
                            BillEventType::BillAccepted,
                            Some(ActionType::CheckBill),
                        ),
                        (
                            payer,
                            BillEventType::BillAccepted,
                            Some(ActionType::CheckBill),
                        ),
                    ],
                    &bill,
                    &chain,
                    true,
                    mock_contact_store,
                    mock,
                    block_transport,
                    notification_transport,
                )
            },
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
        let timestamp = Timestamp::now();
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_request_to_accept(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payee.clone().into()),
                signatory: None,
                signing_timestamp: timestamp,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: timestamp + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &keys,
            None,
            &keys,
            timestamp,
        )
        .unwrap();

        chain.try_add_block(block);

        let (service, event) = expect_service(
            |mock, mock_contact_store, _, _, _, notification_transport, _, block_transport| {
                let payer = payer.clone();
                let payee = payee.clone();
                setup_chain_expectation(
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
                    mock_contact_store,
                    mock,
                    block_transport,
                    notification_transport,
                )
            },
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
        let timestamp = Timestamp::now();
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
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                payment_deadline_timestamp: timestamp + 2 * PAYMENT_DEADLINE_SECONDS,
            },
            &keys,
            None,
            &keys,
            timestamp,
        )
        .unwrap();

        chain.try_add_block(block);

        let (service, event) = expect_service(
            |mock, mock_contact_store, _, _, _, notification_transport, _, block_transport| {
                let payer = payer.clone();
                let payee = payee.clone();
                setup_chain_expectation(
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
                    mock_contact_store,
                    mock,
                    block_transport,
                    notification_transport,
                )
            },
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
        let (service, event) = expect_service(
            |mock, mock_contact_store, _, _, _, notification_transport, _, block_transport| {
                let payer = payer.clone();
                let payee = payee.clone();
                setup_chain_expectation(
                    vec![
                        (payee, BillEventType::BillPaid, Some(ActionType::CheckBill)),
                        (payer, BillEventType::BillPaid, Some(ActionType::CheckBill)),
                    ],
                    &bill,
                    &chain,
                    false,
                    mock_contact_store,
                    mock,
                    block_transport,
                    notification_transport,
                )
            },
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

        let (service, event) = expect_service(
            |mock, mock_contact_store, _, _, _, notification_transport, _, block_transport| {
                let payer = payer.clone();
                let payee = payee.clone();
                let endorsee = endorsee.clone();
                setup_chain_expectation(
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
                    mock_contact_store,
                    mock,
                    block_transport,
                    notification_transport,
                )
            },
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
        let timestamp = Timestamp::now();
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_offer_to_sell(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillOfferToSellBlockData {
                seller: BillParticipantBlockData::Ident(payee.clone().into()),
                buyer: BillParticipantBlockData::Ident(buyer.clone().into()),
                sum: Sum::new_sat(100).expect("sat works"),
                signatory: None,
                payment_address: valid_payment_address_testnet(),
                signing_timestamp: timestamp,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                buying_deadline_timestamp: timestamp + 2 * DAY_IN_SECS,
            },
            &keys,
            None,
            &keys,
            timestamp,
        )
        .unwrap();

        chain.try_add_block(block);

        let (service, event) = expect_service(
            |mock, mock_contact_store, _, _, _, notification_transport, _, block_transport| {
                let payer = payer.clone();
                let payee = payee.clone();
                setup_chain_expectation(
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
                    mock_contact_store,
                    mock,
                    block_transport,
                    notification_transport,
                )
            },
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
        let timestamp = Timestamp::now();
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_offer_to_sell(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillOfferToSellBlockData {
                seller: BillParticipantBlockData::Ident(payee.clone().into()),
                buyer: BillParticipantBlockData::Ident(buyer.clone().into()),
                sum: Sum::new_sat(100).expect("sat works"),
                signatory: None,
                payment_address: valid_payment_address_testnet(),
                signing_timestamp: timestamp,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                buying_deadline_timestamp: timestamp + 2 * DAY_IN_SECS,
            },
            &keys,
            None,
            &keys,
            timestamp,
        )
        .unwrap();

        chain.try_add_block(block);

        let (service, event) = expect_service(
            |mock, mock_contact_store, _, _, _, notification_transport, _, block_transport| {
                let payee = payee.clone();
                setup_chain_expectation(
                    vec![
                        (
                            payee.clone(),
                            BillEventType::BillSold,
                            Some(ActionType::CheckBill),
                        ),
                        (
                            buyer.clone(),
                            BillEventType::BillSold,
                            Some(ActionType::CheckBill),
                        ),
                    ],
                    &bill,
                    &chain,
                    true,
                    mock_contact_store,
                    mock,
                    block_transport,
                    notification_transport,
                )
            },
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
        let timestamp = Timestamp::now();
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
                signer_identity_proof: Some(signed_identity_proof_test().into()),
            },
            &keys,
            None,
            &keys,
            timestamp,
        )
        .unwrap();

        chain.try_add_block(block);

        let (service, event) = expect_service(
            |mock, mock_contact_store, _, _, _, notification_transport, _, block_transport| {
                let payer = payer.clone();
                let payee = payee.clone();
                setup_chain_expectation(
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
                    mock_contact_store,
                    mock,
                    block_transport,
                    notification_transport,
                )
            },
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
        let timestamp = Timestamp::now();
        let keys = get_baseline_identity().key_pair;
        let block = BillBlock::create_block_for_accept(
            bill.id.to_owned(),
            chain.get_latest_block(),
            &BillAcceptBlockData {
                accepter: payer.clone().into(),
                signatory: None,
                signing_timestamp: timestamp,
                signing_address: empty_address(),
                signer_identity_proof: signed_identity_proof_test().into(),
            },
            &keys,
            None,
            &keys,
            timestamp,
        )
        .unwrap();

        chain.try_add_block(block);

        let (service, _) = expect_service(|mock, _, _, _, _, notification_transport, _, _| {
            mock.expect_send_private_event()
                .returning(|_, _, _| Ok(()))
                .once();
            notification_transport
                .expect_send_email_notification()
                .returning(|_, _, _| ());
        });

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
    async fn test_send_retry_messages_success() {
        init_test_cfg();

        let (service, _) = expect_service(
            |mock_transport, mock_contact_store, _, mock_queue, _, _, _, _| {
                let node_id = node_id_test_other();
                let message_id = "test_message_id";
                let sender_id = node_id_test();
                let payload = base58::encode(
                    &borsh::to_vec(&EventEnvelope {
                        version: "1.0".to_string(),
                        event_type: EventType::Bill,
                        data: vec![],
                    })
                    .unwrap(),
                );
                let queued_message = NostrQueuedMessage {
                    id: message_id.to_string(),
                    sender_id: sender_id.to_owned(),
                    node_id: node_id.to_owned(),
                    payload: payload.clone(),
                };

                let identity = get_identity_public_data(
                    &node_id,
                    &Email::new("test@example.com").unwrap(),
                    vec![],
                );

                mock_contact_store
                    .expect_get()
                    .returning(move |_| Ok(Some(as_contact(&identity))));

                mock_transport
                    .expect_send_private_event()
                    .returning(|_, _, _| Ok(()));

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
            },
        );

        let result = service.send_retry_messages().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_retry_messages_with_send_failure() {
        init_test_cfg();

        let (service, _) = expect_service(
            |mock_transport, mock_contact_store, _, mock_queue, _, _, _, _| {
                let node_id = node_id_test_other();
                let message_id = "test_message_id";
                let sender_id = node_id_test();
                let payload = base58::encode(
                    &borsh::to_vec(&EventEnvelope {
                        version: "1.0".to_string(),
                        event_type: EventType::Bill,
                        data: vec![],
                    })
                    .unwrap(),
                );

                let queued_message = NostrQueuedMessage {
                    id: message_id.to_string(),
                    sender_id: sender_id.to_owned(),
                    node_id: node_id.to_owned(),
                    payload: payload.clone(),
                };

                let identity = get_identity_public_data(
                    &node_id,
                    &Email::new("test@example.com").unwrap(),
                    vec![],
                );

                // Set up mocks
                mock_contact_store
                    .expect_get()
                    .returning(move |_| Ok(Some(as_contact(&identity))));

                mock_transport
                    .expect_send_private_event()
                    .returning(|_, _, _| Err(Error::Network("Failed to send".to_string())));

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
            },
        );
        let result = service.send_retry_messages().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_retry_messages_with_multiple_messages() {
        init_test_cfg();

        let (service, _) = expect_service(
            |mock_transport, mock_contact_store, _, mock_queue, _, _, _, _| {
                let node_id1 = node_id_test_other();
                let sender_id = node_id_test();
                let node_id2 = node_id_test_other2();
                let message_id1 = "test_message_id_1";
                let message_id2 = "test_message_id_2";

                let payload1 = base58::encode(
                    &borsh::to_vec(&EventEnvelope {
                        version: "1.0".to_string(),
                        event_type: EventType::Bill,
                        data: vec![],
                    })
                    .unwrap(),
                );

                let payload2 = base58::encode(
                    &borsh::to_vec(&EventEnvelope {
                        version: "1.0".to_string(),
                        event_type: EventType::Bill,
                        data: vec![],
                    })
                    .unwrap(),
                );

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

                let identity1 = get_identity_public_data(
                    &node_id1,
                    &Email::new("test1@example.com").unwrap(),
                    vec![],
                );
                let identity2 = get_identity_public_data(
                    &node_id2,
                    &Email::new("test2@example.com").unwrap(),
                    vec![],
                );

                mock_contact_store
                    .expect_get()
                    .returning(move |_| Ok(Some(as_contact(&identity1))));
                mock_contact_store
                    .expect_get()
                    .returning(move |_| Ok(Some(as_contact(&identity2))));

                // First message succeeds, second fails
                mock_transport
                    .expect_send_private_event()
                    .returning(|_, _, _| Ok(()))
                    .times(1);
                mock_transport
                    .expect_send_private_event()
                    .returning(|_, _, _| Err(Error::Network("Failed to send".to_string())))
                    .times(1);

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
            },
        );

        let result = service.send_retry_messages().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_retry_messages_with_invalid_payload() {
        init_test_cfg();

        let (service, _) = expect_service(|_, _, _, mock_queue, _, _, _, _| {
            let node_id = node_id_test_other();
            let message_id = "test_message_id";
            let sender = node_id_test();
            // Invalid payload that can't be deserialized to EventEnvelope
            let invalid_payload = base58::encode(&borsh::to_vec(&"invalid data").unwrap());

            let queued_message = NostrQueuedMessage {
                id: message_id.to_string(),
                sender_id: sender.to_owned(),
                node_id: node_id.to_owned(),
                payload: invalid_payload,
            };

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
        });

        let result = service.send_retry_messages().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_retry_messages_with_fail_retry_error() {
        init_test_cfg();

        let (service, _) = expect_service(
            |mock_transport, mock_contact_store, _, mock_queue, _, _, _, _| {
                let node_id = node_id_test_other();
                let message_id = "test_message_id";
                let sender = node_id_test();
                let payload = base58::encode(
                    &borsh::to_vec(&EventEnvelope {
                        version: "1.0".to_string(),
                        event_type: EventType::Bill,
                        data: vec![],
                    })
                    .unwrap(),
                );

                let queued_message = NostrQueuedMessage {
                    id: message_id.to_string(),
                    sender_id: sender.to_owned(),
                    node_id: node_id.to_owned(),
                    payload: payload.clone(),
                };

                let identity = get_identity_public_data(
                    &node_id,
                    &Email::new("test@example.com").unwrap(),
                    vec![],
                );

                mock_contact_store
                    .expect_get()
                    .returning(move |_| Ok(Some(as_contact(&identity))));
                mock_transport
                    .expect_send_private_event()
                    .returning(|_, _, _| Err(Error::Network("Failed to send".to_string())));

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
            },
        );

        let result = service.send_retry_messages().await;
        assert!(result.is_ok()); // Should still return Ok despite the internal error
    }

    #[tokio::test]
    async fn test_send_retry_messages_with_succeed_retry_error() {
        init_test_cfg();

        let (service, _) = expect_service(
            |mock_transport, mock_contact_store, _, mock_queue, _, _, _, _| {
                let node_id = node_id_test_other();
                let message_id = "test_message_id";
                let sender = node_id_test();
                let payload = base58::encode(
                    &borsh::to_vec(&EventEnvelope {
                        version: "1.0".to_string(),
                        event_type: EventType::Bill,
                        data: vec![],
                    })
                    .unwrap(),
                );

                let queued_message = NostrQueuedMessage {
                    id: message_id.to_string(),
                    sender_id: sender.to_owned(),
                    node_id: node_id.to_owned(),
                    payload: payload.clone(),
                };

                let identity = get_identity_public_data(
                    &node_id,
                    &Email::new("test@example.com").unwrap(),
                    vec![],
                );

                mock_contact_store
                    .expect_get()
                    .returning(move |_| Ok(Some(as_contact(&identity))));

                mock_transport
                    .expect_send_private_event()
                    .returning(|_, _, _| Ok(()));

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
            },
        );

        let result = service.send_retry_messages().await;
        assert!(result.is_ok()); // Should still return Ok despite the internal error
    }

    #[tokio::test]
    async fn test_send_retry_messages_with_no_messages() {
        init_test_cfg();

        let (service, _) = expect_service(|_, _, _, mock_queue, _, _, _, _| {
            mock_queue
                .expect_get_retry_messages()
                .returning(|_| Ok(vec![]))
                .times(1);
        });

        let result = service.send_retry_messages().await;
        assert!(result.is_ok());
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

        let (service, _) = expect_service(
            |mock,
             mock_contact_store,
             _,
             queue_mock,
             _,
             notification_transport,
             _,
             block_transport| {
                let payer = payer.clone();
                let payee = payee.clone();

                // sending the block events succeeds
                block_transport
                    .expect_send_bill_chain_events()
                    .returning(|_| Ok(()))
                    .once();

                mock_contact_store
                    .expect_get()
                    .returning(move |_| Ok(Some(as_contact(&payer))));

                mock_contact_store
                    .expect_get()
                    .returning(move |_| Ok(Some(as_contact(&payee))));

                // one dm succeeds
                mock.expect_send_private_event()
                    .returning(|_, _, _| Ok(()))
                    .once();

                // now a chain invite should be sent but fails
                mock.expect_send_private_event()
                    .withf(move |_, _, e| {
                        let r: bcr_ebill_core::protocol::Result<Event<ChainInvite>> =
                            e.clone().try_into();
                        r.is_err()
                    })
                    .returning(|_, _, _| Err(Error::Network("Failed to send".to_string())));

                queue_mock
                    .expect_add_message()
                    .returning(|_, _| Ok(()))
                    .once();

                notification_transport
                    .expect_send_email_notification()
                    .returning(|_, _, _| ())
                    .once();
            },
        );

        let event = BillChainEvent::new(
            &bill,
            &chain,
            &BcrKeys::from_private_key(&private_key_test()),
            true,
            &node_id_test(),
        )
        .unwrap();

        service
            .send_bill_is_signed_event(&event)
            .await
            .expect("failed to send event");
    }
}
