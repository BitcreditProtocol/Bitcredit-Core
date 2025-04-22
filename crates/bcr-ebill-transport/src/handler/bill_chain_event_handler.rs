use super::NotificationHandlerApi;
use crate::BillChainEventPayload;
use crate::EventType;
use crate::{Error, Event, EventEnvelope, PushApi, Result};
use async_trait::async_trait;
use bcr_ebill_core::ServiceTraitBounds;
use bcr_ebill_core::Validate;
use bcr_ebill_core::bill::BillKeys;
use bcr_ebill_core::bill::BillValidateActionData;
use bcr_ebill_core::blockchain::Blockchain;
use bcr_ebill_core::blockchain::bill::BillOpCode;
use bcr_ebill_core::blockchain::bill::block::BillIssueBlockData;
use bcr_ebill_core::blockchain::bill::block::NodeId;
use bcr_ebill_core::blockchain::bill::{BillBlock, BillBlockchain};
use bcr_ebill_core::notification::BillEventType;
use bcr_ebill_core::notification::{Notification, NotificationType};
use bcr_ebill_persistence::NotificationStoreApi;
use bcr_ebill_persistence::bill::BillChainStoreApi;
use bcr_ebill_persistence::bill::BillStoreApi;
use log::debug;
use log::error;
use log::info;
use log::warn;
use std::sync::Arc;

#[derive(Clone)]
pub struct BillChainEventHandler {
    notification_store: Arc<dyn NotificationStoreApi>,
    push_service: Arc<dyn PushApi>,
    bill_blockchain_store: Arc<dyn BillChainStoreApi>,
    bill_store: Arc<dyn BillStoreApi>,
}

impl BillChainEventHandler {
    pub fn new(
        notification_store: Arc<dyn NotificationStoreApi>,
        push_service: Arc<dyn PushApi>,
        bill_blockchain_store: Arc<dyn BillChainStoreApi>,
        bill_store: Arc<dyn BillStoreApi>,
    ) -> Self {
        Self {
            notification_store,
            push_service,
            bill_blockchain_store,
            bill_store,
        }
    }

    async fn create_notification(
        &self,
        event: &BillChainEventPayload,
        node_id: &str,
    ) -> Result<()> {
        debug!("creating notification {event:?} for {node_id}");
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
                debug!("sending notification {notification:?} for {node_id}");
                self.push_service.send(notification).await;
            }
            Err(e) => {
                error!("Failed to serialize notification for push service: {}", e);
            }
        }
        Ok(())
    }

    async fn process_chain_data(
        &self,
        bill_id: &str,
        blocks: Vec<BillBlock>,
        keys: Option<BillKeys>,
    ) -> Result<()> {
        if let Ok(existing_chain) = self.bill_blockchain_store.get_chain(bill_id).await {
            self.add_bill_blocks(bill_id, existing_chain, blocks).await
        } else {
            match keys {
                Some(keys) => self.add_new_chain(blocks, &keys).await,
                _ => {
                    error!("Received bill blocks for unknown bill {bill_id}");
                    Err(Error::Blockchain(
                        "Received bill blocks for unknown bill".to_string(),
                    ))
                }
            }
        }
    }

    async fn add_bill_blocks(
        &self,
        bill_id: &str,
        existing: BillBlockchain,
        blocks: Vec<BillBlock>,
    ) -> Result<()> {
        let mut block_added = false;
        let mut chain = existing;
        let bill_keys = self.bill_store.get_keys(bill_id).await.map_err(|e| {
            error!("Could not process received blocks for {bill_id} because the bill keys could not be fetched");
            Error::Persistence(e.to_string())
        })?;
        let is_paid = self.bill_store.is_paid(bill_id).await.map_err(|e| {
            error!("Could not process received blocks for bill {bill_id} because getting paid status failed");
            Error::Persistence(e.to_string())
        })?;
        let bill_first_version = chain.get_first_version_bill(&bill_keys).map_err(|e| {
            error!("Could not process received blocks for bill {bill_id} because getting first version bill data failed");
            Error::Blockchain(e.to_string())
        })?;
        debug!("adding {} bill blocks for bill {bill_id}", blocks.len());
        for block in blocks {
            block_added = self
                .validate_and_save_block(
                    bill_id,
                    &mut chain,
                    &bill_first_version,
                    &bill_keys,
                    block,
                    is_paid,
                )
                .await?;
        }
        // if the bill was changed, we invalidate the cache
        if block_added {
            debug!("block was added for bill {bill_id} - invalidating cache");
            if let Err(e) = self.invalidate_cache_for_bill(bill_id).await {
                error!("Error invalidating cache for bill {bill_id}: {e}");
            }
        }
        Ok(())
    }

    async fn validate_and_save_block(
        &self,
        bill_id: &str,
        chain: &mut BillBlockchain,
        bill_first_version: &BillIssueBlockData,
        bill_keys: &BillKeys,
        block: BillBlock,
        is_paid: bool,
    ) -> Result<bool> {
        let block_height = chain.get_latest_block().id;
        let block_id = block.id;
        // if we already have the block, we skip it
        if block.id <= block_height {
            info!("Skipping block with id {block_id} for {bill_id} as we already have it");
            return Ok(false);
        }
        if block.op_code == BillOpCode::Issue {
            info!(
                "Skipping block {block_id} with op code Issue for {bill_id} as we already have the chain"
            );
            return Ok(false);
        }
        // create a clone of the chain for validating the bill action later, since the chain
        // will be mutated with the integrity checks
        let chain_clone_for_validation = chain.clone();
        // first, do cheap integrity checks
        if !chain.try_add_block(block.clone()) {
            error!("Received invalid block {block_id} for bill {bill_id}");
            return Err(Error::Blockchain(
                "Received invalid block for bill".to_string(),
            ));
        }
        // then, verify signature and signer of the block and get signer and bill action for
        // the block
        let (signer, bill_action) = match block.verify_and_get_signer(bill_keys) {
            Ok(signer) => signer,
            Err(e) => {
                error!(
                    "Received invalid block {block_id} for bill {bill_id} - could not verify signature from block data signer"
                );
                return Err(Error::Blockchain(e.to_string()));
            }
        };

        // then, validate the bill action
        let bill_parties = chain_clone_for_validation
            .get_bill_parties(bill_keys, bill_first_version)
            .map_err(|e| {
                error!("Received invalid block {block_id} for bill {bill_id}: {e}");
                Error::Blockchain(
                    "Received invalid block for bill - couldn't get bill parties".to_string(),
                )
            })?;
        if let Err(e) = (BillValidateActionData {
            blockchain: chain_clone_for_validation,
            drawee_node_id: bill_parties.drawee.node_id,
            payee_node_id: bill_parties.payee.node_id(),
            endorsee_node_id: bill_parties.endorsee.map(|e| e.node_id()),
            maturity_date: bill_first_version.maturity_date.clone(),
            bill_keys: bill_keys.clone(),
            timestamp: block.timestamp,
            signer_node_id: signer,
            bill_action: bill_action.ok_or_else(|| {
                error!(
                    "Received invalid block {block_id} for bill {bill_id} - no valid bill action returned"
                );
                Error::Blockchain(
                    "Received invalid block for bill - no valid bill action returned"
                    .to_string(),
                )
            })?,
            is_paid,
        }).validate()
        {
            error!(
                "Received invalid block {block_id} for bill {bill_id}, bill action validation failed: {e}"
            );
            return Err(Error::Blockchain(e.to_string()));
        }
        // if everything works out - add the block
        self.save_block(bill_id, &block).await?;
        Ok(true) // block was added
    }

    async fn add_new_chain(&self, blocks: Vec<BillBlock>, keys: &BillKeys) -> Result<()> {
        let (bill_id, bill_first_version, chain) = self.get_valid_chain(blocks, keys)?;
        debug!("adding new chain for bill {bill_id}");
        // issue block was validate in get_valid_chain
        let issue_block = chain.get_first_block().to_owned();
        // create a chain that starts from issue, to simulate adding blocks and validating them
        let mut chain_starting_at_issue =
            match BillBlockchain::new_from_blocks(vec![issue_block.clone()]) {
                Ok(chain) => chain,
                Err(e) => {
                    error!("Newly received chain is not valid: {e}");
                    return Err(Error::Blockchain(
                        "Newly received chain is not valid".to_string(),
                    ));
                }
            };
        self.save_block(&bill_id, &issue_block).await?;

        // Only add other blocks, if there are any
        if chain.block_height() > 1 {
            let blocks = chain.blocks()[1..].to_vec();
            for block in blocks {
                self.validate_and_save_block(
                    &bill_id,
                    &mut chain_starting_at_issue,
                    &bill_first_version,
                    keys,
                    block,
                    false, // new chain, we don't know if it's paid
                )
                .await?;
            }
        }
        self.save_keys(&bill_id, keys).await?;
        Ok(())
    }

    fn get_valid_chain(
        &self,
        blocks: Vec<BillBlock>,
        keys: &BillKeys,
    ) -> Result<(String, BillIssueBlockData, BillBlockchain)> {
        // cheap integrity checks first
        match BillBlockchain::new_from_blocks(blocks) {
            Ok(chain) if chain.is_chain_valid() => {
                // make sure first block is of type Issue
                if chain.get_first_block().op_code != BillOpCode::Issue {
                    error!("Newly received chain is not valid - first block is not an Issue block");
                    return Err(Error::Blockchain(
                        "Newly received chain is not valid - first block is not an Issue block"
                            .to_string(),
                    ));
                }
                match chain.get_first_version_bill(keys) {
                    Ok(bill) => {
                        // then, verify signature and signer of each block and get signer
                        for block in chain.blocks().iter() {
                            let _signer = match block.verify_and_get_signer(keys) {
                                Ok(signer) => signer,
                                Err(e) => {
                                    error!(
                                        "Received invalid block for bill {} - could not verify signature from block data signer",
                                        &bill.id
                                    );
                                    return Err(Error::Blockchain(e.to_string()));
                                }
                            };
                        }
                        Ok((bill.id.clone(), bill, chain))
                    }
                    Err(e) => {
                        error!(
                            "Failed to get first version bill from newly received chain: {}",
                            e
                        );
                        Err(Error::Crypto(format!(
                            "Failed to decrypt new bill chain with given keys: {e}"
                        )))
                    }
                }
            }
            _ => {
                error!("Newly received chain is not valid");
                Err(Error::Blockchain(
                    "Newly received chain is not valid".to_string(),
                ))
            }
        }
    }

    async fn save_block(&self, bill_id: &str, block: &BillBlock) -> Result<()> {
        if let Err(e) = self.bill_blockchain_store.add_block(bill_id, block).await {
            error!("Failed to add block to blockchain store: {}", e);
            return Err(Error::Persistence(
                "Failed to add block to blockchain store".to_string(),
            ));
        }
        Ok(())
    }

    async fn invalidate_cache_for_bill(&self, bill_id: &str) -> Result<()> {
        if let Err(e) = self.bill_store.invalidate_bill_in_cache(bill_id).await {
            error!("Failed to invalidate cache for bill {bill_id}: {}", e);
            return Err(Error::Persistence(
                "Failed to invalidate cache for bill".to_string(),
            ));
        }
        Ok(())
    }

    async fn save_keys(&self, bill_id: &str, keys: &BillKeys) -> Result<()> {
        if let Err(e) = self.bill_store.save_keys(bill_id, keys).await {
            error!("Failed to save keys to bill store: {}", e);
            return Err(Error::Persistence(
                "Failed to save keys to bill store".to_string(),
            ));
        }
        Ok(())
    }
}

impl ServiceTraitBounds for BillChainEventHandler {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationHandlerApi for BillChainEventHandler {
    fn handles_event(&self, event_type: &EventType) -> bool {
        event_type == &EventType::Bill
    }

    async fn handle_event(&self, event: EventEnvelope, node_id: &str) -> Result<()> {
        debug!("incoming bill chain event {event:?} for {node_id}");
        if let Ok(decoded) = Event::<BillChainEventPayload>::try_from(event.clone()) {
            if !decoded.data.blocks.is_empty() {
                if let Err(e) = self
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
        BillEventType::BillMintingRequested => "bill_minted".to_string(),
        BillEventType::BillNewQuote => "new_quote".to_string(),
        BillEventType::BillQuoteApproved => "quote_approved".to_string(),
        BillEventType::BillBlock => "".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use bcr_ebill_core::{
        OptionalPostalAddress, PostalAddress,
        bill::BitcreditBill,
        blockchain::bill::block::{
            BillEndorseBlockData, BillIssueBlockData, BillParticipantBlockData, BillRejectBlockData,
        },
        contact::{BillIdentParticipant, BillParticipant, ContactType},
        identity::{Identity, IdentityWithAll},
        notification::ActionType,
        util::BcrKeys,
    };
    use mockall::predicate::{always, eq};

    use crate::handler::test_utils::{
        MockBillChainStore, MockBillStore, MockNotificationStore, MockPushService,
    };

    use super::*;

    #[tokio::test]
    async fn test_create_event_handler() {
        let (notification_store, push_service, bill_chain_store, bill_store) = create_mocks();
        BillChainEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
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

        let (notification_store, push_service, mut bill_chain_store, mut bill_store) =
            create_mocks();

        bill_chain_store
            .expect_get_chain()
            .with(eq(TEST_BILL_ID))
            .times(1)
            .returning(move |_| Err(bcr_ebill_persistence::Error::NoBillBlock));
        bill_chain_store
            .expect_add_block()
            .with(eq(TEST_BILL_ID), eq(chain.blocks()[0].clone()))
            .times(1)
            .returning(move |_, _| Ok(()));

        bill_store
            .expect_save_keys()
            .with(eq(TEST_BILL_ID), always())
            .times(1)
            .returning(move |_, _| Ok(()));

        let handler = BillChainEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
        );
        let event = Event::new(
            EventType::Bill,
            "node_id",
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
            .handle_event(event.try_into().expect("Envelope from event"), "node_id")
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

        let (notification_store, push_service, mut bill_chain_store, mut bill_store) =
            create_mocks();

        bill_chain_store
            .expect_get_chain()
            .with(eq(TEST_BILL_ID))
            .times(1)
            .returning(move |_| Err(bcr_ebill_persistence::Error::NoBillBlock));
        // should persist the issue block, but fail the second block
        bill_chain_store
            .expect_add_block()
            .with(eq(TEST_BILL_ID), eq(chain.blocks()[0].clone()))
            .times(1)
            .returning(move |_, _| Ok(()));

        bill_store
            .expect_save_keys()
            .with(eq(TEST_BILL_ID), always())
            .never();

        let handler = BillChainEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
        );
        let event = Event::new(
            EventType::Bill,
            "node_id",
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
            .handle_event(event.try_into().expect("Envelope from event"), "node_id")
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

        let (notification_store, push_service, mut bill_chain_store, mut bill_store) =
            create_mocks();

        bill_chain_store
            .expect_get_chain()
            .with(eq(TEST_BILL_ID))
            .times(1)
            .returning(move |_| Err(bcr_ebill_persistence::Error::NoBillBlock));
        bill_chain_store
            .expect_add_block()
            .with(eq(TEST_BILL_ID), eq(chain.blocks()[0].clone()))
            .never();

        bill_store
            .expect_save_keys()
            .with(eq(TEST_BILL_ID), always())
            .never();

        let handler = BillChainEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
        );
        let event = Event::new(
            EventType::Bill,
            "node_id",
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
            .handle_event(event.try_into().expect("Envelope from event"), "node_id")
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

        let (notification_store, push_service, mut bill_chain_store, mut bill_store) =
            create_mocks();

        let chain_clone = chain.clone();
        bill_store
            .expect_invalidate_bill_in_cache()
            .returning(|_| Ok(()));
        bill_store.expect_is_paid().returning(|_| Ok(false));
        bill_store.expect_get_keys().returning(|_| {
            Ok(BillKeys {
                private_key: TEST_PRIVATE_KEY_SECP.to_owned(),
                public_key: TEST_PUB_KEY_SECP.to_owned(),
            })
        });
        bill_chain_store
            .expect_get_chain()
            .with(eq(TEST_BILL_ID))
            .times(1)
            .returning(move |_| Ok(chain_clone.clone()));

        bill_chain_store
            .expect_add_block()
            .with(eq(TEST_BILL_ID), eq(block.clone()))
            .times(1)
            .returning(move |_, _| Ok(()));

        let handler = BillChainEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
        );
        let event = Event::new(
            EventType::Bill,
            "node_id",
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
            .handle_event(event.try_into().expect("Envelope from event"), "node_id")
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

        let (notification_store, push_service, mut bill_chain_store, mut bill_store) =
            create_mocks();

        let chain_clone = chain.clone();
        bill_store.expect_get_keys().returning(|_| {
            Ok(BillKeys {
                private_key: TEST_PRIVATE_KEY_SECP.to_owned(),
                public_key: TEST_PUB_KEY_SECP.to_owned(),
            })
        });

        bill_store.expect_is_paid().returning(|_| Ok(false));
        bill_chain_store
            .expect_get_chain()
            .with(eq(TEST_BILL_ID))
            .times(1)
            .returning(move |_| Ok(chain_clone.clone()));

        // block is not added
        bill_chain_store.expect_add_block().never();

        let handler = BillChainEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
        );
        let event = Event::new(
            EventType::Bill,
            "node_id",
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
            .handle_event(event.try_into().expect("Envelope from event"), "node_id")
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

        let (notification_store, push_service, mut bill_chain_store, mut bill_store) =
            create_mocks();

        let chain_clone = chain.clone();
        bill_store.expect_get_keys().returning(|_| {
            Ok(BillKeys {
                private_key: TEST_PRIVATE_KEY_SECP.to_owned(),
                public_key: TEST_PUB_KEY_SECP.to_owned(),
            })
        });

        bill_store.expect_is_paid().returning(|_| Ok(false));
        bill_chain_store
            .expect_get_chain()
            .with(eq(TEST_BILL_ID))
            .times(1)
            .returning(move |_| Ok(chain_clone.clone()));

        // block is not added
        bill_chain_store.expect_add_block().never();

        let handler = BillChainEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
        );
        let event = Event::new(
            EventType::Bill,
            "node_id",
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
            .handle_event(event.try_into().expect("Envelope from event"), "node_id")
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

        let (notification_store, push_service, mut bill_chain_store, bill_store) = create_mocks();

        bill_chain_store
            .expect_get_chain()
            .with(eq(TEST_BILL_ID))
            .times(1)
            .returning(move |_| Err(bcr_ebill_persistence::Error::NoBillBlock));

        bill_chain_store.expect_add_block().never();

        let handler = BillChainEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
        );
        let event = Event::new(
            EventType::Bill,
            "node_id",
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
            .handle_event(event.try_into().expect("Envelope from event"), "node_id")
            .await
            .expect("Event should be handled");
    }

    #[tokio::test]
    async fn test_creates_no_notification_for_non_action_event() {
        let (mut notification_store, mut push_service, bill_chain_store, bill_store) =
            create_mocks();

        // look for currently active notification
        notification_store.expect_get_latest_by_reference().never();

        // store new notification
        notification_store.expect_add().never();

        // send push notification
        push_service.expect_send().never();

        let handler = BillChainEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
        );
        let event = Event::new(
            EventType::Bill,
            "node_id",
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
            .handle_event(event.try_into().expect("Envelope from event"), "node_id")
            .await
            .expect("Event should be handled");
    }

    #[tokio::test]
    async fn test_creates_notification_for_simple_action_event() {
        let (mut notification_store, mut push_service, bill_chain_store, bill_store) =
            create_mocks();

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

        let handler = BillChainEventHandler::new(
            Arc::new(notification_store),
            Arc::new(push_service),
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
        );
        let event = Event::new(
            EventType::Bill,
            "node_id",
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
            .handle_event(event.try_into().expect("Envelope from event"), "node_id")
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
            nostr_relay: None,
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
            node_id: "".to_string(),
            name: "some name".to_string(),
            email: "some@example.com".to_string(),
            postal_address: empty_optional_address(),
            date_of_birth: None,
            country_of_birth: None,
            city_of_birth: None,
            identification_number: None,
            nostr_relay: None,
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
        MockBillChainStore,
        MockBillStore,
    ) {
        (
            MockNotificationStore::new(),
            MockPushService::new(),
            MockBillChainStore::new(),
            MockBillStore::new(),
        )
    }
}
