use super::BillChainEventProcessorApi;
use super::NotificationHandlerApi;
use crate::EventType;
use crate::transport::root_and_reply_id;
use async_trait::async_trait;
use bcr_ebill_api::service::notification_service::event::BillBlockEvent;
use bcr_ebill_api::service::notification_service::event::Event;
use bcr_ebill_api::service::notification_service::{Result, event::EventEnvelope};
use bcr_ebill_core::NodeId;
use bcr_ebill_core::ServiceTraitBounds;
use bcr_ebill_core::blockchain::BlockchainType;
use bcr_ebill_core::util::date::now;
use bcr_ebill_persistence::NostrChainEventStoreApi;
use bcr_ebill_persistence::bill::BillStoreApi;
use bcr_ebill_persistence::nostr::NostrChainEvent;
use log::trace;
use log::{debug, error, warn};
use std::sync::Arc;

#[derive(Clone)]
pub struct BillChainEventHandler {
    bill_store: Arc<dyn BillStoreApi>,
    processor: Arc<dyn BillChainEventProcessorApi>,
    chain_event_store: Arc<dyn NostrChainEventStoreApi>,
}

impl BillChainEventHandler {
    pub fn new(
        processor: Arc<dyn BillChainEventProcessorApi>,
        bill_store: Arc<dyn BillStoreApi>,
        chain_event_store: Arc<dyn NostrChainEventStoreApi>,
    ) -> Self {
        Self {
            bill_store,
            processor,
            chain_event_store,
        }
    }
}

impl ServiceTraitBounds for BillChainEventHandler {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationHandlerApi for BillChainEventHandler {
    fn handles_event(&self, event_type: &EventType) -> bool {
        event_type == &EventType::BillChain
    }

    async fn handle_event(
        &self,
        event: EventEnvelope,
        node_id: &NodeId,
        original_event: Option<Box<nostr::Event>>,
    ) -> Result<()> {
        debug!("incoming bill chain event for {node_id}");
        if let Ok(decoded) = Event::<BillBlockEvent>::try_from(event.clone()) {
            if let Ok(keys) = self.bill_store.get_keys(&decoded.data.bill_id).await {
                let valid = self
                    .processor
                    .process_chain_data(
                        &decoded.data.bill_id,
                        vec![decoded.data.block.clone()],
                        Some(keys.clone()),
                    )
                    .await
                    .inspect_err(|e| error!("Received invalid block {e}"))
                    .is_ok();

                if let Some(original_event) = original_event {
                    self.store_event(
                        original_event,
                        decoded.data.block_height,
                        &decoded.data.block.hash,
                        &decoded.data.bill_id.to_string(),
                        valid,
                    )
                    .await?;
                }
            } else {
                trace!("no keys for incoming bill block");
            }
        } else {
            warn!("Could not decode event to BillChainEventPayload {event:?}");
        }
        Ok(())
    }
}

impl BillChainEventHandler {
    async fn store_event(
        &self,
        event: Box<nostr::Event>,
        block_height: usize,
        block_hash: &str,
        chain_id: &str,
        valid: bool,
    ) -> Result<()> {
        let (root, reply) = root_and_reply_id(&event);
        if let Err(e) = self
            .chain_event_store
            .add_chain_event(NostrChainEvent {
                event_id: event.id.to_string(),
                root_id: root
                    .map(|id| id.to_string())
                    .unwrap_or(event.id.to_string()),
                reply_id: reply.map(|id| id.to_string()),
                author: event.pubkey.to_string(),
                chain_id: chain_id.to_string(),
                chain_type: BlockchainType::Bill,
                block_height,
                block_hash: block_hash.to_string(),
                received: now().timestamp() as u64,
                time: event.created_at.as_u64(),
                payload: *event.clone(),
                valid,
            })
            .await
        {
            error!("Failed to store bill chain nostr event into event store {e}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bcr_ebill_api::constants::CURRENCY_SAT;
    use bcr_ebill_core::{
        OptionalPostalAddress, PostalAddress, PublicKey, SecretKey,
        bill::{BillId, BillKeys, BitcreditBill},
        blockchain::{
            Blockchain,
            bill::{
                BillBlock, BillBlockchain,
                block::{BillEndorseBlockData, BillIssueBlockData, BillParticipantBlockData},
            },
        },
        contact::{BillIdentParticipant, BillParticipant, ContactType},
        country::Country,
        identity::{Identity, IdentityType, IdentityWithAll},
        util::BcrKeys,
    };
    use mockall::predicate::{always, eq};

    use crate::handler::{
        MockBillChainEventProcessorApi,
        test_utils::{MockBillStore, MockNostrChainEventStore, get_test_nostr_event},
    };

    use super::*;

    #[tokio::test]
    async fn test_create_event_handler() {
        let (bill_chain_event_processor, bill_store, event_store) = create_mocks();
        BillChainEventHandler::new(
            Arc::new(bill_chain_event_processor),
            Arc::new(bill_store),
            Arc::new(event_store),
        );
    }

    #[tokio::test]
    async fn test_adds_block_and_event_for_valid_existing_chain_event() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let mut endorsee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        endorsee.node_id = node_id_test_other();
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let chain = get_genesis_chain(Some(bill.clone()));
        let block = BillBlock::create_block_for_endorse(
            bill_id_test(),
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
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();

        let (mut bill_chain_event_processor, mut bill_store, mut event_store) = create_mocks();

        bill_store
            .expect_get_keys()
            .with(eq(bill_id_test()))
            .returning(|_| Ok(get_bill_keys()));

        bill_chain_event_processor
            .expect_process_chain_data()
            .with(eq(bill_id_test()), always(), always())
            .returning(|_, _, _| Ok(()));

        let nostr_event = get_test_nostr_event();
        let nostr_event_id = nostr_event.id.to_string();

        event_store
            .expect_add_chain_event()
            .withf(move |e| {
                e.event_id == nostr_event_id && e.root_id == nostr_event_id && e.reply_id.is_none()
            })
            .returning(|_| Ok(()));

        let handler = BillChainEventHandler::new(
            Arc::new(bill_chain_event_processor),
            Arc::new(bill_store),
            Arc::new(event_store),
        );

        let event = Event::new(
            EventType::Bill,
            BillBlockEvent {
                bill_id: bill_id_test(),
                block_height: 1,
                block: block.clone(),
            },
        );

        handler
            .handle_event(
                event.try_into().expect("Envelope from event"),
                &node_id_test(),
                Some(Box::new(nostr_event)),
            )
            .await
            .expect("Event should be handled");
    }

    #[tokio::test]
    async fn test_does_not_attempt_to_add_block_for_unknown_chain() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let endorsee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let chain = get_genesis_chain(Some(bill.clone()));

        let block = BillBlock::create_block_for_endorse(
            bill_id_test(),
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
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();

        let (mut bill_chain_event_processor, mut bill_store, event_store) = create_mocks();

        bill_store
            .expect_get_keys()
            .with(eq(bill.id))
            .returning(|_| Err(bcr_ebill_persistence::Error::NoIdentity));

        bill_chain_event_processor
            .expect_process_chain_data()
            .with(eq(bill_id_test()), always(), always())
            .returning(|_, _, _| Ok(()))
            .never();

        let handler = BillChainEventHandler::new(
            Arc::new(bill_chain_event_processor),
            Arc::new(bill_store),
            Arc::new(event_store),
        );

        let event = Event::new(
            EventType::Bill,
            BillBlockEvent {
                bill_id: bill_id_test(),
                block_height: 1,
                block: block.clone(),
            },
        );

        handler
            .handle_event(
                event.try_into().expect("Envelope from event"),
                &node_id_test(),
                Some(Box::new(get_test_nostr_event())),
            )
            .await
            .expect("Event should be handled");
    }

    pub fn get_test_bitcredit_bill(
        id: &BillId,
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
        let bill = bill.unwrap_or(get_baseline_bill(&bill_id_test()));
        BillBlockchain::new(
            &BillIssueBlockData::from(bill, None, 1731593928),
            get_baseline_identity().key_pair,
            None,
            BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap()
    }
    fn get_baseline_bill(bill_id: &BillId) -> BitcreditBill {
        let mut bill = empty_bitcredit_bill();
        let keys = BcrKeys::new();

        bill.maturity_date = "2099-10-15".to_string();
        let mut payee = empty_bill_identified_participant();
        payee.name = "payee".to_owned();
        payee.node_id = NodeId::new(keys.pub_key(), bitcoin::Network::Testnet);
        bill.payee = BillParticipant::Ident(payee);
        bill.drawee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        bill.id = bill_id.to_owned();
        bill
    }
    fn empty_bitcredit_bill() -> BitcreditBill {
        BitcreditBill {
            id: bill_id_test(),
            country_of_issuing: Country::AT,
            city_of_issuing: "Vienna".to_string(),
            drawee: empty_bill_identified_participant(),
            drawer: empty_bill_identified_participant(),
            payee: BillParticipant::Ident(empty_bill_identified_participant()),
            endorsee: None,
            currency: CURRENCY_SAT.to_string(),
            sum: 500,
            maturity_date: "2099-11-12".to_string(),
            issue_date: "2099-08-12".to_string(),
            city_of_payment: "Vienna".to_string(),
            country_of_payment: Country::AT,
            files: vec![],
        }
    }

    pub fn get_bill_keys() -> BillKeys {
        BillKeys {
            private_key: private_key_test(),
            public_key: node_id_test().pub_key(),
        }
    }

    fn get_baseline_identity() -> IdentityWithAll {
        let keys = BcrKeys::from_private_key(&private_key_test()).unwrap();
        let mut identity = empty_identity();
        identity.name = "drawer".to_owned();
        identity.node_id = NodeId::new(keys.pub_key(), bitcoin::Network::Testnet);
        identity.postal_address.country = Some(Country::AT);
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
            node_id: node_id_test(),
            name: "some name".to_string(),
            postal_address: empty_address(),
            email: None,
            nostr_relays: vec![],
        }
    }
    fn empty_address() -> PostalAddress {
        PostalAddress {
            country: Country::AT,
            city: "Vienna".to_string(),
            zip: None,
            address: "Some address".to_string(),
        }
    }
    fn empty_identity() -> Identity {
        Identity {
            t: IdentityType::Ident,
            node_id: node_id_test(),
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

    pub fn private_key_test() -> SecretKey {
        SecretKey::from_str("d1ff7427912d3b81743d3b67ffa1e65df2156d3dab257316cbc8d0f35eeeabe9")
            .unwrap()
    }

    pub fn node_id_test() -> NodeId {
        NodeId::from_str("bitcrt02295fb5f4eeb2f21e01eaf3a2d9a3be10f39db870d28f02146130317973a40ac0")
            .unwrap()
    }

    pub fn node_id_test_other() -> NodeId {
        NodeId::from_str("bitcrt03f9f94d1fdc2090d46f3524807e3f58618c36988e69577d70d5d4d1e9e9645a4f")
            .unwrap()
    }

    fn create_mocks() -> (
        MockBillChainEventProcessorApi,
        MockBillStore,
        MockNostrChainEventStore,
    ) {
        (
            MockBillChainEventProcessorApi::new(),
            MockBillStore::new(),
            MockNostrChainEventStore::new(),
        )
    }
}
