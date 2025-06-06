use super::BillChainEventProcessorApi;
use super::NotificationHandlerApi;
use crate::EventType;
use crate::event::bill_blockchain_event::BillBlockEvent;
use crate::{Event, EventEnvelope, Result};
use async_trait::async_trait;
use bcr_ebill_core::ServiceTraitBounds;
use bcr_ebill_persistence::bill::BillStoreApi;
use log::trace;
use log::{debug, error, warn};
use std::sync::Arc;

#[derive(Clone)]
pub struct PublicBillChainEventHandler {
    bill_store: Arc<dyn BillStoreApi>,
    processor: Arc<dyn BillChainEventProcessorApi>,
}

impl PublicBillChainEventHandler {
    pub fn new(
        processor: Arc<dyn BillChainEventProcessorApi>,
        bill_store: Arc<dyn BillStoreApi>,
    ) -> Self {
        Self {
            bill_store,
            processor,
        }
    }
}

impl ServiceTraitBounds for PublicBillChainEventHandler {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationHandlerApi for PublicBillChainEventHandler {
    fn handles_event(&self, event_type: &EventType) -> bool {
        event_type == &EventType::BillChain
    }

    async fn handle_event(&self, event: EventEnvelope, node_id: &str) -> Result<()> {
        debug!("incoming bill chain event for {node_id}");
        if let Ok(decoded) = Event::<BillBlockEvent>::try_from(event.clone()) {
            if let Ok(keys) = self.bill_store.get_keys(&decoded.data.bill_id).await {
                if let Err(e) = self
                    .processor
                    .process_chain_data(
                        &decoded.data.bill_id,
                        vec![decoded.data.block.clone()],
                        Some(keys.clone()),
                    )
                    .await
                {
                    error!("Failed to process chain data: {e}");
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

#[cfg(test)]
mod tests {
    use bcr_ebill_core::{
        OptionalPostalAddress, PostalAddress,
        bill::{BillKeys, BitcreditBill},
        blockchain::{
            Blockchain,
            bill::{
                BillBlock, BillBlockchain,
                block::{BillEndorseBlockData, BillIssueBlockData, BillParticipantBlockData},
            },
        },
        contact::{BillIdentParticipant, BillParticipant, ContactType},
        identity::{Identity, IdentityType, IdentityWithAll},
        util::BcrKeys,
    };
    use mockall::predicate::{always, eq};

    use crate::handler::{MockBillChainEventProcessorApi, test_utils::MockBillStore};

    use super::*;

    #[tokio::test]
    async fn test_create_event_handler() {
        let (bill_chain_event_processor, bill_store) = create_mocks();
        PublicBillChainEventHandler::new(
            Arc::new(bill_chain_event_processor),
            Arc::new(bill_store),
        );
    }

    #[tokio::test]
    async fn test_adds_block_and_event_for_valid_existing_chain_event() {
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

        let (mut bill_chain_event_processor, mut bill_store) = create_mocks();

        bill_store
            .expect_get_keys()
            .with(eq(TEST_BILL_ID))
            .returning(|_| Ok(get_bill_keys()));

        bill_chain_event_processor
            .expect_process_chain_data()
            .with(eq(TEST_BILL_ID), always(), always())
            .returning(|_, _, _| Ok(()));

        let handler = PublicBillChainEventHandler::new(
            Arc::new(bill_chain_event_processor),
            Arc::new(bill_store),
        );

        let event = Event::new(
            EventType::Bill,
            BillBlockEvent {
                bill_id: TEST_BILL_ID.to_string(),
                block: block.clone(),
            },
        );

        handler
            .handle_event(event.try_into().expect("Envelope from event"), "node_id")
            .await
            .expect("Event should be handled");
    }

    #[tokio::test]
    async fn test_does_not_attempt_to_add_block_for_unknown_chain() {
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

        let (mut bill_chain_event_processor, mut bill_store) = create_mocks();

        bill_store
            .expect_get_keys()
            .with(eq(bill.id))
            .returning(|_| Err(bcr_ebill_persistence::Error::NoIdentity));

        bill_chain_event_processor
            .expect_process_chain_data()
            .with(eq(TEST_BILL_ID), always(), always())
            .returning(|_, _, _| Ok(()))
            .never();

        let handler = PublicBillChainEventHandler::new(
            Arc::new(bill_chain_event_processor),
            Arc::new(bill_store),
        );

        let event = Event::new(
            EventType::Bill,
            BillBlockEvent {
                bill_id: TEST_BILL_ID.to_string(),
                block: block.clone(),
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

    fn create_mocks() -> (MockBillChainEventProcessorApi, MockBillStore) {
        (MockBillChainEventProcessorApi::new(), MockBillStore::new())
    }
}
