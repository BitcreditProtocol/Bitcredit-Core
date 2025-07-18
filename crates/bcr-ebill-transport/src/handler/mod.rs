use crate::Result;
use async_trait::async_trait;
use bcr_ebill_api::{service::notification_service::event::EventEnvelope, util::BcrKeys};
use bcr_ebill_core::{
    NodeId, ServiceTraitBounds,
    bill::{BillId, BillKeys},
    blockchain::{bill::BillBlock, company::CompanyBlock, identity::IdentityBlock},
    company::CompanyKeys,
};
use log::trace;
#[cfg(test)]
use mockall::automock;

use super::EventType;

mod bill_action_event_handler;
mod bill_chain_event_handler;
mod bill_chain_event_processor;
mod bill_invite_handler;
mod company_chain_event_handler;
mod company_chain_event_processor;
mod company_invite_handler;
mod identity_chain_event_handler;
mod identity_chain_event_processor;
mod nostr_contact_processor;
mod public_chain_helpers;

pub use bill_action_event_handler::BillActionEventHandler;
pub use bill_chain_event_handler::BillChainEventHandler;
pub use bill_chain_event_processor::BillChainEventProcessor;
pub use bill_invite_handler::BillInviteEventHandler;
pub use company_chain_event_handler::CompanyChainEventHandler;
pub use company_chain_event_processor::CompanyChainEventProcessor;
pub use company_invite_handler::CompanyInviteEventHandler;
pub use identity_chain_event_handler::IdentityChainEventHandler;
pub use identity_chain_event_processor::IdentityChainEventProcessor;
pub use nostr_contact_processor::NostrContactProcessor;
pub use public_chain_helpers::{BlockData, EventContainer, resolve_event_chains};

#[cfg(test)]
impl ServiceTraitBounds for MockNotificationHandlerApi {}

/// Handle an event when we receive it from a channel.
#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait NotificationHandlerApi: ServiceTraitBounds {
    /// Whether this handler handles the given event type.
    fn handles_event(&self, event_type: &EventType) -> bool;

    /// Handle the event. This is called by the notification processor which should
    /// have checked the event type before calling this method. The actual implementation
    /// should be able to deserialize the data into its T type because the EventType
    /// determines the T type. Identity represents the active identity that is receiving
    /// the event.
    async fn handle_event(
        &self,
        event: bcr_ebill_api::service::notification_service::event::EventEnvelope,
        node_id: &NodeId,
        original_event: Option<Box<nostr::Event>>,
    ) -> Result<()>;
}

/// Generalizes the actual handling and validation of a bill block event.
#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait BillChainEventProcessorApi: ServiceTraitBounds {
    /// Processes the chain data for given bill id, some blocks and an optional key that will be
    /// present when we are joining a new chain.
    async fn process_chain_data(
        &self,
        bill_id: &BillId,
        blocks: Vec<BillBlock>,
        keys: Option<BillKeys>,
    ) -> Result<()>;

    /// Validates that a given bill id is relevant for us, and if so also checks that the sender
    /// of the event is part of the chain this event is for.
    async fn validate_chain_event_and_sender(
        &self,
        bill_id: &BillId,
        sender: nostr::PublicKey,
    ) -> Result<bool>;
}

#[cfg(test)]
impl ServiceTraitBounds for MockBillChainEventProcessorApi {}

/// Generalizes the handling and validation of a bill block event.
#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait CompanyChainEventProcessorApi: ServiceTraitBounds {
    /// Processes the chain data for given bill id, some blocks and an optional key that will be
    /// present when we are joining a new chain.
    async fn process_chain_data(
        &self,
        node_id: &NodeId,
        blocks: Vec<CompanyBlock>,
        keys: Option<CompanyKeys>,
    ) -> Result<()>;

    /// Validates that a given bill id is relevant for us, and if so also checks that the sender
    /// of the event is part of the chain this event is for.
    async fn validate_chain_event_and_sender(
        &self,
        node_id: &NodeId,
        sender: nostr::PublicKey,
    ) -> Result<bool>;
}

#[cfg(test)]
impl ServiceTraitBounds for MockCompanyChainEventProcessorApi {}

/// Generalizes the handling and validation of a bill block event.
#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait IdentityChainEventProcessorApi: ServiceTraitBounds {
    /// Processes the chain data for given bill id, some blocks and an optional key that will be
    /// present when we are joining a new chain.
    async fn process_chain_data(
        &self,
        node_id: &NodeId,
        blocks: Vec<IdentityBlock>,
        keys: Option<BcrKeys>,
    ) -> Result<()>;

    /// Validates that a given bill id is relevant for us, and if so also checks that the sender
    /// of the event is part of the chain this event is for.
    fn validate_chain_event_and_sender(&self, node_id: &NodeId, sender: nostr::PublicKey) -> bool;
}

#[cfg(test)]
impl ServiceTraitBounds for MockIdentityChainEventProcessorApi {}

/// Generalizes the handling of other Nostr identities.
#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait NostrContactProcessorApi: ServiceTraitBounds {
    /// Ensures that a given node id is in our Nostr contacts. If not it will be added
    /// with data fetched from Nostr relays.
    async fn ensure_nostr_contact(&self, node_id: &NodeId);
}

#[cfg(test)]
impl ServiceTraitBounds for MockNostrContactProcessorApi {}

/// Logs all events that are received and registered in the event_types.
pub struct LoggingEventHandler {
    pub event_types: Vec<EventType>,
}

impl ServiceTraitBounds for LoggingEventHandler {}

/// Just a dummy handler that logs the event and returns Ok(())
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationHandlerApi for LoggingEventHandler {
    fn handles_event(&self, event_type: &EventType) -> bool {
        self.event_types.contains(event_type)
    }

    async fn handle_event(
        &self,
        event: EventEnvelope,
        identity: &NodeId,
        _: Option<Box<nostr::Event>>,
    ) -> Result<()> {
        trace!("Received event: {event:?} for identity: {identity}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bcr_ebill_api::service::notification_service::event::Event;
    use bcr_ebill_core::notification::BillEventType;
    use serde::{Deserialize, Serialize, de::DeserializeOwned};
    use tokio::sync::Mutex;

    use crate::handler::test_utils::get_test_nostr_event;

    use super::*;

    #[tokio::test]
    async fn test_event_handling() {
        let accepted_event = EventType::Bill;

        // given a handler that accepts the event type
        let event_handler: TestEventHandler<TestEventPayload> =
            TestEventHandler::new(Some(accepted_event.to_owned()));

        // event type should be accepted
        assert!(event_handler.handles_event(&accepted_event));

        // given an event and encode it to an envelope
        let event = create_test_event(&BillEventType::BillPaid);
        let envelope: EventEnvelope = event.clone().try_into().unwrap();
        let nostr_event = Box::new(get_test_nostr_event());

        // handler should run successfully
        event_handler
            .handle_event(
                envelope,
                &NodeId::from_str(
                    "bitcrt02295fb5f4eeb2f21e01eaf3a2d9a3be10f39db870d28f02146130317973a40ac0",
                )
                .unwrap(),
                Some(nostr_event),
            )
            .await
            .expect("event was not handled");

        // handler should have been invoked
        let called = event_handler.called.lock().await;
        assert!(*called, "event was not handled");

        // and the event should have been received
        let received = event_handler.received_event.lock().await.clone().unwrap();
        assert_eq!(event.data, received.data, "handled payload was not correct");
    }

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
    struct TestEventPayload {
        pub event_type: BillEventType,
        pub foo: String,
        pub bar: u32,
    }

    struct TestEventHandler<T: Serialize + DeserializeOwned> {
        pub called: Mutex<bool>,
        pub received_event: Mutex<Option<Event<T>>>,
        pub accepted_event: Option<EventType>,
    }

    impl<T: Serialize + DeserializeOwned + Send + Sync> ServiceTraitBounds for TestEventHandler<T> {}

    impl<T: Serialize + DeserializeOwned> TestEventHandler<T> {
        pub fn new(accepted_event: Option<EventType>) -> Self {
            Self {
                called: Mutex::new(false),
                received_event: Mutex::new(None),
                accepted_event,
            }
        }
    }

    #[async_trait]
    impl NotificationHandlerApi for TestEventHandler<TestEventPayload> {
        fn handles_event(&self, event_type: &EventType) -> bool {
            match &self.accepted_event {
                Some(e) => e == event_type,
                None => true,
            }
        }

        async fn handle_event(
            &self,
            event: EventEnvelope,
            _: &NodeId,
            _: Option<Box<nostr::Event>>,
        ) -> Result<()> {
            *self.called.lock().await = true;
            let event: Event<TestEventPayload> = event.try_into()?;
            *self.received_event.lock().await = Some(event);
            Ok(())
        }
    }

    fn create_test_event_payload(event_type: &BillEventType) -> TestEventPayload {
        TestEventPayload {
            event_type: event_type.clone(),
            foo: "foo".to_string(),
            bar: 42,
        }
    }

    fn create_test_event(event_type: &BillEventType) -> Event<TestEventPayload> {
        Event::new(EventType::Bill, create_test_event_payload(event_type))
    }
}

#[allow(dead_code)]
#[cfg(test)]
mod test_utils {

    use async_trait::async_trait;
    use bcr_ebill_core::{
        NodeId, OptionalPostalAddress, PostalAddress, PublicKey, SecretKey, ServiceTraitBounds,
        bill::{BillId, BillKeys, BitcreditBill, BitcreditBillResult, PaymentState},
        blockchain::{
            bill::{BillBlock, BillBlockchain, BillOpCode, block::BillIssueBlockData},
            company::{CompanyBlock, CompanyBlockchain},
        },
        company::{Company, CompanyKeys},
        contact::{BillIdentParticipant, BillParticipant, ContactType},
        identity::{Identity, IdentityType, IdentityWithAll},
        nostr_contact::NostrPublicKey,
        notification::{ActionType, Notification, NotificationType},
        util::BcrKeys,
    };
    use bcr_ebill_persistence::{
        NostrChainEventStoreApi, NotificationStoreApi, Result,
        bill::{BillChainStoreApi, BillStoreApi},
        company::{CompanyChainStoreApi, CompanyStoreApi},
        identity::{IdentityChainStoreApi, IdentityStoreApi},
        nostr::NostrContactStoreApi,
        notification::NotificationFilter,
    };
    use mockall::mock;
    use nostr::event::EventBuilder;
    use std::{collections::HashMap, str::FromStr};

    use crate::PushApi;

    mock! {
        pub NotificationStore {}

        impl ServiceTraitBounds for NotificationStore {}

        #[async_trait]
        impl NotificationStoreApi for NotificationStore {
            async fn get_active_status_for_node_ids(
                &self,
                node_ids: &[NodeId],
            ) -> Result<HashMap<NodeId, bool>>;
            async fn add(&self, notification: Notification) -> Result<Notification>;
            async fn list(&self, filter: NotificationFilter) -> Result<Vec<Notification>>;
            async fn get_latest_by_references(
                &self,
                reference: &[String],
                notification_type: NotificationType,
            ) -> Result<HashMap<String, Notification>>;
            async fn get_latest_by_reference(
                &self,
                reference: &str,
                notification_type: NotificationType,
            ) -> Result<Option<Notification>>;
            #[allow(unused)]
            async fn list_by_type(&self, notification_type: bcr_ebill_core::notification::NotificationType) -> Result<Vec<Notification>>;
            async fn mark_as_done(&self, notification_id: &str) -> Result<()>;
            #[allow(unused)]
            async fn delete(&self, notification_id: &str) -> Result<()>;
            async fn set_bill_notification_sent(
                &self,
                bill_id: &BillId,
                block_height: i32,
                action_type: ActionType,
            ) -> Result<()>;
            async fn bill_notification_sent(
                &self,
                bill_id: &BillId,
                block_height: i32,
                action_type: ActionType,
            ) -> Result<bool>;
        }
    }

    mock! {
        pub PushService {}

        impl ServiceTraitBounds for PushService {}

        #[async_trait]
        impl PushApi for PushService {
            async fn send(&self, value: serde_json::Value);
            async fn subscribe(&self) -> async_broadcast::Receiver<serde_json::Value> ;
        }
    }

    mock! {
        pub BillChainStore {}

        impl ServiceTraitBounds for BillChainStore {}

        #[async_trait]
        impl BillChainStoreApi for BillChainStore {
            async fn get_latest_block(&self, id: &BillId) -> Result<BillBlock>;
            async fn add_block(&self, id: &BillId, block: &BillBlock) -> Result<()>;
            async fn get_chain(&self, id: &BillId) -> Result<BillBlockchain>;
        }
    }

    mock! {
        pub BillStore {}

        impl ServiceTraitBounds for BillStore {}

        #[async_trait]
        impl BillStoreApi for BillStore {
            async fn get_bills_from_cache(&self, ids: &[BillId], identity_node_id: &NodeId) -> Result<Vec<BitcreditBillResult>>;
            async fn get_bill_from_cache(&self, id: &BillId, identity_node_id: &NodeId) -> Result<Option<BitcreditBillResult>>;
            async fn save_bill_to_cache(&self, id: &BillId, identity_node_id: &NodeId, bill: &BitcreditBillResult) -> Result<()>;
            async fn invalidate_bill_in_cache(&self, id: &BillId) -> Result<()>;
            async fn clear_bill_cache(&self) -> Result<()>;
            async fn exists(&self, id: &BillId) -> Result<bool>;
            async fn get_ids(&self) -> Result<Vec<BillId>>;
            async fn save_keys(&self, id: &BillId, keys: &BillKeys) -> Result<()>;
            async fn get_keys(&self, id: &BillId) -> Result<BillKeys>;
            async fn is_paid(&self, id: &BillId) -> Result<bool>;
            async fn set_payment_state(&self, id: &BillId, payment_state: &PaymentState) -> Result<()>;
            async fn get_payment_state(&self, id: &BillId) -> Result<Option<PaymentState>>;
            async fn set_offer_to_sell_payment_state(
                &self,
                id: &BillId,
                block_id: u64,
                payment_state: &PaymentState,
            ) -> Result<()>;
            async fn get_offer_to_sell_payment_state(
                &self,
                id: &BillId,
                block_id: u64,
            ) -> Result<Option<PaymentState>>;
            async fn set_recourse_payment_state(
                &self,
                id: &BillId,
                block_id: u64,
                payment_state: &PaymentState,
            ) -> Result<()>;
            async fn get_recourse_payment_state(
                &self,
                id: &BillId,
                block_id: u64,
            ) -> Result<Option<PaymentState>>;
            async fn get_bill_ids_waiting_for_payment(&self) -> Result<Vec<BillId>>;
            async fn get_bill_ids_waiting_for_sell_payment(&self) -> Result<Vec<BillId>>;
            async fn get_bill_ids_waiting_for_recourse_payment(&self) -> Result<Vec<BillId>>;
            async fn get_bill_ids_with_op_codes_since(
                &self,
                op_code: std::collections::HashSet<BillOpCode> ,
                since: u64,
            ) -> Result<Vec<BillId>>;
        }
    }

    mock! {
        pub NostrContactStore {}

        impl ServiceTraitBounds for NostrContactStore {}

        #[async_trait]
        impl NostrContactStoreApi for NostrContactStore {
            async fn by_node_id(&self, node_id: &NodeId) -> Result<Option<bcr_ebill_core::nostr_contact::NostrContact>>;
            async fn by_npub(&self, npub: &bcr_ebill_core::nostr_contact::NostrPublicKey) -> Result<Option<bcr_ebill_core::nostr_contact::NostrContact>>;
            async fn upsert(&self, data: &bcr_ebill_core::nostr_contact::NostrContact) -> Result<()>;
            async fn delete(&self, node_id: &NodeId) -> Result<()>;
            async fn set_handshake_status(&self, node_id: &NodeId, status: bcr_ebill_core::nostr_contact::HandshakeStatus) -> Result<()>;
            async fn set_trust_level(&self, node_id: &NodeId, trust_level: bcr_ebill_core::nostr_contact::TrustLevel) -> Result<()>;
            async fn get_npubs(&self, levels: Vec<bcr_ebill_core::nostr_contact::TrustLevel>) -> Result<Vec<NostrPublicKey>>;

        }
    }

    mock! {
        pub IdentityStore {}

        impl ServiceTraitBounds for IdentityStore {}

        #[async_trait]
        impl IdentityStoreApi for IdentityStore {
            async fn exists(&self) -> bool;
            async fn save(&self, identity: &Identity) -> Result<()>;
            async fn get(&self) -> Result<Identity>;
            async fn get_full(&self) -> Result<IdentityWithAll>;
            async fn save_key_pair(&self, key_pair: &BcrKeys, seed: &str) -> Result<()>;
            async fn get_key_pair(&self) -> Result<BcrKeys>;
            async fn get_or_create_key_pair(&self) -> Result<BcrKeys>;
            async fn get_seedphrase(&self) -> Result<String>;
            async fn get_current_identity(&self) -> Result<bcr_ebill_core::identity::ActiveIdentityState>;
            async fn set_current_identity(&self, identity_state: &bcr_ebill_core::identity::ActiveIdentityState) -> Result<()>;
            async fn set_or_check_network(&self, configured_network: bitcoin::Network) -> Result<()>;
        }
    }

    mock! {
        pub IdentityChainStore {}

        impl ServiceTraitBounds for IdentityChainStore {}

        #[async_trait]
        impl IdentityChainStoreApi for IdentityChainStore {
            async fn get_latest_block(&self) -> Result<bcr_ebill_core::blockchain::identity::IdentityBlock>;
            async fn add_block(&self, block: &bcr_ebill_core::blockchain::identity::IdentityBlock) -> Result<()>;
            async fn get_chain(&self) -> Result<bcr_ebill_core::blockchain::identity::IdentityBlockchain>;
        }
    }

    mock! {
        pub CompanyStore {}

        impl ServiceTraitBounds for CompanyStore {}

        #[async_trait]
        impl CompanyStoreApi for CompanyStore {
            async fn search(&self, search_term: &str) -> Result<Vec<Company>>;
            async fn exists(&self, id: &NodeId) -> bool;
            async fn get(&self, id: &NodeId) -> Result<Company>;
            async fn get_all(&self) -> Result<HashMap<NodeId, (Company, CompanyKeys)>>;
            async fn insert(&self, data: &Company) -> Result<()>;
            async fn update(&self, id: &NodeId, data: &Company) -> Result<()>;
            async fn remove(&self, id: &NodeId) -> Result<()>;
            async fn save_key_pair(&self, id: &NodeId, key_pair: &CompanyKeys) -> Result<()>;
            async fn get_key_pair(&self, id: &NodeId) -> Result<CompanyKeys>;
        }
    }

    mock! {
        pub CompanyChainStore {}

        impl ServiceTraitBounds for CompanyChainStore {}

        #[async_trait]
        impl CompanyChainStoreApi for CompanyChainStore {
            async fn get_latest_block(&self, id: &NodeId) -> Result<CompanyBlock>;
            async fn add_block(&self, id: &NodeId, block: &CompanyBlock) -> Result<()>;
            async fn remove(&self, id: &NodeId) -> Result<()>;
            async fn get_chain(&self, id: &NodeId) -> Result<CompanyBlockchain>;
        }
    }

    mock! {
        pub NostrChainEventStore {}
        impl ServiceTraitBounds for NostrChainEventStore {}

        #[async_trait]
        impl NostrChainEventStoreApi for NostrChainEventStore {
          async fn find_chain_events(
              &self,
              chain_id: &str,
              chain_type: bcr_ebill_core::blockchain::BlockchainType,
          ) -> Result<Vec<bcr_ebill_persistence::nostr::NostrChainEvent>>;
          async fn find_latest_block_events(
              &self,
              chain_id: &str,
              chain_type: bcr_ebill_core::blockchain::BlockchainType,
          ) -> Result<Vec<bcr_ebill_persistence::nostr::NostrChainEvent>>;
          async fn find_root_event(
              &self,
              chain_id: &str,
              chain_type: bcr_ebill_core::blockchain::BlockchainType,
          ) -> Result<Option<bcr_ebill_persistence::nostr::NostrChainEvent>>;
          async fn find_by_block_hash(&self, hash: &str) -> Result<Option<bcr_ebill_persistence::nostr::NostrChainEvent>>;
          async fn add_chain_event(&self, event: bcr_ebill_persistence::nostr::NostrChainEvent) -> Result<()>;
          async fn by_event_id(&self, event_id: &str) -> Result<Option<bcr_ebill_persistence::nostr::NostrChainEvent>>;
        }
    }

    pub fn get_test_nostr_event() -> nostr::Event {
        EventBuilder::text_note("message")
            .sign_with_keys(&nostr::key::Keys::generate())
            .expect("Could not create nostr test event")
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
    pub fn get_genesis_chain(bill: Option<BitcreditBill>) -> BillBlockchain {
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
    pub fn get_baseline_bill(bill_id: &BillId) -> BitcreditBill {
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
    pub fn empty_bitcredit_bill() -> BitcreditBill {
        BitcreditBill {
            id: bill_id_test(),
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
            private_key: private_key_test().to_owned(),
            public_key: node_id_test().pub_key(),
        }
    }

    pub fn get_baseline_identity() -> IdentityWithAll {
        let keys = BcrKeys::from_private_key(&private_key_test()).unwrap();
        let mut identity = empty_identity();
        identity.name = "drawer".to_owned();
        identity.node_id = node_id_test();
        identity.postal_address.country = Some("AT".to_owned());
        identity.postal_address.city = Some("Vienna".to_owned());
        identity.postal_address.address = Some("Hayekweg 5".to_owned());
        IdentityWithAll {
            identity,
            key_pair: keys,
        }
    }
    pub fn empty_bill_identified_participant() -> BillIdentParticipant {
        BillIdentParticipant {
            t: ContactType::Person,
            node_id: node_id_test(),
            name: "some name".to_string(),
            postal_address: empty_address(),
            email: None,
            nostr_relays: vec![],
        }
    }
    pub fn empty_address() -> PostalAddress {
        PostalAddress {
            country: "AT".to_string(),
            city: "Vienna".to_string(),
            zip: None,
            address: "Some address".to_string(),
        }
    }
    pub fn empty_identity() -> Identity {
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

    pub fn get_company_data() -> (NodeId, (Company, CompanyKeys)) {
        (
            node_id_test(),
            (
                Company {
                    id: node_id_test(),
                    name: "some_name".to_string(),
                    country_of_registration: Some("AT".to_string()),
                    city_of_registration: Some("Vienna".to_string()),
                    postal_address: empty_address(),
                    email: "company@example.com".to_string(),
                    registration_number: Some("some_number".to_string()),
                    registration_date: Some("2012-01-01".to_string()),
                    proof_of_registration_file: None,
                    logo_file: None,
                    signatories: vec![node_id_test()],
                },
                CompanyKeys {
                    private_key: private_key_test(),
                    public_key: node_id_test().pub_key(),
                },
            ),
        )
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
}
