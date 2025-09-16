use bcr_ebill_api::external::email::EmailClientApi;
use bcr_ebill_api::service::contact_service::ContactServiceApi;
use bcr_ebill_api::service::notification_service::NostrConfig;
use bcr_ebill_api::service::notification_service::event::{EventEnvelope, EventType};
use bcr_ebill_api::service::notification_service::transport::NotificationJsonTransportApi;
use bcr_ebill_api::util::BcrKeys;
use bcr_ebill_api::{Config, DevModeConfig, SurrealDbConfig};
use bcr_ebill_core::bill::{BillKeys, BitcreditBill};
use bcr_ebill_core::blockchain::bill::BillBlockchain;
use bcr_ebill_core::blockchain::bill::block::BillIssueBlockData;
use bcr_ebill_core::{
    NodeId, OptionalPostalAddress, PostalAddress, ServiceTraitBounds,
    bill::BillId,
    blockchain::BlockchainType,
    contact::BillParticipant,
    contact::{BillIdentParticipant, Contact, ContactType},
    identity::{Identity, IdentityType, IdentityWithAll},
    nostr_contact::{HandshakeStatus, NostrContact, NostrPublicKey, TrustLevel},
    notification::{ActionType, BillEventType, Notification},
};
use bcr_ebill_persistence::nostr::{NostrContactStoreApi, NostrQueuedMessageStoreApi};
use bcr_ebill_persistence::notification::EmailNotificationStoreApi;
use bcr_ebill_persistence::{
    ContactStoreApi, NostrChainEventStoreApi, NostrEventOffsetStoreApi, NotificationStoreApi,
};
use nostr_relay_builder::MockRelay;

use crate::chain_keys::ChainKeyServiceApi;
use crate::handler::NotificationHandlerApi;

use super::nostr::NostrClient;
use serde::{Serialize, de::DeserializeOwned};
use std::str::FromStr;
use std::sync::OnceLock;

use bcr_ebill_api::service::notification_service::{NostrContactData, Result, event::Event};

use bcr_ebill_persistence::nostr::NostrChainEvent;

use async_trait::async_trait;
use secp256k1::{PublicKey, SecretKey};
use serde::Deserialize;
use std::collections::HashMap;
use tokio::sync::Mutex;

#[allow(dead_code)]
pub const NOSTR_KEY1: &str = "nsec1gr9hfpprzn0hs5xymm0h547f6nt9x2270cy9chyzq3leprnzr2csprwlds";
#[allow(dead_code)]
pub const NOSTR_KEY2: &str = "nsec1aqz0hckc4wmrzzucqp4cx89528qu6g8deez9m32p2x7ka5c6et8svxt0q3";
#[allow(dead_code)]
pub const NOSTR_NPUB1: &str = "npub1c504lwrnmrt7atmnxxlf54rw3pxjhjv3455h3flnham3hsgjcs0qjk962x";
#[allow(dead_code)]
pub const NOSTR_NPUB2: &str = "npub1zax8v4hasewaxducdn89clqwmv4dp84r6vgpls5j5xg6f7xda3fqh2sg75";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TestEventPayload {
    pub event_type: BillEventType,
    pub foo: String,
    pub bar: u32,
}

pub struct TestEventHandler<T: Serialize + DeserializeOwned> {
    pub called: Mutex<bool>,
    pub received_event: Mutex<Option<Event<T>>>,
    pub accepted_event: Option<EventType>,
}

impl<T: Serialize + DeserializeOwned> TestEventHandler<T> {
    pub fn new(accepted_event: Option<EventType>) -> Self {
        Self {
            called: Mutex::new(false),
            received_event: Mutex::new(None),
            accepted_event,
        }
    }
}

static CONFIG: OnceLock<Config> = OnceLock::new();
pub fn init_test_cfg() {
    match CONFIG.get() {
        Some(_) => (),
        None => {
            let _ = bcr_ebill_api::init(Config {
                app_url: url::Url::parse("https://bitcredit-dev.minibill.tech").unwrap(),
                bitcoin_network: "testnet".to_string(),
                esplora_base_url: "https://esplora.minibill.tech".to_string(),
                db_config: SurrealDbConfig {
                    connection_string: "ws://localhost:8800".to_string(),
                    ..SurrealDbConfig::default()
                },
                data_dir: ".".to_string(),
                nostr_config: bcr_ebill_api::NostrConfig {
                    only_known_contacts: false,
                    relays: vec!["ws://localhost:8080".to_string()],
                },
                mint_config: bcr_ebill_api::MintConfig {
                    default_mint_url: "http://localhost:4242/".into(),
                    default_mint_node_id: NodeId::from_str(
                        "bitcrt03f9f94d1fdc2090d46f3524807e3f58618c36988e69577d70d5d4d1e9e9645a4f",
                    )
                    .unwrap(),
                },
                payment_config: bcr_ebill_api::PaymentConfig {
                    num_confirmations_for_payment: 6,
                },
                dev_mode_config: DevModeConfig { on: false },
            });
        }
    }
}

impl<T: Serialize + DeserializeOwned + Send + Sync> ServiceTraitBounds for TestEventHandler<T> {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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

pub fn create_test_event_payload(event_type: &BillEventType) -> TestEventPayload {
    TestEventPayload {
        event_type: event_type.clone(),
        foo: "foo".to_string(),
        bar: 42,
    }
}

pub fn bill_identified_participant_only_node_id(node_id: NodeId) -> BillIdentParticipant {
    BillIdentParticipant {
        t: ContactType::Person,
        node_id,
        name: "some name".to_string(),
        postal_address: empty_address(),
        email: None,
        nostr_relays: vec![],
    }
}

pub fn create_test_event(event_type: &BillEventType) -> Event<TestEventPayload> {
    Event::new(EventType::Bill, create_test_event_payload(event_type))
}

pub fn get_identity_public_data(
    node_id: &NodeId,
    email: &str,
    nostr_relays: Vec<&str>,
) -> BillIdentParticipant {
    let mut identity = bill_identified_participant_only_node_id(node_id.to_owned());
    identity.email = Some(email.to_owned());
    identity.nostr_relays = nostr_relays
        .iter()
        .map(|nostr_relay| String::from(*nostr_relay))
        .collect();
    identity
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
    bill.endorsee = endorsee.map(|e| BillParticipant::Ident(e.clone()));
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
        private_key: private_key_test(),
        public_key: node_id_test().pub_key(),
    }
}

pub fn get_baseline_identity() -> IdentityWithAll {
    let keys = BcrKeys::from_private_key(&private_key_test()).unwrap();
    let mut identity = empty_identity();
    identity.name = "drawer".to_owned();
    identity.node_id = NodeId::new(keys.pub_key(), bitcoin::Network::Testnet);
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

// bitcrt285psGq4Lz4fEQwfM3We5HPznJq8p1YvRaddszFaU5dY
pub fn bill_id_test() -> BillId {
    BillId::new(
        PublicKey::from_str("026423b7d36d05b8d50a89a1b4ef2a06c88bcd2c5e650f25e122fa682d3b39686c")
            .unwrap(),
        bitcoin::Network::Testnet,
    )
}

pub fn private_key_test() -> SecretKey {
    SecretKey::from_str("d1ff7427912d3b81743d3b67ffa1e65df2156d3dab257316cbc8d0f35eeeabe9").unwrap()
}

pub fn node_id_test() -> NodeId {
    NodeId::from_str("bitcrt02295fb5f4eeb2f21e01eaf3a2d9a3be10f39db870d28f02146130317973a40ac0")
        .unwrap()
}

pub fn node_id_test_other() -> NodeId {
    NodeId::from_str("bitcrt03f9f94d1fdc2090d46f3524807e3f58618c36988e69577d70d5d4d1e9e9645a4f")
        .unwrap()
}

pub fn bill_id_test_other2() -> BillId {
    BillId::new(
        PublicKey::from_str("0364f8de530163a528b4de33405ebe434bbd974a26ac24708674de572efacbdfdd")
            .unwrap(),
        bitcoin::Network::Testnet,
    )
}

pub fn node_id_test_other2() -> NodeId {
    NodeId::from_str("bitcrt039180c169e5f6d7c579cf1cefa37bffd47a2b389c8125601f4068c87bea795943")
        .unwrap()
}

pub async fn get_mock_relay() -> MockRelay {
    MockRelay::run().await.expect("could not create mock relay")
}

pub async fn get_mock_nostr_client() -> NostrClient {
    let relay = get_mock_relay().await;
    let url = relay.url();
    let keys = BcrKeys::new();

    let config = NostrConfig::new(
        keys.clone(),
        vec![url],
        "Test relay user".to_owned(),
        true,
        NodeId::new(keys.pub_key(), bitcoin::Network::Testnet),
    );
    NostrClient::new(&config)
        .await
        .expect("could not create mock nostr client")
}

mockall::mock! {
    pub NotificationJsonTransport {}

    impl ServiceTraitBounds for NotificationJsonTransport {}

    #[async_trait]
    impl NotificationJsonTransportApi for NotificationJsonTransport {
        fn get_sender_node_id(&self) -> NodeId;
        fn get_sender_keys(&self) -> BcrKeys;
        async fn send_private_event(&self, recipient: &BillParticipant, event: EventEnvelope) -> Result<()>;
        async fn send_public_chain_event(
            &self,
            id: &str,
            blockchain: bcr_ebill_core::blockchain::BlockchainType,
            block_time: u64,
            keys: BcrKeys,
            event: EventEnvelope,
            previous_event: Option<nostr::event::Event>,
            root_event: Option<nostr::event::Event>) -> Result<nostr::event::Event>;
        async fn resolve_contact(&self, node_id: &NodeId) -> Result<Option<NostrContactData>>;
        async fn resolve_public_chain(&self, id: &str, chain_type: BlockchainType) -> Result<Vec<nostr::event::Event>>;
        async fn add_contact_subscription(&self, contact: &NodeId) -> Result<()>;
        async fn resolve_private_events(&self, filter: nostr::Filter) -> Result<Vec<nostr::event::Event>>;
        async fn publish_metadata(&self, data: &nostr::nips::nip01::Metadata) -> Result<()>;
        async fn publish_relay_list(&self, relays: Vec<nostr::types::RelayUrl>) -> Result<()>;

    }
}

mockall::mock! {
    pub NotificationHandler {}
    impl ServiceTraitBounds for NotificationHandler {}
    #[async_trait]
    impl NotificationHandlerApi for NotificationHandler {
        async fn handle_event(&self, event: EventEnvelope, identity: &NodeId, original_event: Option<Box<nostr::Event>>) -> Result<()>;
        fn handles_event(&self, event_type: &EventType) -> bool;
    }
}

mockall::mock! {
    pub NotificationStore {}

    impl ServiceTraitBounds for NotificationStore {}

    #[async_trait]
    impl NotificationStoreApi for NotificationStore {
        async fn get_active_status_for_node_ids(
            &self,
            node_ids: &[NodeId],
        ) -> bcr_ebill_persistence::Result<HashMap<NodeId, bool>>;
        async fn add(&self, notification: Notification) -> bcr_ebill_persistence::Result<Notification>;
        async fn list(&self, filter: bcr_ebill_api::NotificationFilter) -> bcr_ebill_persistence::Result<Vec<Notification>>;
        async fn get_latest_by_references(
            &self,
            reference: &[String],
            notification_type: bcr_ebill_core::notification::NotificationType,
        ) -> bcr_ebill_persistence::Result<HashMap<String, Notification>>;
        async fn get_latest_by_reference(
            &self,
            reference: &str,
            notification_type: bcr_ebill_core::notification::NotificationType,
        ) -> bcr_ebill_persistence::Result<Option<Notification>>;
        #[allow(unused)]
        async fn list_by_type(&self, notification_type: bcr_ebill_core::notification::NotificationType) -> bcr_ebill_persistence::Result<Vec<Notification>>;
        async fn mark_as_done(&self, notification_id: &str) -> bcr_ebill_persistence::Result<()>;
        #[allow(unused)]
        async fn delete(&self, notification_id: &str) -> bcr_ebill_persistence::Result<()>;
        async fn set_bill_notification_sent(
            &self,
            bill_id: &BillId,
            block_height: i32,
            action_type: ActionType,
        ) -> bcr_ebill_persistence::Result<()>;
        async fn bill_notification_sent(
            &self,
            bill_id: &BillId,
            block_height: i32,
            action_type: ActionType,
        ) -> bcr_ebill_persistence::Result<bool>;
    }
}

mockall::mock! {
    pub EmailNotificationStore {}

    impl ServiceTraitBounds for EmailNotificationStore {}

    #[async_trait]
    impl EmailNotificationStoreApi for EmailNotificationStore {
        async fn add_email_preferences_link_for_node_id(
            &self,
            email_preferences_link: &url::Url,
            node_id: &NodeId,
        ) -> bcr_ebill_persistence::Result<()>;
        async fn get_email_preferences_link_for_node_id(&self, node_id: &NodeId) -> bcr_ebill_persistence::Result<Option<url::Url>>;
    }
}

mockall::mock! {
    pub NostrQueuedMessageStore {}

    impl ServiceTraitBounds for NostrQueuedMessageStore {}

    #[async_trait]
    impl NostrQueuedMessageStoreApi for NostrQueuedMessageStore {
        async fn add_message(&self, message: bcr_ebill_persistence::nostr::NostrQueuedMessage, max_retries: i32) -> bcr_ebill_persistence::Result<()>;
        async fn get_retry_messages(&self, limit: u64) -> bcr_ebill_persistence::Result<Vec<bcr_ebill_persistence::nostr::NostrQueuedMessage>>;
        async fn fail_retry(&self, id: &str) -> bcr_ebill_persistence::Result<()>;
        async fn succeed_retry(&self, id: &str) -> bcr_ebill_persistence::Result<()>;
    }
}

mockall::mock! {
    pub NostrChainEventStore {}

    impl ServiceTraitBounds for NostrChainEventStore {}

    #[async_trait]
    impl NostrChainEventStoreApi for NostrChainEventStore {
        async fn find_chain_events(&self, chain_id: &str, chain_type: BlockchainType) -> bcr_ebill_persistence::Result<Vec<NostrChainEvent>>;
        async fn find_latest_block_events(&self, chain_id: &str, chain_type: BlockchainType) -> bcr_ebill_persistence::Result<Vec<NostrChainEvent>>;
        async fn find_root_event(&self,chain_id: &str, chain_type: BlockchainType) -> bcr_ebill_persistence::Result<Option<NostrChainEvent>>;
        async fn find_by_block_hash(&self, hash: &str) -> bcr_ebill_persistence::Result<Option<NostrChainEvent>>;
        async fn add_chain_event(&self, event: NostrChainEvent) -> bcr_ebill_persistence::Result<()>;
        async fn by_event_id(&self, event_id: &str) -> bcr_ebill_persistence::Result<Option<NostrChainEvent>>;
    }
}

mockall::mock! {
    pub ChainKeyService {}

    impl ServiceTraitBounds for ChainKeyService {}

    #[async_trait]
    impl ChainKeyServiceApi for ChainKeyService {
        async fn get_chain_keys(
            &self,
            chain_id: &str,
            chain_type: BlockchainType,
        ) -> bcr_ebill_api::service::notification_service::Result<Option<BcrKeys>>;
    }
}

mockall::mock! {
    pub NostrEventOffsetStore {}

    impl ServiceTraitBounds for NostrEventOffsetStore {}

    #[async_trait]
    impl NostrEventOffsetStoreApi for NostrEventOffsetStore {
        async fn current_offset(&self, node_id: &NodeId) -> bcr_ebill_persistence::Result<u64>;
        async fn is_processed(&self, event_id: &str) -> bcr_ebill_persistence::Result<bool>;
        async fn add_event(&self, data: bcr_ebill_persistence::NostrEventOffset) -> bcr_ebill_persistence::Result<()>;
    }
}

mockall::mock! {
    pub ContactService {}
    impl ServiceTraitBounds for ContactService {}
    #[async_trait]
    impl ContactServiceApi for ContactService {
    async fn search(&self, search_term: &str) -> bcr_ebill_api::service::Result<Vec<Contact>>;
    async fn get_contacts(&self) -> bcr_ebill_api::service::Result<Vec<Contact>>;
    async fn get_contact(&self, node_id: &NodeId) -> bcr_ebill_api::service::Result<Contact>;
    async fn get_identity_by_node_id(&self, node_id: &NodeId) -> bcr_ebill_api::service::Result<Option<BillParticipant>>;
    async fn delete(&self, node_id: &NodeId) -> bcr_ebill_api::service::Result<()>;
    async fn update_contact(
        &self,
        node_id: &NodeId,
        name: Option<String>,
        email: Option<String>,
        postal_address: OptionalPostalAddress,
        date_of_birth_or_registration: Option<String>,
        country_of_birth_or_registration: Option<String>,
        city_of_birth_or_registration: Option<String>,
        identification_number: Option<String>,
        avatar_file_upload_id: Option<String>,
        ignore_avatar_file_upload_id: bool,
        proof_document_file_upload_id: Option<String>,
        ignore_proof_document_file_upload_id: bool,
    ) -> bcr_ebill_api::service::Result<()>;
    async fn add_contact(
        &self,
        node_id: &NodeId,
        t: ContactType,
        name: String,
        email: Option<String>,
        postal_address: Option<PostalAddress>,
        date_of_birth_or_registration: Option<String>,
        country_of_birth_or_registration: Option<String>,
        city_of_birth_or_registration: Option<String>,
        identification_number: Option<String>,
        avatar_file_upload_id: Option<String>,
        proof_document_file_upload_id: Option<String>,
    ) -> bcr_ebill_api::service::Result<Contact>;
    async fn deanonymize_contact(
        &self,
        node_id: &NodeId,
        t: ContactType,
        name: String,
        email: Option<String>,
        postal_address: Option<PostalAddress>,
        date_of_birth_or_registration: Option<String>,
        country_of_birth_or_registration: Option<String>,
        city_of_birth_or_registration: Option<String>,
        identification_number: Option<String>,
        avatar_file_upload_id: Option<String>,
        proof_document_file_upload_id: Option<String>,
    ) -> bcr_ebill_api::service::Result<Contact>;
    async fn is_known_npub(&self, npub: &bcr_ebill_core::nostr_contact::NostrPublicKey) -> bcr_ebill_api::service::Result<bool>;
    async fn get_nostr_npubs(&self) -> bcr_ebill_api::service::Result<Vec<bcr_ebill_core::nostr_contact::NostrPublicKey>>;
    async fn get_nostr_contact_by_node_id(&self, node_id: &NodeId) -> bcr_ebill_api::service::Result<Option<bcr_ebill_core::nostr_contact::NostrContact>>;
    async fn open_and_decrypt_file(
        &self,
        contact: Contact,
        id: &NodeId,
        file_name: &str,
        private_key: &SecretKey,
    ) -> bcr_ebill_api::service::Result<Vec<u8>>;
    }
}

mockall::mock! {
    pub EmailClient {}
    #[async_trait]
    impl EmailClientApi for EmailClient {
        async fn start(&self, relay_url: &str, node_id: &NodeId) -> bcr_ebill_api::external::email::Result<String>;
        async fn register(
            &self,
            relay_url: &str,
            email: &str,
            private_key: &nostr::SecretKey,
            challenge: &str,
        ) -> bcr_ebill_api::external::email::Result<url::Url>;
        async fn send_bill_notification(
            &self,
            relay_url: &str,
            kind: BillEventType,
            id: &BillId,
            receiver: &NodeId,
            private_key: &nostr::SecretKey,
        ) -> bcr_ebill_api::external::email::Result<()>;
    }
    impl ServiceTraitBounds for EmailClient {}
}

mockall::mock! {
    pub ContactStore {}

    impl ServiceTraitBounds for ContactStore {}

    #[async_trait]
    impl ContactStoreApi for ContactStore {
        async fn search(&self, search_term: &str) -> bcr_ebill_persistence::Result<Vec<Contact>>;
        async fn get_map(&self) -> bcr_ebill_persistence::Result<HashMap<NodeId, Contact>>;
        async fn get(&self, node_id: &NodeId) -> bcr_ebill_persistence::Result<Option<Contact>>;
        async fn insert(&self, node_id: &NodeId, data: Contact) -> bcr_ebill_persistence::Result<()>;
        async fn delete(&self, node_id: &NodeId) -> bcr_ebill_persistence::Result<()>;
        async fn update(&self, node_id: &NodeId, data: Contact) -> bcr_ebill_persistence::Result<()>;
    }
}

mockall::mock! {
    pub NostrContactStore {}

    impl ServiceTraitBounds for NostrContactStore {}

    #[async_trait]
    impl NostrContactStoreApi for NostrContactStore {
        async fn by_node_id(&self, node_id: &NodeId) -> bcr_ebill_persistence::Result<Option<NostrContact>>;
        async fn by_npub(&self, npub: &NostrPublicKey) -> bcr_ebill_persistence::Result<Option<NostrContact>>;
        async fn upsert(&self, data: &NostrContact) -> bcr_ebill_persistence::Result<()>;
        async fn delete(&self, node_id: &NodeId) -> bcr_ebill_persistence::Result<()>;
        async fn set_handshake_status(&self, node_id: &NodeId, status: HandshakeStatus) -> bcr_ebill_persistence::Result<()>;
        async fn set_trust_level(&self, node_id: &NodeId, trust_level: TrustLevel) -> bcr_ebill_persistence::Result<()>;
        async fn get_npubs(&self, levels: Vec<TrustLevel>) -> bcr_ebill_persistence::Result<Vec<NostrPublicKey>>;
    }
}
