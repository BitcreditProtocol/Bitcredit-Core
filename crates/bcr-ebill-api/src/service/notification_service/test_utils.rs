use crate::{
    data::{bill::BitcreditBill, contact::BillIdentParticipant},
    persistence::DbContext,
    tests::tests::{
        MockBackupStoreApiMock, MockBillChainStoreApiMock, MockBillStoreApiMock,
        MockCompanyChainStoreApiMock, MockCompanyStoreApiMock, MockContactStoreApiMock,
        MockFileUploadStoreApiMock, MockIdentityChainStoreApiMock, MockIdentityStoreApiMock,
        MockMintStore, MockNostrChainEventStore, MockNostrContactStore,
        MockNostrEventOffsetStoreApiMock, MockNostrQueuedMessageStore,
        MockNotificationStoreApiMock, bill_identified_participant_only_node_id,
        empty_bitcredit_bill,
    },
    util::BcrKeys,
};
use bcr_ebill_core::{
    NodeId, ServiceTraitBounds, bill::BillId, contact::BillParticipant, notification::BillEventType,
};
use nostr_relay_builder::prelude::*;

use super::{NostrConfig, nostr::NostrClient};
use bcr_ebill_transport::{Event, EventEnvelope, EventType, handler::NotificationHandlerApi};
use serde::{Serialize, de::DeserializeOwned};
use std::sync::Arc;

/// These mocks might be useful for testing in other modules as well
use async_trait::async_trait;
use serde::Deserialize;
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
        _: Box<nostr::Event>,
    ) -> bcr_ebill_transport::Result<()> {
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

#[allow(dead_code)]
pub fn get_mock_db_context() -> DbContext {
    DbContext {
        contact_store: Arc::new(MockContactStoreApiMock::new()),
        bill_store: Arc::new(MockBillStoreApiMock::new()),
        bill_blockchain_store: Arc::new(MockBillChainStoreApiMock::new()),
        identity_store: Arc::new(MockIdentityStoreApiMock::new()),
        identity_chain_store: Arc::new(MockIdentityChainStoreApiMock::new()),
        company_store: Arc::new(MockCompanyStoreApiMock::new()),
        company_chain_store: Arc::new(MockCompanyChainStoreApiMock::new()),
        file_upload_store: Arc::new(MockFileUploadStoreApiMock::new()),
        nostr_event_offset_store: Arc::new(MockNostrEventOffsetStoreApiMock::new()),
        notification_store: Arc::new(MockNotificationStoreApiMock::new()),
        backup_store: Arc::new(MockBackupStoreApiMock::new()),
        queued_message_store: Arc::new(MockNostrQueuedMessageStore::new()),
        nostr_contact_store: Arc::new(MockNostrContactStore::new()),
        mint_store: Arc::new(MockMintStore::new()),
        nostr_chain_event_store: Arc::new(MockNostrChainEventStore::new()),
    }
}
