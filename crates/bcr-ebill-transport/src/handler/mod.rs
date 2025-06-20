use crate::Result;
use async_trait::async_trait;
use bcr_ebill_core::{
    NodeId, ServiceTraitBounds,
    bill::{BillId, BillKeys},
    blockchain::bill::BillBlock,
};
use log::trace;
#[cfg(test)]
use mockall::automock;

use super::{EventEnvelope, EventType};

mod bill_action_event_handler;
mod bill_chain_event_handler;
mod bill_chain_event_processor;
mod bill_invite_handler;

pub use bill_action_event_handler::BillActionEventHandler;
pub use bill_chain_event_handler::BillChainEventHandler;
pub use bill_chain_event_processor::BillChainEventProcessor;
pub use bill_invite_handler::BillInviteEventHandler;

#[cfg(test)]
impl ServiceTraitBounds for MockNotificationHandlerApi {}

/// Handle an event when we receive it from a channel.
#[allow(dead_code)]
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
        event: EventEnvelope,
        node_id: &NodeId,
        original_event: Box<nostr::Event>,
    ) -> Result<()>;
}

/// Generalizes the actual handling and validation of a bill block event.
#[allow(dead_code)]
#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait BillChainEventProcessorApi: ServiceTraitBounds {
    /// Processes the chain data for given bill id, some blocks and an otptional key that will be
    /// present when we are joining a new chain.
    async fn process_chain_data(
        &self,
        bill_id: &BillId,
        blocks: Vec<BillBlock>,
        keys: Option<BillKeys>,
    ) -> Result<()>;
}

#[cfg(test)]
impl ServiceTraitBounds for MockBillChainEventProcessorApi {}

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
        _: Box<nostr::Event>,
    ) -> Result<()> {
        trace!("Received event: {event:?} for identity: {identity}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bcr_ebill_core::notification::BillEventType;
    use serde::{Deserialize, Serialize, de::DeserializeOwned};
    use tokio::sync::Mutex;

    use crate::{Event, event::EventType, handler::test_utils::get_test_nostr_event};

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
                nostr_event,
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
            _: Box<nostr::Event>,
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

#[cfg(test)]
mod test_utils {
    use async_trait::async_trait;
    use bcr_ebill_core::{
        NodeId, ServiceTraitBounds,
        bill::{BillId, BillKeys, BitcreditBillResult},
        blockchain::bill::{BillBlock, BillBlockchain, BillOpCode},
        nostr_contact::NostrPublicKey,
        notification::{ActionType, Notification, NotificationType},
    };
    use bcr_ebill_persistence::{
        NostrChainEventStoreApi, NotificationStoreApi, Result,
        bill::{BillChainStoreApi, BillStoreApi},
        nostr::NostrContactStoreApi,
        notification::NotificationFilter,
    };
    use mockall::mock;
    use nostr::event::EventBuilder;
    use std::collections::HashMap;

    use crate::PushApi;

    mock! {
        pub NotificationStore {}

        impl ServiceTraitBounds for NotificationStore {}

        #[async_trait]
        impl NotificationStoreApi for NotificationStore {
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
            async fn set_to_paid(&self, id: &BillId, payment_address: &str) -> Result<()>;
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
}
