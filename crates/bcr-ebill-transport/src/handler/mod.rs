use crate::Result;
use async_trait::async_trait;
use bcr_ebill_core::ServiceTraitBounds;
use log::trace;
#[cfg(test)]
use mockall::automock;

use super::{EventEnvelope, EventType};

mod bill_chain_event_handler;

pub use bill_chain_event_handler::BillChainEventHandler;

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
    async fn handle_event(&self, event: EventEnvelope, node_id: &str) -> Result<()>;
}

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

    async fn handle_event(&self, event: EventEnvelope, identity: &str) -> Result<()> {
        trace!("Received event: {event:?} for identity: {identity}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use bcr_ebill_core::notification::BillEventType;
    use serde::{Deserialize, Serialize, de::DeserializeOwned};
    use tokio::sync::Mutex;

    use crate::{Event, event::EventType};

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

        // handler should run successfully
        event_handler
            .handle_event(envelope, "identity")
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

        async fn handle_event(&self, event: EventEnvelope, _: &str) -> Result<()> {
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
        Event::new(
            EventType::Bill,
            "node_id",
            create_test_event_payload(event_type),
        )
    }
}

#[cfg(test)]
mod test_utils {
    use async_trait::async_trait;
    use bcr_ebill_core::{
        ServiceTraitBounds,
        bill::{BillKeys, BitcreditBillResult},
        blockchain::bill::{BillBlock, BillBlockchain, BillOpCode},
        notification::{ActionType, Notification, NotificationType},
    };
    use bcr_ebill_persistence::{
        NotificationStoreApi, Result,
        bill::{BillChainStoreApi, BillStoreApi},
        nostr::NostrContactStoreApi,
        notification::NotificationFilter,
    };
    use mockall::mock;
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
                bill_id: &str,
                block_height: i32,
                action_type: ActionType,
            ) -> Result<()>;
            async fn bill_notification_sent(
                &self,
                bill_id: &str,
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
            async fn get_latest_block(&self, id: &str) -> Result<BillBlock>;
            async fn add_block(&self, id: &str, block: &BillBlock) -> Result<()>;
            async fn get_chain(&self, id: &str) -> Result<BillBlockchain>;
        }
    }

    mock! {
        pub BillStore {}

        impl ServiceTraitBounds for BillStore {}

        #[async_trait]
        impl BillStoreApi for BillStore {
            async fn get_bills_from_cache(&self, ids: &[String]) -> Result<Vec<BitcreditBillResult>>;
            async fn get_bill_from_cache(&self, id: &str) -> Result<Option<BitcreditBillResult>>;
            async fn save_bill_to_cache(&self, id: &str, bill: &BitcreditBillResult) -> Result<()>;
            async fn invalidate_bill_in_cache(&self, id: &str) -> Result<()>;
            async fn clear_bill_cache(&self) -> Result<()>;
            async fn exists(&self, id: &str) -> Result<bool>;
            async fn get_ids(&self) -> Result<Vec<String>>;
            async fn save_keys(&self, id: &str, keys: &BillKeys) -> Result<()>;
            async fn get_keys(&self, id: &str) -> Result<BillKeys>;
            async fn is_paid(&self, id: &str) -> Result<bool>;
            async fn set_to_paid(&self, id: &str, payment_address: &str) -> Result<()>;
            async fn get_bill_ids_waiting_for_payment(&self) -> Result<Vec<String>>;
            async fn get_bill_ids_waiting_for_sell_payment(&self) -> Result<Vec<String>>;
            async fn get_bill_ids_waiting_for_recourse_payment(&self) -> Result<Vec<String>>;
            async fn get_bill_ids_with_op_codes_since(
                &self,
                op_code: std::collections::HashSet<BillOpCode> ,
                since: u64,
            ) -> Result<Vec<String>>;
        }
    }

    mock! {
        pub NostrContactStore {}

        impl ServiceTraitBounds for NostrContactStore {}

        #[async_trait]
        impl NostrContactStoreApi for NostrContactStore {
            async fn by_node_id(&self, node_id: &str) -> Result<Option<bcr_ebill_core::nostr_contact::NostrContact>>;
            async fn by_npub(&self, npub: &nostr::key::PublicKey) -> Result<Option<bcr_ebill_core::nostr_contact::NostrContact>>;
            async fn upsert(&self, data: &bcr_ebill_core::nostr_contact::NostrContact) -> Result<()>;
            async fn delete(&self, node_id: &str) -> Result<()>;
            async fn set_handshake_status(&self, node_id: &str, status: bcr_ebill_core::nostr_contact::HandshakeStatus) -> Result<()>;
            async fn set_trust_level(&self, node_id: &str, trust_level: bcr_ebill_core::nostr_contact::TrustLevel) -> Result<()>;
        }
    }
}
