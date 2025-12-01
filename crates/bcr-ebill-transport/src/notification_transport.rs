use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};

use bcr_ebill_api::external::email::EmailClientApi;
use bcr_ebill_api::service::transport_service::NotificationTransportServiceApi;
use bcr_ebill_api::service::transport_service::{Error, Result};
use bcr_ebill_api::util::{validate_bill_id_network, validate_node_id_network};
use bcr_ebill_core::application::ServiceTraitBounds;
use bcr_ebill_core::application::notification::{Notification, NotificationType};
use bcr_ebill_core::{
    protocol::Sum,
    protocol::blockchain::bill::participant::BillParticipant,
    protocol::event::{ActionType, BillChainEventPayload, Event},
};
use bcr_ebill_persistence::NotificationStoreApi;
use bcr_ebill_persistence::notification::{EmailNotificationStoreApi, NotificationFilter};
use log::error;

use crate::NostrTransportService;

pub struct NotificationTransportService {
    nostr_transport: Arc<NostrTransportService>,
    notification_store: Arc<dyn NotificationStoreApi>,
    email_notification_store: Arc<dyn EmailNotificationStoreApi>,
    #[allow(unused)]
    email_client: Arc<dyn EmailClientApi>,
}

impl NotificationTransportService {
    pub fn new(
        nostr_transport: Arc<NostrTransportService>,
        notification_store: Arc<dyn NotificationStoreApi>,
        email_notification_store: Arc<dyn EmailNotificationStoreApi>,
        email_client: Arc<dyn EmailClientApi>,
    ) -> Self {
        Self {
            nostr_transport,
            notification_store,
            email_notification_store,
            email_client,
        }
    }
}

impl ServiceTraitBounds for NotificationTransportService {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationTransportServiceApi for NotificationTransportService {
    async fn get_client_notifications(
        &self,
        filter: NotificationFilter,
    ) -> Result<Vec<Notification>> {
        for node_id in filter.node_ids.iter() {
            validate_node_id_network(node_id)?;
        }
        let result = self.notification_store.list(filter).await.map_err(|e| {
            error!("Failed to get client notifications: {e}");
            Error::Persistence("Failed to get client notifications".to_string())
        })?;
        Ok(result)
    }

    async fn mark_notification_as_done(&self, notification_id: &str) -> Result<()> {
        let _ = self
            .notification_store
            .mark_as_done(notification_id)
            .await
            .map_err(|e| {
                error!("Failed to mark notification as done: {e}");
                Error::Persistence("Failed to mark notification as done".to_string())
            })?;
        Ok(())
    }

    async fn get_active_bill_notification(&self, bill_id: &BillId) -> Option<Notification> {
        validate_bill_id_network(bill_id).ok()?;
        self.notification_store
            .get_latest_by_reference(&bill_id.to_string(), NotificationType::Bill)
            .await
            .unwrap_or_default()
    }

    async fn get_active_bill_notifications(
        &self,
        bill_ids: &[BillId],
    ) -> HashMap<BillId, Notification> {
        let ids: Vec<String> = bill_ids.iter().map(|bill_id| bill_id.to_string()).collect();
        let refs = self
            .notification_store
            .get_latest_by_references(&ids, NotificationType::Bill)
            .await
            .unwrap_or_default();
        refs.into_iter()
            .filter_map(|(key, value)| match BillId::from_str(&key) {
                Ok(bill_id) => Some((bill_id, value)),
                Err(_) => None,
            })
            .collect()
    }

    async fn get_active_notification_status_for_node_ids(
        &self,
        node_ids: &[NodeId],
    ) -> Result<HashMap<NodeId, bool>> {
        Ok(self
            .notification_store
            .get_active_status_for_node_ids(node_ids)
            .await
            .unwrap_or_default())
    }

    async fn send_request_to_action_timed_out_event(
        &self,
        sender_node_id: &NodeId,
        bill_id: &BillId,
        sum: Option<Sum>,
        timed_out_action: ActionType,
        recipients: Vec<BillParticipant>,
        holder: &NodeId,
        drawee: &NodeId,
        recoursee: &Option<NodeId>,
    ) -> Result<()> {
        if let Some(node) = self
            .nostr_transport
            .get_node_transport(sender_node_id)
            .await
            && let Some(event_type) = timed_out_action.get_timeout_event_type()
        {
            // only send to a recipient once
            let unique: HashMap<NodeId, BillParticipant> =
                HashMap::from_iter(recipients.iter().map(|r| (r.node_id().clone(), r.clone())));

            let payload = BillChainEventPayload {
                event_type,
                bill_id: bill_id.to_owned(),
                action_type: Some(ActionType::CheckBill),
                sum,
            };
            for (_, recipient) in unique {
                let event = Event::new_bill(payload.clone());
                node.send_private_event(sender_node_id, &recipient, event.clone().try_into()?)
                    .await?;

                // Only send email to holder, and only if we are drawee, or recoursee
                if let Some(r) = recoursee {
                    if sender_node_id == r {
                        self.send_email_notification(sender_node_id, holder, &event)
                            .await;
                    }
                } else if sender_node_id == drawee {
                    self.send_email_notification(sender_node_id, holder, &event)
                        .await;
                }
            }
        }
        Ok(())
    }

    async fn check_bill_notification_sent(
        &self,
        bill_id: &BillId,
        block_height: i32,
        action: ActionType,
    ) -> Result<bool> {
        validate_bill_id_network(bill_id)?;
        Ok(self
            .notification_store
            .bill_notification_sent(bill_id, block_height, action)
            .await
            .map_err(|e| {
                error!("Failed to check if bill notification was already sent: {e}");
                Error::Persistence(
                    "Failed to check if bill notification was already sent".to_string(),
                )
            })?)
    }

    /// Stores that a notification was sent for the given bill id and action
    async fn mark_bill_notification_sent(
        &self,
        bill_id: &BillId,
        block_height: i32,
        action: ActionType,
    ) -> Result<()> {
        validate_bill_id_network(bill_id)?;
        self.notification_store
            .set_bill_notification_sent(bill_id, block_height, action)
            .await
            .map_err(|e| {
                error!("Failed to mark bill notification as sent: {e}");
                Error::Persistence("Failed to mark bill notification as sent".to_string())
            })?;
        Ok(())
    }

    /// Fetch email notifications preferences link for the currently selected identity
    async fn get_email_notifications_preferences_link(&self, node_id: &NodeId) -> Result<url::Url> {
        match self
            .email_notification_store
            .get_email_preferences_link_for_node_id(node_id)
            .await
        {
            Ok(Some(link)) => Ok(link),
            Ok(None) => Err(Error::NotFound),
            Err(e) => Err(Error::Persistence(e.to_string())),
        }
    }

    /// Attempts to send an email notification for an event to the receiver
    /// if the receiver does not have email notifications enabled, the relay
    /// ignores the request and returns a quick 200 OK.
    async fn send_email_notification(
        &self,
        _sender: &NodeId,
        _receiver: &NodeId,
        _event: &Event<BillChainEventPayload>,
    ) {
        // TODO: use email client and receiver's mint_url to send
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bcr_common::core::{BillId, NodeId};
    use bcr_ebill_api::service::transport_service::NotificationTransportServiceApi;
    use bcr_ebill_core::{
        application::notification::Notification,
        protocol::Email,
        protocol::blockchain::bill::participant::BillParticipant,
        protocol::crypto::BcrKeys,
        protocol::event::{
            ActionType, BillChainEventPayload, BillEventType, Event, EventEnvelope, EventType,
        },
        protocol::{Result, Sum},
    };
    use bcr_ebill_persistence::notification::NotificationFilter;
    use mockall::predicate::eq;

    use crate::{
        notification_transport::NotificationTransportService,
        test_utils::{
            MockContactStore, MockEmailClient, MockEmailNotificationStore,
            MockNostrChainEventStore, MockNostrContactStore, MockNostrQueuedMessageStore,
            MockNotificationJsonTransport, MockNotificationStore, bill_id_test,
            get_identity_public_data, get_nostr_transport, init_test_cfg, node_id_test,
            node_id_test_other, node_id_test_other2, private_key_test,
        },
    };

    use bcr_ebill_api::service::transport_service::Error;

    #[tokio::test]
    async fn test_send_request_to_action_timed_out_event() {
        init_test_cfg();
        let recipients = vec![
            BillParticipant::Ident(get_identity_public_data(
                &node_id_test(),
                &Email::new("part1@example.com").unwrap(),
                vec![],
            )),
            BillParticipant::Ident(get_identity_public_data(
                &node_id_test_other(),
                &Email::new("part2@example.com").unwrap(),
                vec![],
            )),
            BillParticipant::Ident(get_identity_public_data(
                &node_id_test_other2(),
                &Email::new("part3@example.com").unwrap(),
                vec![],
            )),
        ];

        let service = expect_service(|mock, _, _, _, _, _, _, email_client| {
            // resolves node_id
            mock.expect_get_sender_node_id().returning(node_id_test);
            mock.expect_get_sender_keys()
                .returning(|| BcrKeys::from_private_key(&private_key_test()));

            // expect to send payment timeout event to all recipients
            mock.expect_send_private_event()
                .withf(|_, _, e| check_chain_payload(e, BillEventType::BillPaymentTimeout))
                .returning(|_, _, _| Ok(()))
                .times(3);

            // expect to send acceptance timeout event to all recipients
            mock.expect_send_private_event()
                .withf(|_, _, e| check_chain_payload(e, BillEventType::BillAcceptanceTimeout))
                .returning(|_, _, _| Ok(()))
                .times(3);

            email_client
                .expect_send_bill_notification()
                .returning(|_, _, _, _, _, _, _| Ok(()));
        });

        service
            .send_request_to_action_timed_out_event(
                &node_id_test(),
                &bill_id_test(),
                Some(Sum::new_sat(100).expect("sat works")),
                ActionType::PayBill,
                recipients.clone(),
                &node_id_test(),
                &node_id_test(),
                &None,
            )
            .await
            .expect("failed to send event");

        service
            .send_request_to_action_timed_out_event(
                &node_id_test(),
                &bill_id_test(),
                Some(Sum::new_sat(100).expect("sat works")),
                ActionType::AcceptBill,
                recipients.clone(),
                &node_id_test(),
                &node_id_test(),
                &None,
            )
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn test_send_request_to_action_timed_out_does_not_send_non_timeout_action() {
        init_test_cfg();
        let recipients = vec![
            BillParticipant::Ident(get_identity_public_data(
                &node_id_test(),
                &Email::new("part1@example.com").unwrap(),
                vec![],
            )),
            BillParticipant::Ident(get_identity_public_data(
                &node_id_test_other(),
                &Email::new("part2@example.com").unwrap(),
                vec![],
            )),
            BillParticipant::Ident(get_identity_public_data(
                &node_id_test_other2(),
                &Email::new("part3@example.com").unwrap(),
                vec![],
            )),
        ];

        let service = expect_service(|mock, _, _, _, _, _, _, _| {
            mock.expect_get_sender_node_id().returning(node_id_test);

            // expect to never send timeout event on non expiring events
            mock.expect_send_private_event().never();
        });

        service
            .send_request_to_action_timed_out_event(
                &node_id_test(),
                &bill_id_test(),
                Some(Sum::new_sat(100).expect("sat works")),
                ActionType::CheckBill,
                recipients.clone(),
                &node_id_test(),
                &node_id_test(),
                &None,
            )
            .await
            .expect("failed to send event");
    }

    #[tokio::test]
    async fn get_client_notifications() {
        init_test_cfg();
        let result =
            Notification::new_bill_notification(&bill_id_test(), &node_id_test(), "desc", None);
        let filter = NotificationFilter {
            active: Some(true),
            ..Default::default()
        };

        let service = expect_service(|mock_transport, _, _, _, _, mock_store, _, _| {
            let returning = result.clone();
            mock_store
                .expect_list()
                .with(eq(filter.clone()))
                .returning(move |_| Ok(vec![returning.clone()]));

            mock_transport
                .expect_get_sender_node_id()
                .returning(node_id_test);
        });

        let res = service
            .get_client_notifications(filter)
            .await
            .expect("could not get notifications");
        assert!(!res.is_empty());
        assert_eq!(res[0].id, result.id);
    }

    #[tokio::test]
    async fn wrong_network_failures() {
        init_test_cfg();
        let mainnet_node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Bitcoin);
        let mainnet_bill_id = BillId::new(BcrKeys::new().pub_key(), bitcoin::Network::Bitcoin);
        let filter = NotificationFilter {
            node_ids: vec![mainnet_node_id.clone()],
            ..Default::default()
        };

        let service = expect_service(|mock_transport, _, _, _, _, _, _, _| {
            mock_transport
                .expect_get_sender_node_id()
                .returning(node_id_test);
        });

        assert!(service.get_client_notifications(filter).await.is_err());
        assert!(
            service
                .check_bill_notification_sent(&mainnet_bill_id, 0, ActionType::CheckBill)
                .await
                .is_err()
        );
        assert!(
            service
                .mark_bill_notification_sent(&mainnet_bill_id, 0, ActionType::CheckBill)
                .await
                .is_err()
        );
        assert!(
            service
                .get_active_bill_notification(&mainnet_bill_id)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn get_mark_notification_done() {
        init_test_cfg();

        let service = expect_service(|mock_transport, _, _, _, _, mock_store, _, _| {
            mock_store
                .expect_mark_as_done()
                .with(eq("notification_id"))
                .returning(|_| Ok(()));

            mock_transport
                .expect_get_sender_node_id()
                .returning(node_id_test);
        });

        service
            .mark_notification_as_done("notification_id")
            .await
            .expect("could not mark notification as done");
    }

    #[tokio::test]
    async fn test_get_email_notifications_preferences_link() {
        init_test_cfg();

        let service = expect_service(|mock_transport, _, _, _, _, _, email_store, _| {
            email_store
                .expect_get_email_preferences_link_for_node_id()
                .returning(|_| Ok(Some(url::Url::parse("http://bit.cr/").unwrap())))
                .times(1);
            mock_transport
                .expect_get_sender_node_id()
                .returning(node_id_test);
        });

        let result = service
            .get_email_notifications_preferences_link(&node_id_test())
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.as_ref().unwrap(),
            &url::Url::parse("http://bit.cr/").unwrap()
        );
    }

    #[tokio::test]
    async fn test_get_email_notifications_preferences_link_no_entry() {
        init_test_cfg();
        let service = expect_service(|mock_transport, _, _, _, _, _, email_store, _| {
            email_store
                .expect_get_email_preferences_link_for_node_id()
                .returning(|_| Ok(None))
                .times(1);
            mock_transport
                .expect_get_sender_node_id()
                .returning(node_id_test);
        });
        let result = service
            .get_email_notifications_preferences_link(&node_id_test())
            .await;
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::NotFound)));
    }

    fn get_mocks() -> (
        MockNotificationJsonTransport,
        MockContactStore,
        MockNostrContactStore,
        MockNostrQueuedMessageStore,
        MockNostrChainEventStore,
        MockNotificationStore,
        MockEmailNotificationStore,
        MockEmailClient,
    ) {
        (
            MockNotificationJsonTransport::new(),
            MockContactStore::new(),
            MockNostrContactStore::new(),
            MockNostrQueuedMessageStore::new(),
            MockNostrChainEventStore::new(),
            MockNotificationStore::new(),
            MockEmailNotificationStore::new(),
            MockEmailClient::new(),
        )
    }
    fn get_transport(
        mock_transport: MockNotificationJsonTransport,
        contact_store: MockContactStore,
        nostr_contact_store: MockNostrContactStore,
        queued_message_store: MockNostrQueuedMessageStore,
        chain_events: MockNostrChainEventStore,
        notification_store: MockNotificationStore,
        email_notification_store: MockEmailNotificationStore,
        email_client: MockEmailClient,
    ) -> NotificationTransportService {
        NotificationTransportService::new(
            Arc::new(get_nostr_transport(
                mock_transport,
                contact_store,
                nostr_contact_store,
                queued_message_store,
                chain_events,
            )),
            Arc::new(notification_store),
            Arc::new(email_notification_store),
            Arc::new(email_client),
        )
    }

    fn expect_service(
        expect: impl Fn(
            &mut MockNotificationJsonTransport,
            &mut MockContactStore,
            &mut MockNostrContactStore,
            &mut MockNostrQueuedMessageStore,
            &mut MockNostrChainEventStore,
            &mut MockNotificationStore,
            &mut MockEmailNotificationStore,
            &mut MockEmailClient,
        ),
    ) -> NotificationTransportService {
        let (
            mut transport,
            mut contact_store,
            mut nostr_contact_store,
            mut queued_message_store,
            mut chain_events,
            mut notification_store,
            mut email_notification_store,
            mut email_client,
        ) = get_mocks();
        expect(
            &mut transport,
            &mut contact_store,
            &mut nostr_contact_store,
            &mut queued_message_store,
            &mut chain_events,
            &mut notification_store,
            &mut email_notification_store,
            &mut email_client,
        );
        get_transport(
            transport,
            contact_store,
            nostr_contact_store,
            queued_message_store,
            chain_events,
            notification_store,
            email_notification_store,
            email_client,
        )
    }

    fn check_chain_payload(event: &EventEnvelope, bill_event_type: BillEventType) -> bool {
        let valid_event_type = event.event_type == EventType::Bill;
        let event: Result<Event<BillChainEventPayload>> = event.clone().try_into();
        if let Ok(event) = event {
            valid_event_type && event.data.event_type == bill_event_type
        } else {
            false
        }
    }
}
