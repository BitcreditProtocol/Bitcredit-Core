use async_trait::async_trait;
use bcr_ebill_persistence::traits::propagation::PreparedPropagationMessage;
use std::collections::HashMap;

use super::handler::NotificationHandlerApi;
use super::nostr_transport::NostrTransportService;
use crate::propagation::NostrPropagationService;
use bcr_common::core::NodeId;
use bcr_ebill_api::service::transport_service::Result;
use bcr_ebill_api::service::transport_service::{
    BlockTransportServiceApi, ContactTransportServiceApi, NotificationTransportServiceApi,
    TransportServiceApi,
};
use bcr_ebill_core::application::ServiceTraitBounds;
use bcr_ebill_core::protocol::crypto::BcrKeys;
use bcr_ebill_core::protocol::event::EventType;
use bcr_ebill_core::protocol::event::{BillChainEventPayload, Event};
use bcr_ebill_persistence::traits::propagation::{PropagationStatus, PropagationSubjectType};
use log::{debug, error, info, warn};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::watch;

pub struct TransportService {
    nostr_transport: Arc<NostrTransportService>,
    notification_transport_service: Arc<dyn NotificationTransportServiceApi>,
    contact_transport_service: Arc<dyn ContactTransportServiceApi>,
    block_transport_service: Arc<dyn BlockTransportServiceApi>,
    bill_invite_handler: Arc<dyn NotificationHandlerApi>,
    propagation_service: Arc<NostrPropagationService>,
    retry_loop_started: AtomicBool,
    retry_shutdown: watch::Sender<bool>,
}

impl TransportService {
    pub fn new(
        nostr_transport: Arc<NostrTransportService>,
        notification_transport_service: Arc<dyn NotificationTransportServiceApi>,
        contact_transport_service: Arc<dyn ContactTransportServiceApi>,
        block_transport_service: Arc<dyn BlockTransportServiceApi>,
        bill_invite_handler: Arc<dyn NotificationHandlerApi>,
        propagation_service: Arc<NostrPropagationService>,
    ) -> Self {
        let (retry_shutdown, _) = watch::channel(false);
        Self {
            nostr_transport,
            notification_transport_service,
            contact_transport_service,
            block_transport_service,
            bill_invite_handler,
            propagation_service,
            retry_loop_started: AtomicBool::new(false),
            retry_shutdown,
        }
    }
}

impl ServiceTraitBounds for TransportService {}

#[async_trait]
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
        if !self.retry_loop_started.swap(true, Ordering::AcqRel) {
            let propagation = self.propagation_service.clone();
            let shutdown = self.retry_shutdown.subscribe();
            tokio::spawn(async move {
                propagation.run_retry_loop(shutdown).await;
            });
        }
    }

    async fn ensure_publish_ready(&self) -> Result<()> {
        let available = self
            .nostr_transport
            .get_first_transport()
            .has_connected_write_relay()
            .await;

        if !available {
            return Err(crate::Error::Network(
                "No connected Nostr write relays".to_string(),
            ));
        }

        Ok(())
    }

    async fn add_identity(&self, node_id: &NodeId, keys: &BcrKeys) -> Result<()> {
        self.nostr_transport.add_identity(node_id, keys).await
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

    async fn process_company_historical_bill_invites(&self, company_id: &NodeId) -> Result<()> {
        let node = self.nostr_transport.get_first_transport();
        if !node.has_local_signer(company_id) {
            warn!("Try to process_company_historical_bill_invites without signer in transport");
            return Ok(());
        };
        let events = node
            .resolve_events(
                nostr::filter::Filter::new()
                    .pubkey(company_id.npub())
                    .kinds(vec![nostr::event::Kind::GiftWrap])
                    .since(nostr::types::Timestamp::zero()),
            )
            .await?;
        info!(
            "found {} private events for company {} historical bill invite processing",
            events.len(),
            company_id
        );

        for event in events {
            match node.try_decrypt_private_event(&event).await {
                Ok(Some((_recipient_id, envelope, sender))) => {
                    if envelope.event_type == EventType::BillChainInvite
                        && let Err(e) = self
                            .bill_invite_handler
                            .handle_event(envelope, company_id, Some(sender), Some(Box::new(event)))
                            .await
                    {
                        error!(
                            "Failed to process historical bill invite for company {}: {}",
                            company_id, e
                        );
                    }
                }
                Ok(None) => {
                    debug!(
                        "Could not decrypt event {} for company {}",
                        event.id, company_id
                    );
                }
                Err(e) => {
                    error!(
                        "Error decrypting event {} for company {}: {}",
                        event.id, company_id, e
                    );
                }
            }
        }
        Ok(())
    }

    async fn publish_file_metadata(
        &self,
        node_id: &NodeId,
        plaintext_hash: &str,
        encrypted_hash: &str,
        server_urls: Vec<url::Url>,
        mime_type: Option<String>,
    ) -> Result<()> {
        self.nostr_transport
            .get_first_transport()
            .publish_file_metadata(
                node_id,
                plaintext_hash,
                encrypted_hash,
                server_urls,
                mime_type,
            )
            .await
    }

    async fn query_file_metadata_events(
        &self,
        file_hash: &str,
        nostr_hash: &str,
    ) -> Result<Vec<nostr::event::Event>> {
        self.nostr_transport
            .get_first_transport()
            .query_file_metadata_events(file_hash, nostr_hash)
            .await
    }

    async fn prepare_bill_private_messages(
        &self,
        sender: &NodeId,
        events: &HashMap<NodeId, Event<BillChainEventPayload>>,
    ) -> Result<Vec<PreparedPropagationMessage>> {
        self.nostr_transport
            .prepare_bill_private_messages(sender, events)
            .await
    }

    async fn writable_relay_urls(&self) -> Result<Vec<url::Url>> {
        self.nostr_transport
            .get_first_transport()
            .writable_relay_urls()
            .await
    }

    async fn attempt_propagation(
        &self,
        propagation_id: &str,
        required_message_ids: &[String],
    ) -> Result<()> {
        self.propagation_service
            .attempt_propagation(propagation_id, required_message_ids)
            .await?;
        Ok(())
    }

    async fn get_propagation_status(
        &self,
        propagation_id: &str,
    ) -> Result<Option<PropagationStatus>> {
        self.propagation_service
            .get_propagation_status(propagation_id)
            .await
    }

    async fn get_latest_propagation(
        &self,
        subject_type: PropagationSubjectType,
        subject_id: &str,
    ) -> Result<Option<PropagationStatus>> {
        self.propagation_service
            .get_latest_propagation(subject_type, subject_id)
            .await
    }

    fn stop_propagation_retries(&self) {
        self.retry_shutdown.send_replace(true);
    }

    async fn retry_pending_propagations_now(&self) -> Result<()> {
        // only attempt it if we're online
        self.ensure_publish_ready().await?;
        self.propagation_service.retry_pending_now().await
    }
}

impl Drop for TransportService {
    fn drop(&mut self) {
        self.retry_shutdown.send_replace(true);
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::{
        MockBlockTransportService, MockContactTransportService, MockNostrPropagationStoreApiMock,
        MockNotificationTransportService, get_nostr_transport, test_cfg,
    };
    use crate::test_utils::{
        MockContactStore, MockNostrChainEventStore, MockNostrContactStore,
        MockNotificationJsonTransport, bill_id_test, node_id_test,
    };
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use bcr_ebill_core::protocol::event::{ChainInvite, EventEnvelope, EventType};
    use mockall::predicate::eq;
    use nostr::event::FinalizeEvent;
    use std::sync::Arc;

    use super::super::test_utils::MockNotificationHandler;
    use super::*;

    fn get_transport_with_handler(
        mock_transport: MockNotificationJsonTransport,
        contact_store: MockContactStore,
        nostr_contact_store: MockNostrContactStore,
        chain_events: MockNostrChainEventStore,
        mock_notification_transport: MockNotificationTransportService,
        mock_contact_transport: MockContactTransportService,
        mock_block_transport: MockBlockTransportService,
        handler: Arc<dyn NotificationHandlerApi>,
    ) -> TransportService {
        TransportService::new(
            Arc::new(get_nostr_transport(
                mock_transport,
                contact_store,
                nostr_contact_store,
                chain_events,
            )),
            Arc::new(mock_notification_transport),
            Arc::new(mock_contact_transport),
            Arc::new(mock_block_transport),
            handler,
            Arc::new(NostrPropagationService::new(
                Arc::new(MockNostrPropagationStoreApiMock::new()),
                Arc::new(MockNotificationJsonTransport::new()),
                bitcoin::Network::Testnet,
            )),
        )
    }

    #[tokio::test]
    async fn test_connect() {
        let mut mock_transport = MockNotificationJsonTransport::new();

        // call connect on the inner transport
        mock_transport.expect_connect().returning(|| Ok(()));

        let service = NostrTransportService::new(
            Arc::new(mock_transport),
            Arc::new(MockContactStore::new()),
            Arc::new(MockNostrContactStore::new()),
            Arc::new(MockNostrChainEventStore::new()),
            vec![url::Url::parse("ws://test.relay").unwrap()],
            Arc::new(test_cfg()),
        );

        service.connect().await;
    }

    #[tokio::test]
    async fn test_process_company_historical_bill_invites_success() {
        let company_id = node_id_test();
        let sender_npub = nostr::key::PublicKey::from_hex(
            "22886f449bec154764401cfb139b80f108a39a91c7e7609f9ffd8a4592b86d38",
        )
        .unwrap();

        let mut mock_transport = MockNotificationJsonTransport::new();
        mock_transport
            .expect_has_local_signer()
            .with(eq(company_id.clone()))
            .returning(|_| true);

        let event = nostr::event::EventBuilder::new(nostr::event::Kind::TextNote, "test")
            .finalize(&nostr::key::Keys::generate())
            .expect(" Could not create test event");

        let invite = ChainInvite::bill(bill_id_test().to_string(), BcrKeys::new());
        let envelope: EventEnvelope = Event::new(EventType::BillChainInvite, invite.clone())
            .try_into()
            .unwrap();

        let company_id_for_decrypt = company_id.clone();
        mock_transport
            .expect_resolve_events()
            .returning(move |_| Ok(vec![event.clone()]));
        mock_transport
            .expect_try_decrypt_private_event()
            .returning(move |_| {
                Ok(Some((
                    company_id_for_decrypt.clone(),
                    envelope.clone(),
                    sender_npub,
                )))
            });

        let mut handler = MockNotificationHandler::new();
        let company_id_for_handler = company_id.clone();
        handler
            .expect_handle_event()
            .withf(move |env, node_id, sender, _original_event| {
                env.event_type == EventType::BillChainInvite
                    && *node_id == company_id_for_handler
                    && sender.is_some()
            })
            .returning(|_, _, _, _| Ok(()))
            .times(1);

        let service = get_transport_with_handler(
            mock_transport,
            MockContactStore::new(),
            MockNostrContactStore::new(),
            MockNostrChainEventStore::new(),
            MockNotificationTransportService::new(),
            MockContactTransportService::new(),
            MockBlockTransportService::new(),
            Arc::new(handler),
        );

        let result = service
            .process_company_historical_bill_invites(&company_id)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_process_company_historical_bill_invites_skips_non_invite() {
        let company_id = node_id_test();
        let sender_npub = nostr::key::PublicKey::from_hex(
            "22886f449bec154764401cfb139b80f108a39a91c7e7609f9ffd8a4592b86d38",
        )
        .unwrap();

        let mut mock_transport = MockNotificationJsonTransport::new();
        mock_transport
            .expect_has_local_signer()
            .with(eq(company_id.clone()))
            .returning(|_| true);

        let event = nostr::event::EventBuilder::new(nostr::event::Kind::TextNote, "test")
            .finalize(&nostr::key::Keys::generate())
            .expect(" Could not create test event");

        let non_invite = ChainInvite::company(node_id_test().to_string(), BcrKeys::new());
        let envelope: EventEnvelope = Event::new(EventType::CompanyChainInvite, non_invite.clone())
            .try_into()
            .unwrap();

        let company_id_for_decrypt = company_id.clone();
        mock_transport
            .expect_resolve_events()
            .returning(move |_| Ok(vec![event.clone()]));
        mock_transport
            .expect_try_decrypt_private_event()
            .returning(move |_| {
                Ok(Some((
                    company_id_for_decrypt.clone(),
                    envelope.clone(),
                    sender_npub,
                )))
            });

        let mut handler = MockNotificationHandler::new();
        handler.expect_handle_event().times(0);

        let service = get_transport_with_handler(
            mock_transport,
            MockContactStore::new(),
            MockNostrContactStore::new(),
            MockNostrChainEventStore::new(),
            MockNotificationTransportService::new(),
            MockContactTransportService::new(),
            MockBlockTransportService::new(),
            Arc::new(handler),
        );

        let result = service
            .process_company_historical_bill_invites(&company_id)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_process_company_historical_bill_invites_no_signer() {
        let company_id = node_id_test();

        let mut mock_transport = MockNotificationJsonTransport::new();
        mock_transport
            .expect_has_local_signer()
            .with(eq(company_id.clone()))
            .returning(|_| false);
        mock_transport.expect_resolve_events().times(0);

        let service = get_transport_with_handler(
            mock_transport,
            MockContactStore::new(),
            MockNostrContactStore::new(),
            MockNostrChainEventStore::new(),
            MockNotificationTransportService::new(),
            MockContactTransportService::new(),
            MockBlockTransportService::new(),
            Arc::new(MockNotificationHandler::new()),
        );

        let result = service
            .process_company_historical_bill_invites(&company_id)
            .await;
        assert!(result.is_ok());
    }
}
