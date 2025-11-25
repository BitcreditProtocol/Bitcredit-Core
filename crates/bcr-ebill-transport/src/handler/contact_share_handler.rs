use std::sync::Arc;

use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_api::service::transport_service::transport_client::TransportClientApi;
use bcr_ebill_core::{
    application::ContactShareEvent,
    application::ServiceTraitBounds,
    application::contact::Contact,
    application::nostr_contact::NostrContact,
    application::notification::Notification,
    protocol::{
        crypto::decrypt_ecies,
        event::{Event, EventEnvelope},
    },
};
use bcr_ebill_persistence::{
    ContactStoreApi, NotificationStoreApi, PendingContactShare, ShareDirection,
    nostr::NostrContactStoreApi,
};
use bitcoin::base58;
use log::{debug, warn};
use uuid::Uuid;

use crate::EventType;
use crate::PushApi;
use bcr_ebill_api::service::transport_service::{Error, Result};

use super::NotificationHandlerApi;

#[derive(Clone)]
pub struct ContactShareEventHandler {
    transport: Arc<dyn TransportClientApi>,
    contact_store: Arc<dyn ContactStoreApi>,
    nostr_contact_store: Arc<dyn NostrContactStoreApi>,
    notification_store: Arc<dyn NotificationStoreApi>,
    push_service: Arc<dyn PushApi>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationHandlerApi for ContactShareEventHandler {
    fn handles_event(&self, event_type: &EventType) -> bool {
        event_type == &EventType::ContactShare
    }

    async fn handle_event(
        &self,
        event: EventEnvelope,
        node_id: &NodeId,
        sender: Option<nostr::PublicKey>,
        _: Option<Box<nostr::Event>>,
    ) -> Result<()> {
        debug!("incoming contact share for {node_id}");
        if let Ok(decoded) = Event::<ContactShareEvent>::try_from(event.clone()) {
            // Check if this is a share-back (auto-accept scenario)
            if let Some(pending_share_id) = &decoded.data.share_back_pending_id {
                debug!("share-back pending ID present, checking for matching pending share");
                if let Ok(Some(_pending_share)) = self
                    .nostr_contact_store
                    .get_pending_share(pending_share_id)
                    .await
                {
                    debug!("found matching pending share, auto-accepting");
                    // Auto-accept: immediately add the contact
                    return self
                        .accept_contact_share(&decoded.data, node_id, sender)
                        .await;
                }
            }

            // Regular flow or no matching share-back: create pending share
            if let Ok(Some(contact_data)) =
                self.transport.resolve_contact(&decoded.data.node_id).await
                && let Some(bcr_metadata) = contact_data.get_bcr_metadata()
            {
                let decrypted = decrypt_ecies(
                    &base58::decode(&bcr_metadata.contact_data)?,
                    &decoded.data.private_key,
                )?;
                let contact = serde_json::from_slice::<Contact>(&decrypted)?;

                // Check if contact already exists in contacts
                let contact_exists = self
                    .contact_store
                    .get(&decoded.data.node_id)
                    .await
                    .ok()
                    .flatten()
                    .is_some();

                // Check if contact already exists as a manually created contact (no private key in NostrContact)
                let is_manual_contact = if let Ok(Some(nostr_contact)) = self
                    .nostr_contact_store
                    .by_node_id(&decoded.data.node_id)
                    .await
                {
                    contact_exists && nostr_contact.contact_private_key.is_none()
                } else {
                    false
                };

                // Check if pending share already exists for this contact and receiver
                let pending_exists = self
                    .nostr_contact_store
                    .pending_share_exists_for_node_and_receiver(&decoded.data.node_id, node_id)
                    .await
                    .unwrap_or(false);

                // Only create pending share if it doesn't already exist and is either a manual contact or a new contact
                if !pending_exists && (is_manual_contact || !contact_exists) {
                    // The sender_node_id is the node_id from the ContactShareEvent
                    // (the person sharing their contact)
                    let sender_node_id = decoded.data.node_id.clone();

                    let pending_share_id = Uuid::new_v4().to_string();
                    let pending_share = PendingContactShare {
                        id: pending_share_id.clone(),
                        node_id: decoded.data.node_id.clone(),
                        contact: contact.clone(),
                        sender_node_id,
                        contact_private_key: decoded.data.private_key,
                        receiver_node_id: node_id.clone(),
                        received_at: bcr_ebill_core::protocol::Timestamp::now(),
                        direction: ShareDirection::Incoming,
                        initial_share_id: Some(decoded.data.initial_share_id.clone()),
                    };

                    self.nostr_contact_store
                        .add_pending_share(pending_share)
                        .await
                        .map_err(|e| Error::Persistence(e.to_string()))?;

                    debug!("created pending contact share for {node_id}");

                    // Create notification for the pending contact share
                    let description = if is_manual_contact {
                        "New contact share received for existing manual contact"
                    } else {
                        "New contact share received"
                    };

                    let notification = Notification::new_contact_notification(
                        &pending_share_id,
                        node_id,
                        description,
                        serde_json::to_value(contact).ok(),
                    );

                    self.notification_store
                        .add(notification.clone())
                        .await
                        .map_err(|e| Error::Persistence(e.to_string()))?;

                    debug!("created notification for pending contact share");

                    // Send push notification to connected clients
                    match serde_json::to_value(notification) {
                        Ok(notification_value) => {
                            self.push_service.send(notification_value).await;
                        }
                        Err(e) => {
                            warn!("Failed to serialize notification for push service: {e}");
                        }
                    }
                }
            }
        } else {
            warn!("Could not decode event to ContactShareEvent {event:?}");
        }
        Ok(())
    }
}

impl ServiceTraitBounds for ContactShareEventHandler {}

impl ContactShareEventHandler {
    pub fn new(
        transport: Arc<dyn TransportClientApi>,
        contact_store: Arc<dyn ContactStoreApi>,
        nostr_contact_store: Arc<dyn NostrContactStoreApi>,
        notification_store: Arc<dyn NotificationStoreApi>,
        push_service: Arc<dyn PushApi>,
    ) -> Self {
        Self {
            transport,
            contact_store,
            nostr_contact_store,
            notification_store,
            push_service,
        }
    }

    async fn accept_contact_share(
        &self,
        share_event: &ContactShareEvent,
        node_id: &NodeId,
        _sender: Option<nostr::PublicKey>,
    ) -> Result<()> {
        if let Ok(Some(contact_data)) = self.transport.resolve_contact(&share_event.node_id).await
            && let Some(bcr_metadata) = contact_data.get_bcr_metadata()
        {
            let decrypted = decrypt_ecies(
                &base58::decode(&bcr_metadata.contact_data)?,
                &share_event.private_key,
            )?;
            let contact = serde_json::from_slice::<Contact>(&decrypted)?;

            // Add/update the contact
            if let Ok(Some(_)) = self.contact_store.get(&share_event.node_id).await {
                self.contact_store
                    .update(&share_event.node_id, contact.clone())
                    .await
                    .map_err(|e| Error::Persistence(e.to_string()))?;
            } else {
                self.contact_store
                    .insert(&share_event.node_id, contact.clone())
                    .await
                    .map_err(|e| Error::Persistence(e.to_string()))?;
            }

            // Update NostrContact with the private key
            let upsert = if let Ok(Some(nostr_contact)) = self
                .nostr_contact_store
                .by_node_id(&share_event.node_id)
                .await
            {
                nostr_contact.merge_contact(&contact, Some(share_event.private_key))
            } else {
                NostrContact::from_contact(&contact, Some(share_event.private_key))?
            };
            self.nostr_contact_store
                .upsert(&upsert)
                .await
                .map_err(|e| Error::Persistence(e.to_string()))?;

            debug!("successfully auto-accepted shared contact data for {node_id}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        handler::test_utils::{MockPushService, node_id_test},
        test_utils::{
            MockContactStore, MockNostrContactStore, MockNotificationJsonTransport,
            MockNotificationStore,
        },
    };

    use super::*;
    use bcr_ebill_api::service::transport_service::{BcrMetadata, NostrContactData};
    use bcr_ebill_core::{
        protocol::Name,
        protocol::blockchain::bill::block::ContactType,
        protocol::crypto::{BcrKeys, encrypt_ecies},
    };
    use bitcoin::base58;
    use mockall::predicate::{always, eq};

    #[tokio::test]
    async fn test_process_share_creates_pending_share() {
        let (mut transport, mut contact, mut nostr_contact, mut notification, mut push_service) =
            get_mocks();
        let keys = BcrKeys::new();

        let event = Event::new_contact_share(ContactShareEvent {
            node_id: node_id_test(),
            private_key: keys.get_private_key(),
            initial_share_id: "initial-123".to_string(),
            share_back_pending_id: None,
        });

        transport
            .expect_resolve_contact()
            .with(eq(node_id_test()))
            .returning(move |_| Ok(Some(get_contact_data(keys.clone()))))
            .once();

        contact
            .expect_get()
            .with(eq(node_id_test()))
            .returning(|_| Ok(None))
            .once();

        nostr_contact
            .expect_by_node_id()
            .with(eq(node_id_test()))
            .returning(|_| Ok(None))
            .once();

        // Expect pending share to be checked and created
        nostr_contact
            .expect_pending_share_exists_for_node_and_receiver()
            .with(eq(node_id_test()), eq(node_id_test()))
            .returning(|_, _| Ok(false))
            .once();

        nostr_contact
            .expect_add_pending_share()
            .withf(|share| {
                share.node_id == node_id_test() && share.contact.name.to_string() == "My Name"
            })
            .returning(|_| Ok(()))
            .once();

        // Expect notification to be created
        notification
            .expect_add()
            .withf(|n| {
                n.notification_type
                    == bcr_ebill_core::application::notification::NotificationType::Contact
            })
            .returning(Ok)
            .once();

        // Expect push notification to be sent
        push_service.expect_send().times(1).returning(|_| ());

        let handler = ContactShareEventHandler::new(
            Arc::new(transport),
            Arc::new(contact),
            Arc::new(nostr_contact),
            Arc::new(notification),
            Arc::new(push_service),
        );

        handler
            .handle_event(event.try_into().unwrap(), &node_id_test(), None, None)
            .await
            .expect("Event successfully handled");
    }

    #[tokio::test]
    async fn test_process_share_with_share_back_pending_id_auto_accepts() {
        let (mut transport, mut contact, mut nostr_contact, notification, push_service) =
            get_mocks();
        let keys = BcrKeys::new();
        let pending_share_id = "test_pending_share_id".to_string();

        // Create a pending share that matches the pending_share_id
        let pending_share = PendingContactShare {
            id: pending_share_id.clone(),
            node_id: node_id_test(),
            contact: get_contact(),
            sender_node_id: node_id_test(),
            contact_private_key: keys.get_private_key(),
            receiver_node_id: node_id_test(),
            received_at: bcr_ebill_core::protocol::Timestamp::now(),
            direction: ShareDirection::Outgoing,
            initial_share_id: None,
        };

        let event = Event::new_contact_share(ContactShareEvent {
            node_id: node_id_test(),
            private_key: keys.get_private_key(),
            initial_share_id: "initial-share-back-123".to_string(),
            share_back_pending_id: Some(pending_share_id.clone()),
        });

        // Expect check for share-back pending ID
        nostr_contact
            .expect_get_pending_share()
            .with(eq(pending_share_id))
            .returning(move |_| Ok(Some(pending_share.clone())))
            .once();

        transport
            .expect_resolve_contact()
            .with(eq(node_id_test()))
            .returning(move |_| Ok(Some(get_contact_data(keys.clone()))))
            .once();

        // Auto-accept flow: update or insert contact
        contact
            .expect_get()
            .with(eq(node_id_test()))
            .returning(|_| Ok(None))
            .once();

        contact
            .expect_insert()
            .with(eq(node_id_test()), always())
            .returning(|_, _| Ok(()))
            .once();

        // Auto-accept flow: update nostr contact
        nostr_contact
            .expect_by_node_id()
            .with(eq(node_id_test()))
            .returning(|_| Ok(None))
            .once();

        nostr_contact
            .expect_upsert()
            .withf(|c| c.contact_private_key.is_some())
            .returning(|_| Ok(()))
            .once();

        let handler = ContactShareEventHandler::new(
            Arc::new(transport),
            Arc::new(contact),
            Arc::new(nostr_contact),
            Arc::new(notification),
            Arc::new(push_service),
        );

        handler
            .handle_event(event.try_into().unwrap(), &node_id_test(), None, None)
            .await
            .expect("Event successfully handled with auto-accept");
    }

    #[tokio::test]
    async fn test_process_share_skips_duplicate_pending() {
        let (mut transport, mut contact, mut nostr_contact, notification, push_service) =
            get_mocks();
        let keys = BcrKeys::new();

        let event = Event::new_contact_share(ContactShareEvent {
            node_id: node_id_test(),
            private_key: keys.get_private_key(),
            initial_share_id: "initial-456".to_string(),
            share_back_pending_id: None,
        });

        transport
            .expect_resolve_contact()
            .with(eq(node_id_test()))
            .returning(move |_| Ok(Some(get_contact_data(keys.clone()))))
            .once();

        contact
            .expect_get()
            .with(eq(node_id_test()))
            .returning(|_| Ok(None))
            .once();

        nostr_contact
            .expect_by_node_id()
            .with(eq(node_id_test()))
            .returning(|_| Ok(None))
            .once();

        // Pending share already exists
        nostr_contact
            .expect_pending_share_exists_for_node_and_receiver()
            .with(eq(node_id_test()), eq(node_id_test()))
            .returning(|_, _| Ok(true))
            .once();

        // Should NOT add a new pending share or notification

        let handler = ContactShareEventHandler::new(
            Arc::new(transport),
            Arc::new(contact),
            Arc::new(nostr_contact),
            Arc::new(notification),
            Arc::new(push_service),
        );

        handler
            .handle_event(event.try_into().unwrap(), &node_id_test(), None, None)
            .await
            .expect("Event successfully handled - duplicate skipped");
    }

    fn get_contact_data(keys: BcrKeys) -> NostrContactData {
        let contact = get_contact();
        let payload = serde_json::to_vec(&contact).unwrap();
        let encypted = base58::encode(&encrypt_ecies(payload.as_slice(), &keys.pub_key()).unwrap());

        NostrContactData::new(
            &Name::new("My Name").unwrap(),
            vec![],
            BcrMetadata {
                contact_data: encypted,
            },
        )
    }

    fn get_contact() -> Contact {
        Contact {
            t: ContactType::Person,
            node_id: node_id_test(),
            name: Name::new("My Name").unwrap(),
            email: None,
            postal_address: None,
            date_of_birth_or_registration: None,
            country_of_birth_or_registration: None,
            city_of_birth_or_registration: None,
            identification_number: None,
            avatar_file: None,
            proof_document_file: None,
            nostr_relays: vec![],
            is_logical: false,
        }
    }

    fn get_mocks() -> (
        MockNotificationJsonTransport,
        MockContactStore,
        MockNostrContactStore,
        MockNotificationStore,
        MockPushService,
    ) {
        (
            MockNotificationJsonTransport::new(),
            MockContactStore::new(),
            MockNostrContactStore::new(),
            MockNotificationStore::new(),
            MockPushService::new(),
        )
    }
}
