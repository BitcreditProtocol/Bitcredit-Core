use std::sync::Arc;

use async_trait::async_trait;
use bcr_ebill_api::{
    service::notification_service::{
        event::ContactShareEvent, transport::NotificationJsonTransportApi,
    },
    util::{base58_decode, crypto::decrypt_ecies},
};
use bcr_ebill_core::{NodeId, ServiceTraitBounds, contact::Contact, nostr_contact::NostrContact};
use bcr_ebill_persistence::{ContactStoreApi, nostr::NostrContactStoreApi};
use log::{debug, warn};

use crate::EventType;
use bcr_ebill_api::service::notification_service::event::Event;
use bcr_ebill_api::service::notification_service::{Error, Result, event::EventEnvelope};

use super::NotificationHandlerApi;

#[derive(Clone)]
pub struct ContactShareEventHandler {
    transport: Arc<dyn NotificationJsonTransportApi>,
    contact_store: Arc<dyn ContactStoreApi>,
    nostr_contact_store: Arc<dyn NostrContactStoreApi>,
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
        _: Option<Box<nostr::Event>>,
    ) -> Result<()> {
        debug!("incoming contact share for {node_id}");
        if let Ok(decoded) = Event::<ContactShareEvent>::try_from(event.clone()) {
            if let Ok(Some(contact_data)) =
                self.transport.resolve_contact(&decoded.data.node_id).await
                && let Some(bcr_metadata) = contact_data.get_bcr_metadata()
            {
                let decrypted = decrypt_ecies(
                    &base58_decode(&bcr_metadata.contact_data)?,
                    &decoded.data.private_key,
                )?;
                let contact = serde_json::from_slice::<Contact>(&decrypted)?;
                debug!(
                    "successfully decrypted shared contact data for {node_id} storing keys and contact"
                );
                if let Ok(Some(_)) = self.contact_store.get(&decoded.data.node_id).await {
                    self.contact_store
                        .update(&decoded.data.node_id, contact.clone())
                        .await
                        .map_err(|e| Error::Persistence(e.to_string()))?;
                } else {
                    self.contact_store
                        .insert(&decoded.data.node_id, contact.clone())
                        .await
                        .map_err(|e| Error::Persistence(e.to_string()))?;
                }

                let upsert = if let Ok(Some(nostr_contact)) = self
                    .nostr_contact_store
                    .by_node_id(&decoded.data.node_id)
                    .await
                {
                    nostr_contact.merge_contact(&contact, Some(decoded.data.private_key))
                } else {
                    NostrContact::from_contact(&contact, Some(decoded.data.private_key))?
                };
                self.nostr_contact_store
                    .upsert(&upsert)
                    .await
                    .map_err(|e| Error::Persistence(e.to_string()))?;

                debug!("successfully updated shared contact data and stored keys for {node_id}");
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
        transport: Arc<dyn NotificationJsonTransportApi>,
        contact_store: Arc<dyn ContactStoreApi>,
        nostr_contact_store: Arc<dyn NostrContactStoreApi>,
    ) -> Self {
        Self {
            transport,
            contact_store,
            nostr_contact_store,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        handler::test_utils::node_id_test,
        test_utils::{MockContactStore, MockNostrContactStore, MockNotificationJsonTransport},
    };

    use super::*;
    use bcr_ebill_api::{
        service::notification_service::{BcrMetadata, NostrContactData},
        util::{base58_encode, crypto::encrypt_ecies},
    };
    use bcr_ebill_core::{contact::ContactType, util::crypto::BcrKeys};
    use mockall::predicate::{always, eq};

    #[tokio::test]
    async fn test_process_share_success() {
        let (mut transport, mut contact, mut nostr_contact) = get_mocks();
        let keys = BcrKeys::new();

        let event = Event::new_contact_share(ContactShareEvent {
            node_id: node_id_test(),
            private_key: keys.get_private_key(),
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

        contact
            .expect_insert()
            .with(eq(node_id_test()), always())
            .returning(|_, _| Ok(()))
            .once();

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
        );

        handler
            .handle_event(event.try_into().unwrap(), &node_id_test(), None)
            .await
            .expect("Event successfully handled");
    }

    fn get_contact_data(keys: BcrKeys) -> NostrContactData {
        let contact = get_contact();
        let payload = serde_json::to_vec(&contact).unwrap();
        let encypted = base58_encode(&encrypt_ecies(payload.as_slice(), &keys.pub_key()).unwrap());

        NostrContactData::new(
            "My Name",
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
            name: "My Name".to_owned(),
            email: None,
            postal_address: None,
            date_of_birth_or_registration: None,
            country_of_birth_or_registration: None,
            city_of_birth_or_registration: None,
            identification_number: None,
            avatar_file: None,
            proof_document_file: None,
            nostr_relays: vec![],
        }
    }

    fn get_mocks() -> (
        MockNotificationJsonTransport,
        MockContactStore,
        MockNostrContactStore,
    ) {
        (
            MockNotificationJsonTransport::new(),
            MockContactStore::new(),
            MockNostrContactStore::new(),
        )
    }
}
