use std::sync::Arc;

use crate::handler::NostrContactProcessorApi;
use crate::nostr_transport::NostrTransportService;
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_api::service::transport_service::NostrContactData;
use bcr_ebill_api::util::validate_node_id_network;

use bcr_ebill_api::service::transport_service::ContactTransportServiceApi;
use bcr_ebill_core::application::{ContactShareEvent, ServiceTraitBounds};
use bcr_ebill_core::protocol::crypto::{BcrKeys, decrypt_ecies};
use bcr_ebill_core::protocol::event::Event;
use bcr_ebill_persistence::nostr::NostrContactStoreApi;
use bcr_ebill_persistence::{PendingContactShare, ShareDirection};
use log::error;

use bcr_ebill_api::service::transport_service::{Error, Result};

#[derive(Clone)]
pub struct ContactTransportService {
    nostr_transport: Arc<NostrTransportService>,
    nostr_contact_store: Arc<dyn NostrContactStoreApi>,
    nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
}

impl ContactTransportService {
    pub fn new(
        nostr_transport: Arc<NostrTransportService>,
        nostr_contact_store: Arc<dyn NostrContactStoreApi>,
        nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
    ) -> Self {
        Self {
            nostr_transport,
            nostr_contact_store,
            nostr_contact_processor,
        }
    }
}

impl ServiceTraitBounds for ContactTransportService {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ContactTransportServiceApi for ContactTransportService {
    /// Attempts to resolve the nostr contact for the given Node Id
    async fn resolve_contact(&self, node_id: &NodeId) -> Result<Option<NostrContactData>> {
        validate_node_id_network(node_id)?;
        // take any transport - doesn't matter
        let transport = self.nostr_transport.get_first_transport();
        let res = transport.resolve_contact(node_id).await?;
        Ok(res)
    }

    /// Publish contact data for NodeId to nostr. Will only publish if the NodeId points to a
    /// registered nostr client and therefore is our own.
    async fn publish_contact(&self, node_id: &NodeId, data: &NostrContactData) -> Result<()> {
        let transport = self.nostr_transport.get_node_transport(node_id);
        transport.publish_metadata(node_id, &data.metadata).await?;
        transport
            .publish_relay_list(node_id, data.relays.clone())
            .await?;
        Ok(())
    }

    /// Shares derived keys for private contact information via DM.
    async fn share_contact_details_keys(
        &self,
        recipient: &NodeId,
        contact_id: &NodeId,
        keys: &BcrKeys,
        share_back_pending_id: Option<String>,
    ) -> Result<()> {
        let relays = match self.nostr_contact_store.by_node_id(recipient).await {
            Ok(Some(contact)) => contact.relays,
            _ => self
                .resolve_contact(recipient)
                .await?
                .map(|c| c.relays.iter().map(|r| r.to_owned().into()).collect())
                .unwrap_or_default(),
        };
        if relays.is_empty() {
            error!("No relays found for contact {recipient}");
            return Err(Error::NotFound);
        }

        let private_key = keys.get_private_key();

        // Always generate a pending share ID upfront
        let initial_share_id = uuid::Uuid::new_v4().to_string();

        let event = Event::new_contact_share(ContactShareEvent {
            node_id: contact_id.to_owned(),
            private_key,
            initial_share_id: initial_share_id.clone(),
            share_back_pending_id: share_back_pending_id.clone(),
        });

        self.nostr_transport
            .send_private_event(contact_id, recipient, &relays, event.try_into()?)
            .await?;

        // Create an outgoing pending share to track this share for potential auto-accept
        // Only if this is NOT a share-back (share_back_pending_id is None)
        if share_back_pending_id.is_none()
            && let Ok(Some(contact_data)) = self.resolve_contact(contact_id).await
            && let Some(bcr_metadata) = contact_data.get_bcr_metadata()
            && let Ok(decrypted) = decrypt_ecies(
                &bitcoin::base58::decode(&bcr_metadata.contact_data).unwrap_or_default(),
                &private_key,
            )
            && let Ok(contact) =
                serde_json::from_slice::<bcr_ebill_core::application::contact::Contact>(&decrypted)
        {
            let pending_share = PendingContactShare {
                id: initial_share_id.to_owned(),
                node_id: contact_id.to_owned(),
                contact,
                sender_node_id: contact_id.to_owned(), // We are sharing our own contact
                contact_private_key: private_key,
                receiver_node_id: recipient.to_owned(),
                received_at: bcr_ebill_core::protocol::Timestamp::now(),
                direction: ShareDirection::Outgoing,
                initial_share_id: None, // We are the sender, so no initial_share_id
            };

            // Store the outgoing pending share
            if let Err(e) = self
                .nostr_contact_store
                .add_pending_share(pending_share)
                .await
            {
                error!(
                    "Failed to store pending share {initial_share_id} from {contact_id} to {recipient} with: {e}"
                );
            }
        }

        Ok(())
    }

    /// Ensures that the given node id is in our nostr contacts
    async fn ensure_nostr_contact(&self, node_id: &NodeId) {
        self.nostr_contact_processor
            .ensure_nostr_contact(node_id)
            .await;
    }
}
