use std::sync::Arc;

use crate::handler::NostrContactProcessorApi;
use crate::nostr_transport::NostrTransportService;
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_api::service::transport_service::NostrContactData;
use bcr_ebill_api::util::validate_node_id_network;

use bcr_ebill_api::service::transport_service::ContactTransportServiceApi;
use bcr_ebill_core::ServiceTraitBounds;
use bcr_ebill_core::protocol::{ContactShareEvent, Event};
use bcr_ebill_core::util::BcrKeys;
use bcr_ebill_persistence::nostr::NostrContactStoreApi;
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
        if let Some(transport) = self.nostr_transport.get_first_transport().await {
            let res = transport.resolve_contact(node_id).await?;
            Ok(res)
        } else {
            Ok(None)
        }
    }

    /// Publish contact data for NodeId to nostr. Will only publish if the NodeId points to a
    /// registered nostr client and therefore is our own.
    async fn publish_contact(&self, node_id: &NodeId, data: &NostrContactData) -> Result<()> {
        if let Some(transport) = self.nostr_transport.get_node_transport(node_id).await {
            transport.publish_metadata(&data.metadata).await?;
            transport.publish_relay_list(data.relays.clone()).await?;
        }
        Ok(())
    }

    /// Shares derived keys for private contact information via DM.
    async fn share_contact_details_keys(
        &self,
        recipient: &NodeId,
        contact_id: &NodeId,
        keys: &BcrKeys,
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
        let event = Event::new_contact_share(ContactShareEvent {
            node_id: contact_id.to_owned(),
            private_key: keys.get_private_key(),
        });

        self.nostr_transport
            .send_private_event(contact_id, recipient, &relays, event.try_into()?)
            .await?;
        Ok(())
    }

    /// Ensures that the given node id is in our nostr contacts
    async fn ensure_nostr_contact(&self, node_id: &NodeId) {
        self.nostr_contact_processor
            .ensure_nostr_contact(node_id)
            .await;
    }
}
