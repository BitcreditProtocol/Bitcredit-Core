use super::Result;
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::{application::ServiceTraitBounds, protocol::crypto::BcrKeys};

use super::NostrContactData;

#[cfg(test)]
use mockall::automock;

/// Allows to sync and manage contacts with the remote transport network
#[allow(dead_code)]
#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ContactTransportServiceApi: ServiceTraitBounds {
    /// Attempts to resolve the nostr contact for the given Node Id
    async fn resolve_contact(&self, node_id: &NodeId) -> Result<Option<NostrContactData>>;

    /// Publish contact data for NodeId to nostr. Will only publish if the NodeId points to a
    /// registered nostr client and therefore is our own.
    async fn publish_contact(&self, node_id: &NodeId, contact: &NostrContactData) -> Result<()>;

    /// Shares derived keys for private contact information via DM.
    /// If share_back_pending_id is provided, it will be included in the event to enable auto-accept.
    async fn share_contact_details_keys(
        &self,
        recipient: &NodeId,
        contact_id: &NodeId,
        keys: &BcrKeys,
        share_back_pending_id: Option<String>,
    ) -> Result<()>;

    /// Ensures that the given node id is in our nostr contacts
    async fn ensure_nostr_contact(&self, node_id: &NodeId);
}

#[cfg(test)]
impl ServiceTraitBounds for MockContactTransportServiceApi {}
