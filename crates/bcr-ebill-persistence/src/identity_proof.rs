use super::Result;
use async_trait::async_trait;

use bcr_ebill_core::{
    NodeId, ServiceTraitBounds,
    identity_proof::{IdentityProof, IdentityProofStatus},
};

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait IdentityProofStoreApi: ServiceTraitBounds {
    /// List identity proofs by node id
    async fn list_by_node_id(&self, node_id: &NodeId) -> Result<Vec<IdentityProof>>;
    /// Add identity proof
    async fn add(&self, identity_proof: &IdentityProof) -> Result<()>;
    /// Archive identity proof
    async fn archive(&self, id: &str) -> Result<()>;
    /// Get identity proof by id
    async fn get_by_id(&self, id: &str) -> Result<Option<IdentityProof>>;
    /// Updates the status an identity proof by id
    async fn update_status_by_id(
        &self,
        id: &str,
        status: &IdentityProofStatus,
        status_last_checked_timestamp: u64,
    ) -> Result<()>;
}
