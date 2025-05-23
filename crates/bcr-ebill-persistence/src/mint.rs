use super::Result;
use async_trait::async_trait;

use bcr_ebill_core::{ServiceTraitBounds, mint::MintRequest};

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait MintStoreApi: ServiceTraitBounds {
    /// Checks if there is any minting request for the given bill
    async fn exists_for_bill(&self, requester_node_id: &str, bill_id: &str) -> Result<bool>;
    /// Checks if there is an active request to mint for the given bill and mint
    async fn get_requests(
        &self,
        requester_node_id: &str,
        bill_id: &str,
        mint_node_id: &str,
    ) -> Result<Vec<MintRequest>>;
    /// Checks if there is an active request to mint for the given bill
    async fn get_requests_for_bill(
        &self,
        requester_node_id: &str,
        bill_id: &str,
    ) -> Result<Vec<MintRequest>>;
    /// Adds a new request to mint for a bill and mint
    async fn add_request(
        &self,
        requester_node_id: &str,
        bill_id: &str,
        mint_node_id: &str,
        mint_request_id: &str,
        timestamp: u64,
    ) -> Result<()>;
}
