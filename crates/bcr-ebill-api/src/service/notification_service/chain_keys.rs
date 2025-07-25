use super::Result;
use async_trait::async_trait;
use bcr_ebill_core::{ServiceTraitBounds, blockchain::BlockchainType, util::BcrKeys};

/// Resolver for generic chain keys that are needed to decrypt
/// public chain events.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ChainKeyServiceApi: ServiceTraitBounds {
    /// Get keys for given id and blockchain type
    async fn get_chain_keys(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> Result<Option<BcrKeys>>;
}
