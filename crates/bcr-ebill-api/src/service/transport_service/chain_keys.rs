use super::Result;
use async_trait::async_trait;
use bcr_ebill_core::{
    application::ServiceTraitBounds, protocol::blockchain::BlockchainType,
    protocol::crypto::BcrKeys,
};

/// Resolver for generic chain keys that are needed to decrypt
/// public chain events.
#[async_trait]
pub trait ChainKeyServiceApi: ServiceTraitBounds {
    /// Get keys for given id and blockchain type
    async fn get_chain_keys(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> Result<Option<BcrKeys>>;
}
