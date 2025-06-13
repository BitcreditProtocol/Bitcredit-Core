use std::{str::FromStr, sync::Arc};

use crate::Result;
use async_trait::async_trait;
use bcr_ebill_core::{ServiceTraitBounds, bill::BillId, blockchain::BlockchainType, util::BcrKeys};
use bcr_ebill_persistence::bill::BillStoreApi;
use log::warn;

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

#[derive(Clone)]
pub struct ChainKeyService {
    bill_store: Arc<dyn BillStoreApi>,
}

impl ChainKeyService {
    pub fn new(bill_store: Arc<dyn BillStoreApi>) -> Self {
        Self { bill_store }
    }
}

impl ServiceTraitBounds for ChainKeyService {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ChainKeyServiceApi for ChainKeyService {
    /// Get keys for given id and blockchain type
    async fn get_chain_keys(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> Result<Option<BcrKeys>> {
        let keys = match chain_type {
            BlockchainType::Bill => {
                match self.bill_store.get_keys(&BillId::from_str(chain_id)?).await {
                    Ok(keys) => Some(keys.try_into()?),
                    Err(e) => {
                        warn!("failed to get bill keys for {chain_id} with {e}");
                        None
                    }
                }
            }
            _ => None,
        };

        Ok(keys)
    }
}
