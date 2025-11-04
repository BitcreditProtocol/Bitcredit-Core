use std::{str::FromStr, sync::Arc};

use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_api::service::transport_service::Result;
use bcr_ebill_core::{
    ServiceTraitBounds, ValidationError, blockchain::BlockchainType, util::BcrKeys,
};
use bcr_ebill_persistence::{
    bill::BillStoreApi, company::CompanyStoreApi, identity::IdentityStoreApi,
};
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
    company_store: Arc<dyn CompanyStoreApi>,
    identity_store: Arc<dyn IdentityStoreApi>,
}

impl ChainKeyService {
    pub fn new(
        bill_store: Arc<dyn BillStoreApi>,
        company_store: Arc<dyn CompanyStoreApi>,
        identity_store: Arc<dyn IdentityStoreApi>,
    ) -> Self {
        Self {
            bill_store,
            company_store,
            identity_store,
        }
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
                match self
                    .bill_store
                    .get_keys(&BillId::from_str(chain_id).map_err(ValidationError::from)?)
                    .await
                {
                    Ok(keys) => Some(keys.try_into()?),
                    Err(e) => {
                        warn!("failed to get bill keys for {chain_id} with {e}");
                        None
                    }
                }
            }
            BlockchainType::Company => {
                match self
                    .company_store
                    .get_key_pair(&NodeId::from_str(chain_id).map_err(ValidationError::from)?)
                    .await
                {
                    Ok(keys) => Some(keys.try_into()?),
                    Err(e) => {
                        warn!("failed to get company keys for {chain_id} with {e}");
                        None
                    }
                }
            }
            BlockchainType::Identity => match self.identity_store.get_key_pair().await {
                Ok(keys) => Some(keys),
                Err(e) => {
                    warn!("failed to get identity keys with {e}");
                    None
                }
            },
        };

        Ok(keys)
    }
}
