use std::{str::FromStr, sync::Arc};

use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_api::service::transport_service::Error;
use bcr_ebill_api::service::transport_service::Result;
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::{ProtocolValidationError, blockchain::BlockchainType, crypto::BcrKeys},
};
use bcr_ebill_persistence::Error as PersistenceError;
use bcr_ebill_persistence::{
    traits::bill::BillStoreApi, traits::company::CompanyStoreApi,
    traits::identity::IdentityStoreApi,
};
use log::{debug, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownChain {
    pub chain_type: BlockchainType,
    pub chain_id: String,
}

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
    /// Get all locally known chains for identity/company/bill
    async fn list_known_chains(&self) -> Result<Vec<KnownChain>>;
}

#[derive(Clone)]
pub struct ChainKeyService {
    bill_store: Arc<dyn BillStoreApi>,
    company_store: Arc<dyn CompanyStoreApi>,
    identity_store: Arc<dyn IdentityStoreApi>,
    identity_key_override: Option<(NodeId, BcrKeys)>,
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
            identity_key_override: None,
        }
    }

    pub fn with_identity_key_override(mut self, node_id: NodeId, keys: BcrKeys) -> Self {
        self.identity_key_override = Some((node_id, keys));
        self
    }
}

impl ServiceTraitBounds for ChainKeyService {}

#[async_trait]
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
                    .get_keys(&BillId::from_str(chain_id).map_err(ProtocolValidationError::from)?)
                    .await
                {
                    Ok(keys) => Some(keys),
                    Err(bcr_ebill_persistence::Error::NoSuchEntity(_, _)) => None,
                    Err(e) => {
                        warn!("failed to get bill keys for {chain_id} with {e}");
                        return Err(
                            bcr_ebill_api::service::transport_service::Error::Persistence(
                                e.to_string(),
                            ),
                        );
                    }
                }
            }
            BlockchainType::Company => {
                match self
                    .company_store
                    .get_key_pair(
                        &NodeId::from_str(chain_id).map_err(ProtocolValidationError::from)?,
                    )
                    .await
                {
                    Ok(keys) => Some(keys),
                    Err(bcr_ebill_persistence::Error::NoSuchEntity(_, _)) => None,
                    Err(e) => {
                        warn!("failed to get company keys for {chain_id} with {e}");
                        return Err(
                            bcr_ebill_api::service::transport_service::Error::Persistence(
                                e.to_string(),
                            ),
                        );
                    }
                }
            }
            BlockchainType::Identity => {
                if let Some((expected_id, keys)) = &self.identity_key_override {
                    if chain_id == expected_id.to_string() {
                        Some(keys.clone())
                    } else {
                        None
                    }
                } else {
                    match self.identity_store.get_key_pair().await {
                        Ok(keys) => {
                            let node_id = NodeId::from_str(chain_id)
                                .map_err(ProtocolValidationError::from)?;
                            if node_id.pub_key() == keys.pub_key() {
                                Some(keys)
                            } else {
                                debug!("skipping identity block for other identity");
                                None
                            }
                        }
                        Err(PersistenceError::NoSuchEntity(_, _)) => None,
                        Err(e) => {
                            warn!("failed to get identity keys with {e}");
                            return Err(Error::Persistence(e.to_string()));
                        }
                    }
                }
            }
        };

        Ok(keys)
    }

    async fn list_known_chains(&self) -> Result<Vec<KnownChain>> {
        let mut chains = Vec::new();
        let bill_ids = self
            .bill_store
            .get_key_ids()
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;
        for id in bill_ids {
            chains.push(KnownChain {
                chain_type: BlockchainType::Bill,
                chain_id: id.to_string(),
            });
        }
        let company_ids = self
            .company_store
            .get_key_ids()
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;
        for id in company_ids {
            chains.push(KnownChain {
                chain_type: BlockchainType::Company,
                chain_id: id.to_string(),
            });
        }
        match self.identity_store.get().await {
            Ok(identity) => {
                chains.push(KnownChain {
                    chain_type: BlockchainType::Identity,
                    chain_id: identity.node_id.to_string(),
                });
            }
            Err(PersistenceError::NoSuchEntity(_, _)) => {
                // keys can exist before an identity is initialized
                if let Some((node_id, _)) = &self.identity_key_override {
                    chains.push(KnownChain {
                        chain_type: BlockchainType::Identity,
                        chain_id: node_id.to_string(),
                    });
                }
            }
            Err(e) => {
                return Err(Error::Persistence(e.to_string()));
            }
        }
        chains.sort_by(|a, b| {
            a.chain_type
                .to_string()
                .cmp(&b.chain_type.to_string())
                .then_with(|| a.chain_id.cmp(&b.chain_id))
        });
        chains.dedup_by(|a, b| a.chain_type == b.chain_type && a.chain_id == b.chain_id);
        Ok(chains)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::test_utils::{MockBillStore, MockCompanyStore, MockIdentityStore};
    use crate::test_utils::node_id_test_other;
    use crate::test_utils::{bill_id_test, get_baseline_identity};

    #[tokio::test]
    async fn lists_known_chains_from_keys_even_without_blocks() {
        let mut bills = MockBillStore::new();
        bills
            .expect_get_key_ids()
            .once()
            .returning(|| Ok(vec![bill_id_test()]));

        let mut companies = MockCompanyStore::new();
        companies
            .expect_get_key_ids()
            .once()
            .returning(|| Ok(vec![node_id_test_other()]));

        let mut identity = MockIdentityStore::new();
        identity
            .expect_get()
            .once()
            .returning(|| Ok(get_baseline_identity().identity));

        let service =
            ChainKeyService::new(Arc::new(bills), Arc::new(companies), Arc::new(identity));
        let chains = service.list_known_chains().await.unwrap();
        assert!(chains.contains(&KnownChain {
            chain_type: BlockchainType::Bill,
            chain_id: bill_id_test().to_string(),
        }));
        assert!(chains.contains(&KnownChain {
            chain_type: BlockchainType::Company,
            chain_id: node_id_test_other().to_string(),
        }));
        assert!(chains.contains(&KnownChain {
            chain_type: BlockchainType::Identity,
            chain_id: get_baseline_identity().identity.node_id.to_string(),
        }));
        assert_eq!(chains.len(), 3);
    }
}
