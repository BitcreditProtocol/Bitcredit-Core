use std::{str::FromStr, sync::Arc};

use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_api::service::transport_service::Error;
use bcr_ebill_api::service::transport_service::InvalidIncomingBlock;
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
use log::warn;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownChain {
    pub chain_type: BlockchainType,
    pub chain_id: String,
}

/// Resolver for generic chain keys that are needed to decrypt
/// public chain events.
#[cfg_attr(test, mockall::automock)]
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

#[cfg(test)]
impl ServiceTraitBounds for MockChainKeyServiceApi {}

#[derive(Clone)]
pub struct ChainKeyService {
    bill_store: Arc<dyn BillStoreApi>,
    company_store: Arc<dyn CompanyStoreApi>,
    identity_store: Arc<dyn IdentityStoreApi>,
    identity_key_override: Option<(NodeId, BcrKeys)>,
    bitcoin_network: bitcoin::Network,
}

impl ChainKeyService {
    pub fn new(
        bill_store: Arc<dyn BillStoreApi>,
        company_store: Arc<dyn CompanyStoreApi>,
        identity_store: Arc<dyn IdentityStoreApi>,
        bitcoin_network: bitcoin::Network,
    ) -> Self {
        Self {
            bill_store,
            company_store,
            identity_store,
            identity_key_override: None,
            bitcoin_network,
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
        validate_chain_id(chain_id, chain_type, self.bitcoin_network)?;
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
                        return Err(InvalidIncomingBlock::WrongChain.into());
                    }
                } else {
                    match self.identity_store.get_key_pair().await {
                        Ok(keys) => {
                            let node_id = NodeId::from_str(chain_id)
                                .map_err(ProtocolValidationError::from)?;
                            if node_id == NodeId::new(keys.pub_key(), self.bitcoin_network) {
                                Some(keys)
                            } else {
                                return Err(InvalidIncomingBlock::WrongChain.into());
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

        if let Some(ref key_pair) = keys {
            let derived_id = match chain_type {
                BlockchainType::Bill => {
                    BillId::new(key_pair.pub_key(), self.bitcoin_network).to_string()
                }
                BlockchainType::Company | BlockchainType::Identity => {
                    NodeId::new(key_pair.pub_key(), self.bitcoin_network).to_string()
                }
            };
            if derived_id != chain_id {
                return Err(Error::Persistence(format!(
                    "Stored keys do not match chain {chain_type} {chain_id}"
                )));
            }
        }

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
        let primary_node_id = if let Some((node_id, _)) = &self.identity_key_override {
            Some(node_id.clone())
        } else {
            match self.identity_store.get_key_pair().await {
                Ok(keys) => Some(NodeId::new(keys.pub_key(), self.bitcoin_network)),
                Err(PersistenceError::NoSuchEntity(_, _)) => None,
                Err(e) => {
                    return Err(Error::Persistence(e.to_string()));
                }
            }
        };
        if let Some(node_id) = primary_node_id {
            chains.push(KnownChain {
                chain_type: BlockchainType::Identity,
                chain_id: node_id.to_string(),
            });
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

pub(crate) fn validate_chain_id(
    chain_id: &str,
    chain_type: BlockchainType,
    network: bitcoin::Network,
) -> Result<()> {
    let valid = match chain_type {
        BlockchainType::Bill => {
            let id = BillId::from_str(chain_id).map_err(|_| InvalidIncomingBlock::WrongChain)?;
            id.network() == network && id.to_string() == chain_id
        }
        BlockchainType::Company | BlockchainType::Identity => {
            let id = NodeId::from_str(chain_id).map_err(|_| InvalidIncomingBlock::WrongChain)?;
            id.network() == network && id.to_string() == chain_id
        }
    };
    if !valid {
        return Err(InvalidIncomingBlock::WrongChain.into());
    }
    Ok(())
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
        identity.expect_get().never();
        identity
            .expect_get_key_pair()
            .once()
            .returning(|| Ok(get_baseline_identity().key_pair));

        let service = ChainKeyService::new(
            Arc::new(bills),
            Arc::new(companies),
            Arc::new(identity),
            bitcoin::Network::Testnet,
        );
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

    #[tokio::test]
    async fn foreign_identity_is_not_missing_keys() {
        let keys = BcrKeys::new();
        let foreign_keys = BcrKeys::new();
        let network = bitcoin::Network::Testnet;
        let primary_id = NodeId::new(keys.pub_key(), network);
        let foreign_id = NodeId::new(foreign_keys.pub_key(), network);
        let mut identity = MockIdentityStore::new();
        identity.expect_get_key_pair().once().returning({
            let keys = keys.clone();
            move || Ok(keys.clone())
        });
        let service = ChainKeyService::new(
            Arc::new(MockBillStore::new()),
            Arc::new(MockCompanyStore::new()),
            Arc::new(identity),
            network,
        );
        assert!(matches!(
            service
                .get_chain_keys(&foreign_id.to_string(), BlockchainType::Identity,)
                .await,
            Err(Error::InvalidIncomingBlock(
                InvalidIncomingBlock::WrongChain,
            )),
        ));

        // Same rule during restoration
        let service = service.with_identity_key_override(primary_id, keys);
        assert!(matches!(
            service
                .get_chain_keys(&foreign_id.to_string(), BlockchainType::Identity,)
                .await,
            Err(Error::InvalidIncomingBlock(
                InvalidIncomingBlock::WrongChain,
            )),
        ));
    }

    #[test]
    fn invalid_chain_ids_are_terminal() {
        let network = bitcoin::Network::Testnet;
        let keys = BcrKeys::new();
        for chain_type in [
            BlockchainType::Bill,
            BlockchainType::Company,
            BlockchainType::Identity,
        ] {
            assert!(matches!(
                validate_chain_id("invalid-id", chain_type, network,),
                Err(Error::InvalidIncomingBlock(
                    InvalidIncomingBlock::WrongChain,
                )),
            ));
            let wrong_network_id = match chain_type {
                BlockchainType::Bill => {
                    BillId::new(keys.pub_key(), bitcoin::Network::Bitcoin).to_string()
                }
                _ => NodeId::new(keys.pub_key(), bitcoin::Network::Bitcoin).to_string(),
            };
            assert!(validate_chain_id(&wrong_network_id, chain_type, network,).is_err());
        }
    }
}
