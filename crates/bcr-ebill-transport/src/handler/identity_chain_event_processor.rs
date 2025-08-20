use crate::{Error, Result};
use async_trait::async_trait;
use bcr_ebill_api::{
    service::notification_service::event::{ChainInvite, Event},
    util::BcrKeys,
};
use log::{debug, error, info, warn};
use secp256k1::SecretKey;
use std::{str::FromStr, sync::Arc};

use bcr_ebill_core::{
    NodeId, ServiceTraitBounds,
    blockchain::{
        Block, Blockchain,
        identity::{IdentityBlock, IdentityBlockPayload, IdentityBlockchain},
    },
    company::CompanyKeys,
    identity::Identity,
};
use bcr_ebill_persistence::identity::{IdentityChainStoreApi, IdentityStoreApi};

use super::{IdentityChainEventProcessorApi, NostrContactProcessorApi, NotificationHandlerApi};

#[allow(dead_code)]
#[derive(Clone)]
pub struct IdentityChainEventProcessor {
    blockchain_store: Arc<dyn IdentityChainStoreApi>,
    identity_store: Arc<dyn IdentityStoreApi>,
    company_invite_handler: Arc<dyn NotificationHandlerApi>,
    bill_invite_handler: Arc<dyn NotificationHandlerApi>,
    nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
    bitcoin_network: bitcoin::Network,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl IdentityChainEventProcessorApi for IdentityChainEventProcessor {
    async fn process_chain_data(
        &self,
        node_id: &NodeId,
        blocks: Vec<IdentityBlock>,
        keys: Option<BcrKeys>,
    ) -> Result<()> {
        // check that incoming company blocks are of the same network that we use
        if node_id.network() != self.bitcoin_network {
            warn!("Received identity blocks for node {node_id} for a different network");
            return Err(Error::Blockchain(format!(
                "Received identity blocks for node {node_id} for a different network"
            )));
        }

        if let Ok(mut existing_chain) = self.blockchain_store.get_chain().await {
            self.add_identity_blocks(node_id, &mut existing_chain, blocks)
                .await
        } else {
            match keys {
                Some(keys) => self.add_new_chain(blocks, &keys).await,
                _ => {
                    error!("Received identity blocks for unknown identity {node_id}");
                    Err(Error::Blockchain(
                        "Received identity blocks for unknown identity".to_string(),
                    ))
                }
            }
        }
    }

    fn validate_chain_event_and_sender(&self, node_id: &NodeId, sender: nostr::PublicKey) -> bool {
        node_id.npub() == sender
    }
}

#[allow(unused)]
impl IdentityChainEventProcessor {
    pub fn new(
        blockchain_store: Arc<dyn IdentityChainStoreApi>,
        identity_store: Arc<dyn IdentityStoreApi>,
        company_invite_handler: Arc<dyn NotificationHandlerApi>,
        bill_invite_handler: Arc<dyn NotificationHandlerApi>,
        nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
        bitcoin_network: bitcoin::Network,
    ) -> Self {
        Self {
            blockchain_store,
            identity_store,
            company_invite_handler,
            bill_invite_handler,
            nostr_contact_processor,
            bitcoin_network,
        }
    }

    async fn add_new_chain(&self, blocks: Vec<IdentityBlock>, keys: &BcrKeys) -> Result<()> {
        let (node_id, mut identity, mut chain) = self.get_valid_chain(blocks.clone(), keys)?;
        debug!("updating identity chain for {node_id}");
        // save the identity
        self.identity_store.save(&identity).await.map_err(|e| {
            error!("Failed to save identity {node_id}: {e}");
            Error::Persistence(e.to_string())
        })?;

        // Save the first block of the chain as it is the create block
        self.save_block(chain.get_first_block()).await?;

        // process remaining blocks
        for block in blocks.iter().skip(1) {
            self.add_identity_block(&node_id, keys, &mut identity, &mut chain, block)
                .await?;
        }

        Ok(())
    }

    async fn add_identity_blocks(
        &self,
        node_id: &NodeId,
        chain: &mut IdentityBlockchain,
        blocks: Vec<IdentityBlock>,
    ) -> Result<()> {
        let keys = self
            .identity_store
            .get_key_pair()
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

        let mut identity = self
            .identity_store
            .get()
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

        let mut block_height = chain.get_latest_block().id;
        for block in blocks {
            if block.id <= block_height {
                info!(
                    "Skipping identity block with id {block_height} for {node_id} as we already have it"
                );
                continue;
            }
            self.add_identity_block(node_id, &keys, &mut identity, chain, &block)
                .await?;
            block_height = block.id;
        }
        debug!("Updated identity {node_id} with data from new blocks");
        Ok(())
    }

    async fn add_identity_block(
        &self,
        node_id: &NodeId,
        keys: &BcrKeys,
        identity: &mut Identity,
        chain: &mut IdentityBlockchain,
        block: &IdentityBlock,
    ) -> Result<()> {
        if chain.try_add_block(block.clone()) {
            let data = block
                .get_block_data(keys)
                .map_err(|e| Error::Blockchain(e.to_string()))?;

            // process effects
            match data {
                update @ IdentityBlockPayload::Update(_) => {
                    info!("Updating identity {node_id} from block data");
                    identity.apply_block_data(&update);
                    self.identity_store
                        .save(identity)
                        .await
                        .map_err(|e| Error::Persistence(e.to_string()))?;
                }
                IdentityBlockPayload::AddSignatory(payload) => {
                    info!("Adding signatory to identity {node_id}");
                    self.nostr_contact_processor
                        .ensure_nostr_contact(&payload.signatory)
                        .await
                }
                IdentityBlockPayload::CreateCompany(payload) => {
                    info!("Received company create block. Restoring Company data");
                    let secret_key = SecretKey::from_str(&payload.company_key)
                        .map_err(|e| Error::Crypto(e.to_string()))?;
                    let company_keys = BcrKeys::from_private_key(&secret_key)?;
                    let invite = ChainInvite::company(
                        payload.company_id.to_string(),
                        CompanyKeys {
                            public_key: company_keys.pub_key(),
                            private_key: company_keys.get_private_key(),
                        },
                    );
                    let event = Event::new_company_invite(invite);
                    self.company_invite_handler
                        .handle_event(event.try_into()?, node_id, None)
                        .await?;
                }
                IdentityBlockPayload::SignCompanyBill(payload) => {
                    // NOTE: if we add bill keys when we issue a bill we can recover or company bills
                    // here
                }
                IdentityBlockPayload::SignPersonalBill(payload) => {
                    // NOTE: if we add bill keys when we issue a bill we can recover or own bills here
                }
                IdentityBlockPayload::RemoveSignatory(_) => { /* no action needed */ }
                IdentityBlockPayload::Create(_) => { /* creates a handled on validation */ }
            }

            // persist data
            self.save_block(block).await?;

            // return the updated identity and chain
            Ok(())
        } else {
            error!("Received invalid identity block");
            Err(Error::Blockchain(
                "Received invalid identity block".to_string(),
            ))
        }
    }

    /// Validates all blocks in the given chain and returns the the chain with create block and the
    /// created identity and node id. Will return an error if one of the blocks is invalid.
    fn get_valid_chain(
        &self,
        blocks: Vec<IdentityBlock>,
        keys: &BcrKeys,
    ) -> Result<(NodeId, Identity, IdentityBlockchain)> {
        match IdentityBlockchain::new_from_blocks(blocks) {
            Ok(chain) => {
                let first_block = chain.get_first_block();
                // create block is where we build up the company from
                let payload = match first_block
                    .get_block_data(keys)
                    .map_err(|e| Error::Blockchain(e.to_string()))?
                {
                    IdentityBlockPayload::Create(payload) => payload,
                    _ => {
                        error!(
                            "First block of newly received identity chain is not a Create block"
                        );
                        return Err(Error::Blockchain(
                            "First block of newly received identity chain is not a Create block"
                                .to_string(),
                        ));
                    }
                };

                // now process and validate all the blocks
                for block in chain.blocks().iter() {
                    // validate the payloads
                    if !block.validate_plaintext_hash(&keys.get_private_key()) {
                        error!("Newly received chain block has invalid plaintext hash");
                        return Err(Error::Blockchain(
                            "Newly received chain block has invalid plaintext hash".to_string(),
                        ));
                    }
                }

                // initialize identity and chain from first block
                let mut identity = Identity::from_block_data(payload);
                let node_id = identity.node_id.clone();
                let return_chain = IdentityBlockchain::new_from_blocks(vec![first_block.clone()])
                    .map_err(|e| Error::Blockchain(e.to_string()))?;
                Ok((node_id, identity, return_chain))
            }
            _ => {
                error!("Newly received identity chain is not valid");
                Err(Error::Blockchain(
                    "Newly received identity chain is not valid".to_string(),
                ))
            }
        }
    }

    async fn save_block(&self, block: &IdentityBlock) -> Result<()> {
        if let Err(e) = self.blockchain_store.add_block(block).await {
            error!("Failed to add identity block to blockchain store: {e}");
            return Err(Error::Persistence(
                "Failed to add identity block to blockchain store".to_string(),
            ));
        }
        Ok(())
    }
}

impl ServiceTraitBounds for IdentityChainEventProcessor {}

#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use bcr_ebill_core::{
        blockchain::{
            Blockchain,
            identity::{IdentityBlock, IdentityBlockchain, IdentityUpdateBlockData},
        },
        identity::Identity,
        util::BcrKeys,
    };
    use mockall::predicate::always;

    use crate::handler::{
        IdentityChainEventProcessorApi, MockNostrContactProcessorApi, MockNotificationHandlerApi,
        identity_chain_event_processor::IdentityChainEventProcessor,
        test_utils::{
            MockIdentityChainStore, MockIdentityStore, get_baseline_identity, node_id_test,
        },
    };

    #[tokio::test]
    async fn test_create_event_handler() {
        let (chain_store, store, contact, company_invite, bill_invite) = create_mocks();
        IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            bitcoin::Network::Testnet,
        );
    }

    #[tokio::test]
    async fn test_validate_chain_event_and_sender_invalid_on_no_keys_or_chain() {
        let keys = BcrKeys::new().get_nostr_keys();
        let (chain_store, mut store, contact, company_invite, bill_invite) = create_mocks();

        store
            .expect_get()
            .returning(move || Err(bcr_ebill_persistence::Error::NoIdentityBlock));

        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            bitcoin::Network::Testnet,
        );

        let valid = handler.validate_chain_event_and_sender(&node_id_test(), keys.public_key());
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_validate_chain_event_fails_if_not_own_node_id() {
        let keys = BcrKeys::new();
        let (chain_store, mut store, contact, company_invite, bill_invite) = create_mocks();
        let identity = get_baseline_identity();
        store
            .expect_get()
            .returning(move || Ok(identity.identity.clone()));

        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            bitcoin::Network::Testnet,
        );

        let valid = handler
            .validate_chain_event_and_sender(&node_id_test(), keys.get_nostr_keys().public_key());
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_validate_chain_event() {
        let (chain_store, mut store, contact, company_invite, bill_invite) = create_mocks();
        let full = get_baseline_identity();
        let mut identity = full.identity.clone();
        identity.name = "new name".to_string();
        let keys = full.key_pair.clone();

        store.expect_get().returning(move || Ok(identity.clone()));

        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            bitcoin::Network::Testnet,
        );

        let valid = handler.validate_chain_event_and_sender(
            &full.identity.node_id,
            keys.get_nostr_keys().public_key(),
        );
        assert!(valid);
    }

    #[tokio::test]
    async fn test_process_update_identity_data() {
        let (mut chain_store, mut store, contact, company_invite, bill_invite) = create_mocks();
        let full = get_baseline_identity();
        let identity = full.identity.clone();
        let keys = full.key_pair.clone();
        let blocks = vec![get_identity_create_block(full.identity, &full.key_pair)];
        let chain = IdentityBlockchain::new_from_blocks(blocks).expect("could not create chain");
        let data = IdentityUpdateBlockData {
            name: Some("new_name".to_string()),
            ..Default::default()
        };
        let update_block = get_identity_update_block(chain.get_latest_block(), &keys, &data);

        // checks if we already have the chain
        chain_store
            .expect_get_chain()
            .returning(move || Ok(chain.clone()))
            .once();

        // we have a chain so get the keys
        store
            .expect_get_key_pair()
            .returning(move || Ok(keys.clone()))
            .once();

        // get the current identity state
        let expected_identity = identity.clone();
        store
            .expect_get()
            .returning(move || Ok(expected_identity.clone()))
            .once();

        // apply changes from block and update the identity
        store
            .expect_save()
            .withf(move |n| n.name == "new_name")
            .returning(|_| Ok(()))
            .once();

        // inserts the block
        chain_store
            .expect_add_block()
            .with(always())
            .returning(|_| Ok(()))
            .once();

        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            bitcoin::Network::Testnet,
        );

        handler
            .process_chain_data(&identity.node_id, vec![update_block], None)
            .await
            .expect("Process chain data should be handled");
    }

    pub fn get_identity_create_block(identity: Identity, keys: &BcrKeys) -> IdentityBlock {
        IdentityBlock::create_block_for_create(
            "genesis hash".to_string(),
            &identity.into(),
            keys,
            1731593928,
        )
        .expect("could not create block")
    }

    pub fn get_identity_update_block(
        previous_block: &IdentityBlock,
        keys: &BcrKeys,
        data: &IdentityUpdateBlockData,
    ) -> IdentityBlock {
        IdentityBlock::create_block_for_update(previous_block, data, keys, 1731594928)
            .expect("could not create block")
    }

    fn create_mocks() -> (
        MockIdentityChainStore,
        MockIdentityStore,
        MockNostrContactProcessorApi,
        MockNotificationHandlerApi,
        MockNotificationHandlerApi,
    ) {
        (
            MockIdentityChainStore::new(),
            MockIdentityStore::new(),
            MockNostrContactProcessorApi::new(),
            MockNotificationHandlerApi::new(),
            MockNotificationHandlerApi::new(),
        )
    }
}
