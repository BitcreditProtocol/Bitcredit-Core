use crate::{Error, Result};
use async_trait::async_trait;
use log::{debug, error, info, warn};
use std::{collections::HashSet, sync::Arc};

use bcr_ebill_core::{
    NodeId, ServiceTraitBounds,
    blockchain::{
        Block, Blockchain,
        company::{CompanyBlock, CompanyBlockPayload, CompanyBlockchain},
    },
    company::{Company, CompanyKeys},
};
use bcr_ebill_persistence::company::{CompanyChainStoreApi, CompanyStoreApi};

use super::{CompanyChainEventProcessorApi, NostrContactProcessorApi};

#[derive(Clone)]
pub struct CompanyChainEventProcessor {
    blockchain_store: Arc<dyn CompanyChainStoreApi>,
    company_store: Arc<dyn CompanyStoreApi>,
    nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
    bitcoin_network: bitcoin::Network,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl CompanyChainEventProcessorApi for CompanyChainEventProcessor {
    async fn process_chain_data(
        &self,
        company_id: &NodeId,
        blocks: Vec<CompanyBlock>,
        keys: Option<CompanyKeys>,
    ) -> Result<()> {
        // check that incoming company blocks are of the same network that we use
        if company_id.network() != self.bitcoin_network {
            warn!("Received company blocks for company {company_id} for a different network");
            return Err(Error::Blockchain(format!(
                "Received company blocks for company {company_id} for a different network"
            )));
        }

        if let Ok(mut existing_chain) = self.blockchain_store.get_chain(company_id).await {
            self.add_company_blocks(company_id, &mut existing_chain, blocks)
                .await
        } else {
            match keys {
                Some(keys) => self.add_new_chain(blocks, &keys).await,
                _ => {
                    error!("Received company blocks for unknown company {company_id}");
                    Err(Error::Blockchain(
                        "Received bill blocks for unknown bill".to_string(),
                    ))
                }
            }
        }
    }

    async fn validate_chain_event_and_sender(
        &self,
        company_id: &NodeId,
        sender: nostr::PublicKey,
    ) -> Result<bool> {
        if let Ok(company) = self
            .company_store
            .get(company_id)
            .await
            .map_err(|e| Error::Persistence(e.to_string()))
        {
            let signers = company
                .signatories
                .iter()
                .map(|s| s.npub())
                .collect::<Vec<nostr::PublicKey>>();
            Ok(signers.contains(&sender))
        } else {
            Ok(false)
        }
    }
}

impl CompanyChainEventProcessor {
    pub fn new(
        blockchain_store: Arc<dyn CompanyChainStoreApi>,
        company_store: Arc<dyn CompanyStoreApi>,
        nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
        bitcoin_network: bitcoin::Network,
    ) -> Self {
        Self {
            blockchain_store,
            company_store,
            nostr_contact_processor,
            bitcoin_network,
        }
    }

    async fn add_new_chain(&self, blocks: Vec<CompanyBlock>, keys: &CompanyKeys) -> Result<()> {
        let (company_id, company, chain) = self.get_valid_chain(blocks, keys)?;
        debug!("adding new chain and company {company_id}");
        // add the company
        self.company_store.insert(&company).await.map_err(|e| {
            error!("Failed to insert company {company_id}: {e}");
            Error::Persistence(e.to_string())
        })?;
        // save all blocks
        for block in chain.blocks().iter() {
            self.save_block(&company_id, block).await?;
        }
        // save keys
        self.save_keys(&company_id, keys).await?;

        // we also want the company itself as a contact
        let mut contacts_to_ensure: HashSet<&NodeId> =
            HashSet::from_iter(company.signatories.iter());
        contacts_to_ensure.insert(&company_id);

        // ensure that we have all nostr contacts for the bill participants
        for node_id in contacts_to_ensure {
            self.nostr_contact_processor
                .ensure_nostr_contact(node_id)
                .await
        }

        Ok(())
    }

    async fn add_company_blocks(
        &self,
        company_id: &NodeId,
        chain: &mut CompanyBlockchain,
        blocks: Vec<CompanyBlock>,
    ) -> Result<()> {
        let keys = self
            .company_store
            .get_key_pair(company_id)
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;
        let mut company = self
            .company_store
            .get(company_id)
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

        let mut block_height = chain.get_latest_block().id;
        for block in blocks {
            if block.id <= block_height {
                info!(
                    "Skipping block with id {block_height} for {company_id} as we already have it"
                );
                continue;
            }
            let data = block
                .get_block_data(&keys)
                .map_err(|e| Error::Blockchain(e.to_string()))?;
            if chain.try_add_block(block.clone()) {
                block_height = block.id;
                company.apply_block_data(&data);
                self.save_block(company_id, &block).await?;
                self.company_store
                    .update(company_id, &company)
                    .await
                    .map_err(|e| Error::Persistence(e.to_string()))?;

                if let CompanyBlockPayload::AddSignatory(payload) = data {
                    self.nostr_contact_processor
                        .ensure_nostr_contact(&payload.signatory)
                        .await
                };
            }
        }
        debug!("Updated company {company_id} with data from new blocks");
        Ok(())
    }

    fn get_valid_chain(
        &self,
        blocks: Vec<CompanyBlock>,
        keys: &CompanyKeys,
    ) -> Result<(NodeId, Company, CompanyBlockchain)> {
        match CompanyBlockchain::new_from_blocks(blocks) {
            Ok(chain) if chain.is_chain_valid() => {
                let first_block = chain.get_first_block();
                // create block is where we build up the company from
                let payload = match first_block
                    .get_block_data(keys)
                    .map_err(|e| Error::Blockchain(e.to_string()))?
                {
                    CompanyBlockPayload::Create(payload) => payload,
                    _ => {
                        error!("First block of newly received company chain is not a Create block");
                        return Err(Error::Blockchain(
                            "First block of newly received company chain is not a Create block"
                                .to_string(),
                        ));
                    }
                };

                // extracted node_id
                let node_id = payload.id.clone();

                // initialize company from payload
                let mut company = Company {
                    id: payload.id,
                    name: payload.name,
                    country_of_registration: payload.country_of_registration,
                    city_of_registration: payload.city_of_registration,
                    postal_address: payload.postal_address,
                    email: payload.email,
                    registration_number: payload.registration_number,
                    registration_date: payload.registration_date,
                    proof_of_registration_file: payload.proof_of_registration_file,
                    logo_file: payload.logo_file,
                    signatories: payload.signatories,
                };

                // now process and validate all the blocks
                for block in chain.blocks().iter() {
                    // validate the payloads
                    if !block.validate_plaintext_hash(&keys.private_key) {
                        error!("Newly received chain block has invalid plaintext hash");
                        return Err(Error::Blockchain(
                            "Newly received chain block has invalid plaintext hash".to_string(),
                        ));
                    }
                    // bulid up the company from the payloads
                    match block
                        .get_block_data(keys)
                        .map_err(|e| Error::Blockchain(e.to_string()))?
                    {
                        // no need to handle creates any more
                        CompanyBlockPayload::Create(_) => {}
                        // here we could in theory already pick up company bills for recovery
                        CompanyBlockPayload::SignBill(_payload) => {}
                        p => company.apply_block_data(&p),
                    }
                }
                Ok((node_id, company, chain))
            }
            _ => {
                error!("Newly received company chain is not valid");
                Err(Error::Blockchain(
                    "Newly received company chain is not valid".to_string(),
                ))
            }
        }
    }

    async fn save_block(&self, company_id: &NodeId, block: &CompanyBlock) -> Result<()> {
        if let Err(e) = self.blockchain_store.add_block(company_id, block).await {
            error!("Failed to add company block to blockchain store: {e}");
            return Err(Error::Persistence(
                "Failed to add company block to blockchain store".to_string(),
            ));
        }
        Ok(())
    }

    async fn save_keys(&self, node_id: &NodeId, keys: &CompanyKeys) -> Result<()> {
        if let Err(e) = self.company_store.save_key_pair(node_id, keys).await {
            error!("Failed to save keys to company store: {e}");
            return Err(Error::Persistence(
                "Failed to save keys to bill store".to_string(),
            ));
        }
        Ok(())
    }
}

impl ServiceTraitBounds for CompanyChainEventProcessor {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bcr_ebill_core::{
        NodeId,
        blockchain::{
            Blockchain,
            company::{
                CompanyAddSignatoryBlockData, CompanyBlock, CompanyBlockchain,
                CompanyRemoveSignatoryBlockData, CompanyUpdateBlockData, SignatoryType,
            },
        },
        company::{Company, CompanyKeys},
        util::BcrKeys,
    };
    use mockall::predicate::{always, eq};

    use crate::handler::{
        CompanyChainEventProcessor, CompanyChainEventProcessorApi, MockNostrContactProcessorApi,
        test_utils::{MockCompanyChainStore, MockCompanyStore, get_company_data, node_id_test},
    };

    #[tokio::test]
    async fn test_create_event_handler() {
        let (chain_store, store, contact) = create_mocks();
        CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(contact),
            bitcoin::Network::Testnet,
        );
    }

    #[tokio::test]
    async fn test_validate_chain_event_and_sender_invalid_on_no_keys_or_chain() {
        let keys = BcrKeys::new().get_nostr_keys();
        let (chain_store, mut store, contact) = create_mocks();

        store
            .expect_get()
            .with(eq(node_id_test()))
            .returning(move |_| Err(bcr_ebill_persistence::Error::NoCompanyBlock));

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(contact),
            bitcoin::Network::Testnet,
        );

        let valid = handler
            .validate_chain_event_and_sender(&node_id_test(), keys.public_key())
            .await
            .expect("Event should be handled");
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_validate_chain_event_fails_if_not_signatory() {
        let keys = BcrKeys::new();
        let (chain_store, mut store, contact) = create_mocks();
        let (_, (company, _)) = get_company_data();
        store
            .expect_get()
            .with(eq(node_id_test()))
            .returning(move |_| Ok(company.clone()));

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(contact),
            bitcoin::Network::Testnet,
        );

        let valid = handler
            .validate_chain_event_and_sender(&node_id_test(), keys.get_nostr_keys().public_key())
            .await
            .expect("Event should be handled");
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_validate_chain_event() {
        let keys = BcrKeys::new();
        let (chain_store, mut store, contact) = create_mocks();
        let (_, (mut company, _)) = get_company_data();
        company.signatories = vec![NodeId::new(keys.pub_key(), bitcoin::Network::Testnet)];
        store
            .expect_get()
            .with(eq(node_id_test()))
            .returning(move |_| Ok(company.clone()));

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(contact),
            bitcoin::Network::Testnet,
        );

        let valid = handler
            .validate_chain_event_and_sender(&node_id_test(), keys.get_nostr_keys().public_key())
            .await
            .expect("Event should be handled");
        assert!(valid);
    }

    #[tokio::test]
    async fn test_process_create_company_data() {
        let (mut chain_store, mut store, mut contact) = create_mocks();
        let (node_id, (company, keys)) = get_company_data();
        let blocks = vec![get_company_create_block(
            node_id.clone(),
            company.clone(),
            &keys,
        )];

        // checks if we already have the chain
        chain_store
            .expect_get_chain()
            .with(eq(node_id.clone()))
            .returning(|_| Err(bcr_ebill_persistence::Error::NoCompanyBlock))
            .once();

        // it is valid so add the company
        let expected_company = company.clone();
        store
            .expect_insert()
            .withf(move |c| c.id == expected_company.id.clone() && c.name == expected_company.name)
            .returning(|_| Ok(()))
            .once();

        // inserts the block
        chain_store
            .expect_add_block()
            .with(eq(node_id.clone()), always())
            .returning(|_, _| Ok(()))
            .once();

        // adds the keys
        store
            .expect_save_key_pair()
            .with(eq(node_id.clone()), always())
            .returning(|_, _| Ok(()))
            .once();

        // and ensures that we have all nostr contacts for the company participants
        contact
            .expect_ensure_nostr_contact()
            .with(eq(node_id.clone()))
            .returning(|_| ())
            .once();

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(contact),
            bitcoin::Network::Testnet,
        );

        handler
            .process_chain_data(&node_id, blocks, Some(keys))
            .await
            .expect("Process chain data should be handled");
    }

    #[tokio::test]
    async fn test_process_update_company_data() {
        let (mut chain_store, mut store, mut contact) = create_mocks();
        let (node_id, (company, keys)) = get_company_data();
        let blocks = vec![get_company_create_block(
            node_id.clone(),
            company.clone(),
            &keys,
        )];
        let chain = CompanyBlockchain::new_from_blocks(blocks).expect("could not create chain");
        let data = CompanyUpdateBlockData {
            name: Some("new_name".to_string()),
            ..Default::default()
        };
        let update_block = get_company_update_block(
            node_id.clone(),
            chain.get_latest_block(),
            &BcrKeys::new(),
            &keys,
            &data,
        );

        // checks if we already have the chain
        chain_store
            .expect_get_chain()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(chain.clone()))
            .once();

        // we have a chain so get the keys
        store
            .expect_get_key_pair()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(keys.clone()))
            .once();

        // get the current company state
        let expected_company = company.clone();
        store
            .expect_get()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(expected_company.clone()))
            .once();

        // apply changes from block and update the company
        let expected_node = node_id.clone();
        store
            .expect_update()
            .withf(move |n, c| {
                n == &expected_node.clone() && c.id == expected_node.clone() && c.name == "new_name"
            })
            .returning(|_, _| Ok(()))
            .once();

        // inserts the block
        chain_store
            .expect_add_block()
            .with(eq(node_id.clone()), always())
            .returning(|_, _| Ok(()))
            .once();

        // we already have the keys
        store
            .expect_save_key_pair()
            .with(eq(node_id.clone()), always())
            .returning(|_, _| Ok(()))
            .never();

        // no need to ensure contacts in case of an update
        contact
            .expect_ensure_nostr_contact()
            .with(eq(node_id.clone()))
            .returning(|_| ())
            .never();

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(contact),
            bitcoin::Network::Testnet,
        );

        handler
            .process_chain_data(&node_id, vec![update_block], None)
            .await
            .expect("Process chain data should be handled");
    }

    #[tokio::test]
    async fn test_process_add_company_signatory() {
        let (mut chain_store, mut store, mut contact) = create_mocks();
        let new_node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        let (node_id, (company, keys)) = get_company_data();
        let blocks = vec![get_company_create_block(
            node_id.clone(),
            company.clone(),
            &keys,
        )];
        let chain = CompanyBlockchain::new_from_blocks(blocks).expect("could not create chain");
        let data = CompanyAddSignatoryBlockData {
            signatory: new_node_id.clone(),
            t: SignatoryType::Solo,
        };
        let update_block = get_company_add_signatory_block(
            node_id.clone(),
            chain.get_latest_block(),
            &BcrKeys::new(),
            &keys,
            &data,
        );

        // checks if we already have the chain
        chain_store
            .expect_get_chain()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(chain.clone()))
            .once();

        // we have a chain so get the keys
        store
            .expect_get_key_pair()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(keys.clone()))
            .once();

        // get the current company state
        let expected_company = company.clone();
        store
            .expect_get()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(expected_company.clone()))
            .once();

        // apply changes from block with the signatory
        let expected_node = node_id.clone();
        let expected_new_node = new_node_id.clone();
        store
            .expect_update()
            .withf(move |n, c| {
                n == &expected_node.clone()
                    && c.id == expected_node.clone()
                    && c.signatories.contains(&expected_new_node.clone())
            })
            .returning(|_, _| Ok(()))
            .once();

        // inserts the block
        chain_store
            .expect_add_block()
            .with(eq(node_id.clone()), always())
            .returning(|_, _| Ok(()))
            .once();

        // we already have the keys
        store
            .expect_save_key_pair()
            .with(eq(node_id.clone()), always())
            .returning(|_, _| Ok(()))
            .never();

        // ensure the new node is a contact
        contact
            .expect_ensure_nostr_contact()
            .with(eq(new_node_id.clone()))
            .returning(|_| ())
            .once();

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(contact),
            bitcoin::Network::Testnet,
        );

        handler
            .process_chain_data(&node_id, vec![update_block], None)
            .await
            .expect("Process chain data should be handled");
    }

    #[tokio::test]
    async fn test_process_remove_company_signatory() {
        let (mut chain_store, mut store, mut contact) = create_mocks();
        let new_node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        let (node_id, (mut company, keys)) = get_company_data();
        company.signatories.push(new_node_id.clone());

        let blocks = vec![get_company_create_block(
            node_id.clone(),
            company.clone(),
            &keys,
        )];
        let chain = CompanyBlockchain::new_from_blocks(blocks).expect("could not create chain");
        let data = CompanyRemoveSignatoryBlockData {
            signatory: new_node_id.clone(),
        };
        let update_block = get_company_remove_signatory_block(
            node_id.clone(),
            chain.get_latest_block(),
            &BcrKeys::new(),
            &keys,
            &data,
        );

        // checks if we already have the chain
        chain_store
            .expect_get_chain()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(chain.clone()))
            .once();

        // we have a chain so get the keys
        store
            .expect_get_key_pair()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(keys.clone()))
            .once();

        // get the current company state
        let expected_company = company.clone();
        store
            .expect_get()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(expected_company.clone()))
            .once();

        // apply changes from block with the signatory
        let expected_node = node_id.clone();
        let expected_new_node = new_node_id.clone();
        store
            .expect_update()
            .withf(move |n, c| {
                n == &expected_node.clone()
                    && c.id == expected_node.clone()
                    && !c.signatories.contains(&expected_new_node.clone())
            })
            .returning(|_, _| Ok(()))
            .once();

        // inserts the block
        chain_store
            .expect_add_block()
            .with(eq(node_id.clone()), always())
            .returning(|_, _| Ok(()))
            .once();

        // we already have the keys
        store
            .expect_save_key_pair()
            .with(eq(node_id.clone()), always())
            .returning(|_, _| Ok(()))
            .never();

        // no need to ensure contacts in case of a remove
        contact
            .expect_ensure_nostr_contact()
            .with(eq(new_node_id.clone()))
            .returning(|_| ())
            .never();

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(contact),
            bitcoin::Network::Testnet,
        );

        handler
            .process_chain_data(&node_id, vec![update_block], None)
            .await
            .expect("Process chain data should be handled");
    }

    fn get_company_create_block(
        node_id: NodeId,
        company: Company,
        keys: &CompanyKeys,
    ) -> CompanyBlock {
        CompanyBlock::create_block_for_create(
            node_id,
            "genesis hash".to_string(),
            &company.into(),
            &BcrKeys::new(),
            keys,
            1731593928,
        )
        .expect("could not create block")
    }

    fn get_company_update_block(
        node_id: NodeId,
        previous_block: &CompanyBlock,
        keys: &BcrKeys,
        company_keys: &CompanyKeys,
        data: &CompanyUpdateBlockData,
    ) -> CompanyBlock {
        CompanyBlock::create_block_for_update(
            node_id,
            previous_block,
            data,
            keys,
            company_keys,
            1731594928,
        )
        .expect("could not create block")
    }

    fn get_company_add_signatory_block(
        node_id: NodeId,
        previous_block: &CompanyBlock,
        keys: &BcrKeys,
        company_keys: &CompanyKeys,
        data: &CompanyAddSignatoryBlockData,
    ) -> CompanyBlock {
        CompanyBlock::create_block_for_add_signatory(
            node_id,
            previous_block,
            data,
            keys,
            company_keys,
            &data.signatory.pub_key(),
            1731594928,
        )
        .expect("could not create block")
    }

    fn get_company_remove_signatory_block(
        node_id: NodeId,
        previous_block: &CompanyBlock,
        keys: &BcrKeys,
        company_keys: &CompanyKeys,
        data: &CompanyRemoveSignatoryBlockData,
    ) -> CompanyBlock {
        CompanyBlock::create_block_for_remove_signatory(
            node_id,
            previous_block,
            data,
            keys,
            company_keys,
            1731594928,
        )
        .expect("could not create block")
    }

    fn create_mocks() -> (
        MockCompanyChainStore,
        MockCompanyStore,
        MockNostrContactProcessorApi,
    ) {
        (
            MockCompanyChainStore::new(),
            MockCompanyStore::new(),
            MockNostrContactProcessorApi::new(),
        )
    }
}
