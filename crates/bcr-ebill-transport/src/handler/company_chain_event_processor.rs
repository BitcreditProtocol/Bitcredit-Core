use crate::{
    Error, Result,
    handler::{
        NotificationHandlerApi,
        public_chain_helpers::{BlockData, resolve_event_chains},
    },
};
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_api::service::transport_service::transport_client::TransportClientApi;
use bcr_ebill_core::protocol::{
    crypto::BcrKeys,
    event::{ChainInvite, Event},
};
use log::{debug, error, info, warn};
use std::sync::Arc;

use bcr_ebill_core::{
    application::ServiceTraitBounds,
    application::company::Company,
    protocol::BlockId,
    protocol::blockchain::{
        Blockchain, BlockchainType,
        bill::BillOpCode,
        company::{CompanyBlock, CompanyBlockPayload, CompanyBlockchain},
    },
};
use bcr_ebill_persistence::{
    company::{CompanyChainStoreApi, CompanyStoreApi},
    identity::IdentityStoreApi,
};

use super::{CompanyChainEventProcessorApi, NostrContactProcessorApi};

#[derive(Clone)]
pub struct CompanyChainEventProcessor {
    blockchain_store: Arc<dyn CompanyChainStoreApi>,
    company_store: Arc<dyn CompanyStoreApi>,
    identity_store: Arc<dyn IdentityStoreApi>,
    nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
    bill_invite_handler: Arc<dyn NotificationHandlerApi>,
    transport: Arc<dyn TransportClientApi>,
    bitcoin_network: bitcoin::Network,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl CompanyChainEventProcessorApi for CompanyChainEventProcessor {
    async fn process_chain_data(
        &self,
        company_id: &NodeId,
        blocks: Vec<CompanyBlock>,
        keys: Option<BcrKeys>,
    ) -> Result<()> {
        // check that incoming company blocks are of the same network that we use
        if company_id.network() != self.bitcoin_network {
            warn!("Received company blocks for company {company_id} for a different network");
            return Err(Error::Blockchain(format!(
                "Received company blocks for company {company_id} for a different network"
            )));
        }

        let identity = self
            .identity_store
            .get()
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?
            .node_id;

        if let Ok(mut existing_chain) = self.blockchain_store.get_chain(company_id).await {
            self.add_company_blocks(company_id, &mut existing_chain, blocks, &identity)
                .await
        } else {
            match keys {
                Some(keys) => self.add_new_chain(blocks, &keys, &identity).await,
                _ => {
                    error!("Received company blocks for unknown company {company_id}");
                    Err(Error::Blockchain(
                        "Received company blocks for unknown company".to_string(),
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

    async fn resync_chain(&self, company_id: &NodeId) -> Result<()> {
        match (
            self.blockchain_store.get_chain(company_id).await,
            self.company_store.get_key_pair(company_id).await,
        ) {
            (Ok(mut existing_chain), Ok(company_keys)) => {
                debug!("starting company chain resync for company {company_id}");
                if let Ok(chain_data) = resolve_event_chains(
                    self.transport.clone(),
                    &company_id.to_string(),
                    BlockchainType::Company,
                    &company_keys,
                )
                .await
                {
                    let identity = self
                        .identity_store
                        .get()
                        .await
                        .map_err(|e| Error::Persistence(e.to_string()))?
                        .node_id;

                    for data in chain_data.iter() {
                        let blocks: Vec<CompanyBlock> = data
                            .iter()
                            .filter_map(|d| match d.block.clone() {
                                BlockData::Company(block) => Some(block),
                                _ => None,
                            })
                            .collect();
                        if !data.is_empty()
                            && self
                                .add_company_blocks(
                                    company_id,
                                    &mut existing_chain,
                                    blocks,
                                    &identity,
                                )
                                .await
                                .is_ok()
                        {
                            debug!(
                                "resynced company {company_id} with {} remote events",
                                data.len()
                            );
                            break;
                        }
                    }
                    debug!("finished company chain resync for {company_id}");
                    Ok(())
                } else {
                    let message =
                        format!("Could not refetch chain data from Nostr for company {company_id}");
                    error!("{message}");
                    Err(Error::Network(message))
                }
            }
            _ => {
                let message = format!(
                    "Could not refetch chain for {company_id} because the company keys or chain could not be fetched"
                );
                error!("{message}");
                Err(Error::Persistence(message))
            }
        }
    }
}

impl CompanyChainEventProcessor {
    pub fn new(
        blockchain_store: Arc<dyn CompanyChainStoreApi>,
        company_store: Arc<dyn CompanyStoreApi>,
        identity_store: Arc<dyn IdentityStoreApi>,
        nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
        bill_invite_handler: Arc<dyn NotificationHandlerApi>,
        transport: Arc<dyn TransportClientApi>,
        bitcoin_network: bitcoin::Network,
    ) -> Self {
        Self {
            blockchain_store,
            company_store,
            identity_store,
            nostr_contact_processor,
            bitcoin_network,
            bill_invite_handler,
            transport,
        }
    }

    async fn add_new_chain(
        &self,
        blocks: Vec<CompanyBlock>,
        keys: &BcrKeys,
        identity: &NodeId,
    ) -> Result<()> {
        let (company_id, mut company, mut chain, we_are_signatory) =
            self.get_valid_chain(blocks.clone(), keys, identity)?;
        if we_are_signatory {
            debug!(
                "adding new chain and company {company_id} with {} blocks",
                blocks.len()
            );
            // add the company
            self.company_store.insert(&company).await.map_err(|e| {
                error!("Failed to insert company {company_id}: {e}");
                Error::Persistence(e.to_string())
            })?;

            // save keys
            self.save_keys(&company_id, keys).await?;

            // save the first block
            self.save_block(&company_id, chain.get_first_block())
                .await?;

            // save all blocks
            for block in blocks.iter().skip(1) {
                self.add_company_block(
                    &company_id,
                    keys,
                    &mut company,
                    &mut chain,
                    block,
                    identity,
                )
                .await?;
            }

            // also add the company to our nostr contacts
            self.nostr_contact_processor
                .ensure_nostr_contact(&company_id)
                .await;

            // as well as all the company signatories
            for signatory in company.signatories.iter() {
                self.nostr_contact_processor
                    .ensure_nostr_contact(signatory)
                    .await;
            }
        } else {
            info!("We are not a signatory for company {company_id} so skipping chain");
        }
        Ok(())
    }

    async fn add_company_blocks(
        &self,
        company_id: &NodeId,
        chain: &mut CompanyBlockchain,
        blocks: Vec<CompanyBlock>,
        identity: &NodeId,
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
        for block in blocks.iter() {
            if block.id <= block_height {
                info!(
                    "Skipping block with id {block_height} for {company_id} as we already have it"
                );
                continue;
            }

            match self
                .add_company_block(company_id, &keys, &mut company, chain, block, identity)
                .await
            {
                Ok(_) => {
                    block_height = block.id;
                    Ok(())
                }
                Err(e) => {
                    // if we received a single block (normal block populate) and we are missing blocks, we try to resync
                    if blocks.len() == 1
                        && BlockId::next_from_previous_block_id(&chain.get_latest_block().id)
                            < block.id
                    {
                        info!(
                            "Received invalid block {} for company {company_id} - missing blocks - try to resync",
                            block.id
                        );
                        self.resync_chain(company_id).await?;
                        break;
                    } else {
                        error!("Error adding block for company {company_id}: {e}");
                        Err(e)
                    }
                }
            }?;
        }
        debug!("Updated company {company_id} with data from new blocks");
        Ok(())
    }

    async fn add_company_block(
        &self,
        company_id: &NodeId,
        keys: &BcrKeys,
        company: &mut Company,
        chain: &mut CompanyBlockchain,
        block: &CompanyBlock,
        identity: &NodeId,
    ) -> Result<()> {
        if chain.try_add_block(block.clone()) {
            let data = block
                .get_block_data(keys)
                .map_err(|e| Error::Blockchain(e.to_string()))?;
            match data {
                CompanyBlockPayload::Create(_) => { /* creates are handled on validation */ }
                update @ CompanyBlockPayload::Update(_) => {
                    info!("Updating company {company_id} from block data");
                    company.apply_block_data(&update, identity);
                    self.company_store
                        .update(company_id, company)
                        .await
                        .map_err(|e| Error::Persistence(e.to_string()))?;
                }
                CompanyBlockPayload::AddSignatory(payload) => {
                    info!("Adding signatory to company {company_id} and contacts");
                    self.nostr_contact_processor
                        .ensure_nostr_contact(&payload.signatory)
                        .await;
                    company.apply_block_data(&CompanyBlockPayload::AddSignatory(payload), identity);
                    self.company_store
                        .update(company_id, company)
                        .await
                        .map_err(|e| Error::Persistence(e.to_string()))?;
                }
                update @ CompanyBlockPayload::RemoveSignatory(_) => {
                    info!("Removing signatory from company {company_id}");
                    company.apply_block_data(&update, identity);
                    self.company_store
                        .update(company_id, company)
                        .await
                        .map_err(|e| Error::Persistence(e.to_string()))?;
                }
                CompanyBlockPayload::SignBill(payload) => {
                    if let Some(bill_key) = payload.bill_key
                        && payload.operation == BillOpCode::Issue
                    {
                        info!("Adding detected company bill {}", payload.bill_id);
                        let bill_keys = BcrKeys::from_private_key(&bill_key);
                        let invite = ChainInvite::bill(
                            payload.bill_id.to_string(),
                            BcrKeys::from_private_key(&bill_keys.get_private_key()),
                        );
                        // we want to process all blocks for the company even if we don't have all
                        // the bills.
                        if let Err(e) = self
                            .bill_invite_handler
                            .handle_event(
                                Event::new_bill(invite).try_into()?,
                                &company.id,
                                None,
                                None,
                            )
                            .await
                        {
                            error!(
                                "Failed to add company bill {} when adding company: {e}",
                                payload.bill_id
                            );
                        }
                    }
                }
                CompanyBlockPayload::IdentityProof(_) => {
                    // TODO: handle identity proof blocks
                }
            }

            // persist data
            self.save_block(company_id, block).await?;
            Ok(())
        } else {
            error!("Received invalid company block");
            Err(Error::Blockchain(
                "Received invalid company block".to_string(),
            ))
        }
    }
    fn get_valid_chain(
        &self,
        blocks: Vec<CompanyBlock>,
        keys: &BcrKeys,
        identity: &NodeId,
    ) -> Result<(NodeId, Company, CompanyBlockchain, bool)> {
        match CompanyBlockchain::new_from_blocks(blocks.clone()) {
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
                let company = Company::from_block_data(payload, identity);

                // check if we are a signatory
                let we_are_signatory = {
                    let mut aggregate = company.clone();
                    for block in blocks.iter().skip(1) {
                        if let Ok(data) = &block.get_block_data(keys) {
                            aggregate.apply_block_data(data, identity);
                        }
                    }
                    aggregate.active
                };

                // chain with just the create block
                let return_chain = CompanyBlockchain::new_from_blocks(vec![first_block.clone()])
                    .map_err(|e| Error::Blockchain(e.to_string()))?;

                Ok((node_id, company, return_chain, we_are_signatory))
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

    async fn save_keys(&self, node_id: &NodeId, keys: &BcrKeys) -> Result<()> {
        if let Err(e) = self.company_store.save_key_pair(node_id, keys).await {
            error!("Failed to save keys to company store: {e}");
            return Err(Error::Persistence(
                "Failed to save keys to company store".to_string(),
            ));
        }
        Ok(())
    }
}

impl ServiceTraitBounds for CompanyChainEventProcessor {}

#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use bcr_common::core::NodeId;
    use bcr_ebill_core::protocol::event::{CompanyBlockEvent, Event, EventEnvelope};
    use bcr_ebill_core::{
        application::company::Company,
        protocol::Name,
        protocol::Sha256Hash,
        protocol::Timestamp,
        protocol::blockchain::{
            Blockchain, BlockchainType,
            company::{
                CompanyAddSignatoryBlockData, CompanyBlock, CompanyBlockchain,
                CompanyIdentityProofBlockData, CompanyRemoveSignatoryBlockData,
                CompanyUpdateBlockData, SignatoryType,
            },
        },
        protocol::crypto::BcrKeys,
    };
    use mockall::predicate::{always, eq};

    use crate::handler::test_utils::signed_identity_proof_test;
    use crate::{
        handler::{
            CompanyChainEventProcessor, CompanyChainEventProcessorApi,
            MockNostrContactProcessorApi, MockNotificationHandlerApi,
            test_utils::{
                MockCompanyChainStore, MockCompanyStore, MockIdentityStore, get_company_data,
                node_id_test,
            },
        },
        test_utils::{MockNotificationJsonTransport, get_baseline_identity},
        transport::create_public_chain_event,
    };

    #[tokio::test]
    async fn test_create_event_handler() {
        let (chain_store, store, contact, bill, identity, transport) = create_mocks();
        CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(identity),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );
    }

    #[tokio::test]
    async fn test_validate_chain_event_and_sender_invalid_on_no_keys_or_chain() {
        let keys = BcrKeys::new().get_nostr_keys();
        let (chain_store, mut store, contact, bill, identity, transport) = create_mocks();

        store
            .expect_get()
            .with(eq(node_id_test()))
            .returning(move |_| {
                Err(bcr_ebill_persistence::Error::NoSuchEntity(
                    "company block".to_string(),
                    node_id_test().to_string(),
                ))
            });

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(identity),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(transport),
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
        let (chain_store, mut store, contact, bill, identity, transport) = create_mocks();
        let (_, (company, _)) = get_company_data();
        store
            .expect_get()
            .with(eq(node_id_test()))
            .returning(move |_| Ok(company.clone()));

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(identity),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(transport),
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
        let (chain_store, mut store, contact, bill, identity, transport) = create_mocks();
        let (_, (mut company, _)) = get_company_data();
        company.signatories = vec![NodeId::new(keys.pub_key(), bitcoin::Network::Testnet)];
        store
            .expect_get()
            .with(eq(node_id_test()))
            .returning(move |_| Ok(company.clone()));

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(identity),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(transport),
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
        let (mut chain_store, mut store, mut contact, bill, mut identity, transport) =
            create_mocks();
        let (node_id, (company, keys)) = get_company_data();
        let blocks = vec![get_company_create_block(
            node_id.clone(),
            company.clone(),
            &keys,
        )];

        let node_id_clone = node_id.clone();
        // checks if we already have the chain
        chain_store
            .expect_get_chain()
            .with(eq(node_id.clone()))
            .returning(move |_| {
                Err(bcr_ebill_persistence::Error::NoSuchEntity(
                    "company block".to_string(),
                    node_id_clone.to_string(),
                ))
            })
            .once();

        // we need to validate if we are a signatory with our identity
        identity
            .expect_get()
            .returning(|| Ok(get_baseline_identity().identity))
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
            .times(2);

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(identity),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        handler
            .process_chain_data(&node_id, blocks, Some(keys))
            .await
            .expect("Process chain data should be handled");
    }

    #[tokio::test]
    async fn test_process_update_company_data() {
        let (mut chain_store, mut store, mut contact, bill, mut identity, transport) =
            create_mocks();
        let (node_id, (company, keys)) = get_company_data();
        let blocks = vec![get_company_create_block(
            node_id.clone(),
            company.clone(),
            &keys,
        )];
        let chain = CompanyBlockchain::new_from_blocks(blocks).expect("could not create chain");
        let data = CompanyUpdateBlockData {
            name: Some(Name::new("new_name").unwrap()),
            ..Default::default()
        };
        let update_block = get_company_update_block(
            node_id.clone(),
            chain.get_latest_block(),
            &BcrKeys::new(),
            &keys,
            &data,
        );

        // we need to validate if we are a signatory with our identity
        identity
            .expect_get()
            .returning(|| Ok(get_baseline_identity().identity))
            .once();

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
                n == &expected_node.clone()
                    && c.id == expected_node.clone()
                    && c.name == Name::new("new_name").unwrap()
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
            Arc::new(identity),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        handler
            .process_chain_data(&node_id, vec![update_block], None)
            .await
            .expect("Process chain data should be handled");
    }

    #[tokio::test]
    async fn test_recovers_chain_on_missing_blocks() {
        let (mut chain_store, mut store, mut contact, bill, mut identity, mut transport) =
            create_mocks();
        let (node_id, (company, keys)) = get_company_data();
        let bcr_keys: BcrKeys = keys.clone();
        let blocks = vec![get_company_create_block(
            node_id.clone(),
            company.clone(),
            &keys,
        )];
        let skipped_chain =
            CompanyBlockchain::new_from_blocks(blocks).expect("could not create chain");
        let data_skipped = CompanyUpdateBlockData {
            name: Some(Name::new("new_name").unwrap()),
            ..Default::default()
        };

        let skipped_block = get_company_update_block(
            node_id.clone(),
            skipped_chain.get_latest_block(),
            &BcrKeys::new(),
            &keys,
            &data_skipped,
        );

        let mut full_chain = skipped_chain.clone();
        full_chain.try_add_block(skipped_block.clone());

        let data = CompanyUpdateBlockData {
            name: Some(Name::new("another_name").unwrap()),
            ..Default::default()
        };
        let update_block = get_company_update_block(
            node_id.clone(),
            full_chain.get_latest_block(),
            &BcrKeys::new(),
            &keys,
            &data,
        );

        let event1 = generate_test_event(
            &bcr_keys,
            None,
            None,
            as_event_payload(&node_id, skipped_chain.get_latest_block()),
            &node_id,
        );

        let event2 = generate_test_event(
            &bcr_keys,
            Some(event1.clone()),
            Some(event1.clone()),
            as_event_payload(&node_id, &skipped_block),
            &node_id,
        );

        let event3 = generate_test_event(
            &bcr_keys,
            Some(event2.clone()),
            Some(event1.clone()),
            as_event_payload(&node_id, &update_block),
            &node_id,
        );

        let nostr_chain = vec![event1.clone(), event2.clone(), event3.clone()];

        // we need to validate if we are a signatory with our identity
        identity
            .expect_get()
            .returning(|| Ok(get_baseline_identity().identity))
            .times(2);

        // checks if we already have the chain
        chain_store
            .expect_get_chain()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(skipped_chain.clone()))
            .times(2);

        // we have a chain so get the keys
        store
            .expect_get_key_pair()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(keys.clone()))
            .times(3);

        // get the current company state
        let expected_company = company.clone();
        store
            .expect_get()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(expected_company.clone()))
            .times(2);

        // and queries the chain from the transport
        transport
            .expect_resolve_public_chain()
            .with(eq(node_id.to_string()), eq(BlockchainType::Company))
            .returning(move |_, _| Ok(nostr_chain.clone()))
            .once();

        // apply changes from skipped block and update the company
        let expected_node = node_id.clone();
        store
            .expect_update()
            .withf(move |n, c| {
                n == &expected_node.clone()
                    && c.id == expected_node.clone()
                    && c.name == Name::new("new_name").unwrap()
            })
            .returning(|_, _| Ok(()))
            .once();

        // apply changes from last block and update the company
        let expected_node = node_id.clone();
        store
            .expect_update()
            .withf(move |n, c| {
                n == &expected_node.clone()
                    && c.id == expected_node.clone()
                    && c.name == Name::new("another_name").unwrap()
            })
            .returning(|_, _| Ok(()))
            .once();

        // inserts the block
        chain_store
            .expect_add_block()
            .with(eq(node_id.clone()), always())
            .returning(|_, _| Ok(()))
            .times(2);

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
            Arc::new(identity),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        handler
            .process_chain_data(&node_id, vec![update_block], None)
            .await
            .expect("Process chain data should be handled");
    }

    fn as_event_payload(id: &NodeId, block: &CompanyBlock) -> EventEnvelope {
        Event::new_company_chain(CompanyBlockEvent {
            node_id: id.clone(),
            block_height: block.id.inner() as usize,
            block: block.clone(),
        })
        .try_into()
        .expect("could not create envelope")
    }

    fn generate_test_event(
        keys: &BcrKeys,
        previous: Option<nostr::Event>,
        root: Option<nostr::Event>,
        data: EventEnvelope,
        node_id: &NodeId,
    ) -> nostr::Event {
        create_public_chain_event(
            &node_id.to_string(),
            data,
            Timestamp::new(1000).unwrap(),
            BlockchainType::Company,
            keys.clone(),
            previous,
            root,
        )
        .expect("could not create chain event")
        .sign_with_keys(&keys.get_nostr_keys())
        .expect("could not sign event")
    }

    #[tokio::test]
    async fn test_process_add_company_signatory() {
        let (mut chain_store, mut store, mut contact, bill, mut identity, transport) =
            create_mocks();
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

        // we need to validate if we are a signatory with our identity
        identity
            .expect_get()
            .returning(|| Ok(get_baseline_identity().identity))
            .once();

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
            Arc::new(identity),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        handler
            .process_chain_data(&node_id, vec![update_block], None)
            .await
            .expect("Process chain data should be handled");
    }

    #[tokio::test]
    async fn test_process_remove_company_signatory() {
        let (mut chain_store, mut store, mut contact, bill, mut identity, transport) =
            create_mocks();
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

        // we need to validate if we are a signatory with our identity
        identity
            .expect_get()
            .returning(|| Ok(get_baseline_identity().identity))
            .once();

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
            Arc::new(identity),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        handler
            .process_chain_data(&node_id, vec![update_block], None)
            .await
            .expect("Process chain data should be handled");
    }

    #[tokio::test]
    async fn test_process_identity_proof() {
        let (mut chain_store, mut store, contact, bill, mut identity, transport) = create_mocks();
        let (node_id, (company, keys)) = get_company_data();
        let blocks = vec![get_company_create_block(
            node_id.clone(),
            company.clone(),
            &keys,
        )];
        let chain = CompanyBlockchain::new_from_blocks(blocks).expect("could not create chain");
        let test_signed_identity = signed_identity_proof_test();
        let data = CompanyIdentityProofBlockData {
            proof: test_signed_identity.0,
            data: test_signed_identity.1,
        };
        let update_block = get_company_identity_proof_block(
            node_id.clone(),
            chain.get_latest_block(),
            &BcrKeys::new(),
            &keys,
            &data,
        );

        // we need to validate if we are a signatory with our identity
        identity
            .expect_get()
            .returning(|| Ok(get_baseline_identity().identity))
            .once();

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

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(identity),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        handler
            .process_chain_data(&node_id, vec![update_block], None)
            .await
            .expect("Process chain data should be handled");
    }

    pub fn get_company_create_block(
        node_id: NodeId,
        company: Company,
        keys: &BcrKeys,
    ) -> CompanyBlock {
        CompanyBlock::create_block_for_create(
            node_id,
            Sha256Hash::new("genesis hash"),
            &company.into(),
            &BcrKeys::new(),
            keys,
            Timestamp::new(1731593928).unwrap(),
        )
        .expect("could not create block")
    }

    pub fn get_company_update_block(
        node_id: NodeId,
        previous_block: &CompanyBlock,
        keys: &BcrKeys,
        company_keys: &BcrKeys,
        data: &CompanyUpdateBlockData,
    ) -> CompanyBlock {
        CompanyBlock::create_block_for_update(
            node_id,
            previous_block,
            data,
            keys,
            company_keys,
            Timestamp::new(1731594928).unwrap(),
        )
        .expect("could not create block")
    }

    fn get_company_add_signatory_block(
        node_id: NodeId,
        previous_block: &CompanyBlock,
        keys: &BcrKeys,
        company_keys: &BcrKeys,
        data: &CompanyAddSignatoryBlockData,
    ) -> CompanyBlock {
        CompanyBlock::create_block_for_add_signatory(
            node_id,
            previous_block,
            data,
            keys,
            company_keys,
            &data.signatory.pub_key(),
            Timestamp::new(1731594928).unwrap(),
        )
        .expect("could not create block")
    }

    fn get_company_remove_signatory_block(
        node_id: NodeId,
        previous_block: &CompanyBlock,
        keys: &BcrKeys,
        company_keys: &BcrKeys,
        data: &CompanyRemoveSignatoryBlockData,
    ) -> CompanyBlock {
        CompanyBlock::create_block_for_remove_signatory(
            node_id,
            previous_block,
            data,
            keys,
            company_keys,
            Timestamp::new(1731594928).unwrap(),
        )
        .expect("could not create block")
    }

    fn get_company_identity_proof_block(
        node_id: NodeId,
        previous_block: &CompanyBlock,
        keys: &BcrKeys,
        company_keys: &BcrKeys,
        data: &CompanyIdentityProofBlockData,
    ) -> CompanyBlock {
        CompanyBlock::create_block_for_identity_proof(
            node_id,
            previous_block,
            data,
            keys,
            company_keys,
            Timestamp::new(1731594928).unwrap(),
        )
        .expect("could not create block")
    }

    fn create_mocks() -> (
        MockCompanyChainStore,
        MockCompanyStore,
        MockNostrContactProcessorApi,
        MockNotificationHandlerApi,
        MockIdentityStore,
        MockNotificationJsonTransport,
    ) {
        (
            MockCompanyChainStore::new(),
            MockCompanyStore::new(),
            MockNostrContactProcessorApi::new(),
            MockNotificationHandlerApi::new(),
            MockIdentityStore::new(),
            MockNotificationJsonTransport::new(),
        )
    }
}
