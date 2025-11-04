use crate::handler::public_chain_helpers::{BlockData, EventContainer, resolve_event_chains};
use crate::{Error, Result};
use async_trait::async_trait;
use bcr_common::core::BillId;
use bcr_ebill_api::service::transport_service::transport::NotificationJsonTransportApi;
use bcr_ebill_core::ServiceTraitBounds;
use bcr_ebill_core::Validate;
use bcr_ebill_core::bill::BillKeys;
use bcr_ebill_core::bill::{BillValidateActionData, BillValidationActionMode};
use bcr_ebill_core::block_id::BlockId;
use bcr_ebill_core::blockchain::bill::BillOpCode;
use bcr_ebill_core::blockchain::bill::block::BillIssueBlockData;
use bcr_ebill_core::blockchain::bill::{BillBlock, BillBlockchain};
use bcr_ebill_core::blockchain::{Block, Blockchain, BlockchainType};
use bcr_ebill_core::util::BcrKeys;
use bcr_ebill_persistence::bill::BillChainStoreApi;
use bcr_ebill_persistence::bill::BillStoreApi;
use log::{debug, error, info, warn};
use std::sync::Arc;

use super::{BillChainEventProcessorApi, NostrContactProcessorApi};

impl ServiceTraitBounds for BillChainEventProcessor {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl BillChainEventProcessorApi for BillChainEventProcessor {
    async fn process_chain_data(
        &self,
        bill_id: &BillId,
        blocks: Vec<BillBlock>,
        keys: Option<BillKeys>,
    ) -> Result<()> {
        // check that incoming bills are of the same network that we use
        if bill_id.network() != self.bitcoin_network {
            warn!("Received bill blocks for bill {bill_id} for a different network");
            return Err(Error::Blockchain(format!(
                "Received bill blocks for bill {bill_id} for a different network"
            )));
        }

        if let Ok(existing_chain) = self.bill_blockchain_store.get_chain(bill_id).await {
            self.add_bill_blocks(bill_id, existing_chain, blocks).await
        } else {
            match keys {
                Some(keys) => self.add_new_chain(blocks, &keys).await,
                _ => {
                    error!("Received bill blocks for unknown bill {bill_id}");
                    Err(Error::Blockchain(
                        "Received bill blocks for unknown bill".to_string(),
                    ))
                }
            }
        }
    }

    async fn validate_chain_event_and_sender(
        &self,
        bill_id: &BillId,
        sender: nostr::PublicKey,
    ) -> Result<bool> {
        if let (Ok(bill_keys), Ok(chain)) = (
            self.bill_store.get_keys(bill_id).await,
            self.bill_blockchain_store.get_chain(bill_id).await,
        ) {
            let participants = chain
                .get_all_nodes_from_bill(&bill_keys)
                .map_err(|e| Error::Blockchain(e.to_string()))?
                .iter()
                .map(|p| p.npub())
                .collect::<Vec<nostr::PublicKey>>();

            Ok(participants.contains(&sender))
        } else {
            Ok(false)
        }
    }

    async fn resolve_chain(
        &self,
        bill_id: &BillId,
        bill_keys: &BillKeys,
    ) -> Result<Vec<Vec<EventContainer>>> {
        let bcr_keys = BcrKeys::from_private_key(&bill_keys.private_key)?;
        resolve_event_chains(
            self.transport.clone(),
            &bill_id.to_string(),
            BlockchainType::Bill,
            &bcr_keys,
        )
        .await
    }

    async fn resync_chain(&self, bill_id: &BillId) -> Result<()> {
        match (
            self.bill_blockchain_store.get_chain(bill_id).await,
            self.bill_store.get_keys(bill_id).await,
        ) {
            (Ok(existing_chain), Ok(bill_keys)) => {
                debug!("starting bill chain resync for {bill_id}");
                let bcr_keys = BcrKeys::from_private_key(&bill_keys.private_key)?;
                if let Ok(chain_data) = resolve_event_chains(
                    self.transport.clone(),
                    &bill_id.to_string(),
                    BlockchainType::Bill,
                    &bcr_keys,
                )
                .await
                {
                    for data in chain_data.iter() {
                        let blocks: Vec<BillBlock> = data
                            .iter()
                            .filter_map(|d| match d.block.clone() {
                                BlockData::Bill(block) => Some(block),
                                _ => None,
                            })
                            .collect();
                        if !data.is_empty()
                            && self
                                .add_bill_blocks(bill_id, existing_chain.clone(), blocks)
                                .await
                                .is_ok()
                        {
                            debug!("resynced bill {bill_id} with {} remote events", data.len());
                            break;
                        }
                    }
                    debug!("finished bill chain resync for {bill_id}");
                    Ok(())
                } else {
                    let message = format!("Could not refetch chain data from Nostr for {bill_id}");
                    error!("{message}");
                    Err(Error::Network(message))
                }
            }
            _ => {
                let message = format!(
                    "Could not refetch chain for {bill_id} because the bill keys or chain could not be fetched"
                );
                error!("{message}");
                Err(Error::Persistence(message))
            }
        }
    }
}

#[derive(Clone)]
pub struct BillChainEventProcessor {
    bill_blockchain_store: Arc<dyn BillChainStoreApi>,
    bill_store: Arc<dyn BillStoreApi>,
    nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
    transport: Arc<dyn NotificationJsonTransportApi>,
    bitcoin_network: bitcoin::Network,
}

impl BillChainEventProcessor {
    pub fn new(
        bill_blockchain_store: Arc<dyn BillChainStoreApi>,
        bill_store: Arc<dyn BillStoreApi>,
        nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
        transport: Arc<dyn NotificationJsonTransportApi>,
        bitcoin_network: bitcoin::Network,
    ) -> Self {
        Self {
            bill_blockchain_store,
            bill_store,
            nostr_contact_processor,
            transport,
            bitcoin_network,
        }
    }

    async fn add_bill_blocks(
        &self,
        bill_id: &BillId,
        existing: BillBlockchain,
        blocks: Vec<BillBlock>,
    ) -> Result<()> {
        let mut block_added = false;
        let mut chain = existing;
        let bill_keys = self.bill_store.get_keys(bill_id).await.map_err(|e| {
            error!("Could not process received blocks for {bill_id} because the bill keys could not be fetched");
            Error::Persistence(e.to_string())
        })?;
        let is_paid = self.bill_store.is_paid(bill_id).await.map_err(|e| {
            error!("Could not process received blocks for bill {bill_id} because getting paid status failed");
            Error::Persistence(e.to_string())
        })?;
        let bill_first_version = chain.get_first_version_bill(&bill_keys).map_err(|e| {
            error!("Could not process received blocks for bill {bill_id} because getting first version bill data failed");
            Error::Blockchain(e.to_string())
        })?;

        debug!("adding {} bill blocks for bill {bill_id}", blocks.len());
        for block in blocks.iter() {
            block_added = match self
                .validate_and_save_block(
                    bill_id,
                    &mut chain,
                    &bill_first_version,
                    &bill_keys,
                    block.clone(),
                    is_paid,
                )
                .await
            {
                Ok(added) => Ok(added),
                Err(e) => {
                    // if we received a single block (normal block populate) and we are missing blocks, we try to resync
                    if blocks.len() == 1
                        && BlockId::next_from_previous_block_id(&chain.get_latest_block().id)
                            < block.id
                    {
                        info!(
                            "Received invalid block {} for bill {bill_id} - missing blocks - try to resync",
                            block.id
                        );
                        self.resync_chain(bill_id).await?;
                        break;
                    } else {
                        error!("Error adding block for bill {bill_id}: {e}");
                        Err(e)
                    }
                }
            }?;
        }
        // if the bill was changed, we invalidate the cache
        if block_added {
            debug!("block was added for bill {bill_id} - invalidating cache");
            if let Err(e) = self.invalidate_cache_for_bill(bill_id).await {
                error!("Error invalidating cache for bill {bill_id}: {e}");
            }

            // ensure that we have all nostr contacts for the bill participants
            let node_ids = chain
                .get_all_nodes_from_bill(&bill_keys)
                .unwrap_or_default();
            for node_id in node_ids {
                self.nostr_contact_processor
                    .ensure_nostr_contact(&node_id)
                    .await
            }
        }
        Ok(())
    }

    async fn validate_and_save_block(
        &self,
        bill_id: &BillId,
        chain: &mut BillBlockchain,
        bill_first_version: &BillIssueBlockData,
        bill_keys: &BillKeys,
        block: BillBlock,
        is_paid: bool,
    ) -> Result<bool> {
        let block_height = chain.get_latest_block().id;
        let block_id = block.id;
        // if we already have the block, we skip it
        if block.id <= block_height {
            info!("Skipping block with id {block_id} for {bill_id} as we already have it");
            return Ok(false);
        }
        if block.op_code == BillOpCode::Issue {
            info!(
                "Skipping block {block_id} with op code Issue for {bill_id} as we already have the chain"
            );
            return Ok(false);
        }
        // validate plaintext hash
        if !block.validate_plaintext_hash(&bill_keys.private_key) {
            error!("Received invalid block {block_id} for bill {bill_id} - invalid plaintext hash");
            return Err(Error::Blockchain(format!(
                "Received invalid block {block_id} for bill {bill_id} - invalid plaintext hash"
            )));
        }
        // create a clone of the chain for validating the bill action later, since the chain
        // will be mutated with the integrity checks
        let chain_clone_for_validation = chain.clone();
        // first, do cheap integrity checks
        if !chain.try_add_block(block.clone()) {
            error!("Received invalid block {block_id} for bill {bill_id}");
            return Err(Error::Blockchain(
                "Received invalid block for bill".to_string(),
            ));
        }
        // then, verify signature and signer of the block and get signer and bill action for
        // the block
        let (signer, bill_action) = match block.verify_and_get_signer(bill_keys) {
            Ok(signer) => signer,
            Err(e) => {
                error!(
                    "Received invalid block {block_id} for bill {bill_id} - could not verify signature from block data signer"
                );
                return Err(Error::Blockchain(e.to_string()));
            }
        };

        // then, validate the bill action
        let bill_parties = chain_clone_for_validation
            .get_bill_parties(bill_keys, bill_first_version)
            .map_err(|e| {
                error!("Received invalid block {block_id} for bill {bill_id}: {e}");
                Error::Blockchain(
                    "Received invalid block for bill - couldn't get bill parties".to_string(),
                )
            })?;
        if let Err(e) = (BillValidateActionData {
            blockchain: chain_clone_for_validation,
            drawee_node_id: bill_parties.drawee.node_id,
            payee_node_id: bill_parties.payee.node_id(),
            endorsee_node_id: bill_parties.endorsee.map(|e| e.node_id()),
            maturity_date: bill_first_version.maturity_date.clone(),
            bill_keys: bill_keys.clone(),
            timestamp: block.timestamp,
            signer_node_id: signer,
            is_paid,
            mode: BillValidationActionMode::Deep(
                bill_action.ok_or_else(|| {
                    error!(
                        "Received invalid block {block_id} for bill {bill_id} - no valid bill action returned"
                    );
                    Error::Blockchain(
                        "Received invalid block for bill - no valid bill action returned"
                        .to_string(),
                    )
                })?),
        }).validate()
        {
            error!(
                "Received invalid block {block_id} for bill {bill_id}, bill action validation failed: {e}"
            );
            return Err(Error::Blockchain(e.to_string()));
        }
        // if everything works out - add the block
        self.save_block(bill_id, &block).await?;
        Ok(true) // block was added
    }

    async fn add_new_chain(&self, blocks: Vec<BillBlock>, keys: &BillKeys) -> Result<()> {
        let (bill_id, bill_first_version, chain) = self.get_valid_chain(blocks, keys)?;
        debug!("adding new chain for bill {bill_id}");
        // issue block was validated in get_valid_chain
        let issue_block = chain.get_first_block().to_owned();
        // validate plaintext hash
        if !issue_block.validate_plaintext_hash(&keys.private_key) {
            error!("Newly received chain issue block has invalid plaintext hash");
            return Err(Error::Blockchain(
                "Newly received chain issue block has invalid plaintext hash".to_string(),
            ));
        }
        // create a chain that starts from issue, to simulate adding blocks and validating them
        let mut chain_starting_at_issue =
            match BillBlockchain::new_from_blocks(vec![issue_block.clone()]) {
                Ok(chain) => chain,
                Err(e) => {
                    error!("Newly received chain is not valid: {e}");
                    return Err(Error::Blockchain(
                        "Newly received chain is not valid".to_string(),
                    ));
                }
            };
        self.save_block(&bill_id, &issue_block).await?;

        // Only add other blocks, if there are any
        if chain.block_height() > 1 {
            let blocks = chain.blocks()[1..].to_vec();
            for block in blocks {
                self.validate_and_save_block(
                    &bill_id,
                    &mut chain_starting_at_issue,
                    &bill_first_version,
                    keys,
                    block,
                    false, // new chain, we don't know if it's paid
                )
                .await?;
            }
        }
        self.save_keys(&bill_id, keys).await?;

        // ensure that we have all nostr contacts for the bill participants
        let node_ids = chain.get_all_nodes_from_bill(keys).unwrap_or_default();
        for node_id in node_ids {
            self.nostr_contact_processor
                .ensure_nostr_contact(&node_id)
                .await
        }

        Ok(())
    }

    fn get_valid_chain(
        &self,
        blocks: Vec<BillBlock>,
        keys: &BillKeys,
    ) -> Result<(BillId, BillIssueBlockData, BillBlockchain)> {
        // cheap integrity checks first
        match BillBlockchain::new_from_blocks(blocks) {
            Ok(chain) if chain.is_chain_valid() => {
                // make sure first block is of type Issue
                if chain.get_first_block().op_code != BillOpCode::Issue {
                    error!("Newly received chain is not valid - first block is not an Issue block");
                    return Err(Error::Blockchain(
                        "Newly received chain is not valid - first block is not an Issue block"
                            .to_string(),
                    ));
                }
                match chain.get_first_version_bill(keys) {
                    Ok(bill) => {
                        // then, verify signature and signer of each block and get signer
                        for block in chain.blocks().iter() {
                            let _signer = match block.verify_and_get_signer(keys) {
                                Ok(signer) => signer,
                                Err(e) => {
                                    error!(
                                        "Received invalid block for bill {} - could not verify signature from block data signer",
                                        &bill.id
                                    );
                                    return Err(Error::Blockchain(e.to_string()));
                                }
                            };
                        }
                        Ok((bill.id.clone(), bill, chain))
                    }
                    Err(e) => {
                        error!("Failed to get first version bill from newly received chain: {e}");
                        Err(Error::Crypto(format!(
                            "Failed to decrypt new bill chain with given keys: {e}"
                        )))
                    }
                }
            }
            _ => {
                error!("Newly received chain is not valid");
                Err(Error::Blockchain(
                    "Newly received chain is not valid".to_string(),
                ))
            }
        }
    }

    async fn save_block(&self, bill_id: &BillId, block: &BillBlock) -> Result<()> {
        if let Err(e) = self.bill_blockchain_store.add_block(bill_id, block).await {
            error!("Failed to add block to blockchain store: {e}");
            return Err(Error::Persistence(
                "Failed to add block to blockchain store".to_string(),
            ));
        }
        Ok(())
    }

    async fn invalidate_cache_for_bill(&self, bill_id: &BillId) -> Result<()> {
        if let Err(e) = self.bill_store.invalidate_bill_in_cache(bill_id).await {
            error!("Failed to invalidate cache for bill {bill_id}: {e}");
            return Err(Error::Persistence(
                "Failed to invalidate cache for bill".to_string(),
            ));
        }
        Ok(())
    }

    async fn save_keys(&self, bill_id: &BillId, keys: &BillKeys) -> Result<()> {
        if let Err(e) = self.bill_store.save_keys(bill_id, keys).await {
            error!("Failed to save keys to bill store: {e}");
            return Err(Error::Persistence(
                "Failed to save keys to bill store".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bcr_common::core::NodeId;
    use bcr_ebill_core::{
        blockchain::bill::block::{
            BillAcceptBlockData, BillEndorseBlockData, BillParticipantBlockData,
            BillRejectBlockData, BillRequestToAcceptBlockData,
        },
        constants::ACCEPT_DEADLINE_SECONDS,
        contact::BillIdentParticipant,
        protocol::{BillBlockEvent, Event, EventEnvelope},
        timestamp::Timestamp,
        util::BcrKeys,
    };
    use mockall::predicate::{always, eq};

    use crate::{
        handler::{
            MockNostrContactProcessorApi,
            test_utils::{
                MockBillChainStore, MockBillStore, bill_id_test, empty_address, get_baseline_bill,
                get_baseline_identity, get_bill_keys, get_genesis_chain, get_test_bitcredit_bill,
                node_id_test, node_id_test_other, private_key_test,
            },
        },
        test_utils::MockNotificationJsonTransport,
        transport::create_public_chain_event,
    };

    use super::*;

    #[tokio::test]
    async fn test_create_event_handler() {
        let (bill_chain_store, bill_store, contact, transport) = create_mocks();
        BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(contact),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );
    }

    #[tokio::test]
    async fn test_validate_chain_event_and_sender_invalid_on_no_keys_or_chain() {
        let keys = BcrKeys::new().get_nostr_keys();
        let (mut bill_chain_store, mut bill_store, contact, transport) = create_mocks();

        bill_store
            .expect_get_keys()
            .with(eq(bill_id_test()))
            .returning(move |_| Err(bcr_ebill_persistence::Error::NoBillBlock));

        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id_test()))
            .returning(move |_| Err(bcr_ebill_persistence::Error::NoBillBlock));

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(contact),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        let valid = handler
            .validate_chain_event_and_sender(&bill_id_test(), keys.public_key())
            .await
            .expect("Event should be handled");
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_validate_chain_event_and_sender() {
        let bill = get_baseline_bill(&bill_id_test());
        let node_id = node_id_test();
        let npub = node_id.npub();

        let (mut bill_chain_store, mut bill_store, contact, transport) = create_mocks();

        bill_store
            .expect_get_keys()
            .with(eq(bill_id_test()))
            .returning(move |_| Ok(get_bill_keys()));

        let chain = get_genesis_chain(Some(bill.clone()));
        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id_test()))
            .returning(move |_| Ok(chain.clone()));

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(contact),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        let valid = handler
            .validate_chain_event_and_sender(&bill_id_test(), npub)
            .await
            .expect("Event should be handled");

        assert!(valid);
    }

    #[tokio::test]
    async fn test_creates_new_chain_for_new_chain_event() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let mut payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        payee.node_id = node_id_test_other();
        let drawer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, Some(&drawer), None);
        let chain = get_genesis_chain(Some(bill.clone()));
        let keys = get_bill_keys();

        let (mut bill_chain_store, mut bill_store, mut contact, transport) = create_mocks();

        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id_test()))
            .times(1)
            .returning(move |_| Err(bcr_ebill_persistence::Error::NoBillBlock));
        bill_chain_store
            .expect_add_block()
            .with(eq(bill_id_test()), eq(chain.blocks()[0].clone()))
            .times(1)
            .returning(move |_, _| Ok(()));

        bill_store
            .expect_save_keys()
            .with(eq(bill_id_test()), always())
            .times(1)
            .returning(move |_, _| Ok(()));

        // Store new contact
        contact.expect_ensure_nostr_contact().returning(|_| ());

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(contact),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        handler
            .process_chain_data(&bill_id_test(), chain.blocks().clone(), Some(keys.clone()))
            .await
            .expect("Event should be handled");
    }

    #[tokio::test]
    async fn test_adds_block_for_existing_chain_event() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let mut endorsee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        endorsee.node_id = node_id_test_other();
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let chain = get_genesis_chain(Some(bill.clone()));
        let block = BillBlock::create_block_for_endorse(
            bill_id_test(),
            chain.get_latest_block(),
            &BillEndorseBlockData {
                endorsee: BillParticipantBlockData::Ident(endorsee.clone().into()),
                // endorsed by payee
                endorser: BillParticipantBlockData::Ident(
                    BillIdentParticipant::new(get_baseline_identity().identity)
                        .unwrap()
                        .into(),
                ),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1000,
                signing_address: Some(empty_address()),
            },
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();

        let (mut bill_chain_store, mut bill_store, mut contact, transport) = create_mocks();

        let chain_clone = chain.clone();
        bill_store
            .expect_invalidate_bill_in_cache()
            .returning(|_| Ok(()));
        bill_store.expect_is_paid().returning(|_| Ok(false));
        bill_store.expect_get_keys().returning(|_| {
            Ok(BillKeys {
                private_key: private_key_test().to_owned(),
                public_key: node_id_test().pub_key(),
            })
        });
        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id_test()))
            .times(1)
            .returning(move |_| Ok(chain_clone.clone()));

        bill_chain_store
            .expect_add_block()
            .with(eq(bill_id_test()), eq(block.clone()))
            .times(1)
            .returning(move |_, _| Ok(()));

        contact.expect_ensure_nostr_contact().returning(|_| ());

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(contact),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        handler
            .process_chain_data(&bill_id_test(), vec![block.clone()], None)
            .await
            .expect("Event should be handled");
    }

    #[tokio::test]
    async fn test_recovers_chain_on_missing_blocks() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let mut endorsee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        endorsee.node_id = node_id_test_other();
        let bcr_keys = BcrKeys::from_private_key(&private_key_test()).unwrap();
        let bill_id = BillId::new(bcr_keys.pub_key(), bitcoin::Network::Testnet);
        let bill = get_test_bitcredit_bill(&bill_id, &payer, &payee, None, None);
        let chain = get_genesis_chain(Some(bill.clone()));

        let ts = chain.get_latest_block().timestamp + 1000;
        let block1 = BillBlock::create_block_for_request_to_accept(
            bill_id.clone(),
            chain.get_latest_block(),
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(empty_address()),
                acceptance_deadline_timestamp: ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &bcr_keys,
            None,
            &bcr_keys,
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();

        let block2 = BillBlock::create_block_for_accept(
            bill_id.clone(),
            &block1,
            &BillAcceptBlockData {
                accepter: payer.clone().into(),
                signatory: None,
                signing_timestamp: block1.timestamp + 1000,
                signing_address: empty_address(),
            },
            &bcr_keys,
            None,
            &bcr_keys,
            block1.timestamp + 1000,
        )
        .unwrap();

        let event1 = generate_test_event(
            &bcr_keys,
            None,
            None,
            as_event_payload(&bill_id_test(), chain.get_latest_block()),
            &bill_id,
        );

        let event2 = generate_test_event(
            &bcr_keys,
            Some(event1.clone()),
            Some(event1.clone()),
            as_event_payload(&bill_id_test(), &block1),
            &bill_id,
        );

        let event3 = generate_test_event(
            &bcr_keys,
            Some(event2.clone()),
            Some(event1.clone()),
            as_event_payload(&bill_id_test(), &block2),
            &bill_id,
        );

        // mock the nostr chain
        let nostr_chain = vec![event1.clone(), event2.clone(), event3.clone()];

        let (mut bill_chain_store, mut bill_store, mut contact, mut transport) = create_mocks();

        let chain_clone = chain.clone();
        bill_store
            .expect_invalidate_bill_in_cache()
            .returning(|_| Ok(()));
        bill_store.expect_is_paid().returning(|_| Ok(false));
        bill_store.expect_get_keys().returning(move |_| {
            Ok(BillKeys {
                private_key: bcr_keys.get_private_key().to_owned(),
                public_key: bcr_keys.pub_key(),
            })
        });

        let expected_bill_id = bill_id.clone();
        // on chain recovery we ask for the existing chain two times
        bill_chain_store
            .expect_get_chain()
            .with(eq(expected_bill_id))
            .times(2)
            .returning(move |_| Ok(chain_clone.clone()));

        transport
            .expect_resolve_public_chain()
            .with(eq(bill_id.to_string()), eq(BlockchainType::Bill))
            .returning(move |_, _| Ok(nostr_chain.clone()))
            .once();

        // recovery adds the missing block
        bill_chain_store
            .expect_add_block()
            .with(eq(bill_id.clone()), eq(block1.clone()))
            .times(1)
            .returning(move |_, _| Ok(()));

        // and then the received block
        bill_chain_store
            .expect_add_block()
            .with(eq(bill_id.clone()), eq(block2.clone()))
            .times(1)
            .returning(move |_, _| Ok(()));

        contact.expect_ensure_nostr_contact().returning(|_| ());

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(contact),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        handler
            .process_chain_data(&bill_id, vec![block2.clone()], None)
            .await
            .expect("Event should be handled");
    }

    fn as_event_payload(id: &BillId, block: &BillBlock) -> EventEnvelope {
        Event::new_bill(BillBlockEvent {
            bill_id: id.clone(),
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
        bill_id: &BillId,
    ) -> nostr::Event {
        create_public_chain_event(
            &bill_id.to_string(),
            data,
            Timestamp::new(1000).unwrap(),
            BlockchainType::Bill,
            keys.clone(),
            previous,
            root,
        )
        .expect("could not create chain event")
        .sign_with_keys(&keys.get_nostr_keys())
        .expect("could not sign event")
    }

    #[tokio::test]
    async fn test_fails_to_create_new_chain_for_new_chain_event_if_block_validation_fails() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let mut payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        payee.node_id = node_id_test_other();
        let drawer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, Some(&drawer), None);
        let mut chain = get_genesis_chain(Some(bill.clone()));
        let keys = get_bill_keys();

        // reject to pay without a request to accept will fail
        let block = BillBlock::create_block_for_reject_to_pay(
            bill_id_test(),
            chain.get_latest_block(),
            &BillRejectBlockData {
                rejecter: payer.clone().into(),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1000,
                signing_address: empty_address(),
            },
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();
        assert!(chain.try_add_block(block));

        let (mut bill_chain_store, mut bill_store, contact, transport) = create_mocks();

        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id_test()))
            .times(1)
            .returning(move |_| Err(bcr_ebill_persistence::Error::NoBillBlock));
        // should persist the issue block, but fail the second block
        bill_chain_store
            .expect_add_block()
            .with(eq(bill_id_test()), eq(chain.blocks()[0].clone()))
            .times(1)
            .returning(move |_, _| Ok(()));

        bill_store
            .expect_save_keys()
            .with(eq(bill_id_test()), always())
            .never();

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(contact),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        let result = handler
            .process_chain_data(&bill_id_test(), chain.blocks().clone(), Some(keys.clone()))
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fails_to_create_new_chain_for_new_chain_event_if_block_signing_check_fails() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        // drawer has a different key than signer, signing check will fail
        let mut drawer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        drawer.node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, Some(&drawer), None);
        let chain = get_genesis_chain(Some(bill.clone()));
        let keys = get_bill_keys();

        let (mut bill_chain_store, mut bill_store, contact, transport) = create_mocks();

        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id_test()))
            .times(1)
            .returning(move |_| Err(bcr_ebill_persistence::Error::NoBillBlock));
        bill_chain_store
            .expect_add_block()
            .with(eq(bill_id_test()), eq(chain.blocks()[0].clone()))
            .never();

        bill_store
            .expect_save_keys()
            .with(eq(bill_id_test()), always())
            .never();

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(contact),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        let result = handler
            .process_chain_data(&bill_id_test(), chain.blocks().clone(), Some(keys.clone()))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fails_to_add_block_for_invalid_bill_action() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let chain = get_genesis_chain(Some(bill.clone()));

        // reject to pay without a request to accept will fail
        let block = BillBlock::create_block_for_reject_to_pay(
            bill_id_test(),
            chain.get_latest_block(),
            &BillRejectBlockData {
                rejecter: payer.clone().into(),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1000,
                signing_address: empty_address(),
            },
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();

        let (mut bill_chain_store, mut bill_store, contact, transport) = create_mocks();

        let chain_clone = chain.clone();
        bill_store.expect_get_keys().returning(|_| {
            Ok(BillKeys {
                private_key: private_key_test().to_owned(),
                public_key: node_id_test().pub_key(),
            })
        });

        bill_store.expect_is_paid().returning(|_| Ok(false));
        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id_test()))
            .times(1)
            .returning(move |_| Ok(chain_clone.clone()));

        // block is not added
        bill_chain_store.expect_add_block().never();

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(contact),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        let result = handler
            .process_chain_data(&bill_id_test(), vec![block.clone()], None)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fails_to_add_block_for_invalidly_signed_blocks() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let endorsee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        // endorser is different than block signer - signature won't be able to be validated
        let mut endorser = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        endorser.node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let chain = get_genesis_chain(Some(bill.clone()));

        let block = BillBlock::create_block_for_endorse(
            bill_id_test(),
            chain.get_latest_block(),
            &BillEndorseBlockData {
                endorsee: BillParticipantBlockData::Ident(endorsee.clone().into()),
                // endorsed by payee
                endorser: BillParticipantBlockData::Ident(endorser.clone().into()),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1000,
                signing_address: Some(empty_address()),
            },
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();

        let (mut bill_chain_store, mut bill_store, contact, transport) = create_mocks();

        let chain_clone = chain.clone();
        bill_store.expect_get_keys().returning(|_| {
            Ok(BillKeys {
                private_key: private_key_test().to_owned(),
                public_key: node_id_test().pub_key(),
            })
        });

        bill_store.expect_is_paid().returning(|_| Ok(false));
        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id_test()))
            .times(1)
            .returning(move |_| Ok(chain_clone.clone()));

        // block is not added
        bill_chain_store.expect_add_block().never();

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(contact),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        let result = handler
            .process_chain_data(&bill_id_test(), vec![block.clone()], None)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fails_to_add_block_for_unknown_chain() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let endorsee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let chain = get_genesis_chain(Some(bill.clone()));

        let block = BillBlock::create_block_for_endorse(
            bill_id_test(),
            chain.get_latest_block(),
            &BillEndorseBlockData {
                endorsee: BillParticipantBlockData::Ident(endorsee.clone().into()),
                // endorsed by payee
                endorser: BillParticipantBlockData::Ident(
                    BillIdentParticipant::new(get_baseline_identity().identity)
                        .unwrap()
                        .into(),
                ),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1000,
                signing_address: Some(empty_address()),
            },
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();

        let (mut bill_chain_store, bill_store, contact, transport) = create_mocks();

        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id_test()))
            .times(1)
            .returning(move |_| Err(bcr_ebill_persistence::Error::NoBillBlock));

        bill_chain_store.expect_add_block().never();

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(contact),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        let result = handler
            .process_chain_data(&bill_id_test(), vec![block.clone()], None)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fails_to_add_block_for_bill_id_from_different_network() {
        let (bill_chain_store, bill_store, contact, transport) = create_mocks();
        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(contact),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );
        let mainnet_bill_id = BillId::new(BcrKeys::new().pub_key(), bitcoin::Network::Bitcoin);

        let result = handler
            .process_chain_data(&mainnet_bill_id, vec![], None)
            .await;

        assert!(result.is_err());
        assert!(result.as_ref().unwrap_err().to_string().contains("network"));
    }

    fn create_mocks() -> (
        MockBillChainStore,
        MockBillStore,
        MockNostrContactProcessorApi,
        MockNotificationJsonTransport,
    ) {
        (
            MockBillChainStore::new(),
            MockBillStore::new(),
            MockNostrContactProcessorApi::new(),
            MockNotificationJsonTransport::new(),
        )
    }
}
