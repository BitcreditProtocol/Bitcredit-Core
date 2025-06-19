use crate::NotificationJsonTransportApi;
use crate::{Error, Result};
use async_trait::async_trait;
use bcr_ebill_core::Validate;
use bcr_ebill_core::bill::BillValidateActionData;
use bcr_ebill_core::bill::{BillId, BillKeys};
use bcr_ebill_core::blockchain::Blockchain;
use bcr_ebill_core::blockchain::bill::BillOpCode;
use bcr_ebill_core::blockchain::bill::block::BillIssueBlockData;
use bcr_ebill_core::blockchain::bill::{BillBlock, BillBlockchain};
use bcr_ebill_core::nostr_contact::HandshakeStatus;
use bcr_ebill_core::nostr_contact::NostrContact;
use bcr_ebill_core::nostr_contact::TrustLevel;
use bcr_ebill_core::{NodeId, ServiceTraitBounds};
use bcr_ebill_persistence::bill::BillChainStoreApi;
use bcr_ebill_persistence::bill::BillStoreApi;
use bcr_ebill_persistence::nostr::NostrContactStoreApi;
use log::{debug, error, info};
use std::sync::Arc;

use super::BillChainEventProcessorApi;

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
}

#[derive(Clone)]
pub struct BillChainEventProcessor {
    bill_blockchain_store: Arc<dyn BillChainStoreApi>,
    bill_store: Arc<dyn BillStoreApi>,
    transport: Arc<dyn NotificationJsonTransportApi>,
    nostr_contact_store: Arc<dyn NostrContactStoreApi>,
}

impl BillChainEventProcessor {
    pub fn new(
        bill_blockchain_store: Arc<dyn BillChainStoreApi>,
        bill_store: Arc<dyn BillStoreApi>,
        transport: Arc<dyn NotificationJsonTransportApi>,
        nostr_contact_store: Arc<dyn NostrContactStoreApi>,
    ) -> Self {
        Self {
            bill_blockchain_store,
            bill_store,
            transport,
            nostr_contact_store,
        }
    }

    pub async fn ensure_nostr_contact(&self, node_id: &NodeId) {
        // we already have the contact in the store, no need to resolve it
        if let Ok(Some(_)) = self.nostr_contact_store.by_node_id(node_id).await {
            return;
        }
        // Let's try to get some details and add the contact
        if let Ok(Some(contact)) = self.transport.resolve_contact(node_id).await {
            let relays = contact
                .relays
                .iter()
                .map(|r| r.as_str().to_owned())
                .collect();
            if let Err(e) = self
                .nostr_contact_store
                .upsert(&NostrContact {
                    npub: node_id.npub(),
                    name: contact.metadata.name,
                    relays,
                    trust_level: TrustLevel::Participant,
                    handshake_status: HandshakeStatus::None,
                })
                .await
            {
                error!("Failed to save nostr contact information for node_id {node_id}: {e}");
            }
        } else {
            info!("Could not resolve nostr contact information for node_id {node_id}");
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
        for block in blocks {
            block_added = self
                .validate_and_save_block(
                    bill_id,
                    &mut chain,
                    &bill_first_version,
                    &bill_keys,
                    block,
                    is_paid,
                )
                .await?;
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
                self.ensure_nostr_contact(&node_id).await
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
            bill_action: bill_action.ok_or_else(|| {
                error!(
                    "Received invalid block {block_id} for bill {bill_id} - no valid bill action returned"
                );
                Error::Blockchain(
                    "Received invalid block for bill - no valid bill action returned"
                    .to_string(),
                )
            })?,
            is_paid,
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
        // issue block was validate in get_valid_chain
        let issue_block = chain.get_first_block().to_owned();
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
            self.ensure_nostr_contact(&node_id).await
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
    use std::str::FromStr;

    use bcr_ebill_core::{
        OptionalPostalAddress, PostalAddress, PublicKey, SecretKey,
        bill::BitcreditBill,
        blockchain::bill::block::{
            BillEndorseBlockData, BillIssueBlockData, BillParticipantBlockData, BillRejectBlockData,
        },
        contact::{BillIdentParticipant, BillParticipant, ContactType},
        identity::{Identity, IdentityType, IdentityWithAll},
        util::BcrKeys,
    };
    use mockall::predicate::{always, eq};
    use nostr::nips::nip01::Metadata;

    use crate::{
        handler::test_utils::{MockBillChainStore, MockBillStore, MockNostrContactStore},
        transport::NostrContactData,
    };

    use crate::transport::MockNotificationJsonTransportApi;

    use super::*;

    #[tokio::test]
    async fn test_create_event_handler() {
        let (bill_chain_store, bill_store, transport, contact_store) = create_mocks();
        BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(transport),
            Arc::new(contact_store),
        );
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

        let (mut bill_chain_store, mut bill_store, mut transport, mut contact_store) =
            create_mocks();

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

        // If we don't have the contact in the store, we will try to resolve it via Nostr
        contact_store.expect_by_node_id().returning(|_| Ok(None));

        // If we get data it should be store to the store
        transport.expect_resolve_contact().returning(|_| {
            Ok(Some(NostrContactData {
                metadata: Metadata {
                    name: Some("name".to_string()),
                    ..Default::default()
                },
                relays: vec![],
            }))
        });

        contact_store.expect_upsert().returning(|_| Ok(()));

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(transport),
            Arc::new(contact_store),
        );

        handler
            .process_chain_data(&bill_id_test(), chain.blocks().clone(), Some(keys.clone()))
            .await
            .expect("Event should be handled");
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

        let (mut bill_chain_store, mut bill_store, transport, contact_store) = create_mocks();

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
            Arc::new(transport),
            Arc::new(contact_store),
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

        let (mut bill_chain_store, mut bill_store, transport, contact_store) = create_mocks();

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
            Arc::new(transport),
            Arc::new(contact_store),
        );

        let result = handler
            .process_chain_data(&bill_id_test(), chain.blocks().clone(), Some(keys.clone()))
            .await;
        assert!(result.is_err());
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

        let (mut bill_chain_store, mut bill_store, transport, mut contact_store) = create_mocks();

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

        contact_store.expect_by_node_id().returning(move |_| {
            Ok(Some(NostrContact {
                npub: node_id_test().npub(),
                name: Some("name".to_string()),
                relays: vec!["wws://some.example.com".to_string()],
                trust_level: TrustLevel::Participant,
                handshake_status: HandshakeStatus::None,
            }))
        });

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(transport),
            Arc::new(contact_store),
        );

        handler
            .process_chain_data(&bill_id_test(), vec![block.clone()], None)
            .await
            .expect("Event should be handled");
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

        let (mut bill_chain_store, mut bill_store, transport, contact_store) = create_mocks();

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
            Arc::new(transport),
            Arc::new(contact_store),
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

        let (mut bill_chain_store, mut bill_store, transport, contact_store) = create_mocks();

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
            Arc::new(transport),
            Arc::new(contact_store),
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

        let (mut bill_chain_store, bill_store, transport, contact_store) = create_mocks();

        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id_test()))
            .times(1)
            .returning(move |_| Err(bcr_ebill_persistence::Error::NoBillBlock));

        bill_chain_store.expect_add_block().never();

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(transport),
            Arc::new(contact_store),
        );

        let result = handler
            .process_chain_data(&bill_id_test(), vec![block.clone()], None)
            .await;

        assert!(result.is_err());
    }

    pub fn get_test_bitcredit_bill(
        id: &BillId,
        payer: &BillIdentParticipant,
        payee: &BillIdentParticipant,
        drawer: Option<&BillIdentParticipant>,
        endorsee: Option<&BillIdentParticipant>,
    ) -> BitcreditBill {
        let mut bill = empty_bitcredit_bill();
        bill.id = id.to_owned();
        bill.payee = BillParticipant::Ident(payee.clone());
        bill.drawee = payer.clone();
        if let Some(drawer) = drawer {
            bill.drawer = drawer.clone();
        }
        bill.endorsee = endorsee.map(|e| BillParticipant::Ident(e.to_owned()));
        bill
    }
    fn get_genesis_chain(bill: Option<BitcreditBill>) -> BillBlockchain {
        let bill = bill.unwrap_or(get_baseline_bill(&bill_id_test()));
        BillBlockchain::new(
            &BillIssueBlockData::from(bill, None, 1731593928),
            get_baseline_identity().key_pair,
            None,
            BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap()
    }
    fn get_baseline_bill(bill_id: &BillId) -> BitcreditBill {
        let mut bill = empty_bitcredit_bill();
        let keys = BcrKeys::new();

        bill.maturity_date = "2099-10-15".to_string();
        let mut payee = empty_bill_identified_participant();
        payee.name = "payee".to_owned();
        payee.node_id = NodeId::new(keys.pub_key(), bitcoin::Network::Testnet);
        bill.payee = BillParticipant::Ident(payee);
        bill.drawee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        bill.id = bill_id.to_owned();
        bill
    }
    fn empty_bitcredit_bill() -> BitcreditBill {
        BitcreditBill {
            id: bill_id_test(),
            country_of_issuing: "AT".to_string(),
            city_of_issuing: "Vienna".to_string(),
            drawee: empty_bill_identified_participant(),
            drawer: empty_bill_identified_participant(),
            payee: BillParticipant::Ident(empty_bill_identified_participant()),
            endorsee: None,
            currency: "sat".to_string(),
            sum: 500,
            maturity_date: "2099-11-12".to_string(),
            issue_date: "2099-08-12".to_string(),
            city_of_payment: "Vienna".to_string(),
            country_of_payment: "AT".to_string(),
            language: "DE".to_string(),
            files: vec![],
        }
    }

    pub fn get_bill_keys() -> BillKeys {
        BillKeys {
            private_key: private_key_test().to_owned(),
            public_key: node_id_test().pub_key(),
        }
    }

    fn get_baseline_identity() -> IdentityWithAll {
        let keys = BcrKeys::from_private_key(&private_key_test()).unwrap();
        let mut identity = empty_identity();
        identity.name = "drawer".to_owned();
        identity.node_id = node_id_test();
        identity.postal_address.country = Some("AT".to_owned());
        identity.postal_address.city = Some("Vienna".to_owned());
        identity.postal_address.address = Some("Hayekweg 5".to_owned());
        IdentityWithAll {
            identity,
            key_pair: keys,
        }
    }
    fn empty_bill_identified_participant() -> BillIdentParticipant {
        BillIdentParticipant {
            t: ContactType::Person,
            node_id: node_id_test(),
            name: "some name".to_string(),
            postal_address: empty_address(),
            email: None,
            nostr_relays: vec![],
        }
    }
    fn empty_address() -> PostalAddress {
        PostalAddress {
            country: "AT".to_string(),
            city: "Vienna".to_string(),
            zip: None,
            address: "Some address".to_string(),
        }
    }
    fn empty_identity() -> Identity {
        Identity {
            t: IdentityType::Ident,
            node_id: node_id_test(),
            name: "some name".to_string(),
            email: Some("some@example.com".to_string()),
            postal_address: empty_optional_address(),
            date_of_birth: None,
            country_of_birth: None,
            city_of_birth: None,
            identification_number: None,
            nostr_relays: vec![],
            profile_picture_file: None,
            identity_document_file: None,
        }
    }

    pub fn empty_optional_address() -> OptionalPostalAddress {
        OptionalPostalAddress {
            country: None,
            city: None,
            zip: None,
            address: None,
        }
    }

    // bitcrt285psGq4Lz4fEQwfM3We5HPznJq8p1YvRaddszFaU5dY
    pub fn bill_id_test() -> BillId {
        BillId::new(
            PublicKey::from_str(
                "026423b7d36d05b8d50a89a1b4ef2a06c88bcd2c5e650f25e122fa682d3b39686c",
            )
            .unwrap(),
            bitcoin::Network::Testnet,
        )
    }

    pub fn private_key_test() -> SecretKey {
        SecretKey::from_str("d1ff7427912d3b81743d3b67ffa1e65df2156d3dab257316cbc8d0f35eeeabe9")
            .unwrap()
    }

    pub fn node_id_test() -> NodeId {
        NodeId::from_str("bitcrt02295fb5f4eeb2f21e01eaf3a2d9a3be10f39db870d28f02146130317973a40ac0")
            .unwrap()
    }

    pub fn node_id_test_other() -> NodeId {
        NodeId::from_str("bitcrt03f9f94d1fdc2090d46f3524807e3f58618c36988e69577d70d5d4d1e9e9645a4f")
            .unwrap()
    }

    fn create_mocks() -> (
        MockBillChainStore,
        MockBillStore,
        MockNotificationJsonTransportApi,
        MockNostrContactStore,
    ) {
        (
            MockBillChainStore::new(),
            MockBillStore::new(),
            MockNotificationJsonTransportApi::new(),
            MockNostrContactStore::new(),
        )
    }
}
