use crate::{
    Error, Result,
    handler::public_chain_helpers::{BlockData, resolve_event_chains},
};
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_api::service::transport_service::transport_client::TransportClientApi;
use bcr_ebill_core::{
    protocol::crypto::BcrKeys,
    protocol::event::{ChainInvite, Event},
};
use log::{debug, error, info, warn};
use std::sync::Arc;

use bcr_ebill_core::{
    application::ServiceTraitBounds,
    application::identity::{Identity, IdentityWithAll},
    protocol::BlockId,
    protocol::blockchain::{
        Blockchain, BlockchainType,
        bill::BillOpCode,
        identity::{IdentityBlock, IdentityBlockPayload, IdentityBlockchain},
    },
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
    transport: Arc<dyn TransportClientApi>,
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

    async fn resync_chain(&self) -> Result<()> {
        match (
            self.blockchain_store.get_chain().await,
            self.identity_store.get_full().await,
        ) {
            (Ok(mut existing_chain), Ok(IdentityWithAll { identity, key_pair })) => {
                debug!(
                    "starting identity chain resync for identity {}",
                    identity.node_id
                );
                if let Ok(chain_data) = resolve_event_chains(
                    self.transport.clone(),
                    &identity.node_id.to_string(),
                    BlockchainType::Identity,
                    &key_pair,
                )
                .await
                {
                    for data in chain_data.iter() {
                        let blocks: Vec<IdentityBlock> = data
                            .iter()
                            .filter_map(|d| match d.block.clone() {
                                BlockData::Identity(block) => Some(block),
                                _ => None,
                            })
                            .collect();
                        if !data.is_empty()
                            && self
                                .add_identity_blocks(&identity.node_id, &mut existing_chain, blocks)
                                .await
                                .is_ok()
                        {
                            debug!(
                                "resynced identity {} with {} remote events",
                                identity.node_id,
                                data.len()
                            );
                            break;
                        }
                    }
                    debug!("finished identity chain resync for {}", &identity.node_id);
                    Ok(())
                } else {
                    let message = format!(
                        "Could not refetch chain data from Nostr for identity {}",
                        &identity.node_id
                    );
                    error!("{message}");
                    Err(Error::Network(message))
                }
            }
            _ => {
                let message = "Could not refetch chain for local identity because the identity keys or chain could not be fetched".to_string();
                error!("{message}");
                Err(Error::Persistence(message))
            }
        }
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
        transport: Arc<dyn TransportClientApi>,
        bitcoin_network: bitcoin::Network,
    ) -> Self {
        Self {
            blockchain_store,
            identity_store,
            company_invite_handler,
            bill_invite_handler,
            nostr_contact_processor,
            transport,
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
        for block in blocks.iter() {
            if block.id <= block_height {
                info!(
                    "Skipping identity block with id {block_height} for {node_id} as we already have it"
                );
                continue;
            }
            match self
                .add_identity_block(node_id, &keys, &mut identity, chain, block)
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
                            "Received invalid block {} for identity {node_id} - missing blocks - try to resync",
                            block.id
                        );
                        self.resync_chain().await?;
                        break;
                    } else {
                        error!("Error adding block for identity {node_id}: {e}");
                        Err(e)
                    }
                }
            }?;
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
                IdentityBlockPayload::InviteSignatory(payload) => {
                    info!("Adding signatory to identity {node_id}");
                    self.nostr_contact_processor
                        .ensure_nostr_contact(&payload.signatory)
                        .await
                }
                IdentityBlockPayload::CreateCompany(payload) => {
                    info!("Received company create block. Restoring Company data");
                    let secret_key = payload.company_key;
                    let company_keys = BcrKeys::from_private_key(&secret_key);
                    let invite = ChainInvite::company(
                        payload.company_id.to_string(),
                        BcrKeys::from_private_key(&company_keys.get_private_key()),
                    );
                    let event = Event::new_company_invite(invite);
                    self.company_invite_handler
                        .handle_event(event.try_into()?, node_id, None, None)
                        .await?;
                }
                IdentityBlockPayload::SignPersonalBill(payload) => {
                    if let Some(bill_key) = payload.bill_key
                        && payload.operation == BillOpCode::Issue
                    {
                        debug!(
                            "Found personal bill issue block so adding bill {}",
                            payload.bill_id
                        );
                        let secret_key = bill_key;
                        let bill_keys = BcrKeys::from_private_key(&secret_key);
                        let invite = ChainInvite::bill(
                            payload.bill_id.to_string(),
                            BcrKeys::from_private_key(&bill_keys.get_private_key()),
                        );
                        self.bill_invite_handler
                            .handle_event(Event::new_bill(invite).try_into()?, node_id, None, None)
                            .await?;
                    }
                }
                IdentityBlockPayload::AcceptSignatoryInvite(_) => { /* no action needed */ }
                IdentityBlockPayload::RejectSignatoryInvite(_) => { /* no action needed */ }
                IdentityBlockPayload::SignCompanyBill(_) => { /* handled in company chain */ }
                IdentityBlockPayload::RemoveSignatory(_) => { /* no action needed */ }
                IdentityBlockPayload::Create(_) => { /* creates are handled on validation */ }
                IdentityBlockPayload::IdentityProof(data) => {
                    self.identity_store
                        .set_email_confirmation(&data.proof, &data.data)
                        .await
                        .map_err(|e| Error::Persistence(e.to_string()))?;
                }
            }

            // persist data
            self.save_block(block).await?;
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
            Ok(chain) if chain.is_chain_valid() => {
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

                // initialize identity and chain from first block
                let identity = Identity::from_block_data(payload);
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

    use bcr_common::core::NodeId;
    use bcr_ebill_core::protocol::event::{Event, EventEnvelope, IdentityBlockEvent};
    use bcr_ebill_core::{
        application::identity::Identity,
        protocol::Name,
        protocol::Sha256Hash,
        protocol::Timestamp,
        protocol::blockchain::{
            Blockchain, BlockchainType,
            identity::{
                IdentityBlock, IdentityBlockchain, IdentityProofBlockData, IdentityUpdateBlockData,
            },
        },
        protocol::crypto::BcrKeys,
    };
    use mockall::predicate::{always, eq};

    use crate::test_utils::signed_identity_proof_test;
    use crate::{
        handler::{
            IdentityChainEventProcessorApi, MockNostrContactProcessorApi,
            MockNotificationHandlerApi,
            identity_chain_event_processor::IdentityChainEventProcessor,
            test_utils::{
                MockIdentityChainStore, MockIdentityStore, get_baseline_identity, node_id_test,
            },
        },
        test_utils::MockNotificationJsonTransport,
        transport::create_public_chain_event,
    };

    #[tokio::test]
    async fn test_create_event_handler() {
        let (chain_store, store, contact, company_invite, bill_invite, transport) = create_mocks();
        IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );
    }

    #[tokio::test]
    async fn test_validate_chain_event_and_sender_invalid_on_no_keys_or_chain() {
        let keys = BcrKeys::new().get_nostr_keys();
        let (chain_store, mut store, contact, company_invite, bill_invite, transport) =
            create_mocks();

        store.expect_get().returning(move || {
            Err(bcr_ebill_persistence::Error::NoSuchEntity(
                "identity block".to_string(),
                node_id_test().to_string(),
            ))
        });

        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        let valid = handler.validate_chain_event_and_sender(&node_id_test(), keys.public_key());
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_validate_chain_event_fails_if_not_own_node_id() {
        let keys = BcrKeys::new();
        let (chain_store, mut store, contact, company_invite, bill_invite, transport) =
            create_mocks();
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
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        let valid = handler
            .validate_chain_event_and_sender(&node_id_test(), keys.get_nostr_keys().public_key());
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_validate_chain_event() {
        let (chain_store, mut store, contact, company_invite, bill_invite, transport) =
            create_mocks();
        let full = get_baseline_identity();
        let mut identity = full.identity.clone();
        identity.name = Name::new("new name").unwrap();
        let keys = full.key_pair.clone();

        store.expect_get().returning(move || Ok(identity.clone()));

        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(transport),
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
        let (mut chain_store, mut store, contact, company_invite, bill_invite, transport) =
            create_mocks();
        let full = get_baseline_identity();
        let identity = full.identity.clone();
        let keys = full.key_pair.clone();
        let blocks = vec![get_identity_create_block(full.identity, &full.key_pair)];
        let chain = IdentityBlockchain::new_from_blocks(blocks).expect("could not create chain");
        let data = IdentityUpdateBlockData {
            name: Some(Name::new("new_name").unwrap()),
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
            .withf(move |n| n.name == Name::new("new_name").unwrap())
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
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        handler
            .process_chain_data(&identity.node_id, vec![update_block], None)
            .await
            .expect("Process chain data should be handled");
    }

    #[tokio::test]
    async fn test_recovers_chain_on_missing_blocks() {
        let (mut chain_store, mut store, contact, company_invite, bill_invite, mut transport) =
            create_mocks();
        let full = get_baseline_identity();
        let identity = full.identity.clone();
        let keys = full.key_pair.clone();
        let blocks = vec![get_identity_create_block(
            full.identity.clone(),
            &full.key_pair,
        )];
        let skipped_chain =
            IdentityBlockchain::new_from_blocks(blocks).expect("could not create chain");

        let data_skipped = IdentityUpdateBlockData {
            name: Some(Name::new("new_name").unwrap()),
            ..Default::default()
        };
        let skipped_block =
            get_identity_update_block(skipped_chain.get_latest_block(), &keys, &data_skipped);

        let mut full_chain = skipped_chain.clone();
        full_chain.try_add_block(skipped_block.clone());

        let data = IdentityUpdateBlockData {
            name: Some(Name::new("another_name").unwrap()),
            ..Default::default()
        };
        let update_block = get_identity_update_block(full_chain.get_latest_block(), &keys, &data);

        let event1 = generate_test_event(
            &keys,
            None,
            None,
            as_event_payload(&full.identity.node_id, skipped_chain.get_latest_block()),
            &full.identity.node_id,
        );

        let event2 = generate_test_event(
            &keys,
            Some(event1.clone()),
            Some(event1.clone()),
            as_event_payload(&full.identity.node_id, &skipped_block),
            &full.identity.node_id,
        );

        let event3 = generate_test_event(
            &keys,
            Some(event2.clone()),
            Some(event1.clone()),
            as_event_payload(&full.identity.node_id, &update_block),
            &full.identity.node_id,
        );

        let nostr_chain = vec![event1.clone(), event2.clone(), event3.clone()];

        // checks if we already have the chain two times with one call for the chain resync
        chain_store
            .expect_get_chain()
            .returning(move || Ok(skipped_chain.clone()))
            .times(2);

        // we have a chain so get the keys
        store
            .expect_get_key_pair()
            .returning(move || Ok(keys.clone()))
            .times(2);

        // get the current identity state
        let expected_identity = identity.clone();
        store
            .expect_get()
            .returning(move || Ok(expected_identity.clone()))
            .times(2);

        // chain resync gets the full identity
        let full_id = full.clone();
        store
            .expect_get_full()
            .returning(move || Ok(full_id.clone()));

        // and queries the chain from the transport
        transport
            .expect_resolve_public_chain()
            .with(
                eq(full.identity.node_id.to_string()),
                eq(BlockchainType::Identity),
            )
            .returning(move |_, _| Ok(nostr_chain.clone()))
            .once();

        // apply missing block event
        store
            .expect_save()
            .withf(move |n| n.name == Name::new("new_name").unwrap())
            .returning(|_| Ok(()))
            .once();

        // apply last block event
        store
            .expect_save()
            .withf(move |n| n.name == Name::new("another_name").unwrap())
            .returning(|_| Ok(()))
            .once();

        // inserts the blocks
        chain_store
            .expect_add_block()
            .with(always())
            .returning(|_| Ok(()))
            .times(2);

        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        handler
            .process_chain_data(&identity.node_id, vec![update_block], None)
            .await
            .expect("Process chain data should be handled");
    }

    fn as_event_payload(id: &NodeId, block: &IdentityBlock) -> EventEnvelope {
        Event::new_identity_chain(IdentityBlockEvent {
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
            BlockchainType::Identity,
            keys.clone(),
            previous,
            root,
        )
        .expect("could not create chain event")
        .sign_with_keys(&keys.get_nostr_keys())
        .expect("could not sign event")
    }

    #[tokio::test]
    async fn test_process_identity_proof() {
        let (mut chain_store, mut store, contact, company_invite, bill_invite, transport) =
            create_mocks();
        let full = get_baseline_identity();
        let identity = full.identity.clone();
        let keys = full.key_pair.clone();
        let blocks = vec![get_identity_create_block(full.identity, &full.key_pair)];
        let chain = IdentityBlockchain::new_from_blocks(blocks).expect("could not create chain");
        let test_signed_identity = signed_identity_proof_test();
        let data = IdentityProofBlockData {
            proof: test_signed_identity.0,
            data: test_signed_identity.1,
        };
        let identity_proof_block = get_identity_proof_block(chain.get_latest_block(), &keys, &data);

        // get the current identity state
        let expected_identity = identity.clone();
        store
            .expect_get()
            .returning(move || Ok(expected_identity.clone()))
            .once();

        // incoming identity proof is set
        store
            .expect_set_email_confirmation()
            .returning(|_, _| Ok(()))
            .times(1);

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
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );

        handler
            .process_chain_data(&identity.node_id, vec![identity_proof_block], None)
            .await
            .expect("Process chain data should be handled");
    }

    pub fn get_identity_create_block(identity: Identity, keys: &BcrKeys) -> IdentityBlock {
        IdentityBlock::create_block_for_create(
            Sha256Hash::new("genesis hash"),
            &identity.into(),
            keys,
            Timestamp::new(1731593928).unwrap(),
        )
        .expect("could not create block")
    }

    pub fn get_identity_update_block(
        previous_block: &IdentityBlock,
        keys: &BcrKeys,
        data: &IdentityUpdateBlockData,
    ) -> IdentityBlock {
        IdentityBlock::create_block_for_update(
            previous_block,
            data,
            keys,
            Timestamp::new(1731594928).unwrap(),
        )
        .expect("could not create block")
    }

    pub fn get_identity_proof_block(
        previous_block: &IdentityBlock,
        keys: &BcrKeys,
        data: &IdentityProofBlockData,
    ) -> IdentityBlock {
        IdentityBlock::create_block_for_identity_proof(
            previous_block,
            data,
            keys,
            Timestamp::new(1731594928).unwrap(),
        )
        .expect("could not create block")
    }

    fn create_mocks() -> (
        MockIdentityChainStore,
        MockIdentityStore,
        MockNostrContactProcessorApi,
        MockNotificationHandlerApi,
        MockNotificationHandlerApi,
        MockNotificationJsonTransport,
    ) {
        (
            MockIdentityChainStore::new(),
            MockIdentityStore::new(),
            MockNostrContactProcessorApi::new(),
            MockNotificationHandlerApi::new(),
            MockNotificationHandlerApi::new(),
            MockNotificationJsonTransport::new(),
        )
    }
}
