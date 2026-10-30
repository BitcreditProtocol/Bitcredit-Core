use crate::{
    Error, Result,
    handler::public_chain_helpers::{
        BlockData, chain_matches_local, compare_block_chains, find_first_difference, is_fork_block,
        resolve_event_chains, resolve_fork,
    },
};
use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_api::{
    Config,
    service::transport_service::{ResyncMode, transport_client::TransportClientApi},
};
use bcr_ebill_core::{
    application::contact::Contact,
    protocol::{
        EmailIdentityProofData, File, SignedIdentityProof, Validate,
        blockchain::{
            Block,
            bill::ContactType,
            identity::{IdentityType, IdentityValidateActionData},
        },
        crypto::BcrKeys,
        event::{ChainInvite, Event},
        file_reference::FileReferenceContext,
    },
};
use bitcoin::secp256k1::SecretKey;
use log::{debug, error, info, warn};
use std::{collections::HashSet, sync::Arc};

use bcr_ebill_core::{
    application::ServiceTraitBounds,
    application::identity::{Identity, IdentityWithAll},
    protocol::blockchain::{
        Blockchain, BlockchainType,
        bill::BillOpCode,
        identity::{IdentityBlock, IdentityBlockPayload, IdentityBlockchain},
    },
    protocol::{BlockId, EditOptionalFieldMode},
};
use bcr_ebill_persistence::{
    ContactStoreApi, NostrChainEventStoreApi, traits::transaction::TransactionManagerApi,
};
use bcr_ebill_persistence::{
    FileReferenceStoreApi,
    traits::identity::{IdentityChainStoreApi, IdentityStoreApi},
};

use super::inbound_file_anchor::{anchor_important_file, identity_file_context};
use super::{IdentityChainEventProcessorApi, NostrContactProcessorApi, NotificationHandlerApi};

#[derive(Debug, Clone)]
struct PreparedIdentityBlock {
    block_id: BlockId,
    identity_changed: bool,
    email_confirmation: Option<PreparedEmailConfirmation>,
    files_to_anchor: Vec<PreparedFileAnchor>,
    post_commit_effects: Vec<IdentityPostCommitEffect>,
}

#[derive(Debug, Clone)]
struct PreparedEmailConfirmation {
    proof: SignedIdentityProof,
    data: EmailIdentityProofData,
}

#[derive(Debug, Clone)]
struct PreparedFileAnchor {
    file: File,
    context: FileReferenceContext,
}

#[derive(Debug, Clone)]
enum IdentityPostCommitEffect {
    EnsureNostrContact(NodeId),
    RestoreCompany {
        company_id: NodeId,
        company_key: SecretKey,
    },
    RestoreBill {
        bill_id: BillId,
        bill_key: SecretKey,
    },
}

#[derive(Debug, Clone)]
struct PreparedIdentityChain {
    node_id: NodeId,
    identity: Identity,
    chain: IdentityBlockchain,
    blocks: Vec<PreparedIdentityBlock>,
    create_files_to_anchor: Vec<PreparedFileAnchor>,
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct IdentityChainEventProcessor {
    blockchain_store: Arc<dyn IdentityChainStoreApi>,
    identity_store: Arc<dyn IdentityStoreApi>,
    file_reference_store: Arc<dyn FileReferenceStoreApi>,
    company_invite_handler: Arc<dyn NotificationHandlerApi>,
    bill_invite_handler: Arc<dyn NotificationHandlerApi>,
    nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
    chain_event_store: Arc<dyn NostrChainEventStoreApi>,
    transport: Arc<dyn TransportClientApi>,
    contact_store: Arc<dyn ContactStoreApi>,
    transaction_mgr: Arc<dyn TransactionManagerApi>,
    bitcoin_network: bitcoin::Network,
    config: Arc<Config>,
}

#[async_trait]
impl IdentityChainEventProcessorApi for IdentityChainEventProcessor {
    async fn process_chain_data(
        &self,
        node_id: &NodeId,
        blocks: Vec<IdentityBlock>,
        keys: Option<BcrKeys>,
    ) -> Result<()> {
        // check that incoming identity blocks are of the same network that we use
        if node_id.network() != self.bitcoin_network {
            warn!("Received identity blocks for node {node_id} for a different network");
            return Err(Error::Blockchain(format!(
                "Received identity blocks for node {node_id} for a different network"
            )));
        }

        if let Ok(mut existing_chain) = self.blockchain_store.get_chain().await {
            self.add_identity_blocks(node_id, &mut existing_chain, blocks, false)
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

    fn validate_chain_event_and_sender(
        &self,
        node_id: &NodeId,
        sender: nostr::key::PublicKey,
    ) -> bool {
        node_id.npub() == sender
    }

    async fn resync_chain(&self, mode: ResyncMode) -> Result<()> {
        match (
            self.blockchain_store.get_chain().await,
            self.identity_store.get_full().await,
        ) {
            (Ok(existing_chain), Ok(IdentityWithAll { identity, key_pair })) => {
                debug!(
                    "starting identity chain resync for identity {}",
                    identity.node_id
                );

                let expected_local_tip = existing_chain.get_latest_block().clone();

                let Ok(chain_data) = resolve_event_chains(
                    self.transport.clone(),
                    &identity.node_id.to_string(),
                    BlockchainType::Identity,
                    &Some(key_pair.clone()),
                )
                .await
                else {
                    let message = format!(
                        "Could not refetch chain data from Nostr for identity {}",
                        identity.node_id
                    );
                    error!("{message}");
                    return Err(Error::Network(message));
                };

                // Handle only missing metadata, which doesn't mutate existing chains, but only fetches missing nostr events
                // In this mode, we don't care about local, or remote chain divergences, we're just adding missing metadata for local, unpublished blocks
                if let ResyncMode::OnlyMissingMetadata { ref up_to_hash } = mode {
                    let identity_id = identity.node_id.clone();
                    let Some(local_chain_end) = existing_chain
                        .blocks()
                        .iter()
                        .position(|block| block.hash() == up_to_hash)
                    else {
                        // if we get here, that means we didn't find a matching chain on nostr to update metadata
                        return Err(Error::Blockchain(format!(
                            "Could not restore Nostr metadata for identity {identity_id}: block with hash {up_to_hash} does not exist in the local chain"
                        )));
                    };
                    let local_blocks = &existing_chain.blocks()[..=local_chain_end];
                    for data in &chain_data {
                        let blocks: Vec<IdentityBlock> = data
                            .iter()
                            .filter_map(|d| match d.block.clone() {
                                BlockData::Identity(block) => Some(block),
                                _ => None,
                            })
                            .collect();
                        if blocks.is_empty() {
                            continue;
                        }
                        if !chain_matches_local(local_blocks, &blocks) {
                            continue;
                        }
                        let existing_events = self
                            .chain_event_store
                            .find_chain_events(&identity_id.to_string(), BlockchainType::Identity)
                            .await
                            .map_err(|e| {
                                error!(
                                    "Failed to fetch chain events for identity {identity_id}: {e}"
                                );

                                Error::Persistence(format!(
                                    "Failed to fetch chain events for identity {identity_id}: {e}"
                                ))
                            })?;
                        let existing_block_hashes: HashSet<_> = existing_events
                            .iter()
                            .map(|event| event.block_hash.clone())
                            .collect();
                        let mut events_added = 0;
                        // match local blocks and event containers - these are guaranteed to match because of
                        // the chain_matches_local check above
                        for (local_block, event_container) in
                            local_blocks
                                .iter()
                                .zip(data.iter().filter(|event_container| {
                                    matches!(event_container.block, BlockData::Identity(_))
                                }))
                        {
                            let BlockData::Identity(remote_block) = &event_container.block else {
                                continue;
                            };
                            // if we have the block as a chain event - continue
                            if existing_block_hashes.contains(&local_block.hash) {
                                continue;
                            }
                            // otherwise, add it
                            let event = event_container.as_chain_store_event(
                                &identity_id.to_string(),
                                BlockchainType::Identity,
                                remote_block.id.inner() as usize,
                            );
                            self.chain_event_store.add_chain_event(event)
                                .await
                                .map_err(|e| {
                                    error!(
                                        "Failed to restore missing chain event for identity {identity_id}, block {}: {e}",
                                        local_block.id
                                    );
                                    Error::Persistence(format!(
                                            "Failed to restore missing chain event for identity {identity_id}, block {}: {e}",
                                            local_block.id
                                    ))
                                })?;
                            events_added += 1;
                        }
                        if events_added > 0 {
                            info!(
                                "Restored {events_added} missing Nostr chain event(s) for identity {identity_id} up to block hash {up_to_hash}"
                            );
                        }
                        return Ok(());
                    }

                    let message = "Could not restore Nostr metadata for identity: no Nostr chain matches the local identity chain".to_owned();
                    error!("{message}");
                    return Err(Error::Blockchain(message));
                }

                // Other modes
                let mut candidates: Vec<(usize, PreparedIdentityChain, Option<BlockId>)> =
                    Vec::new();

                let mut saw_authoritative_genesis_mismatch = false;

                for (data_index, data) in chain_data.iter().enumerate() {
                    let blocks: Vec<IdentityBlock> = data
                        .iter()
                        .filter_map(|d| match d.block.clone() {
                            BlockData::Identity(block) => Some(block),
                            _ => None,
                        })
                        .collect();
                    if blocks.is_empty() {
                        continue;
                    }
                    // turn raw Nostr chain into longest protocol-valid prefix chain
                    let prepared = match self
                        .prepare_identity_chain_valid_prefix(&blocks, &key_pair)
                    {
                        Ok(prepared) => prepared,
                        Err(e) => {
                            debug!(
                                "Identity chain candidate could not even produce a valid genesis for {}: {e}",
                                identity.node_id
                            );
                            continue;
                        }
                    };
                    if prepared.node_id != identity.node_id {
                        debug!(
                            "Ignoring identity chain candidate for {}, expected {}",
                            prepared.node_id, identity.node_id
                        );
                        continue;
                    }
                    let replace_from = match mode {
                        ResyncMode::Normal => {
                            let (is_preferred, fork_point) =
                                resolve_fork(existing_chain.blocks(), prepared.chain.blocks());
                            if !is_preferred {
                                continue;
                            }
                            fork_point
                        }
                        // In this mode, we want to find the point where the local chain diverges from the Nostr chain
                        ResyncMode::NostrAuthoritative => {
                            let difference = find_first_difference(
                                existing_chain.blocks(),
                                prepared.chain.blocks(),
                            );
                            if difference == Some(BlockId::first()) {
                                saw_authoritative_genesis_mismatch = true;
                                continue;
                            }
                            difference
                        }
                        ResyncMode::OnlyMissingMetadata { .. } => {
                            // metadata-only resync handled above
                            return Ok(());
                        }
                    };
                    candidates.push((data_index, prepared, replace_from));
                }

                // sort candidates by their protocol-valid chains
                candidates.sort_by(|(_, a, _), (_, b, _)| {
                    compare_block_chains(a.chain.blocks(), b.chain.blocks())
                });

                // select the best chain
                let Some((selected_data_index, prepared, replace_from)) =
                    candidates.into_iter().next()
                else {
                    if matches!(mode, ResyncMode::NostrAuthoritative)
                        && saw_authoritative_genesis_mismatch
                    {
                        return Err(Error::Blockchain(
                            "Nostr-authoritative resync could not find a valid identity chain with matching genesis".to_string(),
                        ));
                    }
                    debug!(
                        "finished identity chain resync for {} - no preferred valid remote chain found",
                        identity.node_id
                    );
                    return Ok(());
                };

                let data = &chain_data[selected_data_index];
                // the point from which the chain is different
                // normal:
                // local:   1 2 3
                // remote:  1 2 3 4 5
                // replace_from = None
                // changed_from = 4
                //
                // fork:
                // local:   1 2 3A 4A
                // remote:  1 2 3B 4B 5B
                // replace_from = Some(3)
                // changed_from = 3
                let changed_from = replace_from.unwrap_or_else(|| {
                    BlockId::next_from_previous_block_id(&expected_local_tip.id)
                });

                let replacement_blocks: Vec<IdentityBlock> = prepared
                    .chain
                    .blocks()
                    .iter()
                    .filter(|block| block.id >= changed_from)
                    .cloned()
                    .collect();

                let canonical_chain_changed = replace_from.is_some()
                    || prepared.chain.blocks().len() != existing_chain.blocks().len();

                // persist atomically
                if canonical_chain_changed {
                    let mut tx = self
                        .transaction_mgr
                        .begin()
                        .await
                        .map_err(|e| Error::Persistence(e.to_string()))?;

                    if let Some(replace_from) = replace_from {
                        info!(
                            "Fork resolution for identity {}: replacing blocks from height {replace_from}",
                            identity.node_id
                        );

                        tx.replace_identity_blocks_from_height(
                            &expected_local_tip,
                            replace_from,
                            &replacement_blocks,
                        )
                        .await
                        .map_err(|e| Error::Persistence(e.to_string()))?;
                    } else {
                        tx.append_identity_blocks(Some(&expected_local_tip), &replacement_blocks)
                            .await
                            .map_err(|e| Error::Persistence(e.to_string()))?;
                    }

                    // save the identity rebuilt from the complete winning remote chain
                    tx.save_identity(&prepared.identity).await.map_err(|e| {
                        error!("Failed to save resynced identity {}: {e}", identity.node_id);
                        Error::Persistence(e.to_string())
                    })?;

                    for prepared_block in prepared
                        .blocks
                        .iter()
                        .filter(|prepared_block| prepared_block.block_id >= changed_from)
                    {
                        if let Some(confirmation) = &prepared_block.email_confirmation {
                            tx.set_identity_email_confirmation(
                                &confirmation.proof,
                                &confirmation.data,
                            )
                            .await
                            .map_err(|e| Error::Persistence(e.to_string()))?;
                        }
                    }

                    tx.commit()
                        .await
                        .map_err(|e| Error::Persistence(e.to_string()))?;

                    // file refs
                    for prepared_block in prepared
                        .blocks
                        .iter()
                        .filter(|prepared_block| prepared_block.block_id >= changed_from)
                    {
                        for anchor in &prepared_block.files_to_anchor {
                            anchor_important_file(
                                &self.file_reference_store,
                                &anchor.file,
                                anchor.context.clone(),
                            )
                            .await?;
                        }
                    }
                }

                // nostr-event updates
                let accepted_block_count = prepared.chain.blocks().len();

                if let Err(e) = self
                    .chain_event_store
                    .remove_chain_events(&identity.node_id.to_string(), BlockchainType::Identity)
                    .await
                {
                    error!("Failed to invalidate old identity chain events during resync: {e}");
                }

                // only save nostr events up to the last valid event
                for event_container in data
                    .iter()
                    .filter(|event_container| {
                        matches!(event_container.block, BlockData::Identity(_))
                    })
                    .take(accepted_block_count)
                {
                    let event = event_container.as_chain_store_event(
                        &identity.node_id.to_string(),
                        BlockchainType::Identity,
                        event_container.block.get_block_height() as usize,
                    );

                    if let Err(e) = self.chain_event_store.add_chain_event(event).await {
                        error!("Failed to store identity chain event during resync: {e}");
                    }
                }

                // post-persistence effects
                for prepared_block in prepared
                    .blocks
                    .into_iter()
                    .filter(|prepared_block| prepared_block.block_id >= changed_from)
                {
                    self.process_post_commit_effects(
                        &identity.node_id,
                        prepared_block.post_commit_effects,
                    )
                    .await?;
                }

                debug!(
                    "resynced identity {} to valid remote block height {} from {} raw remote events",
                    identity.node_id,
                    prepared.chain.get_latest_block().id,
                    data.len(),
                );
                return Ok(());
            }
            _ => {
                let message = "Could not refetch chain for local identity because the identity keys or chain could not be fetched".to_string();
                error!("{message}");
                Err(Error::Persistence(message))
            }
        }
    }

    fn valid_chain_prefix_len(
        &self,
        node_id: &NodeId,
        blocks: &[IdentityBlock],
        keys: &BcrKeys,
    ) -> Result<usize> {
        let prepared = self.prepare_identity_chain_valid_prefix(blocks, keys)?;
        if &prepared.node_id != node_id {
            return Err(Error::Blockchain(format!(
                "Identity chain belongs to {}, expected {}",
                prepared.node_id, node_id,
            )));
        }
        Ok(prepared.chain.blocks().len())
    }
}

#[allow(unused)]
impl IdentityChainEventProcessor {
    pub fn new(
        blockchain_store: Arc<dyn IdentityChainStoreApi>,
        identity_store: Arc<dyn IdentityStoreApi>,
        file_reference_store: Arc<dyn FileReferenceStoreApi>,
        company_invite_handler: Arc<dyn NotificationHandlerApi>,
        bill_invite_handler: Arc<dyn NotificationHandlerApi>,
        nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
        chain_event_store: Arc<dyn NostrChainEventStoreApi>,
        transport: Arc<dyn TransportClientApi>,
        contact_store: Arc<dyn ContactStoreApi>,
        transaction_mgr: Arc<dyn TransactionManagerApi>,
        bitcoin_network: bitcoin::Network,
        config: Arc<Config>,
    ) -> Self {
        Self {
            blockchain_store,
            identity_store,
            file_reference_store,
            company_invite_handler,
            bill_invite_handler,
            nostr_contact_processor,
            chain_event_store,
            transport,
            contact_store,
            transaction_mgr,
            bitcoin_network,
            config,
        }
    }

    async fn add_new_chain(&self, blocks: Vec<IdentityBlock>, keys: &BcrKeys) -> Result<()> {
        // prepare & validate
        let prepared = self.prepare_identity_chain_valid_prefix(&blocks, keys)?;
        let node_id = prepared.node_id.clone();
        debug!("updating identity chain for {node_id}");

        // persist atomically

        let mut tx = self
            .transaction_mgr
            .begin()
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

        tx.append_identity_blocks(None, prepared.chain.blocks())
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

        tx.save_identity(&prepared.identity).await.map_err(|e| {
            error!("Failed to save identity {node_id}: {e}");
            Error::Persistence(e.to_string())
        })?;

        for prepared_block in &prepared.blocks {
            if let Some(confirmation) = &prepared_block.email_confirmation {
                tx.set_identity_email_confirmation(&confirmation.proof, &confirmation.data)
                    .await
                    .map_err(|e| Error::Persistence(e.to_string()))?;
            }
        }

        tx.commit()
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

        // anchored files from create
        for anchor in &prepared.create_files_to_anchor {
            anchor_important_file(
                &self.file_reference_store,
                &anchor.file,
                anchor.context.clone(),
            )
            .await?;
        }

        for prepared_block in &prepared.blocks {
            for anchor in &prepared_block.files_to_anchor {
                anchor_important_file(
                    &self.file_reference_store,
                    &anchor.file,
                    anchor.context.clone(),
                )
                .await?;
            }
        }

        // effects

        for prepared_block in prepared.blocks {
            self.process_post_commit_effects(&node_id, prepared_block.post_commit_effects)
                .await?;
        }

        // add to contacts without files if it's not there already, but don't fail
        if let Ok(None) = self.contact_store.get(&node_id).await
            && let Err(e) = self
                .contact_store
                .insert(
                    &node_id,
                    Contact {
                        t: if matches!(prepared.identity.t, IdentityType::Ident) {
                            ContactType::Person
                        } else {
                            ContactType::Anon
                        },
                        node_id: prepared.identity.node_id.to_owned(),
                        name: prepared.identity.name.clone(),
                        email: prepared.identity.email.clone(),
                        postal_address: prepared.identity.postal_address.to_full_postal_address(),
                        date_of_birth_or_registration: prepared.identity.date_of_birth.clone(),
                        country_of_birth_or_registration: prepared
                            .identity
                            .country_of_birth
                            .clone(),
                        city_of_birth_or_registration: prepared.identity.city_of_birth.clone(),
                        identification_number: prepared.identity.identification_number.clone(),
                        avatar_file: None,
                        proof_document_file: None,
                        nostr_relays: self.config.nostr_config.relays.clone(),
                        is_logical: false,
                        mint_url: Some(self.config.mint_config.default_mint_url.clone()),
                    },
                )
                .await
        {
            error!("Could not create contact for own identity {node_id}: {e}");
        }

        Ok(())
    }

    // validate and prepare a chain up to any invalid blocks
    fn prepare_identity_chain_valid_prefix(
        &self,
        blocks: &[IdentityBlock],
        keys: &BcrKeys,
    ) -> Result<PreparedIdentityChain> {
        let Some(first_block) = blocks.first() else {
            return Err(Error::Blockchain(
                "Received empty identity chain".to_string(),
            ));
        };

        // first block needs to be valid, otherwise we can't recover a valid prefix chain
        let (node_id, mut identity, mut chain) =
            self.get_valid_chain(vec![first_block.clone()], keys)?;

        let mut create_files_to_anchor = Vec::new();
        if let Some(file) = &identity.profile_picture_file {
            create_files_to_anchor.push(PreparedFileAnchor {
                file: file.clone(),
                context: identity_file_context("profile_picture_file"),
            });
        }
        if let Some(file) = &identity.identity_document_file {
            create_files_to_anchor.push(PreparedFileAnchor {
                file: file.clone(),
                context: identity_file_context("identity_document_file"),
            });
        }
        let mut prepared_blocks = Vec::new();
        for block in blocks.iter().skip(1) {
            match self.prepare_identity_block(&chain, &identity, block, keys) {
                Ok((prepared, candidate_chain, candidate_identity)) => {
                    chain = candidate_chain;
                    identity = candidate_identity;
                    prepared_blocks.push(prepared);
                }
                Err(e) => {
                    warn!(
                        "Ignoring invalid identity chain tail starting at block {} for {}: {e}",
                        block.id, node_id,
                    );
                    // keep the valid chain up to, but excluding, this invalid block
                    break;
                }
            }
        }
        Ok(PreparedIdentityChain {
            node_id,
            identity,
            chain,
            blocks: prepared_blocks,
            create_files_to_anchor,
        })
    }

    async fn add_identity_blocks(
        &self,
        node_id: &NodeId,
        chain: &mut IdentityBlockchain,
        blocks: Vec<IdentityBlock>,
        from_resync: bool,
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
                if blocks.len() == 1 && !from_resync {
                    let latest = chain.get_latest_block();
                    if is_fork_block(latest, block) {
                        info!(
                            "Split chain detected for identity {node_id} at height {} - resyncing",
                            block.id
                        );
                        self.resync_chain(ResyncMode::Normal).await?;
                        // resync potentially changed the complete chain - don't continue
                        return Ok(());
                    }
                }
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
                }
                Err(e) => {
                    // if we received a single block (normal block populate) and we are missing blocks, we try to resync
                    if blocks.len() == 1
                        && !from_resync
                        && BlockId::next_from_previous_block_id(&chain.get_latest_block().id)
                            < block.id
                    {
                        info!(
                            "Received invalid block {} for identity {node_id} - missing blocks - try to resync",
                            block.id
                        );
                        self.resync_chain(ResyncMode::Normal).await?;
                        // resync potentially changed the complete chain - don't continue
                        return Ok(());
                    }
                    error!("Error adding block for identity {node_id}: {e}");
                    return Err(e);
                }
            }
        }
        debug!("Updated identity {node_id} with data from new blocks");
        Ok(())
    }

    /// Validates a single identity block for a chain WITHOUT persisting or processing side effects.
    /// Returns the candidate chain if the block was validated
    fn validate_identity_block_for_chain(
        &self,
        chain: &IdentityBlockchain,
        block: &IdentityBlock,
        keys: &BcrKeys,
        identity_id: &NodeId,
    ) -> Result<IdentityBlockchain> {
        let block_id = block.id;
        // verify signature and signer of the block and get data to validate
        let verify_and_get_signer = match block.verify_and_get_signer(keys) {
            Ok(d) => d,
            Err(e) => {
                error!(
                    "Received invalid block {block_id} for identity {identity_id} - could not verify signature from block data signer"
                );
                return Err(Error::Blockchain(e.to_string()));
            }
        };
        if let Err(e) = (IdentityValidateActionData {
            blockchain: chain.to_owned(),
            id: identity_id.clone(),
            op: block.op_code().clone(),
            keys: keys.to_owned(),
            identity_proof_data: verify_and_get_signer.identity_proof_data,
        })
        .validate()
        {
            error!(
                "Received invalid block {block_id} for identity {identity_id}, identity action validation failed: {e}"
            );
            return Err(Error::Blockchain(e.to_string()));
        }
        let mut candidate_chain = chain.clone();
        if !candidate_chain.try_add_block(block.clone()) {
            error!("Received invalid identity block");
            return Err(Error::Blockchain(
                "Received invalid identity block".to_string(),
            ));
        }
        Ok(candidate_chain)
    }

    async fn add_identity_block(
        &self,
        node_id: &NodeId,
        keys: &BcrKeys,
        identity: &mut Identity,
        chain: &mut IdentityBlockchain,
        block: &IdentityBlock,
    ) -> Result<()> {
        let expected_latest = chain.get_latest_block().clone();
        // prepare & validate
        let (prepared, candidate_chain, candidate_identity) =
            self.prepare_identity_block(chain, identity, block, keys)?;

        // persist atomically

        let mut tx = self
            .transaction_mgr
            .begin()
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

        tx.append_identity_blocks(Some(&expected_latest), std::slice::from_ref(block))
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

        if prepared.identity_changed {
            tx.save_identity(&candidate_identity)
                .await
                .map_err(|e| Error::Persistence(e.to_string()))?;
        }

        if let Some(confirmation) = &prepared.email_confirmation {
            tx.set_identity_email_confirmation(&confirmation.proof, &confirmation.data)
                .await
                .map_err(|e| Error::Persistence(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

        // non-transactional derived/local state
        for anchor in &prepared.files_to_anchor {
            anchor_important_file(
                &self.file_reference_store,
                &anchor.file,
                anchor.context.clone(),
            )
            .await?;
        }

        // mutate after persistence succeeded
        *identity = candidate_identity;
        *chain = candidate_chain;

        // effects

        self.process_post_commit_effects(&identity.node_id, prepared.post_commit_effects)
            .await?;

        Ok(())
    }

    async fn process_post_commit_effects(
        &self,
        node_id: &NodeId,
        effects: Vec<IdentityPostCommitEffect>,
    ) -> Result<()> {
        for effect in effects {
            match effect {
                IdentityPostCommitEffect::EnsureNostrContact(signatory) => {
                    self.nostr_contact_processor
                        .ensure_nostr_contact(&signatory)
                        .await;
                }
                IdentityPostCommitEffect::RestoreCompany {
                    company_id,
                    company_key,
                } => {
                    let company_keys = BcrKeys::from_private_key(&company_key);
                    let invite = ChainInvite::company(company_id.to_string(), company_keys);
                    self.company_invite_handler
                        .handle_event(
                            Event::new_company_invite(invite).try_into()?,
                            node_id,
                            None,
                            None,
                        )
                        .await?;
                }
                IdentityPostCommitEffect::RestoreBill { bill_id, bill_key } => {
                    let bill_keys = BcrKeys::from_private_key(&bill_key);
                    let invite = ChainInvite::bill(bill_id.to_string(), bill_keys);
                    self.bill_invite_handler
                        .handle_event(Event::new_bill(invite).try_into()?, node_id, None, None)
                        .await?;
                }
            }
        }
        Ok(())
    }

    /// Prepares side effects for an identity block (contacts, invites, etc.) without persistence
    fn prepare_identity_block(
        &self,
        chain: &IdentityBlockchain,
        identity: &Identity,
        block: &IdentityBlock,
        keys: &BcrKeys,
    ) -> Result<(PreparedIdentityBlock, IdentityBlockchain, Identity)> {
        let candidate_chain =
            self.validate_identity_block_for_chain(chain, block, keys, &identity.node_id)?;
        let data = block
            .get_block_data(keys)
            .map_err(|e| Error::Blockchain(e.to_string()))?;
        let mut candidate_identity = identity.clone();
        let mut identity_changed = false;
        let mut email_confirmation = None;
        let mut files_to_anchor = vec![];
        let mut post_commit_effects = vec![];
        match &data {
            IdentityBlockPayload::Update(payload) => {
                if let EditOptionalFieldMode::Set(file) = &payload.profile_picture_file {
                    files_to_anchor.push(PreparedFileAnchor {
                        file: file.clone(),
                        context: identity_file_context("profile_picture_file"),
                    });
                }
                if let EditOptionalFieldMode::Set(file) = &payload.identity_document_file {
                    files_to_anchor.push(PreparedFileAnchor {
                        file: file.clone(),
                        context: identity_file_context("identity_document_file"),
                    });
                }
                candidate_identity.apply_block_data(&data);
                identity_changed = true;
            }
            IdentityBlockPayload::IdentityProof(data) => {
                email_confirmation = Some(PreparedEmailConfirmation {
                    proof: data.proof.clone(),
                    data: data.data.clone(),
                });
            }
            IdentityBlockPayload::InviteSignatory(data) => {
                post_commit_effects.push(IdentityPostCommitEffect::EnsureNostrContact(
                    data.signatory.clone(),
                ));
            }
            IdentityBlockPayload::CreateCompany(data) => {
                post_commit_effects.push(IdentityPostCommitEffect::RestoreCompany {
                    company_id: data.company_id.clone(),
                    company_key: data.company_key,
                });
            }
            IdentityBlockPayload::SignPersonalBill(data) if data.operation == BillOpCode::Issue => {
                if let Some(bill_key) = data.bill_key {
                    post_commit_effects.push(IdentityPostCommitEffect::RestoreBill {
                        bill_id: data.bill_id.clone(),
                        bill_key,
                    });
                }
            }
            _ => {}
        }
        Ok((
            PreparedIdentityBlock {
                block_id: block.id,
                identity_changed,
                email_confirmation,
                files_to_anchor,
                post_commit_effects,
            },
            candidate_chain,
            candidate_identity,
        ))
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
}

impl ServiceTraitBounds for IdentityChainEventProcessor {}

#[cfg(test)]
pub mod tests {
    use crate::handler::test_utils::{
        MockPersistenceTransactionApiMock, MockTransactionManagerApiMock, transaction_manager_with,
        update_identity_block_with_name,
    };
    use crate::test_utils::{MockContactStore, signed_identity_proof_test, test_cfg, test_ts};
    use crate::{
        handler::{
            IdentityChainEventProcessorApi, MockNostrContactProcessorApi,
            MockNotificationHandlerApi,
            identity_chain_event_processor::IdentityChainEventProcessor,
            test_utils::{
                MockIdentityChainStore, MockIdentityStore, MockNostrChainEventStore,
                get_baseline_identity, node_id_test,
            },
        },
        test_utils::{MockFileReferenceStore, MockNotificationJsonTransport},
        transport::create_public_chain_event,
    };
    use bcr_common::core::NodeId;
    use bcr_ebill_api::service::transport_service::ResyncMode;
    use bcr_ebill_core::protocol::event::{Event, EventEnvelope, IdentityBlockEvent};
    use bcr_ebill_core::{
        application::identity::Identity,
        protocol::blockchain::{
            Blockchain, BlockchainType,
            identity::{
                IdentityBlock, IdentityBlockchain, IdentityProofBlockData, IdentityUpdateBlockData,
            },
        },
        protocol::crypto::BcrKeys,
        protocol::{Name, Sha256Hash, Timestamp},
    };
    use mockall::predicate::eq;
    use nostr::event::FinalizeEvent;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_create_event_handler() {
        let (
            chain_store,
            store,
            contact,
            company_invite,
            bill_invite,
            chain_event_store,
            transport,
            contact_store,
        ) = create_mocks();
        IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            Arc::new(MockTransactionManagerApiMock::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );
    }

    #[tokio::test]
    async fn test_validate_chain_event_and_sender_invalid_on_no_keys_or_chain() {
        let keys = BcrKeys::new().get_nostr_keys();
        let (
            chain_store,
            mut store,
            contact,
            company_invite,
            bill_invite,
            chain_event_store,
            transport,
            contact_store,
        ) = create_mocks();

        store.expect_get().returning(move || {
            Err(bcr_ebill_persistence::Error::NoSuchEntity(
                "identity block".to_string(),
                node_id_test().to_string(),
            ))
        });

        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            Arc::new(MockTransactionManagerApiMock::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let valid = handler.validate_chain_event_and_sender(&node_id_test(), keys.public_key());
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_validate_chain_event_fails_if_not_own_node_id() {
        let keys = BcrKeys::new();
        let (
            chain_store,
            mut store,
            contact,
            company_invite,
            bill_invite,
            chain_event_store,
            transport,
            contact_store,
        ) = create_mocks();
        let identity = get_baseline_identity();
        store
            .expect_get()
            .returning(move || Ok(identity.identity.clone()));

        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            Arc::new(MockTransactionManagerApiMock::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let valid = handler
            .validate_chain_event_and_sender(&node_id_test(), keys.get_nostr_keys().public_key());
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_validate_chain_event() {
        let (
            chain_store,
            mut store,
            contact,
            company_invite,
            bill_invite,
            chain_event_store,
            transport,
            contact_store,
        ) = create_mocks();
        let full = get_baseline_identity();
        let mut identity = full.identity.clone();
        identity.name = Name::new("new name").unwrap();
        let keys = full.key_pair.clone();

        store.expect_get().returning(move || Ok(identity.clone()));

        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            Arc::new(MockTransactionManagerApiMock::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let valid = handler.validate_chain_event_and_sender(
            &full.identity.node_id,
            keys.get_nostr_keys().public_key(),
        );
        assert!(valid);
    }

    #[tokio::test]
    async fn test_process_update_identity_data() {
        let (
            mut chain_store,
            mut store,
            contact,
            company_invite,
            bill_invite,
            chain_event_store,
            transport,
            contact_store,
        ) = create_mocks();
        let full = get_baseline_identity();
        let identity = full.identity.clone();
        let keys = full.key_pair.clone();
        let create_block = get_identity_create_block(full.identity, &full.key_pair);
        let test_signed_identity = signed_identity_proof_test();
        let data = IdentityProofBlockData {
            proof: test_signed_identity.0,
            data: test_signed_identity.1,
        };
        let identity_proof_block = get_identity_proof_block(&create_block, &keys, &data);
        let blocks = vec![create_block, identity_proof_block];
        let chain = IdentityBlockchain::new_from_blocks(blocks).expect("could not create chain");
        let data = update_identity_block_with_name(Some(Name::new("new_name").unwrap()));
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
        let expected_block_hash = update_block.hash.clone();
        let mut tx = MockPersistenceTransactionApiMock::new();
        tx.expect_append_identity_blocks()
            .withf(move |expected_latest, blocks| {
                expected_latest.is_some()
                    && blocks.len() == 1
                    && blocks[0].hash == expected_block_hash
            })
            .returning(|_, _| Ok(()))
            .once();
        tx.expect_save_identity()
            .withf(|identity| identity.name == Name::new("new_name").unwrap())
            .returning(|_| Ok(()))
            .once();
        tx.expect_commit().return_once(|| Ok(()));
        let transaction_mgr = transaction_manager_with(tx);

        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            Arc::new(transaction_mgr),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .process_chain_data(&identity.node_id, vec![update_block], None)
            .await
            .expect("Process chain data should be handled");
    }

    #[tokio::test]
    async fn test_recovers_chain_on_missing_blocks() {
        let (
            mut chain_store,
            mut store,
            contact,
            company_invite,
            bill_invite,
            mut chain_event_store,
            mut transport,
            contact_store,
        ) = create_mocks();
        let full = get_baseline_identity();
        let identity = full.identity.clone();
        let keys = full.key_pair.clone();
        let create_block = get_identity_create_block(full.identity.clone(), &full.key_pair);
        let test_signed_identity = signed_identity_proof_test();
        let data = IdentityProofBlockData {
            proof: test_signed_identity.0,
            data: test_signed_identity.1,
        };
        let identity_proof_block = get_identity_proof_block(&create_block, &keys, &data);
        let blocks = vec![create_block, identity_proof_block];
        let skipped_chain =
            IdentityBlockchain::new_from_blocks(blocks).expect("could not create chain");

        let data_skipped = update_identity_block_with_name(Some(Name::new("new_name").unwrap()));
        let skipped_block =
            get_identity_update_block(skipped_chain.get_latest_block(), &keys, &data_skipped);

        let mut full_chain = skipped_chain.clone();
        full_chain.try_add_block(skipped_block.clone());
        let data = update_identity_block_with_name(Some(Name::new("another_name").unwrap()));
        let update_block = get_identity_update_block(full_chain.get_latest_block(), &keys, &data);

        let event1 = generate_test_event(
            &keys,
            None,
            None,
            as_event_payload(&full.identity.node_id, skipped_chain.get_first_block()),
            &full.identity.node_id,
        );

        let event1_proof = generate_test_event(
            &keys,
            Some(event1.clone()),
            Some(event1.clone()),
            as_event_payload(&full.identity.node_id, skipped_chain.get_latest_block()),
            &full.identity.node_id,
        );

        let event2 = generate_test_event(
            &keys,
            Some(event1_proof.clone()),
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

        let nostr_chain = vec![
            event1.clone(),
            event1_proof.clone(),
            event2.clone(),
            event3.clone(),
        ];

        // checks if we already have the chain two times with one call for the chain resync
        chain_store
            .expect_get_chain()
            .returning(move || Ok(skipped_chain.clone()))
            .times(2);

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

        chain_event_store
            .expect_remove_chain_events()
            .returning(|_, _| Ok(()));

        chain_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()))
            .times(0..);

        let expected_final_name = Name::new("another_name").unwrap();
        let mut tx = MockPersistenceTransactionApiMock::new();
        tx.expect_append_identity_blocks()
            .withf(|expected_latest, blocks| expected_latest.is_some() && blocks.len() == 2)
            .returning(|_, _| Ok(()))
            .once();
        tx.expect_save_identity()
            .withf(move |identity| identity.name == expected_final_name)
            .returning(|_| Ok(()))
            .once();
        tx.expect_commit().return_once(|| Ok(()));
        let transaction_mgr = transaction_manager_with(tx);

        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            Arc::new(transaction_mgr),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
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
        previous: Option<nostr::event::Event>,
        root: Option<nostr::event::Event>,
        data: EventEnvelope,
        node_id: &NodeId,
    ) -> nostr::event::Event {
        create_public_chain_event(
            &node_id.to_string(),
            data,
            Timestamp::new(1000).unwrap(),
            BlockchainType::Identity,
            previous,
            root,
        )
        .expect("could not create chain event")
        .finalize(&keys.get_nostr_keys())
        .expect("could not sign event")
    }

    #[tokio::test]
    async fn test_process_identity_proof() {
        let (
            mut chain_store,
            mut store,
            contact,
            company_invite,
            bill_invite,
            chain_event_store,
            transport,
            contact_store,
        ) = create_mocks();
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
        let expected_hash = identity_proof_block.hash.clone();
        let mut tx = MockPersistenceTransactionApiMock::new();
        tx.expect_append_identity_blocks()
            .withf(move |expected_latest, blocks| {
                expected_latest.is_some() && blocks.len() == 1 && blocks[0].hash == expected_hash
            })
            .returning(|_, _| Ok(()))
            .once();
        tx.expect_set_identity_email_confirmation()
            .returning(|_, _| Ok(()))
            .once();
        tx.expect_commit().return_once(|| Ok(()));
        let transaction_mgr = transaction_manager_with(tx);

        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            Arc::new(transaction_mgr),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
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
            test_ts(),
        )
        .expect("could not create block")
    }

    pub fn get_identity_update_block(
        previous_block: &IdentityBlock,
        keys: &BcrKeys,
        data: &IdentityUpdateBlockData,
    ) -> IdentityBlock {
        IdentityBlock::create_block_for_update(previous_block, data, keys, test_ts())
            .expect("could not create block")
    }

    pub fn get_identity_proof_block(
        previous_block: &IdentityBlock,
        keys: &BcrKeys,
        data: &IdentityProofBlockData,
    ) -> IdentityBlock {
        IdentityBlock::create_block_for_identity_proof(previous_block, data, keys, test_ts())
            .expect("could not create block")
    }

    fn create_mocks() -> (
        MockIdentityChainStore,
        MockIdentityStore,
        MockNostrContactProcessorApi,
        MockNotificationHandlerApi,
        MockNotificationHandlerApi,
        MockNostrChainEventStore,
        MockNotificationJsonTransport,
        MockContactStore,
    ) {
        (
            MockIdentityChainStore::new(),
            MockIdentityStore::new(),
            MockNostrContactProcessorApi::new(),
            MockNotificationHandlerApi::new(),
            MockNotificationHandlerApi::new(),
            MockNostrChainEventStore::new(),
            MockNotificationJsonTransport::new(),
            MockContactStore::new(),
        )
    }

    #[tokio::test]
    async fn test_resync_chain_only_missing_metadata_fails_if_nostr_chain_does_not_match() {
        let (
            mut chain_store,
            mut store,
            contact,
            company_invite,
            bill_invite,
            mut chain_event_store,
            mut transport,
            contact_store,
        ) = create_mocks();

        let full = get_baseline_identity();
        let identity = full.identity.clone();
        let keys = full.key_pair.clone();

        let create_block = get_identity_create_block(identity.clone(), &keys);

        let signed_identity = signed_identity_proof_test();
        let proof_data = IdentityProofBlockData {
            proof: signed_identity.0,
            data: signed_identity.1,
        };

        // Local #2
        let local_block = get_identity_proof_block(&create_block, &keys, &proof_data);

        let local_chain =
            IdentityBlockchain::new_from_blocks(vec![create_block.clone(), local_block.clone()])
                .expect("could not create local chain");

        // Different remote #2
        let remote_update_data =
            update_identity_block_with_name(Some(Name::new("remote").unwrap()));
        let remote_block = get_identity_update_block(&create_block, &keys, &remote_update_data);

        assert_ne!(local_block.hash, remote_block.hash);

        let event0 = generate_test_event(
            &keys,
            None,
            None,
            as_event_payload(&identity.node_id, &create_block),
            &identity.node_id,
        );

        let remote_event = generate_test_event(
            &keys,
            Some(event0.clone()),
            Some(event0.clone()),
            as_event_payload(&identity.node_id, &remote_block),
            &identity.node_id,
        );

        let local_chain_clone = local_chain.clone();
        chain_store
            .expect_get_chain()
            .times(1)
            .returning(move || Ok(local_chain_clone.clone()));

        chain_store.expect_add_block().times(0);
        chain_store.expect_remove_blocks_from_height().times(0);

        let full_clone = full.clone();
        store
            .expect_get_full()
            .times(1)
            .returning(move || Ok(full_clone.clone()));

        transport
            .expect_resolve_public_chain()
            .times(1)
            .returning(move |_, _| Ok(vec![event0.clone(), remote_event.clone()]));

        // No matching candidate => don't inspect or mutate metadata
        chain_event_store.expect_find_chain_events().times(0);
        chain_event_store.expect_add_chain_event().times(0);
        chain_event_store.expect_remove_chain_events().times(0);

        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            Arc::new(MockTransactionManagerApiMock::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let result = handler
            .resync_chain(ResyncMode::OnlyMissingMetadata {
                up_to_hash: local_block.hash.clone(),
            })
            .await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no Nostr chain matches")
        );
    }

    #[tokio::test]
    async fn test_resync_chain_only_missing_metadata_matches_up_to_hash() {
        let (
            mut chain_store,
            mut store,
            contact,
            company_invite,
            bill_invite,
            mut chain_event_store,
            mut transport,
            contact_store,
        ) = create_mocks();

        let full = get_baseline_identity();
        let identity = full.identity.clone();
        let keys = full.key_pair.clone();

        let create_block = get_identity_create_block(identity.clone(), &keys);

        let signed_identity = signed_identity_proof_test();
        let proof_data = IdentityProofBlockData {
            proof: signed_identity.0,
            data: signed_identity.1,
        };
        let predecessor = get_identity_proof_block(&create_block, &keys, &proof_data);

        // Local block which has already been persisted, but is currently
        // being published and therefore does not exist on Nostr yet
        let update_data = update_identity_block_with_name(Some(Name::new("local only").unwrap()));
        let local_only_block = get_identity_update_block(&predecessor, &keys, &update_data);

        let mut local_chain =
            IdentityBlockchain::new_from_blocks(vec![create_block.clone(), predecessor.clone()])
                .expect("could not create local identity chain");

        assert!(local_chain.try_add_block(local_only_block.clone()));

        // Nostr only knows the chain through missing previous
        let event0 = generate_test_event(
            &keys,
            None,
            None,
            as_event_payload(&identity.node_id, &create_block),
            &identity.node_id,
        );

        let event1 = generate_test_event(
            &keys,
            Some(event0.clone()),
            Some(event0.clone()),
            as_event_payload(&identity.node_id, &predecessor),
            &identity.node_id,
        );

        let nostr_chain = vec![event0, event1];

        let local_chain_clone = local_chain.clone();
        chain_store
            .expect_get_chain()
            .times(1)
            .returning(move || Ok(local_chain_clone.clone()));

        // Metadata-only recovery must never mutate the blockchain
        chain_store.expect_add_block().times(0);
        chain_store.expect_remove_blocks_from_height().times(0);

        let full_clone = full.clone();
        store
            .expect_get_full()
            .times(1)
            .returning(move || Ok(full_clone.clone()));

        transport
            .expect_resolve_public_chain()
            .with(
                eq(identity.node_id.to_string()),
                eq(BlockchainType::Identity),
            )
            .times(1)
            .returning(move |_, _| Ok(nostr_chain.clone()));

        // Simulate all Nostr metadata being missing locally.
        chain_event_store
            .expect_find_chain_events()
            .with(
                eq(identity.node_id.to_string()),
                eq(BlockchainType::Identity),
            )
            .times(1)
            .returning(|_, _| Ok(vec![]));

        chain_event_store.expect_remove_chain_events().times(0);

        let create_hash = create_block.hash.clone();
        let predecessor_hash = predecessor.hash.clone();
        let local_only_hash = local_only_block.hash.clone();

        // Only create + missing are in the recovery prefix
        chain_event_store
            .expect_add_chain_event()
            .withf(move |event| {
                (event.block_hash == create_hash || event.block_hash == predecessor_hash)
                    && event.block_hash != local_only_hash
            })
            .times(2)
            .returning(|_| Ok(()));

        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            Arc::new(MockTransactionManagerApiMock::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .resync_chain(ResyncMode::OnlyMissingMetadata {
                up_to_hash: predecessor.hash.clone(),
            })
            .await
            .expect("metadata recovery should ignore the unpublished local tip");
    }

    #[tokio::test]
    async fn test_resync_chain_skips_invalid_preferred_candidate_and_uses_next_valid_candidate() {
        let (
            mut chain_store,
            mut store,
            contact,
            company_invite,
            bill_invite,
            mut chain_event_store,
            mut transport,
            contact_store,
        ) = create_mocks();
        let full = get_baseline_identity();
        let identity = full.identity.clone();
        let keys = full.key_pair.clone();
        // Local:
        // Create -> IdentityProof
        let create_block = get_identity_create_block(identity.clone(), &keys);
        let signed_identity = signed_identity_proof_test();
        let proof_data = IdentityProofBlockData {
            proof: signed_identity.0,
            data: signed_identity.1,
        };
        let proof_block = get_identity_proof_block(&create_block, &keys, &proof_data);
        let local_chain =
            IdentityBlockchain::new_from_blocks(vec![create_block.clone(), proof_block.clone()])
                .expect("could not create local chain");
        // Candidate A:
        // Create -> Proof -> bad #3 -> bad #4
        // longer, so it will be ranked ahead of B, but it fails validation
        let wrong_keys = BcrKeys::new();
        let bad_data_1 = update_identity_block_with_name(Some(Name::new("bad-1").unwrap()));
        let bad_block_1 =
            get_identity_update_block(local_chain.get_latest_block(), &wrong_keys, &bad_data_1);
        let bad_data_2 = update_identity_block_with_name(Some(Name::new("bad-2").unwrap()));
        let bad_block_2 = get_identity_update_block(&bad_block_1, &wrong_keys, &bad_data_2);
        // Candidate B:
        // Create -> Proof -> valid #3
        let expected_name = Name::new("good").unwrap();
        let good_data = update_identity_block_with_name(Some(expected_name.clone()));
        let good_block =
            get_identity_update_block(local_chain.get_latest_block(), &keys, &good_data);
        // Build the Nostr events
        let event0 = generate_test_event(
            &keys,
            None,
            None,
            as_event_payload(&identity.node_id, &create_block),
            &identity.node_id,
        );
        let event1 = generate_test_event(
            &keys,
            Some(event0.clone()),
            Some(event0.clone()),
            as_event_payload(&identity.node_id, &proof_block),
            &identity.node_id,
        );
        let bad_event_1 = generate_test_event(
            &keys,
            Some(event1.clone()),
            Some(event0.clone()),
            as_event_payload(&identity.node_id, &bad_block_1),
            &identity.node_id,
        );
        let bad_event_2 = generate_test_event(
            &keys,
            Some(bad_event_1.clone()),
            Some(event0.clone()),
            as_event_payload(&identity.node_id, &bad_block_2),
            &identity.node_id,
        );
        let good_event = generate_test_event(
            &keys,
            Some(event1.clone()),
            Some(event0.clone()),
            as_event_payload(&identity.node_id, &good_block),
            &identity.node_id,
        );
        let nostr_events = vec![event0, event1, bad_event_1, bad_event_2, good_event];

        // Initial local state
        let local_chain_clone = local_chain.clone();
        chain_store
            .expect_get_chain()
            .once()
            .returning(move || Ok(local_chain_clone.clone()));
        // extension, not a fork
        chain_store.expect_remove_blocks_from_height().times(0);
        let full_clone = full.clone();
        store
            .expect_get_full()
            .once()
            .returning(move || Ok(full_clone.clone()));
        transport
            .expect_resolve_public_chain()
            .with(
                eq(identity.node_id.to_string()),
                eq(BlockchainType::Identity),
            )
            .once()
            .returning(move |_, _| Ok(nostr_events.clone()));
        chain_event_store
            .expect_remove_chain_events()
            .once()
            .returning(|_, _| Ok(()));
        // Create + Proof + the selected good block
        chain_event_store
            .expect_add_chain_event()
            .times(3)
            .returning(|_| Ok(()));

        let mut tx = MockPersistenceTransactionApiMock::new();
        tx.expect_append_identity_blocks()
            .withf(|expected_latest, blocks| expected_latest.is_some() && blocks.len() == 1)
            .returning(|_, _| Ok(()))
            .once();
        tx.expect_save_identity().returning(|_| Ok(())).once();
        tx.expect_commit().return_once(|| Ok(()));
        let transaction_mgr = transaction_manager_with(tx);

        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            Arc::new(transaction_mgr),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );
        handler
            .resync_chain(ResyncMode::Normal)
            .await
            .expect("second valid candidate should be used");
    }

    #[tokio::test]
    async fn test_resync_chain_rebuilds_identity_instead_of_retaining_discarded_fork_state() {
        let (
            mut chain_store,
            mut store,
            contact,
            company_invite,
            bill_invite,
            mut chain_event_store,
            mut transport,
            contact_store,
        ) = create_mocks();
        let mut full = get_baseline_identity();
        let keys = full.key_pair.clone();
        // The Create block represents the original identity
        let original_identity = full.identity.clone();
        let create_block = get_identity_create_block(original_identity.clone(), &keys);
        // Local fork changes the name
        let discarded_name = Name::new("discarded-fork-name").unwrap();
        let local_update_data = update_identity_block_with_name(Some(discarded_name.clone()));
        let local_update = get_identity_update_block(&create_block, &keys, &local_update_data);
        let local_chain =
            IdentityBlockchain::new_from_blocks(vec![create_block.clone(), local_update])
                .expect("could not create local chain");
        // Simulate the identity having already been derived from the local fork
        full.identity.name = discarded_name;

        // Remote  chain has the same Create block but IdentityProof as #2. It does NOT contain the name update
        let signed_identity = signed_identity_proof_test();
        let proof_data = IdentityProofBlockData {
            proof: signed_identity.0,
            data: signed_identity.1,
        };
        let remote_proof = get_identity_proof_block(&create_block, &keys, &proof_data);
        let event0 = generate_test_event(
            &keys,
            None,
            None,
            as_event_payload(&original_identity.node_id, &create_block),
            &original_identity.node_id,
        );
        let event1 = generate_test_event(
            &keys,
            Some(event0.clone()),
            Some(event0.clone()),
            as_event_payload(&original_identity.node_id, &remote_proof),
            &original_identity.node_id,
        );
        let local_chain_clone = local_chain.clone();
        chain_store
            .expect_get_chain()
            .once()
            .returning(move || Ok(local_chain_clone.clone()));

        // Block #2 from the local fork must be replaced
        let full_clone = full.clone();
        store
            .expect_get_full()
            .once()
            .returning(move || Ok(full_clone.clone()));

        transport
            .expect_resolve_public_chain()
            .once()
            .returning(move |_, _| Ok(vec![event0.clone(), event1.clone()]));
        chain_event_store
            .expect_remove_chain_events()
            .once()
            .returning(|_, _| Ok(()));
        chain_event_store
            .expect_add_chain_event()
            .times(2)
            .returning(|_| Ok(()));

        let mut tx = MockPersistenceTransactionApiMock::new();
        tx.expect_replace_identity_blocks_from_height()
            .returning(|_, _, _| Ok(()))
            .once();
        tx.expect_save_identity().returning(|_| Ok(())).once();
        tx.expect_set_identity_email_confirmation()
            .returning(|_, _| Ok(()))
            .once();
        tx.expect_commit().return_once(|| Ok(()));

        let transaction_mgr = transaction_manager_with(tx);

        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            Arc::new(transaction_mgr),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );
        handler
            .resync_chain(ResyncMode::NostrAuthoritative)
            .await
            .expect("resync should replace local fork");
    }

    #[tokio::test]
    async fn test_add_new_chain_persists_valid_prefix_before_invalid_tail() {
        let (
            chain_store,
            mut store,
            contact,
            company_invite,
            bill_invite,
            chain_event_store,
            transport,
            mut contact_store,
        ) = create_mocks();
        let full = get_baseline_identity();
        let identity = full.identity.clone();
        let keys = full.key_pair.clone();
        let create_block = get_identity_create_block(identity.clone(), &keys);
        // Correctly linked to Create, but signed with the wrong key, so it is not a valid identity block
        let wrong_keys = BcrKeys::new();
        let bad_update_data = update_identity_block_with_name(Some(Name::new("invalid").unwrap()));
        let bad_update = get_identity_update_block(&create_block, &wrong_keys, &bad_update_data);
        // The invalid update must not contribute any derived state
        store.expect_set_email_confirmation().times(0);
        // add_new_chain creates the own-identity contact after successfully importing the valid prefix
        contact_store.expect_get().once().returning(|_| Ok(None));
        contact_store
            .expect_insert()
            .once()
            .returning(|_, _| Ok(()));

        let mut tx = MockPersistenceTransactionApiMock::new();
        tx.expect_append_identity_blocks()
            .returning(|_, _| Ok(()))
            .once();
        tx.expect_save_identity().returning(|_| Ok(())).once();
        tx.expect_commit().return_once(|| Ok(()));

        let transaction_mgr = transaction_manager_with(tx);

        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            Arc::new(transaction_mgr),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );
        let result = handler
            .add_new_chain(vec![create_block, bad_update], &keys)
            .await;
        assert!(
            result.is_ok(),
            "valid chain prefix should be restored even if the tail is invalid"
        );
    }

    #[tokio::test]
    async fn test_resync_chain_recovers_valid_prefix_before_invalid_tail() {
        let (
            mut chain_store,
            mut store,
            contact,
            company_invite,
            bill_invite,
            mut chain_event_store,
            mut transport,
            contact_store,
        ) = create_mocks();
        let mut full = get_baseline_identity();
        let original_identity = full.identity.clone();
        let keys = full.key_pair.clone();
        // Local chain: Create -> Proof -> Update #3
        let create_block = get_identity_create_block(original_identity.clone(), &keys);
        let signed_identity = signed_identity_proof_test();
        let proof_data = IdentityProofBlockData {
            proof: signed_identity.0,
            data: signed_identity.1,
        };
        let proof_block = get_identity_proof_block(&create_block, &keys, &proof_data);
        let local_name = Name::new("local-3").unwrap();
        let local_update_data = update_identity_block_with_name(Some(local_name.clone()));
        let local_update = get_identity_update_block(&proof_block, &keys, &local_update_data);
        let local_chain = IdentityBlockchain::new_from_blocks(vec![
            create_block.clone(),
            proof_block.clone(),
            local_update.clone(),
        ])
        .expect("could not create local chain");
        // Make persisted aggregate consistent with local block #3
        full.identity.name = local_name;
        // Valid remote continuation: #4 -> #5
        let name_4 = Name::new("valid-4").unwrap();
        let update_4_data = update_identity_block_with_name(Some(name_4));
        let valid_block_4 = get_identity_update_block(&local_update, &keys, &update_4_data);
        let expected_final_name = Name::new("valid-5").unwrap();
        let update_5_data = update_identity_block_with_name(Some(expected_final_name.clone()));
        let valid_block_5 = get_identity_update_block(&valid_block_4, &keys, &update_5_data);

        // Invalid remote tail: #6
        // correct previous hash / height, but block signature belongs to some other key
        let wrong_keys = BcrKeys::new();
        let invalid_6_data = update_identity_block_with_name(Some(Name::new("invalid-6").unwrap()));
        let invalid_block_6 =
            get_identity_update_block(&valid_block_5, &wrong_keys, &invalid_6_data);

        // Nostr events themselves are signed by our correct keys - the embedded identity block #6 is bad
        let event_1 = generate_test_event(
            &keys,
            None,
            None,
            as_event_payload(&original_identity.node_id, &create_block),
            &original_identity.node_id,
        );
        let event_2 = generate_test_event(
            &keys,
            Some(event_1.clone()),
            Some(event_1.clone()),
            as_event_payload(&original_identity.node_id, &proof_block),
            &original_identity.node_id,
        );
        let event_3 = generate_test_event(
            &keys,
            Some(event_2.clone()),
            Some(event_1.clone()),
            as_event_payload(&original_identity.node_id, &local_update),
            &original_identity.node_id,
        );
        let event_4 = generate_test_event(
            &keys,
            Some(event_3.clone()),
            Some(event_1.clone()),
            as_event_payload(&original_identity.node_id, &valid_block_4),
            &original_identity.node_id,
        );
        let event_5 = generate_test_event(
            &keys,
            Some(event_4.clone()),
            Some(event_1.clone()),
            as_event_payload(&original_identity.node_id, &valid_block_5),
            &original_identity.node_id,
        );
        let event_6 = generate_test_event(
            &keys,
            Some(event_5.clone()),
            Some(event_1.clone()),
            as_event_payload(&original_identity.node_id, &invalid_block_6),
            &original_identity.node_id,
        );
        let nostr_events = vec![event_1, event_2, event_3, event_4, event_5, event_6];

        // Existing local state
        let local_chain_clone = local_chain.clone();
        chain_store
            .expect_get_chain()
            .once()
            .returning(move || Ok(local_chain_clone.clone()));
        // This is only an extension. Nothing should be truncated
        chain_store.expect_remove_blocks_from_height().times(0);

        let mut tx = MockPersistenceTransactionApiMock::new();
        tx.expect_append_identity_blocks()
            .withf(|expected_latest, blocks| expected_latest.is_some() && blocks.len() == 2)
            .returning(|_, _| Ok(()))
            .once();
        tx.expect_save_identity().returning(|_| Ok(())).once();
        tx.expect_commit().return_once(|| Ok(()));

        let transaction_mgr = transaction_manager_with(tx);

        // Identity aggregate
        let full_clone = full.clone();
        store
            .expect_get_full()
            .once()
            .returning(move || Ok(full_clone.clone()));

        // The old proof block is part of the already-existing prefix, so it must not be persisted again
        store.expect_set_email_confirmation().times(0);

        // Nostr
        transport
            .expect_resolve_public_chain()
            .with(
                eq(original_identity.node_id.to_string()),
                eq(BlockchainType::Identity),
            )
            .once()
            .returning(move |_, _| Ok(nostr_events.clone()));
        chain_event_store
            .expect_remove_chain_events()
            .once()
            .returning(|_, _| Ok(()));

        // Metadata should be rebuilt through block #5 only, not #6
        let allowed_hashes = [
            create_block.hash.clone(),
            proof_block.hash.clone(),
            local_update.hash.clone(),
            valid_block_4.hash.clone(),
            valid_block_5.hash.clone(),
        ];
        let invalid_6_hash = invalid_block_6.hash.clone();
        chain_event_store
            .expect_add_chain_event()
            .withf(move |event| {
                allowed_hashes.contains(&event.block_hash) && event.block_hash != invalid_6_hash
            })
            .times(5)
            .returning(|_| Ok(()));
        let handler = IdentityChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            Arc::new(transaction_mgr),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );
        handler
            .resync_chain(ResyncMode::Normal)
            .await
            .expect("resync should recover valid blocks before an invalid remote tail");
    }
}
