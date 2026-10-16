use crate::{
    Error, Result,
    handler::public_chain_helpers::{
        BlockData, chain_matches_local, find_first_difference, is_fork_block, resolve_event_chains,
        resolve_fork,
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
use bcr_ebill_persistence::{ContactStoreApi, NostrChainEventStoreApi};
use bcr_ebill_persistence::{
    FileReferenceStoreApi,
    traits::identity::{IdentityChainStoreApi, IdentityStoreApi},
};

use super::inbound_file_anchor::{anchor_important_file, identity_file_context};
use super::{IdentityChainEventProcessorApi, NostrContactProcessorApi, NotificationHandlerApi};

#[derive(Debug, Clone)]
struct PreparedIdentityBlock {
    block: IdentityBlock,
    chain: IdentityBlockchain,
    identity: Identity,
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
            (Ok(mut existing_chain), Ok(IdentityWithAll { identity, key_pair })) => {
                debug!(
                    "starting identity chain resync for identity {}",
                    identity.node_id
                );

                if let Ok(chain_data) = resolve_event_chains(
                    self.transport.clone(),
                    &identity.node_id.to_string(),
                    BlockchainType::Identity,
                    &Some(key_pair.to_owned()),
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

                        if blocks.is_empty() {
                            continue;
                        }

                        let fork_point = match mode {
                            ResyncMode::Normal => {
                                let (is_preferred, fork_point) =
                                    resolve_fork(existing_chain.blocks(), &blocks);

                                if !is_preferred {
                                    continue;
                                }

                                fork_point
                            }
                            // In this mode, we want to find the point where the local chain diverges from the Nostr chain
                            ResyncMode::NostrAuthoritative => {
                                find_first_difference(existing_chain.blocks(), &blocks)
                            }

                            // In this mode, we don't care about local, or remote chain divergences, we're just adding missing metadata for local, unpublished blocks
                            ResyncMode::OnlyMissingMetadata { ref up_to_hash } => {
                                let identity_id = identity.node_id.clone();
                                let Some(local_chain_end) = existing_chain
                                    .blocks()
                                    .iter()
                                    .position(|block| block.hash() == up_to_hash)
                                else {
                                    return Err(Error::Blockchain(format!(
                                        "Could not restore Nostr metadata for identity {identity_id}: block with hash {up_to_hash} does not exist in the local chain"
                                    )));
                                };
                                let local_blocks = &existing_chain.blocks()[..=local_chain_end];

                                // we're only interested in remote chains with the same blocks we have locally
                                if !chain_matches_local(local_blocks, &blocks) {
                                    continue;
                                }

                                let existing_events = match self
                                    .chain_event_store
                                    .find_chain_events(
                                        &identity_id.to_string(),
                                        BlockchainType::Identity,
                                    )
                                    .await
                                {
                                    Ok(ev) => ev,
                                    Err(e) => {
                                        error!(
                                            "Failed to fetch chain events for identity {identity_id}: {e}"
                                        );
                                        return Err(Error::Persistence(format!(
                                            "Failed to fetch chain events for identity {identity_id}: {e}"
                                        )));
                                    }
                                };

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
                                    let BlockData::Identity(remote_block) = &event_container.block
                                    else {
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

                                    self.chain_event_store
                                            .add_chain_event(event)
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
                        };

                        if matches!(mode, ResyncMode::NostrAuthoritative)
                            && fork_point == Some(BlockId::first())
                        {
                            return Err(Error::Blockchain(
                                    "Nostr-authoritative resync cannot replace a differing genesis block".to_string(),
                            ));
                        }

                        let mut test_chain = existing_chain.clone();
                        if let Some(fork_id) = &fork_point {
                            test_chain.truncate_from(*fork_id);
                        }

                        match self.validate_identity_blocks_for_chain(
                            &mut test_chain,
                            &blocks,
                            &key_pair,
                            &identity.node_id,
                        ) {
                            Ok(_) => {
                                if let Some(fork_id) = fork_point {
                                    info!(
                                        "Fork resolution for identity {}: replacing blocks from height {fork_id} with preferred remote chain",
                                        identity.node_id
                                    );
                                    self.blockchain_store
                                        .remove_blocks_from_height(fork_id)
                                        .await
                                        .map_err(|e| Error::Persistence(e.to_string()))?;
                                    existing_chain.truncate_from(fork_id);
                                }

                                if let Err(e) = self
                                    .add_identity_blocks(
                                        &identity.node_id,
                                        &mut existing_chain,
                                        blocks,
                                        true,
                                    )
                                    .await
                                {
                                    error!(
                                        "Failed to add blocks after truncation for identity {}: {e}",
                                        identity.node_id
                                    );
                                    return Err(e);
                                }

                                if let Err(e) = self
                                    .chain_event_store
                                    .remove_chain_events(
                                        &identity.node_id.to_string(),
                                        BlockchainType::Identity,
                                    )
                                    .await
                                {
                                    error!(
                                        "Failed to invalidate old identity chain events during resync: {e}"
                                    );
                                }

                                for event_container in data.iter() {
                                    let event = event_container.as_chain_store_event(
                                        &identity.node_id.to_string(),
                                        BlockchainType::Identity,
                                        event_container.block.get_block_height() as usize,
                                    );
                                    if let Err(e) =
                                        self.chain_event_store.add_chain_event(event).await
                                    {
                                        error!(
                                            "Failed to store identity chain event during resync: {e}"
                                        );
                                    }
                                }

                                debug!(
                                    "resynced identity {} with {} remote events",
                                    identity.node_id,
                                    data.len()
                                );
                                return Ok(());
                            }
                            Err(e) => {
                                debug!(
                                    "Chain candidate failed validation for identity {}: {e}",
                                    identity.node_id
                                );
                                continue;
                            }
                        }
                    }

                    // if we get here, that means we didn't find a matching chain on nostr to update metadata
                    if matches!(mode, ResyncMode::OnlyMissingMetadata { .. }) {
                        let message = "Could not restore Nostr metadata for identity: no Nostr chain matches the local identity chain".to_owned();

                        error!("{message}");
                        return Err(Error::Blockchain(message));
                    }

                    debug!("finished identity chain resync for {}", identity.node_id);
                    Ok(())
                } else {
                    let message = format!(
                        "Could not refetch chain data from Nostr for identity {}",
                        identity.node_id
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
        file_reference_store: Arc<dyn FileReferenceStoreApi>,
        company_invite_handler: Arc<dyn NotificationHandlerApi>,
        bill_invite_handler: Arc<dyn NotificationHandlerApi>,
        nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
        chain_event_store: Arc<dyn NostrChainEventStoreApi>,
        transport: Arc<dyn TransportClientApi>,
        contact_store: Arc<dyn ContactStoreApi>,
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
            bitcoin_network,
            config,
        }
    }

    async fn add_new_chain(&self, blocks: Vec<IdentityBlock>, keys: &BcrKeys) -> Result<()> {
        // prepare & validate
        let prepared = self.prepare_full_identity_chain(&blocks, keys)?;
        let node_id = prepared.node_id.clone();
        debug!("updating identity chain for {node_id}");

        // persist - TODO (tx): make transactional

        self.identity_store
            .save(&prepared.identity)
            .await
            .map_err(|e| {
                error!("Failed to save identity {node_id}: {e}");
                Error::Persistence(e.to_string())
            })?;

        // Save the first block of the chain as it is the create block
        self.save_block(prepared.chain.get_first_block()).await?;

        // anchored files from create
        for anchor in &prepared.create_files_to_anchor {
            anchor_important_file(
                &self.file_reference_store,
                &anchor.file,
                anchor.context.clone(),
            )
            .await?;
        }

        // remaining blocks and state derived from them
        for prepared_block in &prepared.blocks {
            self.save_block(&prepared_block.block).await?;
            if let Some(confirmation) = &prepared_block.email_confirmation {
                self.identity_store
                    .set_email_confirmation(&confirmation.proof, &confirmation.data)
                    .await
                    .map_err(|e| Error::Persistence(e.to_string()))?;
            }
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

    fn prepare_full_identity_chain(
        &self,
        blocks: &[IdentityBlock],
        keys: &BcrKeys,
    ) -> Result<PreparedIdentityChain> {
        let (node_id, mut identity, mut chain) = self.get_valid_chain(blocks.to_vec(), keys)?;

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
            let prepared = self.prepare_identity_block(&chain, &identity, block, keys)?;
            identity = prepared.identity.clone();
            chain = prepared.chain.clone();
            prepared_blocks.push(prepared);
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

    /// Validates multiple identity blocks for a chain WITHOUT persisting or processing side effects.
    /// Returns Ok(()) if all blocks are valid, Err otherwise.
    fn validate_identity_blocks_for_chain(
        &self,
        chain: &IdentityBlockchain,
        blocks: &[IdentityBlock],
        keys: &BcrKeys,
        identity_id: &NodeId,
    ) -> Result<IdentityBlockchain> {
        let mut candidate = chain.clone();
        for block in blocks {
            if block.id <= candidate.get_latest_block().id {
                continue;
            }
            candidate =
                self.validate_identity_block_for_chain(&candidate, block, keys, identity_id)?;
        }
        Ok(candidate)
    }

    async fn add_identity_block(
        &self,
        node_id: &NodeId,
        keys: &BcrKeys,
        identity: &mut Identity,
        chain: &mut IdentityBlockchain,
        block: &IdentityBlock,
    ) -> Result<()> {
        // prepare & validate
        let prepared = self.prepare_identity_block(chain, identity, block, keys)?;

        // persist - TODO (tx): make transactional

        if prepared.identity_changed {
            self.identity_store
                .save(&prepared.identity)
                .await
                .map_err(|e| Error::Persistence(e.to_string()))?;
        }

        if let Some(confirmation) = &prepared.email_confirmation {
            self.identity_store
                .set_email_confirmation(&confirmation.proof, &confirmation.data)
                .await
                .map_err(|e| Error::Persistence(e.to_string()))?;
        }

        for anchor in &prepared.files_to_anchor {
            anchor_important_file(
                &self.file_reference_store,
                &anchor.file,
                anchor.context.clone(),
            )
            .await?;
        }

        self.save_block(&prepared.block).await?;

        // mutate after persistence succeeded
        *identity = prepared.identity;
        *chain = prepared.chain;

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
    ) -> Result<PreparedIdentityBlock> {
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
        Ok(PreparedIdentityBlock {
            block: block.clone(),
            chain: candidate_chain,
            identity: candidate_identity,
            identity_changed,
            email_confirmation,
            files_to_anchor,
            post_commit_effects,
        })
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
    use crate::handler::test_utils::update_identity_block_with_name;
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
    use mockall::predicate::{always, eq};
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
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
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

        chain_event_store
            .expect_remove_chain_events()
            .returning(|_, _| Ok(()));

        chain_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()))
            .times(0..);

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
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(company_invite),
            Arc::new(bill_invite),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
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
}
