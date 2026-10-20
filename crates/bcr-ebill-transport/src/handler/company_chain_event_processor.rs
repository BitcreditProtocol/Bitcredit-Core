use crate::{
    Error, PushApi, Result,
    handler::{
        NotificationHandlerApi,
        public_chain_helpers::{
            BlockData, chain_matches_local, compare_block_chains, find_first_difference,
            is_fork_block, resolve_event_chains, resolve_fork,
        },
    },
};
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_api::{
    Config,
    service::transport_service::{ResyncMode, transport_client::TransportClientApi},
};
use bcr_ebill_core::{
    application::{
        company::CompanyStatus,
        contact::Contact,
        identity::ActiveIdentityState,
        notification::{Notification, NotificationLevel, NotificationType},
    },
    protocol::{
        EditOptionalFieldMode, EmailIdentityProofData, File, SignedIdentityProof, Timestamp,
        Validate,
        blockchain::{Block, bill::ContactType, company::CompanyValidateActionData},
        crypto::BcrKeys,
        event::{ChainInvite, Event},
        file_reference::FileReferenceContext,
    },
};
use log::{debug, error, info, trace, warn};
use std::{collections::HashSet, sync::Arc};

use bcr_ebill_core::{
    application::ServiceTraitBounds,
    application::company::{Company, CompanySignatoryStatus},
    protocol::BlockId,
    protocol::blockchain::{
        Blockchain, BlockchainType,
        bill::BillOpCode,
        company::{CompanyBlock, CompanyBlockPayload, CompanyBlockchain},
    },
};
use bcr_ebill_persistence::{
    ContactStoreApi, FileReferenceStoreApi, NostrChainEventStoreApi, NotificationStoreApi,
    traits::company::{CompanyChainStoreApi, CompanyStoreApi},
    traits::identity::IdentityStoreApi,
};

use super::inbound_file_anchor::{anchor_important_file, company_file_context};
use super::{CompanyChainEventProcessorApi, NostrContactProcessorApi};

#[derive(Clone)]
pub struct CompanyChainEventProcessor {
    blockchain_store: Arc<dyn CompanyChainStoreApi>,
    company_store: Arc<dyn CompanyStoreApi>,
    file_reference_store: Arc<dyn FileReferenceStoreApi>,
    identity_store: Arc<dyn IdentityStoreApi>,
    notification_store: Arc<dyn NotificationStoreApi>,
    nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
    bill_invite_handler: Arc<dyn NotificationHandlerApi>,
    push_service: Arc<dyn PushApi>,
    chain_event_store: Arc<dyn NostrChainEventStoreApi>,
    transport: Arc<dyn TransportClientApi>,
    contact_store: Arc<dyn ContactStoreApi>,
    bitcoin_network: bitcoin::Network,
    config: Arc<Config>,
}

#[derive(Debug, Clone)]
struct PreparedCompanyBlock {
    block_id: BlockId,
    timestamp: Timestamp,
    payload: CompanyBlockPayload,
    company_changed: bool,
    email_confirmation: Option<PreparedCompanyEmailConfirmation>,
    files_to_anchor: Vec<PreparedFileAnchor>,
}

#[derive(Debug, Clone)]
struct PreparedCompanyEmailConfirmation {
    proof: SignedIdentityProof,
    data: EmailIdentityProofData,
}

#[derive(Debug, Clone)]
struct PreparedFileAnchor {
    file: File,
    context: FileReferenceContext,
}

#[derive(Debug, Clone)]
struct PreparedCompanyChain {
    company_id: NodeId,
    initial_company: Company, // state after create
    company: Company,         // final company, aggregated from all state changes
    chain: CompanyBlockchain,
    blocks: Vec<PreparedCompanyBlock>,
    create_files_to_anchor: Vec<PreparedFileAnchor>,
}

#[async_trait]
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
            self.add_company_blocks(company_id, &mut existing_chain, blocks, &identity, false)
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
        sender: nostr::key::PublicKey,
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
                .map(|s| s.node_id.npub())
                .collect::<Vec<nostr::key::PublicKey>>();
            Ok(signers.contains(&sender))
        } else {
            Ok(false)
        }
    }

    async fn resync_chain(&self, company_id: &NodeId, mode: ResyncMode) -> Result<()> {
        match (
            self.blockchain_store.get_chain(company_id).await,
            self.company_store.get_key_pair(company_id).await,
        ) {
            (Ok(existing_chain), Ok(company_keys)) => {
                debug!("starting company chain resync for company {company_id}");

                let expected_local_tip = existing_chain.get_latest_block().clone();

                let Ok(chain_data) = resolve_event_chains(
                    self.transport.clone(),
                    &company_id.to_string(),
                    BlockchainType::Company,
                    &Some(company_keys.to_owned()),
                )
                .await
                else {
                    let message =
                        format!("Could not refetch chain data from Nostr for company {company_id}");
                    error!("{message}");
                    return Err(Error::Network(message));
                };

                // Pre-fetch identity needed for block processing
                let identity = self
                    .identity_store
                    .get()
                    .await
                    .map_err(|e| Error::Persistence(e.to_string()))?
                    .node_id;

                if let ResyncMode::OnlyMissingMetadata { ref up_to_hash } = mode {
                    let Some(local_chain_end) = existing_chain
                        .blocks()
                        .iter()
                        .position(|block| block.hash() == up_to_hash)
                    else {
                        return Err(Error::Blockchain(format!(
                            "Could not restore Nostr metadata for company {company_id}: block with hash {up_to_hash} does not exist in the local chain"
                        )));
                    };
                    let local_blocks = &existing_chain.blocks()[..=local_chain_end];
                    for data in &chain_data {
                        let blocks: Vec<CompanyBlock> = data
                            .iter()
                            .filter_map(|d| match d.block.clone() {
                                BlockData::Company(block) => Some(block),
                                _ => None,
                            })
                            .collect();
                        if blocks.is_empty() {
                            continue;
                        }
                        // we're only interested in remote chains with the same blocks we have locally
                        if !chain_matches_local(local_blocks, &blocks) {
                            continue;
                        }

                        let existing_events = match self
                            .chain_event_store
                            .find_chain_events(&company_id.to_string(), BlockchainType::Company)
                            .await
                        {
                            Ok(ev) => ev,
                            Err(e) => {
                                error!(
                                    "Failed to fetch chain events for company {company_id}: {e}"
                                );
                                return Err(Error::Persistence(format!(
                                    "Failed to fetch chain events for company {company_id}: {e}"
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
                                    matches!(event_container.block, BlockData::Company(_))
                                }))
                        {
                            let BlockData::Company(remote_block) = &event_container.block else {
                                continue;
                            };

                            // if we have the block as a chain event - continue
                            if existing_block_hashes.contains(&local_block.hash) {
                                continue;
                            }

                            // otherwise, add it
                            let event = event_container.as_chain_store_event(
                                &company_id.to_string(),
                                BlockchainType::Company,
                                remote_block.id.inner() as usize,
                            );

                            self.chain_event_store
                                            .add_chain_event(event)
                                            .await
                                            .map_err(|e| {
                                                error!(
                                                    "Failed to restore missing chain event for company {company_id}, block {}: {e}",
                                                    local_block.id
                                                );

                                                Error::Persistence(format!(
                                                        "Failed to restore missing chain event for company {company_id}, block {}: {e}",
                                                        local_block.id
                                                ))
                                            })?;

                            events_added += 1;
                        }

                        if events_added > 0 {
                            info!(
                                "Restored {events_added} missing Nostr chain event(s) for company {company_id} up to block hash {up_to_hash}"
                            );
                        }

                        return Ok(());
                    }

                    let message = format!(
                        "Could not restore Nostr metadata for company {company_id}: no Nostr chain matches the local company chain"
                    );
                    error!("{message}");
                    return Err(Error::Blockchain(message));
                }

                let mut candidates: Vec<(usize, PreparedCompanyChain, Option<BlockId>)> =
                    Vec::new();

                let mut saw_authoritative_genesis_mismatch = false;

                for (data_index, data) in chain_data.iter().enumerate() {
                    let blocks: Vec<CompanyBlock> = data
                        .iter()
                        .filter_map(|d| match d.block.clone() {
                            BlockData::Company(block) => Some(block),
                            _ => None,
                        })
                        .collect();
                    if blocks.is_empty() {
                        continue;
                    }
                    // turn raw Nostr chain into longest protocol-valid prefix chain
                    let prepared = match self.prepare_company_chain_valid_prefix(
                        &blocks,
                        &company_keys,
                        &identity,
                    ) {
                        Ok(prepared) => prepared,
                        Err(e) => {
                            debug!(
                                "Company chain candidate could not produce a valid genesis for {company_id}: {e}"
                            );
                            continue;
                        }
                    };

                    if &prepared.company_id != company_id {
                        debug!(
                            "Ignoring company chain candidate for {}, expected {company_id}",
                            prepared.company_id
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
                            "Nostr-authoritative resync could not find a valid company chain with matching genesis".to_string(),
                        ));
                    }
                    debug!(
                        "finished company chain resync for {company_id} - no preferred valid remote chain found"
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

                let replacement_blocks: Vec<CompanyBlock> = prepared
                    .chain
                    .blocks()
                    .iter()
                    .filter(|block| block.id >= changed_from)
                    .cloned()
                    .collect();

                let canonical_chain_changed = replace_from.is_some()
                    || prepared.chain.blocks().len() != existing_chain.blocks().len();

                // persist - TODO (tx): make transactional
                if canonical_chain_changed {
                    if let Some(replace_from) = replace_from {
                        self.blockchain_store
                            .remove_blocks_from_height(company_id, replace_from)
                            .await
                            .map_err(|e| Error::Persistence(e.to_string()))?;
                    }

                    for block in &replacement_blocks {
                        self.save_block(company_id, block).await?;
                    }

                    // Rebuild company from the winning chain
                    self.company_store
                        .update(company_id, &prepared.company)
                        .await
                        .map_err(|e| Error::Persistence(e.to_string()))?;

                    for prepared_block in prepared
                        .blocks
                        .iter()
                        .filter(|prepared_block| prepared_block.block_id >= changed_from)
                    {
                        if let Some(confirmation) = &prepared_block.email_confirmation {
                            self.company_store
                                .set_email_confirmation(
                                    company_id,
                                    &confirmation.proof,
                                    &confirmation.data,
                                )
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
                }

                // nostr-event updates
                let accepted_block_count = prepared.chain.blocks().len();

                if let Err(e) = self
                    .chain_event_store
                    .remove_chain_events(&company_id.to_string(), BlockchainType::Company)
                    .await
                {
                    error!("Failed to invalidate old company chain events during resync: {e}");
                }

                // only save nostr events up to the last valid event
                for event_container in data
                    .iter()
                    .filter(|event_container| {
                        matches!(event_container.block, BlockData::Company(_))
                    })
                    .take(accepted_block_count)
                {
                    let event = event_container.as_chain_store_event(
                        &company_id.to_string(),
                        BlockchainType::Company,
                        event_container.block.get_block_height() as usize,
                    );
                    if let Err(e) = self.chain_event_store.add_chain_event(event).await {
                        error!("Failed to store company chain event during resync: {e}");
                    }
                }

                // post-persistence effects for changed blocks
                self.replay_prepared_company_effects(&prepared, &identity, Some(changed_from))
                    .await?;

                debug!(
                    "finished company chain resync for {company_id} to valid remote block height {} from {} raw remote events",
                    prepared.chain.get_latest_block().id,
                    data.len(),
                );
                Ok(())
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

    async fn valid_chain_prefix_len(
        &self,
        company_id: &NodeId,
        blocks: &[CompanyBlock],
        keys: &BcrKeys,
    ) -> Result<usize> {
        let identity = self
            .identity_store
            .get()
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?
            .node_id;
        let prepared = self.prepare_company_chain_valid_prefix(blocks, keys, &identity)?;
        if &prepared.company_id != company_id {
            return Err(Error::Blockchain(format!(
                "Company chain belongs to {}, expected {}",
                prepared.company_id, company_id,
            )));
        }
        Ok(prepared.chain.blocks().len())
    }
}

impl CompanyChainEventProcessor {
    pub fn new(
        blockchain_store: Arc<dyn CompanyChainStoreApi>,
        company_store: Arc<dyn CompanyStoreApi>,
        file_reference_store: Arc<dyn FileReferenceStoreApi>,
        identity_store: Arc<dyn IdentityStoreApi>,
        notification_store: Arc<dyn NotificationStoreApi>,
        nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
        bill_invite_handler: Arc<dyn NotificationHandlerApi>,
        push_service: Arc<dyn PushApi>,
        chain_event_store: Arc<dyn NostrChainEventStoreApi>,
        transport: Arc<dyn TransportClientApi>,
        contact_store: Arc<dyn ContactStoreApi>,
        bitcoin_network: bitcoin::Network,
        config: Arc<Config>,
    ) -> Self {
        Self {
            blockchain_store,
            company_store,
            file_reference_store,
            identity_store,
            notification_store,
            nostr_contact_processor,
            bill_invite_handler,
            push_service,
            chain_event_store,
            bitcoin_network,
            contact_store,
            transport,
            config,
        }
    }

    async fn add_new_chain(
        &self,
        blocks: Vec<CompanyBlock>,
        keys: &BcrKeys,
        identity: &NodeId,
    ) -> Result<()> {
        let prepared = self.prepare_company_chain_valid_prefix(&blocks, keys, identity)?;
        let company_id = prepared.company_id.clone();
        let we_are_signatory_or_invited = matches!(
            prepared.company.status,
            CompanyStatus::Active | CompanyStatus::Invited
        );
        if !we_are_signatory_or_invited {
            info!("We are not a signatory for company {company_id} so skipping chain");
            return Ok(());
        }

        // persist - TODO (tx): make transactional

        self.company_store
            .insert(&prepared.company)
            .await
            .map_err(|e| {
                error!("Failed to insert company {company_id}: {e}");
                Error::Persistence(e.to_string())
            })?;
        self.save_keys(&company_id, keys).await?;

        // Save the first block of the chain as it is the create block
        self.save_block(&company_id, prepared.chain.get_first_block())
            .await?;

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
        for (block, prepared_block) in prepared.chain.blocks().iter().skip(1).zip(&prepared.blocks)
        {
            self.save_block(&company_id, block).await?;
            if let Some(confirmation) = &prepared_block.email_confirmation {
                self.company_store
                    .set_email_confirmation(&company_id, &confirmation.proof, &confirmation.data)
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
        self.transport
            .add_identity(company_id.clone(), keys.clone())
            .await?;

        self.replay_prepared_company_effects(&prepared, identity, None)
            .await?;

        // also add the company to our nostr contacts
        self.nostr_contact_processor
            .ensure_nostr_contact(&company_id)
            .await;

        // as well as all the company signatories
        for signatory in prepared.company.signatories.iter() {
            self.nostr_contact_processor
                .ensure_nostr_contact(&signatory.node_id)
                .await;
        }

        // add to contacts without files if it's not there already, but don't fail
        if let Ok(None) = self.contact_store.get(&company_id).await
            && let Err(e) = self
                .contact_store
                .insert(
                    &company_id,
                    Contact {
                        t: ContactType::Company,
                        node_id: company_id.to_owned(),
                        name: prepared.company.name.clone(),
                        email: Some(prepared.company.email.clone()),
                        postal_address: Some(prepared.company.postal_address.clone()),
                        date_of_birth_or_registration: prepared.company.registration_date.clone(),
                        country_of_birth_or_registration: prepared
                            .company
                            .country_of_registration
                            .clone(),
                        city_of_birth_or_registration: prepared
                            .company
                            .city_of_registration
                            .clone(),
                        identification_number: prepared.company.registration_number.clone(),
                        avatar_file: None,
                        proof_document_file: None,
                        nostr_relays: self.config.nostr_config.relays.clone(),
                        is_logical: false,
                        mint_url: Some(self.config.mint_config.default_mint_url.clone()),
                    },
                )
                .await
        {
            error!(
                "Could not create contact for company {company_id} identity {identity} was added for: {e}"
            );
        }
        Ok(())
    }

    async fn add_company_blocks(
        &self,
        company_id: &NodeId,
        chain: &mut CompanyBlockchain,
        blocks: Vec<CompanyBlock>,
        identity: &NodeId,
        from_resync: bool,
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
                if blocks.len() == 1 && !from_resync {
                    let latest = chain.get_latest_block();
                    if is_fork_block(latest, block) {
                        info!(
                            "Split chain detected for company {company_id} at height {} - resyncing",
                            block.id
                        );
                        // resync potentially changed the complete chain - don't continue
                        self.resync_chain(company_id, ResyncMode::Normal).await?;
                        return Ok(());
                    }
                }
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
                        && !from_resync
                        && BlockId::next_from_previous_block_id(&chain.get_latest_block().id)
                            < block.id
                    {
                        info!(
                            "Received invalid block {} for company {company_id} - missing blocks - try to resync",
                            block.id
                        );
                        self.resync_chain(company_id, ResyncMode::Normal).await?;
                        // resync potentially changed the complete chain - don't continue
                        return Ok(());
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

    /// Validates a single company block for a chain WITHOUT persisting or processing side effects.
    /// Returns the candidate chain if the block was validated
    fn validate_company_block_for_chain(
        &self,
        chain: &CompanyBlockchain,
        block: &CompanyBlock,
        company_keys: &BcrKeys,
    ) -> Result<CompanyBlockchain> {
        let company_id = block.company_id.clone();
        let block_id = block.id;

        // structural validation is only done against the clone
        let mut candidate_chain = chain.clone();

        if !candidate_chain.try_add_block(block.clone()) {
            error!("Received invalid company block");
            return Err(Error::Blockchain(
                "Received invalid company block".to_string(),
            ));
        }

        let verify_and_get_signer = block.verify_and_get_signer(company_keys).map_err(|e| {
            error!("Received invalid block {block_id} for company {company_id} - could not verify signature from block data signer");
            Error::Blockchain(e.to_string())
        })?;

        // validation the chain before this block
        (CompanyValidateActionData {
            blockchain: chain.clone(),
            company_id: company_id.clone(),
            signer_node_id: verify_and_get_signer.signer,
            op: block.op_code().clone(),
            company_keys: company_keys.clone(),
            invitee: verify_and_get_signer.invitee,
            removee: verify_and_get_signer.removee,
            identity_proof_data: verify_and_get_signer.identity_proof_data,
        })
        .validate()
        .map_err(|e| {
            error!(
                "Received invalid block {block_id} for company \
             {company_id}, company action validation failed: {e}"
            );

            Error::Blockchain(e.to_string())
        })?;

        Ok(candidate_chain)
    }

    fn apply_company_payload(
        company: &mut Company,
        payload: &CompanyBlockPayload,
        identity_node_id: &NodeId,
        timestamp: Timestamp,
    ) -> bool {
        match payload {
            CompanyBlockPayload::Create(_) | CompanyBlockPayload::SignBill(_) => false,
            _ => {
                company.apply_block_data(payload, identity_node_id, timestamp);
                true
            }
        }
    }

    fn prepare_company_block(
        &self,
        chain: &CompanyBlockchain,
        company: &Company,
        block: &CompanyBlock,
        keys: &BcrKeys,
        identity_node_id: &NodeId,
    ) -> Result<(PreparedCompanyBlock, CompanyBlockchain, Company)> {
        let candidate_chain = self.validate_company_block_for_chain(chain, block, keys)?;
        let payload = block
            .get_block_data(keys)
            .map_err(|e| Error::Blockchain(e.to_string()))?;
        let mut candidate_company = company.clone();
        let mut email_confirmation = None;
        let mut files_to_anchor = Vec::new();
        if let CompanyBlockPayload::Update(data) = &payload {
            if let EditOptionalFieldMode::Set(file) = &data.logo_file {
                files_to_anchor.push(PreparedFileAnchor {
                    file: file.clone(),
                    context: company_file_context(&company.id, "logo_file"),
                });
            }
            if let EditOptionalFieldMode::Set(file) = &data.proof_of_registration_file {
                files_to_anchor.push(PreparedFileAnchor {
                    file: file.clone(),
                    context: company_file_context(&company.id, "proof_of_registration_file"),
                });
            }
        }
        if let CompanyBlockPayload::IdentityProof(data) = &payload
            && &data.data.node_id == identity_node_id
        {
            email_confirmation = Some(PreparedCompanyEmailConfirmation {
                proof: data.proof.clone(),
                data: data.data.clone(),
            });
        }
        let company_changed = Self::apply_company_payload(
            &mut candidate_company,
            &payload,
            identity_node_id,
            block.timestamp(),
        );
        Ok((
            PreparedCompanyBlock {
                block_id: block.id,
                timestamp: block.timestamp(),
                payload,
                company_changed,
                email_confirmation,
                files_to_anchor,
            },
            candidate_chain,
            candidate_company,
        ))
    }

    async fn add_company_block(
        &self,
        company_id: &NodeId,
        keys: &BcrKeys,
        company: &mut Company,
        chain: &mut CompanyBlockchain,
        block: &CompanyBlock,
        identity_node_id: &NodeId,
    ) -> Result<()> {
        let (prepared, candidate_chain, candidate_company) =
            self.prepare_company_block(chain, company, block, keys, identity_node_id)?;

        // persist - TODO (tx): make transactional

        if prepared.company_changed {
            self.company_store
                .update(company_id, &candidate_company)
                .await
                .map_err(|e| Error::Persistence(e.to_string()))?;
        }

        if let Some(confirmation) = &prepared.email_confirmation {
            self.company_store
                .set_email_confirmation(company_id, &confirmation.proof, &confirmation.data)
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

        self.save_block(company_id, block).await?;

        // mutate after persistence succeeded
        *company = candidate_company;
        *chain = candidate_chain;

        // effects

        self.process_company_block_post_commit_effects(
            company_id,
            company,
            &prepared.payload,
            identity_node_id,
        )
        .await?;
        Ok(())
    }

    /// Processes side effects for a company block (contacts, updates, invites, etc.) WITHOUT persisting the block itself.
    async fn process_company_block_post_commit_effects(
        &self,
        company_id: &NodeId,
        company: &Company,
        payload: &CompanyBlockPayload,
        identity_node_id: &NodeId,
    ) -> Result<()> {
        match payload {
            CompanyBlockPayload::Create(_)
            | CompanyBlockPayload::Update(_)
            | CompanyBlockPayload::IdentityProof(_) => {
                // Canonical state already handled.
            }
            CompanyBlockPayload::InviteSignatory(payload) => {
                info!("Signatory invited to company {company_id}, adding to contacts");
                self.nostr_contact_processor
                    .ensure_nostr_contact(&payload.invitee)
                    .await;

                // if we're invited, create a notification
                if &payload.invitee == identity_node_id
                    && let Err(e) = self
                        .create_notification_for_company(
                            company,
                            identity_node_id,
                            &CompanyBlockPayload::InviteSignatory(payload.clone()),
                        )
                        .await
                {
                    error!("Couldn't create notification for company invite for {company_id}: {e}");
                }

                for signatory in company.signatories.iter() {
                    if signatory.node_id != payload.inviter
                        && signatory.node_id != payload.invitee
                        && matches!(
                            signatory.status,
                            CompanySignatoryStatus::InviteAcceptedIdentityProven { .. }
                        )
                        && let Err(e) = self
                            .save_company_notification(
                                company_id,
                                &signatory.node_id,
                                &format!(
                                    "{} invited {} to become a signatory",
                                    payload.inviter, payload.invitee
                                ),
                                Some(serde_json::to_value(company)?),
                                NotificationLevel::Informational,
                            )
                            .await
                    {
                        error!(
                            "Couldn't create notification for signatory {} about company invite for {company_id}: {e}",
                            signatory.node_id
                        );
                    }
                }

                // reset local hiding state for the invited user, so it's shown again
                if let Err(e) = self
                    .company_store
                    .delete_local_signatory_override(company_id, &payload.invitee)
                    .await
                {
                    warn!(
                        "Couldn't reset local signatory override for company {company_id} and {}: {e}",
                        payload.invitee
                    );
                }
            }
            CompanyBlockPayload::SignatoryAcceptInvite(payload) => {
                info!("Signatory accepted invite to company {company_id}");
                self.nostr_contact_processor
                    .ensure_nostr_contact(&payload.accepter)
                    .await;

                if let Some(inviter) = company
                    .signatories
                    .iter()
                    .find(|s| matches!(&s.status, CompanySignatoryStatus::Invited { inviter, .. } if *inviter == payload.accepter))
                    .map(|s| s.node_id.clone())
                {
                    for signatory in company.signatories.iter() {
                        if signatory.node_id != payload.accepter
                            && matches!(
                                signatory.status,
                                CompanySignatoryStatus::InviteAcceptedIdentityProven { .. }
                            )
                        {
                            let desc = if signatory.node_id == inviter {
                                format!("{} accepted your invitation to become a signatory", payload.accepter)
                            } else {
                                format!("{} accepted the invitation to become a signatory", payload.accepter)
                            };
                            if let Err(e) = self
                                .save_company_notification(
                                    company_id,
                                    &signatory.node_id,
                                    &desc,
                                    Some(serde_json::to_value(company)?),
                                    NotificationLevel::Informational,
                                )
                                .await
                            {
                                error!("Couldn't create notification for signatory {} about invite accept for {company_id}: {e}", signatory.node_id);
                            }
                        }
                    }
                }
            }
            CompanyBlockPayload::SignatoryRejectInvite(payload) => {
                info!("Signatory rejected invite to company {company_id}");

                if let Some(inviter) = company
                    .signatories
                    .iter()
                    .find(|s| matches!(&s.status, CompanySignatoryStatus::Invited { inviter, .. } if *inviter == payload.rejecter))
                    .map(|s| s.node_id.clone())
                {
                    for signatory in company.signatories.iter() {
                        if signatory.node_id != payload.rejecter
                            && matches!(
                                signatory.status,
                                CompanySignatoryStatus::InviteAcceptedIdentityProven { .. }
                            )
                        {
                            let desc = if signatory.node_id == inviter {
                                format!("{} rejected your invitation to become a signatory", payload.rejecter)
                            } else {
                                format!("{} rejected the invitation to become a signatory", payload.rejecter)
                            };
                            if let Err(e) = self
                                .save_company_notification(
                                    company_id,
                                    &signatory.node_id,
                                    &desc,
                                    Some(serde_json::to_value(company)?),
                                    NotificationLevel::Informational,
                                )
                                .await
                            {
                                error!("Couldn't create notification for signatory {} about invite reject for {company_id}: {e}", signatory.node_id);
                            }
                        }
                    }
                }
            }
            CompanyBlockPayload::RemoveSignatory(payload) => {
                let removee = payload.removee.clone();
                info!("Removing signatory from company {company_id}");

                // if we're being removed and current identity is that company - change it
                if &removee == identity_node_id
                    && let Ok(Some(active_node_id)) = self
                        .identity_store
                        .get_current_identity()
                        .await
                        .map(|i| i.company)
                    && &active_node_id == company_id
                    && let Err(e) = self
                        .identity_store
                        .set_current_identity(&ActiveIdentityState {
                            personal: identity_node_id.to_owned(),
                            company: None,
                        })
                        .await
                {
                    error!(
                        "Couldn't set active identity to personal after removing self from company: {e}"
                    );
                }

                if let Err(e) = self
                    .create_notification_for_company(
                        company,
                        &payload.removee,
                        &CompanyBlockPayload::RemoveSignatory(payload.clone()),
                    )
                    .await
                {
                    error!(
                        "Couldn't create notification for removed signatory {} from company {company_id}: {e}",
                        payload.removee
                    );
                }

                for signatory in company.signatories.iter() {
                    if signatory.node_id != payload.remover
                        && signatory.node_id != payload.removee
                        && matches!(
                            signatory.status,
                            CompanySignatoryStatus::InviteAcceptedIdentityProven { .. }
                        )
                        && let Err(e) = self
                            .create_notification_for_company(
                                company,
                                &signatory.node_id,
                                &CompanyBlockPayload::RemoveSignatory(payload.clone()),
                            )
                            .await
                    {
                        error!(
                            "Couldn't create notification for signatory {} about removal from company {company_id}: {e}",
                            signatory.node_id
                        );
                    }
                }
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
                        .handle_event(Event::new_bill(invite).try_into()?, &company.id, None, None)
                        .await
                    {
                        error!(
                            "Failed to add company bill {} when adding company: {e}",
                            payload.bill_id
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn prepare_company_chain_valid_prefix(
        &self,
        blocks: &[CompanyBlock],
        keys: &BcrKeys,
        identity_node_id: &NodeId,
    ) -> Result<PreparedCompanyChain> {
        let Some(first_block) = blocks.first() else {
            return Err(Error::Blockchain(
                "Received empty company chain".to_string(),
            ));
        };
        // first block needs to be valid, otherwise we can't recover a valid prefix chain
        let (company_id, initial_company, mut chain) =
            self.get_valid_chain(first_block, keys, identity_node_id)?;

        let mut company = initial_company.clone();
        let mut create_files_to_anchor = Vec::new();
        if let Some(file) = &company.logo_file {
            create_files_to_anchor.push(PreparedFileAnchor {
                file: file.clone(),
                context: company_file_context(&company_id, "logo_file"),
            });
        }
        if let Some(file) = &company.proof_of_registration_file {
            create_files_to_anchor.push(PreparedFileAnchor {
                file: file.clone(),
                context: company_file_context(&company_id, "proof_of_registration_file"),
            });
        }

        let mut prepared_blocks = Vec::new();
        for block in blocks.iter().skip(1) {
            match self.prepare_company_block(&chain, &company, block, keys, identity_node_id) {
                Ok((prepared, candidate_chain, candidate_company)) => {
                    chain = candidate_chain;
                    company = candidate_company;
                    prepared_blocks.push(prepared);
                }
                Err(e) => {
                    warn!(
                        "Ignoring invalid company chain tail starting at block {} for {}: {e}",
                        block.id, company_id
                    );

                    // keep the valid chain up to, but excluding, this invalid block
                    break;
                }
            }
        }
        Ok(PreparedCompanyChain {
            company_id,
            initial_company,
            company,
            chain,
            blocks: prepared_blocks,
            create_files_to_anchor,
        })
    }

    fn get_valid_chain(
        &self,
        first_block: &CompanyBlock,
        keys: &BcrKeys,
        identity_node_id: &NodeId,
    ) -> Result<(NodeId, Company, CompanyBlockchain)> {
        let chain = CompanyBlockchain::new_from_blocks(vec![first_block.clone()])
            .map_err(|e| Error::Blockchain(e.to_string()))?;
        if !chain.is_chain_valid() {
            return Err(Error::Blockchain(
                "Newly received company chain has invalid Create block".to_string(),
            ));
        }
        let payload = first_block
            .get_block_data(keys)
            .map_err(|e| Error::Blockchain(e.to_string()))?;
        let CompanyBlockPayload::Create(payload) = payload else {
            error!("First block of newly received company chain is not a Create block");
            return Err(Error::Blockchain(
                "First block of newly received company chain is not a Create block".to_string(),
            ));
        };
        let company = Company::from_block_data(payload, identity_node_id);
        let company_id = company.id.clone();
        Ok((company_id, company, chain))
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

    async fn create_notification_for_company(
        &self,
        company: &Company,
        node_id: &NodeId,
        payload: &CompanyBlockPayload,
    ) -> Result<()> {
        let company_id = &company.id;
        let (description, event, level) = match payload {
            CompanyBlockPayload::InviteSignatory(_) => (
                format!(
                    "{} have requested you to become an authorised signer",
                    company.name
                ),
                Some(serde_json::to_value(company)?),
                NotificationLevel::ActionRequired,
            ),
            CompanyBlockPayload::RemoveSignatory(payload) => {
                let description = if node_id == &payload.removee {
                    format!("You were removed from {}", company.name)
                } else {
                    format!("{} was removed from {}", payload.removee, company.name)
                };
                (
                    description,
                    Some(serde_json::to_value(company)?),
                    NotificationLevel::Informational,
                )
            }
            _ => return Ok(()),
        };
        self.save_company_notification(company_id, node_id, &description, event, level)
            .await
    }

    async fn save_company_notification(
        &self,
        company_id: &NodeId,
        node_id: &NodeId,
        description: &str,
        event: Option<serde_json::Value>,
        level: NotificationLevel,
    ) -> Result<()> {
        debug!(
            "Company notification: company_id={} recipient={} level={:?} desc=\"{}\"",
            company_id, node_id, level, description
        );
        let notification =
            Notification::new_company_notification(company_id, node_id, description, event, level);

        // mark Company event as done if any active one exists
        // BUT only if we're not demoting an ActionRequired notification to Informational
        match self
            .notification_store
            .get_latest_by_reference_and_node_id(
                &company_id.to_string(),
                NotificationType::Company,
                node_id,
            )
            .await
        {
            Ok(Some(currently_active)) => {
                let should_replace = match (currently_active.level, level) {
                    // Never demote ActionRequired to Informational
                    (NotificationLevel::ActionRequired, NotificationLevel::Informational) => {
                        trace!(
                            "Skipping company notification for {company_id}: would demote ActionRequired to Informational"
                        );
                        false
                    }
                    _ => true,
                };
                if should_replace
                    && let Err(e) = self
                        .notification_store
                        .mark_as_done(&currently_active.id)
                        .await
                {
                    error!("Failed to mark currently active notification as done: {e}");
                }
            }
            Err(e) => error!("Failed to get latest notification by reference: {e}"),
            Ok(None) => {}
        }

        // save new notification to database
        self.notification_store
            .add(notification.clone())
            .await
            .map_err(|e| {
                error!("Failed to save new notification to database: {e}");
                Error::Persistence("Failed to save new notification to database".to_string())
            })?;

        // send push notification to connected clients
        match serde_json::to_value(notification) {
            Ok(notification) => {
                trace!("sending notification {notification:?} for {node_id}");
                self.push_service.send(notification).await;
            }
            Err(e) => {
                error!("Failed to serialize notification for push service: {e}");
            }
        }
        Ok(())
    }

    // helper to apply payloads to a given company
    async fn replay_prepared_company_effects(
        &self,
        prepared: &PreparedCompanyChain,
        identity_node_id: &NodeId,
        changed_from: Option<BlockId>,
    ) -> Result<()> {
        let mut company = prepared.initial_company.clone();
        for prepared_block in &prepared.blocks {
            if prepared_block.company_changed {
                Self::apply_company_payload(
                    &mut company,
                    &prepared_block.payload,
                    identity_node_id,
                    prepared_block.timestamp,
                );
            }
            let should_process = match changed_from {
                Some(changed_from) => prepared_block.block_id >= changed_from,
                None => true,
            };
            if should_process {
                self.process_company_block_post_commit_effects(
                    &prepared.company_id,
                    &company,
                    &prepared_block.payload,
                    identity_node_id,
                )
                .await?;
            }
        }
        Ok(())
    }
}

impl ServiceTraitBounds for CompanyChainEventProcessor {}

#[cfg(test)]
#[allow(unused_mut)]
pub mod tests {
    use std::sync::Arc;

    use bcr_common::core::NodeId;
    use bcr_ebill_api::service::transport_service::ResyncMode;
    use bcr_ebill_core::application::company::CompanySignatoryStatus;
    use bcr_ebill_core::protocol::blockchain::Block;
    use bcr_ebill_core::protocol::blockchain::company::CompanyBlockPayload;
    use bcr_ebill_core::protocol::blockchain::company::block::{
        CompanyCreateBlockData, CompanySignatoryAcceptInviteBlockData,
        CompanySignatoryRejectInviteBlockData,
    };
    use bcr_ebill_core::protocol::event::{CompanyBlockEvent, Event, EventEnvelope};
    use bcr_ebill_core::protocol::file_reference::{FileReference, FileReferenceContext};
    use bcr_ebill_core::protocol::{EditOptionalFieldMode, File, Name};
    use bcr_ebill_core::{
        application::company::Company,
        application::notification::{Notification, NotificationLevel},
        protocol::Sha256Hash,
        protocol::Timestamp,
        protocol::blockchain::{
            Blockchain, BlockchainType,
            company::{
                CompanyBlock, CompanyBlockchain,
                block::{
                    CompanyIdentityProofBlockData, CompanyInviteSignatoryBlockData,
                    CompanyRemoveSignatoryBlockData, CompanyUpdateBlockData, SignatoryType,
                },
            },
        },
        protocol::crypto::BcrKeys,
    };
    use mockall::predicate::{always, eq};
    use nostr::event::FinalizeEvent;

    use crate::handler::test_utils::{
        MockNotificationStore, get_valid_activated_signatory, node_id_test_another,
        private_key_test, private_key_test_another, update_company_block_with_name,
    };
    use crate::push_notification::MockPushApi;
    use crate::test_utils::{
        MockContactStore, MockFileReferenceStore, signed_identity_proof_test, test_cfg, test_ts,
    };
    use crate::{
        handler::{
            CompanyChainEventProcessor, CompanyChainEventProcessorApi,
            MockNostrContactProcessorApi, MockNotificationHandlerApi,
            test_utils::{
                MockCompanyChainStore, MockCompanyStore, MockIdentityStore,
                MockNostrChainEventStore, get_company_data, node_id_test,
            },
        },
        test_utils::{MockNotificationJsonTransport, get_baseline_identity},
        transport::create_public_chain_event,
    };

    #[tokio::test]
    async fn test_create_event_handler() {
        let (
            chain_store,
            store,
            notification_store,
            contact,
            bill,
            identity,
            chain_event_store,
            transport,
            push_service,
            contact_store,
        ) = create_mocks();
        CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity),
            Arc::new(notification_store),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(push_service),
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
            notification_store,
            contact,
            bill,
            identity,
            chain_event_store,
            transport,
            push_service,
            contact_store,
        ) = create_mocks();

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
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity),
            Arc::new(notification_store),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(push_service),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
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
        let (
            chain_store,
            mut store,
            notification_store,
            contact,
            bill,
            identity,
            chain_event_store,
            transport,
            push_service,
            contact_store,
        ) = create_mocks();
        let (_, (company, _)) = get_company_data();
        store
            .expect_get()
            .with(eq(node_id_test()))
            .returning(move |_| Ok(company.clone()));

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity),
            Arc::new(notification_store),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(push_service),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
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
        let (
            chain_store,
            mut store,
            notification_store,
            contact,
            bill,
            identity,
            chain_event_store,
            transport,
            push_service,
            contact_store,
        ) = create_mocks();
        let (_, (mut company, _)) = get_company_data();
        company.signatories = vec![get_valid_activated_signatory(&NodeId::new(
            keys.pub_key(),
            bitcoin::Network::Testnet,
        ))];
        store
            .expect_get()
            .with(eq(node_id_test()))
            .returning(move |_| Ok(company.clone()));

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity),
            Arc::new(notification_store),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(push_service),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let valid = handler
            .validate_chain_event_and_sender(&node_id_test(), keys.get_nostr_keys().public_key())
            .await
            .expect("Event should be handled");
        assert!(valid);
    }

    #[tokio::test]
    async fn test_process_create_company_data() {
        let (
            mut chain_store,
            mut store,
            notification_store,
            mut contact,
            bill,
            mut identity,
            chain_event_store,
            mut transport,
            push_service,
            mut contact_store,
        ) = create_mocks();
        let (node_id, (company, keys)) = get_company_data();
        let _blocks = [get_company_create_block(
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

        contact_store.expect_get().returning(|_| Ok(None));
        contact_store.expect_insert().returning(|_, _| Ok(()));

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

        transport
            .expect_add_identity()
            .with(eq(node_id.clone()), eq(keys.clone()))
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
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity),
            Arc::new(notification_store),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(push_service),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let block = get_company_create_block(node_id.clone(), company.clone(), &keys);
        handler
            .process_chain_data(&node_id, vec![block], Some(keys.clone()))
            .await
            .expect("Process chain data should be handled");
    }

    #[tokio::test]
    async fn test_process_update_company_data() {
        let (
            mut chain_store,
            mut store,
            notification_store,
            mut contact,
            bill,
            mut identity,
            chain_event_store,
            transport,
            push_service,
            contact_store,
        ) = create_mocks();
        let (node_id, (company, keys)) = get_company_data();
        let blocks = vec![get_company_create_block(
            node_id.clone(),
            company.clone(),
            &keys,
        )];
        let mut chain = CompanyBlockchain::new_from_blocks(blocks).expect("could not create chain");
        chain = add_creator_identity_proof_block(chain);
        let data = update_company_block_with_name(Some(Name::new("new_name").unwrap()));
        let update_block = get_company_update_block(
            node_id.clone(),
            chain.get_latest_block(),
            &BcrKeys::from_private_key(&private_key_test()),
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
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity),
            Arc::new(notification_store),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(push_service),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .process_chain_data(&node_id, vec![update_block], None)
            .await
            .expect("Process chain data should be handled");
    }

    #[tokio::test]
    async fn test_recovers_chain_on_missing_blocks() {
        let (
            mut chain_store,
            mut store,
            notification_store,
            mut contact,
            bill,
            mut identity,
            mut chain_event_store,
            mut transport,
            push_service,
            contact_store,
        ) = create_mocks();
        let (node_id, (company, keys)) = get_company_data();
        let bcr_keys: BcrKeys = keys.clone();
        let blocks = vec![get_company_create_block(
            node_id.clone(),
            company.clone(),
            &keys,
        )];
        let mut skipped_chain =
            CompanyBlockchain::new_from_blocks(blocks).expect("could not create chain");
        skipped_chain = add_creator_identity_proof_block(skipped_chain);
        let data_skipped = update_company_block_with_name(Some(Name::new("new_name").unwrap()));
        let skipped_block = get_company_update_block(
            node_id.clone(),
            skipped_chain.get_latest_block(),
            &BcrKeys::from_private_key(&private_key_test()),
            &keys,
            &data_skipped,
        );

        let mut full_chain = skipped_chain.clone();
        assert!(full_chain.try_add_block(skipped_block.clone()));

        let data = update_company_block_with_name(Some(Name::new("another_name").unwrap()));
        let update_block = get_company_update_block(
            node_id.clone(),
            full_chain.get_latest_block(),
            &BcrKeys::from_private_key(&private_key_test()),
            &keys,
            &data,
        );

        let event1 = generate_test_event(
            &bcr_keys,
            None,
            None,
            as_event_payload(&node_id, skipped_chain.get_first_block()),
            &node_id,
        );

        let event2 = generate_test_event(
            &bcr_keys,
            Some(event1.clone()),
            Some(event1.clone()),
            as_event_payload(&node_id, skipped_chain.get_latest_block()),
            &node_id,
        );

        let event3 = generate_test_event(
            &bcr_keys,
            Some(event2.clone()),
            Some(event1.clone()),
            as_event_payload(&node_id, &skipped_block),
            &node_id,
        );

        let event4 = generate_test_event(
            &bcr_keys,
            Some(event3.clone()),
            Some(event1.clone()),
            as_event_payload(&node_id, &update_block),
            &node_id,
        );

        let nostr_chain = vec![
            event1.clone(),
            event2.clone(),
            event3.clone(),
            event4.clone(),
        ];

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
            .times(2);

        // get the current company state
        let expected_company = company.clone();
        store
            .expect_get()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(expected_company.clone()))
            .once();

        // and queries the chain from the transport
        transport
            .expect_resolve_public_chain()
            .with(eq(node_id.to_string()), eq(BlockchainType::Company))
            .returning(move |_, _| Ok(nostr_chain.clone()))
            .once();

        let expected_node = node_id.clone();
        store
            .expect_update()
            .withf(move |n, c| {
                n == &expected_node
                    && c.id == expected_node
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

        chain_event_store
            .expect_remove_chain_events()
            .returning(|_, _| Ok(()));

        chain_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()))
            .times(4);

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity),
            Arc::new(notification_store),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(push_service),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
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
        previous: Option<nostr::event::Event>,
        root: Option<nostr::event::Event>,
        data: EventEnvelope,
        node_id: &NodeId,
    ) -> nostr::event::Event {
        create_public_chain_event(
            &node_id.to_string(),
            data,
            Timestamp::new(1000).unwrap(),
            BlockchainType::Company,
            previous,
            root,
        )
        .expect("could not create chain event")
        .finalize(&keys.get_nostr_keys())
        .expect("could not sign event")
    }

    #[tokio::test]
    async fn test_process_invite_company_signatory() {
        let (
            mut chain_store,
            mut store,
            notification_store,
            mut contact,
            bill,
            mut identity,
            chain_event_store,
            transport,
            push_service,
            contact_store,
        ) = create_mocks();
        let new_node_id = node_id_test_another();
        let (node_id, (company, keys)) = get_company_data();
        let blocks = vec![get_company_create_block(
            node_id.clone(),
            company.clone(),
            &keys,
        )];
        let mut chain = CompanyBlockchain::new_from_blocks(blocks).expect("could not create chain");
        chain = add_creator_identity_proof_block(chain);
        let data = CompanyInviteSignatoryBlockData {
            invitee: new_node_id.clone(),
            inviter: node_id_test(),
            t: SignatoryType::Solo,
        };
        let update_block = get_company_invite_signatory_block(
            node_id.clone(),
            chain.get_latest_block(),
            &BcrKeys::from_private_key(&private_key_test()),
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

        // if node is invited, we clean local overrides
        store
            .expect_delete_local_signatory_override()
            .with(eq(node_id.clone()), eq(new_node_id.clone()))
            .returning(|_, _| Ok(()))
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
                    && c.signatories
                        .iter()
                        .any(|s| s.node_id == expected_new_node.clone())
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
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity),
            Arc::new(notification_store),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(push_service),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .process_chain_data(&node_id, vec![update_block], None)
            .await
            .expect("Process chain data should be handled");
    }

    #[tokio::test]
    async fn test_process_accept_company_invite() {
        let (
            mut chain_store,
            mut store,
            notification_store,
            mut contact,
            bill,
            mut identity,
            chain_event_store,
            transport,
            push_service,
            contact_store,
        ) = create_mocks();
        let new_node_id = node_id_test_another();
        let (node_id, (mut company, keys)) = get_company_data();
        company
            .signatories
            .push(get_valid_activated_signatory(&new_node_id.clone()));

        let blocks = vec![get_company_create_block(
            node_id.clone(),
            company.clone(),
            &keys,
        )];
        let mut chain = CompanyBlockchain::new_from_blocks(blocks).expect("could not create chain");
        chain = add_invite_signatory_block(chain);
        let data = CompanySignatoryAcceptInviteBlockData {
            accepter: new_node_id.clone(),
        };
        let update_block = get_company_accept_invite_block(
            node_id.clone(),
            chain.get_latest_block(),
            &BcrKeys::from_private_key(&private_key_test_another()),
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
                    && c.signatories.iter().any(|s| {
                        s.node_id == expected_new_node.clone()
                            && matches!(s.status, CompanySignatoryStatus::InviteAccepted { .. })
                    })
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
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity),
            Arc::new(notification_store),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(push_service),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .process_chain_data(&node_id, vec![update_block], None)
            .await
            .expect("Process chain data should be handled");
    }

    #[tokio::test]
    async fn test_process_reject_company_invite() {
        let (
            mut chain_store,
            mut store,
            notification_store,
            mut contact,
            bill,
            mut identity,
            chain_event_store,
            transport,
            push_service,
            contact_store,
        ) = create_mocks();
        let new_node_id = node_id_test_another();
        let (node_id, (mut company, keys)) = get_company_data();
        company
            .signatories
            .push(get_valid_activated_signatory(&new_node_id.clone()));

        let blocks = vec![get_company_create_block(
            node_id.clone(),
            company.clone(),
            &keys,
        )];
        let mut chain = CompanyBlockchain::new_from_blocks(blocks).expect("could not create chain");
        chain = add_invite_signatory_block(chain);
        let data = CompanySignatoryRejectInviteBlockData {
            rejecter: new_node_id.clone(),
        };
        let update_block = get_company_reject_invite_block(
            node_id.clone(),
            chain.get_latest_block(),
            &BcrKeys::from_private_key(&private_key_test_another()),
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
                    && c.signatories.iter().any(|s| {
                        s.node_id == expected_new_node.clone()
                            && matches!(s.status, CompanySignatoryStatus::InviteRejected { .. })
                    })
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

        // no need to ensure contacts in case of a reject
        contact
            .expect_ensure_nostr_contact()
            .with(eq(new_node_id.clone()))
            .returning(|_| ())
            .never();

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity),
            Arc::new(notification_store),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(push_service),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .process_chain_data(&node_id, vec![update_block], None)
            .await
            .expect("Process chain data should be handled");
    }

    #[tokio::test]
    async fn test_process_remove_company_signatory() {
        let (
            mut chain_store,
            mut store,
            mut notification_store,
            mut contact,
            bill,
            mut identity,
            chain_event_store,
            transport,
            mut push_service,
            contact_store,
        ) = create_mocks();
        let new_node_id = node_id_test_another();
        let (node_id, (mut company, keys)) = get_company_data();
        company
            .signatories
            .push(get_valid_activated_signatory(&new_node_id.clone()));

        let blocks = vec![get_company_create_block(
            node_id.clone(),
            company.clone(),
            &keys,
        )];
        let mut chain = CompanyBlockchain::new_from_blocks(blocks).expect("could not create chain");
        chain = add_creator_identity_proof_block(chain);
        chain = add_invite_signatory_block(chain);
        let data = CompanyRemoveSignatoryBlockData {
            remover: node_id_test(),
            removee: new_node_id.clone(),
        };
        let remove_block = get_company_remove_signatory_block(
            node_id.clone(),
            chain.get_latest_block(),
            &BcrKeys::from_private_key(&private_key_test()),
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
                    && c.signatories.iter().any(|s| {
                        s.node_id == expected_new_node.clone()
                            && matches!(s.status, CompanySignatoryStatus::Removed { .. })
                    })
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

        notification_store
            .expect_get_latest_by_reference_and_node_id()
            .returning(|_, _, _| Ok(None));

        notification_store.expect_add().returning(|_| {
            Ok(Notification::new_company_notification(
                &node_id_test(),
                &node_id_test_another(),
                "test",
                None,
                NotificationLevel::Informational,
            ))
        });

        push_service.expect_send().returning(|_| ());

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity),
            Arc::new(notification_store),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(push_service),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .process_chain_data(&node_id, vec![remove_block], None)
            .await
            .expect("Process chain data should be handled");
    }

    #[tokio::test]
    async fn test_process_identity_proof() {
        let (
            mut chain_store,
            mut store,
            notification_store,
            contact,
            bill,
            mut identity,
            chain_event_store,
            transport,
            push_service,
            contact_store,
        ) = create_mocks();
        let (node_id, (company, keys)) = get_company_data();
        let blocks = vec![get_company_create_block(
            node_id.clone(),
            company.clone(),
            &keys,
        )];
        let chain = CompanyBlockchain::new_from_blocks(blocks).expect("could not create chain");
        let (proof, mut d) = signed_identity_proof_test();
        d.company_node_id = Some(node_id.clone());
        let data = CompanyIdentityProofBlockData {
            proof,
            data: d,
            reference_block: None,
        };
        let update_block = get_company_identity_proof_block(
            node_id.clone(),
            chain.get_latest_block(),
            &BcrKeys::from_private_key(&private_key_test()),
            &keys,
            &data,
        );

        // we need to validate if we are a signatory with our identity
        identity
            .expect_get()
            .returning(|| Ok(get_baseline_identity().identity))
            .once();

        // incoming identity proof is set
        store
            .expect_set_email_confirmation()
            .returning(|_, _, _| Ok(()))
            .once();

        // apply changes from block with the identity proof
        let expected_node = node_id.clone();
        let expected_new_node = data.data.node_id.clone();
        store
            .expect_update()
            .withf(move |n, c| {
                n == &expected_node.clone()
                    && c.id == expected_node.clone()
                    && c.signatories.iter().any(|s| {
                        s.node_id == expected_new_node.clone()
                            && matches!(
                                s.status,
                                CompanySignatoryStatus::InviteAcceptedIdentityProven { .. }
                            )
                    })
            })
            .returning(|_, _| Ok(()))
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
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity),
            Arc::new(notification_store),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(push_service),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
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
            &CompanyCreateBlockData {
                id: company.id,
                name: company.name,
                country_of_registration: company.country_of_registration,
                city_of_registration: company.city_of_registration,
                postal_address: company.postal_address,
                email: company.email,
                registration_number: company.registration_number,
                registration_date: company.registration_date,
                proof_of_registration_file: company.proof_of_registration_file,
                logo_file: company.logo_file,
                creation_time: test_ts(),
                creator: node_id_test(),
            },
            &BcrKeys::from_private_key(&private_key_test()),
            keys,
            test_ts() - 10,
        )
        .expect("could not create block")
    }

    fn add_creator_identity_proof_block(mut chain: CompanyBlockchain) -> CompanyBlockchain {
        let (proof, mut data) = signed_identity_proof_test();
        data.company_node_id = Some(node_id_test());
        let identity_proof_block = CompanyBlock::create_block_for_identity_proof(
            node_id_test(),
            chain.get_latest_block(),
            &CompanyIdentityProofBlockData {
                proof,
                data,
                reference_block: Some(chain.get_latest_block().id()),
            },
            &BcrKeys::from_private_key(&private_key_test()),
            &BcrKeys::from_private_key(&private_key_test()),
            test_ts() - 9,
        )
        .unwrap();
        assert!(chain.try_add_block(identity_proof_block));
        assert!(chain.is_chain_valid());
        chain
    }

    fn add_invite_signatory_block(mut chain: CompanyBlockchain) -> CompanyBlockchain {
        let block = CompanyBlock::create_block_for_invite_signatory(
            node_id_test(),
            chain.get_latest_block(),
            &CompanyInviteSignatoryBlockData {
                invitee: node_id_test_another(),
                inviter: node_id_test(),
                t: SignatoryType::Solo,
            },
            &BcrKeys::from_private_key(&private_key_test()),
            &BcrKeys::from_private_key(&private_key_test()),
            &node_id_test().pub_key(),
            test_ts() - 8,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
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
            test_ts(),
        )
        .expect("could not create block")
    }

    fn get_company_invite_signatory_block(
        node_id: NodeId,
        previous_block: &CompanyBlock,
        keys: &BcrKeys,
        company_keys: &BcrKeys,
        data: &CompanyInviteSignatoryBlockData,
    ) -> CompanyBlock {
        CompanyBlock::create_block_for_invite_signatory(
            node_id,
            previous_block,
            data,
            keys,
            company_keys,
            &data.invitee.pub_key(),
            test_ts(),
        )
        .expect("could not create block")
    }

    fn get_company_accept_invite_block(
        node_id: NodeId,
        previous_block: &CompanyBlock,
        keys: &BcrKeys,
        company_keys: &BcrKeys,
        data: &CompanySignatoryAcceptInviteBlockData,
    ) -> CompanyBlock {
        CompanyBlock::create_block_for_accept_signatory_invite(
            node_id,
            previous_block,
            data,
            keys,
            company_keys,
            test_ts(),
        )
        .expect("could not create block")
    }

    fn get_company_reject_invite_block(
        node_id: NodeId,
        previous_block: &CompanyBlock,
        keys: &BcrKeys,
        company_keys: &BcrKeys,
        data: &CompanySignatoryRejectInviteBlockData,
    ) -> CompanyBlock {
        CompanyBlock::create_block_for_reject_signatory_invite(
            node_id,
            previous_block,
            data,
            keys,
            company_keys,
            test_ts(),
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
            test_ts(),
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
            test_ts(),
        )
        .expect("could not create block")
    }

    #[tokio::test]
    async fn test_process_company_block_post_commit_effects_does_not_persist_canonical_state() {
        let (mut chain_store, mut store, _, _, _, identity_store, _, _, _, _) = create_mocks();
        let (_, (company, _)) = get_company_data();
        let identity_node_id = get_baseline_identity().identity.node_id;
        let update_data = CompanyBlockPayload::Update(update_company_block_with_name(Some(
            Name::new("Updated Company").unwrap(),
        )));
        // post-commit effects must not persist canonical state
        chain_store.expect_add_block().times(0);
        store.expect_update().times(0);
        store.expect_set_email_confirmation().times(0);
        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity_store),
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            Arc::new(MockNotificationHandlerApi::new()),
            Arc::new(MockPushApi::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockNotificationJsonTransport::new()),
            Arc::new(MockContactStore::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );
        let result = handler
            .process_company_block_post_commit_effects(
                &company.id,
                &company,
                &update_data,
                &identity_node_id,
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_add_company_block_anchors_inbound_files() {
        let mut chain_store = MockCompanyChainStore::new();
        let mut store = MockCompanyStore::new();
        let mut file_reference_store = MockFileReferenceStore::new();

        let (company_id, (company, company_keys)) = get_company_data();
        let identity_node_id = get_baseline_identity().identity.node_id;
        let create_block =
            get_company_create_block(company_id.clone(), company.clone(), &company_keys);
        let mut chain = CompanyBlockchain::new_from_blocks(vec![create_block])
            .expect("could not create company chain");
        chain = add_creator_identity_proof_block(chain);
        let logo_file = File {
            name: Name::new("logo.png").unwrap(),
            hash: Sha256Hash::new("company_logo_file_hash_123456789012"),
            nostr_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .parse()
                .unwrap(),
        };

        let expected_hash = logo_file.hash.clone();
        let expected_name = logo_file.name.clone();
        let update_data = CompanyUpdateBlockData {
            name: None,
            email: None,
            country: None,
            city: None,
            zip: EditOptionalFieldMode::Ignore,
            address: None,
            country_of_registration: EditOptionalFieldMode::Ignore,
            city_of_registration: EditOptionalFieldMode::Ignore,
            registration_number: EditOptionalFieldMode::Ignore,
            registration_date: EditOptionalFieldMode::Ignore,
            logo_file: EditOptionalFieldMode::Set(logo_file),
            proof_of_registration_file: EditOptionalFieldMode::Ignore,
        };
        let update_block = get_company_update_block(
            company_id.clone(),
            chain.get_latest_block(),
            &BcrKeys::from_private_key(&private_key_test()),
            &company_keys,
            &update_data,
        );

        // company state is updated here
        store
            .expect_update()
            .with(eq(company_id.clone()), always())
            .once()
            .returning(|_, _| Ok(()));
        chain_store
            .expect_add_block()
            .with(eq(company_id.clone()), always())
            .once()
            .returning(|_, _| Ok(()));

        // inbound file is anchored as part of persistence
        let company_id_clone = company_id.clone();
        file_reference_store
            .expect_upsert()
            .withf(
                move |hash: &Sha256Hash,
                      _nostr_hash: &bitcoin::hashes::sha256::Hash,
                      name: &Option<Name>,
                      server_urls: &Vec<url::Url>,
                      is_important: &Option<bool>,
                      context: &Vec<FileReferenceContext>| {
                    *hash == expected_hash
                        && *name == Some(expected_name.clone())
                        && server_urls.is_empty()
                        && *is_important == Some(true)
                        && context
                            == &vec![FileReferenceContext::Company {
                                company_id: company_id_clone.to_string(),
                                field: "logo_file".to_string(),
                            }]
                },
            )
            .once()
            .returning(|hash, nostr_hash, name, _, is_important, context| {
                let mut file_ref = FileReference::new(hash.clone(), *nostr_hash, name);

                file_ref.is_important = is_important.unwrap_or(false);
                file_ref.context = context;

                Ok(file_ref)
            });

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(file_reference_store),
            Arc::new(MockIdentityStore::new()),
            Arc::new(MockNotificationStore::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            Arc::new(MockNotificationHandlerApi::new()),
            Arc::new(MockPushApi::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockNotificationJsonTransport::new()),
            Arc::new(MockContactStore::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let mut current_company = company.clone();
        handler
            .add_company_block(
                &company_id,
                &company_keys,
                &mut current_company,
                &mut chain,
                &update_block,
                &identity_node_id,
            )
            .await
            .expect("company block should be added");
    }

    fn create_mocks() -> (
        MockCompanyChainStore,
        MockCompanyStore,
        MockNotificationStore,
        MockNostrContactProcessorApi,
        MockNotificationHandlerApi,
        MockIdentityStore,
        MockNostrChainEventStore,
        MockNotificationJsonTransport,
        MockPushApi,
        MockContactStore,
    ) {
        (
            MockCompanyChainStore::new(),
            MockCompanyStore::new(),
            MockNotificationStore::new(),
            MockNostrContactProcessorApi::new(),
            MockNotificationHandlerApi::new(),
            MockIdentityStore::new(),
            MockNostrChainEventStore::new(),
            MockNotificationJsonTransport::new(),
            MockPushApi::new(),
            MockContactStore::new(),
        )
    }

    #[tokio::test]
    async fn test_resync_chain_only_missing_metadata_fails_if_nostr_chain_does_not_match() {
        let (
            mut chain_store,
            mut store,
            notification_store,
            contact,
            bill,
            mut identity_store,
            mut chain_event_store,
            mut transport,
            push_service,
            contact_store,
        ) = create_mocks();

        let (company_id, (company, keys)) = get_company_data();

        let create_block = get_company_create_block(company_id.clone(), company, &keys);

        // Local #2
        let base_chain = CompanyBlockchain::new_from_blocks(vec![create_block.clone()])
            .expect("could not create company chain");

        let local_chain = add_creator_identity_proof_block(base_chain);
        let local_block = local_chain.get_latest_block().clone();

        // Different remote #2
        let remote_update_data = update_company_block_with_name(Some(Name::new("remote").unwrap()));

        let remote_block = get_company_update_block(
            company_id.clone(),
            &create_block,
            &BcrKeys::from_private_key(&private_key_test()),
            &keys,
            &remote_update_data,
        );

        assert_ne!(local_block.hash, remote_block.hash);

        let event0 = generate_test_event(
            &keys,
            None,
            None,
            as_event_payload(&company_id, &create_block),
            &company_id,
        );

        let remote_event = generate_test_event(
            &keys,
            Some(event0.clone()),
            Some(event0.clone()),
            as_event_payload(&company_id, &remote_block),
            &company_id,
        );

        let local_chain_clone = local_chain.clone();
        chain_store
            .expect_get_chain()
            .times(1)
            .returning(move |_| Ok(local_chain_clone.clone()));

        chain_store.expect_add_block().times(0);
        chain_store.expect_remove_blocks_from_height().times(0);

        let keys_clone = keys.clone();
        store
            .expect_get_key_pair()
            .times(1)
            .returning(move |_| Ok(keys_clone.clone()));

        identity_store
            .expect_get()
            .times(1)
            .returning(|| Ok(get_baseline_identity().identity));

        transport
            .expect_resolve_public_chain()
            .times(1)
            .returning(move |_, _| Ok(vec![event0.clone(), remote_event.clone()]));

        chain_event_store.expect_find_chain_events().times(0);
        chain_event_store.expect_add_chain_event().times(0);
        chain_event_store.expect_remove_chain_events().times(0);

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity_store),
            Arc::new(notification_store),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(push_service),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let result = handler
            .resync_chain(
                &company_id,
                ResyncMode::OnlyMissingMetadata {
                    up_to_hash: local_block.hash.clone(),
                },
            )
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
            notification_store,
            contact,
            bill,
            mut identity_store,
            mut chain_event_store,
            mut transport,
            push_service,
            contact_store,
        ) = create_mocks();

        let (company_id, (company, keys)) = get_company_data();

        let create_block = get_company_create_block(company_id.clone(), company.clone(), &keys);

        let base_chain = CompanyBlockchain::new_from_blocks(vec![create_block.clone()])
            .expect("could not create company chain");

        // #2: missing which is already on Nostr
        let prefix_chain = add_creator_identity_proof_block(base_chain);
        let predecessor = prefix_chain.get_latest_block().clone();

        // #3: already persisted locally but not yet published
        let update_data = update_company_block_with_name(Some(Name::new("local only").unwrap()));

        let local_only_block = get_company_update_block(
            company_id.clone(),
            &predecessor,
            &BcrKeys::from_private_key(&private_key_test()),
            &keys,
            &update_data,
        );

        let mut local_chain = prefix_chain.clone();
        assert!(local_chain.try_add_block(local_only_block.clone()));

        let event0 = generate_test_event(
            &keys,
            None,
            None,
            as_event_payload(&company_id, &create_block),
            &company_id,
        );

        let event1 = generate_test_event(
            &keys,
            Some(event0.clone()),
            Some(event0.clone()),
            as_event_payload(&company_id, &predecessor),
            &company_id,
        );

        let nostr_chain = vec![event0, event1];

        let local_chain_clone = local_chain.clone();
        chain_store
            .expect_get_chain()
            .with(eq(company_id.clone()))
            .times(1)
            .returning(move |_| Ok(local_chain_clone.clone()));

        // Metadata recovery must not touch canonical company blocks
        chain_store.expect_add_block().times(0);
        chain_store.expect_remove_blocks_from_height().times(0);

        let keys_clone = keys.clone();
        store
            .expect_get_key_pair()
            .with(eq(company_id.clone()))
            .times(1)
            .returning(move |_| Ok(keys_clone.clone()));

        // resync_chain() fetches our personal identity before processing candidates.
        identity_store
            .expect_get()
            .times(1)
            .returning(|| Ok(get_baseline_identity().identity));

        transport
            .expect_resolve_public_chain()
            .with(eq(company_id.to_string()), eq(BlockchainType::Company))
            .times(1)
            .returning(move |_, _| Ok(nostr_chain.clone()));

        chain_event_store
            .expect_find_chain_events()
            .with(eq(company_id.to_string()), eq(BlockchainType::Company))
            .times(1)
            .returning(|_, _| Ok(vec![]));

        chain_event_store.expect_remove_chain_events().times(0);

        let create_hash = create_block.hash.clone();
        let predecessor_hash = predecessor.hash.clone();
        let local_only_hash = local_only_block.hash.clone();

        chain_event_store
            .expect_add_chain_event()
            .withf(move |event| {
                (event.block_hash == create_hash || event.block_hash == predecessor_hash)
                    && event.block_hash != local_only_hash
            })
            .times(2)
            .returning(|_| Ok(()));

        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity_store),
            Arc::new(notification_store),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(push_service),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .resync_chain(
                &company_id,
                ResyncMode::OnlyMissingMetadata {
                    up_to_hash: predecessor.hash.clone(),
                },
            )
            .await
            .expect("company metadata recovery should ignore the unpublished local tip");
    }

    #[tokio::test]
    async fn test_add_new_chain_persists_valid_prefix_before_invalid_tail() {
        let (
            mut chain_store,
            mut store,
            notification_store,
            mut contact,
            bill,
            identity_store,
            chain_event_store,
            mut transport,
            push_service,
            mut contact_store,
        ) = create_mocks();
        let (company_id, (company, keys)) = get_company_data();
        let identity_node_id = get_baseline_identity().identity.node_id;
        let create_block = get_company_create_block(company_id.clone(), company.clone(), &keys);
        let base_chain = CompanyBlockchain::new_from_blocks(vec![create_block.clone()])
            .expect("could not create company chain");
        let valid_chain = add_creator_identity_proof_block(base_chain);
        let proof_block = valid_chain.get_latest_block().clone();
        let expected_name = Name::new("valid-prefix").unwrap();
        let valid_update_data = update_company_block_with_name(Some(expected_name.clone()));
        let valid_update = get_company_update_block(
            company_id.clone(),
            &proof_block,
            &BcrKeys::from_private_key(&private_key_test()),
            &keys,
            &valid_update_data,
        );

        // Correct height and previous hash, but signed by somebody who is not allowed to update this company
        let wrong_signer = BcrKeys::new();
        let invalid_update_data =
            update_company_block_with_name(Some(Name::new("invalid-tail").unwrap()));
        let invalid_update = get_company_update_block(
            company_id.clone(),
            &valid_update,
            &wrong_signer,
            &keys,
            &invalid_update_data,
        );

        // final company must represent the last VALID block
        let expected_company_id = company_id.clone();
        store
            .expect_insert()
            .withf(move |company| {
                company.id == expected_company_id && company.name == expected_name
            })
            .once()
            .returning(|_| Ok(()));
        store
            .expect_save_key_pair()
            .with(eq(company_id.clone()), eq(keys.clone()))
            .once()
            .returning(|_, _| Ok(()));
        // creator identity proof is part of the valid prefix
        store
            .expect_set_email_confirmation()
            .once()
            .returning(|_, _, _| Ok(()));
        // final aggregate is inserted only once
        store.expect_update().times(0);
        // Create + Proof + valid Update may be persisted
        let allowed_hashes = [
            create_block.hash.clone(),
            proof_block.hash.clone(),
            valid_update.hash.clone(),
        ];

        let invalid_hash = invalid_update.hash.clone();
        chain_store
            .expect_add_block()
            .withf(move |_, block| {
                allowed_hashes.contains(&block.hash) && block.hash != invalid_hash
            })
            .times(3)
            .returning(|_, _| Ok(()));
        transport
            .expect_add_identity()
            .with(eq(company_id.clone()), eq(keys.clone()))
            .once()
            .returning(|_, _| Ok(()));
        // the company itself + creator/signatory
        contact
            .expect_ensure_nostr_contact()
            .times(2)
            .returning(|_| ());
        contact_store
            .expect_get()
            .with(eq(company_id.clone()))
            .once()
            .returning(|_| Ok(None));
        contact_store
            .expect_insert()
            .once()
            .returning(|_, _| Ok(()));
        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity_store),
            Arc::new(notification_store),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(push_service),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );
        handler
            .add_new_chain(
                vec![create_block, proof_block, valid_update, invalid_update],
                &keys,
                &identity_node_id,
            )
            .await
            .expect("valid company prefix should be restored even when the remote tail is invalid");
    }

    #[tokio::test]
    async fn test_resync_chain_recovers_valid_prefix_before_invalid_tail() {
        let (
            mut chain_store,
            mut store,
            notification_store,
            contact,
            bill,
            mut identity_store,
            mut chain_event_store,
            mut transport,
            push_service,
            contact_store,
        ) = create_mocks();
        let (company_id, (company, keys)) = get_company_data();
        // Create -> Proof -> Update #3
        let create_block = get_company_create_block(company_id.clone(), company, &keys);
        let base_chain = CompanyBlockchain::new_from_blocks(vec![create_block.clone()])
            .expect("could not create company chain");
        let mut local_chain = add_creator_identity_proof_block(base_chain);
        let proof_block = local_chain.get_latest_block().clone();
        let local_update_data = update_company_block_with_name(Some(Name::new("local-3").unwrap()));
        let local_update = get_company_update_block(
            company_id.clone(),
            &proof_block,
            &BcrKeys::from_private_key(&private_key_test()),
            &keys,
            &local_update_data,
        );
        assert!(local_chain.try_add_block(local_update.clone()));

        // valid remote #4 -> #5
        let valid_4_data = update_company_block_with_name(Some(Name::new("valid-4").unwrap()));
        let valid_block_4 = get_company_update_block(
            company_id.clone(),
            &local_update,
            &BcrKeys::from_private_key(&private_key_test()),
            &keys,
            &valid_4_data,
        );
        let expected_final_name = Name::new("valid-5").unwrap();
        let valid_5_data = update_company_block_with_name(Some(expected_final_name.clone()));
        let valid_block_5 = get_company_update_block(
            company_id.clone(),
            &valid_block_4,
            &BcrKeys::from_private_key(&private_key_test()),
            &keys,
            &valid_5_data,
        );

        // invalid #6
        let wrong_signer = BcrKeys::new();
        let invalid_6_data = update_company_block_with_name(Some(Name::new("invalid-6").unwrap()));
        let invalid_block_6 = get_company_update_block(
            company_id.clone(),
            &valid_block_5,
            &wrong_signer,
            &keys,
            &invalid_6_data,
        );

        // nostr events are valid company events
        let event_1 = generate_test_event(
            &keys,
            None,
            None,
            as_event_payload(&company_id, &create_block),
            &company_id,
        );
        let event_2 = generate_test_event(
            &keys,
            Some(event_1.clone()),
            Some(event_1.clone()),
            as_event_payload(&company_id, &proof_block),
            &company_id,
        );
        let event_3 = generate_test_event(
            &keys,
            Some(event_2.clone()),
            Some(event_1.clone()),
            as_event_payload(&company_id, &local_update),
            &company_id,
        );
        let event_4 = generate_test_event(
            &keys,
            Some(event_3.clone()),
            Some(event_1.clone()),
            as_event_payload(&company_id, &valid_block_4),
            &company_id,
        );
        let event_5 = generate_test_event(
            &keys,
            Some(event_4.clone()),
            Some(event_1.clone()),
            as_event_payload(&company_id, &valid_block_5),
            &company_id,
        );
        let event_6 = generate_test_event(
            &keys,
            Some(event_5.clone()),
            Some(event_1.clone()),
            as_event_payload(&company_id, &invalid_block_6),
            &company_id,
        );
        let nostr_events = vec![event_1, event_2, event_3, event_4, event_5, event_6];
        let local_chain_clone = local_chain.clone();
        chain_store
            .expect_get_chain()
            .with(eq(company_id.clone()))
            .once()
            .returning(move |_| Ok(local_chain_clone.clone()));
        // extension, not a fork
        chain_store.expect_remove_blocks_from_height().times(0);

        // only #4 and #5 are new valid blocks
        let valid_4_hash = valid_block_4.hash.clone();
        let valid_5_hash = valid_block_5.hash.clone();
        chain_store
            .expect_add_block()
            .withf(move |_, block| block.hash == valid_4_hash || block.hash == valid_5_hash)
            .times(2)
            .returning(|_, _| Ok(()));

        let keys_clone = keys.clone();
        store
            .expect_get_key_pair()
            .with(eq(company_id.clone()))
            .once()
            .returning(move |_| Ok(keys_clone.clone()));
        identity_store
            .expect_get()
            .once()
            .returning(|| Ok(get_baseline_identity().identity));
        // must stop at valid #5
        store
            .expect_update()
            .withf(move |_, company| company.name == expected_final_name)
            .once()
            .returning(|_, _| Ok(()));

        store.expect_set_email_confirmation().times(0);
        transport
            .expect_resolve_public_chain()
            .with(eq(company_id.to_string()), eq(BlockchainType::Company))
            .once()
            .returning(move |_, _| Ok(nostr_events.clone()));
        chain_event_store
            .expect_remove_chain_events()
            .once()
            .returning(|_, _| Ok(()));

        // metadata until #5 only
        let allowed_hashes = [
            create_block.hash.clone(),
            proof_block.hash.clone(),
            local_update.hash.clone(),
            valid_block_4.hash.clone(),
            valid_block_5.hash.clone(),
        ];

        let invalid_hash = invalid_block_6.hash.clone();
        chain_event_store
            .expect_add_chain_event()
            .withf(move |event| {
                allowed_hashes.contains(&event.block_hash) && event.block_hash != invalid_hash
            })
            .times(5)
            .returning(|_| Ok(()));
        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity_store),
            Arc::new(notification_store),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(push_service),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .resync_chain(&company_id, ResyncMode::Normal)
            .await
            .expect("resync should recover valid company blocks before an invalid remote tail");
    }

    #[tokio::test]
    async fn test_resync_chain_selects_best_valid_prefix_not_longest_raw_branch() {
        let (
            mut chain_store,
            mut store,
            notification_store,
            contact,
            bill,
            mut identity_store,
            mut chain_event_store,
            mut transport,
            push_service,
            contact_store,
        ) = create_mocks();
        let (company_id, (company, keys)) = get_company_data();
        // Create -> Proof
        let create_block = get_company_create_block(company_id.clone(), company, &keys);
        let base_chain = CompanyBlockchain::new_from_blocks(vec![create_block.clone()])
            .expect("could not create company chain");
        let local_chain = add_creator_identity_proof_block(base_chain);
        let proof_block = local_chain.get_latest_block().clone();

        // Candidate A
        // Create -> Proof -> A3 -> BAD4 -> BAD5
        // Valid prefix length = 3
        let a3_data = update_company_block_with_name(Some(Name::new("candidate-a").unwrap()));
        let a3 = get_company_update_block(
            company_id.clone(),
            &proof_block,
            &BcrKeys::from_private_key(&private_key_test()),
            &keys,
            &a3_data,
        );

        let wrong_signer = BcrKeys::new();
        let bad4_data = update_company_block_with_name(Some(Name::new("bad-4").unwrap()));
        let bad4 =
            get_company_update_block(company_id.clone(), &a3, &wrong_signer, &keys, &bad4_data);
        let bad5_data = update_company_block_with_name(Some(Name::new("bad-5").unwrap()));
        let bad5 =
            get_company_update_block(company_id.clone(), &bad4, &wrong_signer, &keys, &bad5_data);

        // Candidate B
        // Create -> Proof -> B3 -> B4
        // Valid prefix length = 4, B must win
        let b3_data = update_company_block_with_name(Some(Name::new("good-3").unwrap()));
        let b3 = get_company_update_block(
            company_id.clone(),
            &proof_block,
            &BcrKeys::from_private_key(&private_key_test()),
            &keys,
            &b3_data,
        );
        let expected_name = Name::new("good-4").unwrap();
        let b4_data = update_company_block_with_name(Some(expected_name.clone()));
        let b4 = get_company_update_block(
            company_id.clone(),
            &b3,
            &BcrKeys::from_private_key(&private_key_test()),
            &keys,
            &b4_data,
        );
        let event_1 = generate_test_event(
            &keys,
            None,
            None,
            as_event_payload(&company_id, &create_block),
            &company_id,
        );
        let event_2 = generate_test_event(
            &keys,
            Some(event_1.clone()),
            Some(event_1.clone()),
            as_event_payload(&company_id, &proof_block),
            &company_id,
        );
        let event_a3 = generate_test_event(
            &keys,
            Some(event_2.clone()),
            Some(event_1.clone()),
            as_event_payload(&company_id, &a3),
            &company_id,
        );
        let event_bad4 = generate_test_event(
            &keys,
            Some(event_a3.clone()),
            Some(event_1.clone()),
            as_event_payload(&company_id, &bad4),
            &company_id,
        );
        let event_bad5 = generate_test_event(
            &keys,
            Some(event_bad4.clone()),
            Some(event_1.clone()),
            as_event_payload(&company_id, &bad5),
            &company_id,
        );
        let event_b3 = generate_test_event(
            &keys,
            Some(event_2.clone()),
            Some(event_1.clone()),
            as_event_payload(&company_id, &b3),
            &company_id,
        );
        let event_b4 = generate_test_event(
            &keys,
            Some(event_b3.clone()),
            Some(event_1.clone()),
            as_event_payload(&company_id, &b4),
            &company_id,
        );
        // A has 5 blocks, B only 4
        let nostr_events = vec![
            event_1, event_2, event_a3, event_bad4, event_bad5, event_b3, event_b4,
        ];
        let local_chain_clone = local_chain.clone();
        chain_store
            .expect_get_chain()
            .once()
            .returning(move |_| Ok(local_chain_clone.clone()));
        chain_store.expect_remove_blocks_from_height().times(0);

        // only B3 + B4 may be persisted
        let b3_hash = b3.hash.clone();
        let b4_hash = b4.hash.clone();

        chain_store
            .expect_add_block()
            .withf(move |_, block| block.hash == b3_hash || block.hash == b4_hash)
            .times(2)
            .returning(|_, _| Ok(()));

        let keys_clone = keys.clone();
        store
            .expect_get_key_pair()
            .once()
            .returning(move |_| Ok(keys_clone.clone()));
        identity_store
            .expect_get()
            .once()
            .returning(|| Ok(get_baseline_identity().identity));
        store
            .expect_update()
            .withf(move |_, company| company.name == expected_name)
            .once()
            .returning(|_, _| Ok(()));
        store.expect_set_email_confirmation().times(0);
        transport
            .expect_resolve_public_chain()
            .once()
            .returning(move |_, _| Ok(nostr_events.clone()));

        chain_event_store
            .expect_remove_chain_events()
            .once()
            .returning(|_, _| Ok(()));

        // selected B: Create + Proof + B3 + B4
        let selected_hashes = [
            create_block.hash.clone(),
            proof_block.hash.clone(),
            b3.hash.clone(),
            b4.hash.clone(),
        ];
        chain_event_store
            .expect_add_chain_event()
            .withf(move |event| selected_hashes.contains(&event.block_hash))
            .times(4)
            .returning(|_| Ok(()));
        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity_store),
            Arc::new(notification_store),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(push_service),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );
        handler
            .resync_chain(&company_id, ResyncMode::Normal)
            .await
            .expect("the longest protocol-valid prefix must win, not the longest raw Nostr branch");
    }
}
