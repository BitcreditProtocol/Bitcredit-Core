use super::inbound_file_anchor::{anchor_important_file, company_file_context};
use super::{CompanyChainEventProcessorApi, NostrContactProcessorApi};
use crate::handler::incoming_chain_application::{
    BlockPosition, map_remote_block_data_error, preferred_extension, valid_fork_step,
    validate_remote_plaintext,
};
use crate::{
    Error, PushApi, Result,
    handler::{
        IncomingChainApplyResult, NotificationHandlerApi,
        incoming_chain_application::{
            block_position, classify_verified_application_result, deferred_position,
            map_block_signer_error, map_chain_action_validation_error,
            validate_incoming_block_integrity,
        },
        public_chain_helpers::{
            BlockData, chain_matches_local, compare_block_chains, find_first_difference,
            resolve_event_chains,
        },
    },
};
use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_api::{
    Config,
    service::transport_service::{
        InvalidIncomingBlock, ResyncMode, transport_client::TransportClientApi,
    },
};
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
use bcr_ebill_core::{
    application::{
        contact::Contact,
        identity::ActiveIdentityState,
        notification::{Notification, NotificationLevel, NotificationType},
    },
    protocol::{
        EditOptionalFieldMode, EmailIdentityProofData, File, SignedIdentityProof, Timestamp,
        Validate,
        blockchain::{
            Block,
            bill::ContactType,
            company::{CompanyOpCode, CompanyValidateActionData},
        },
        crypto::BcrKeys,
        event::{ChainInvite, Event},
        file_reference::FileReferenceContext,
    },
};
use bcr_ebill_persistence::{
    ContactStoreApi, Error as PersistenceError, FileReferenceStoreApi, NostrChainEventStoreApi,
    NotificationStoreApi,
    traits::{
        company::{CompanyChainStoreApi, CompanyStoreApi},
        identity::IdentityStoreApi,
        transaction::TransactionManagerApi,
    },
};
use log::{debug, error, info, trace, warn};
use std::{collections::HashSet, sync::Arc};

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
    transaction_mgr: Arc<dyn TransactionManagerApi>,
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
    async fn resync_chain(&self, company_id: &NodeId, mode: ResyncMode) -> Result<()> {
        if matches!(mode, ResyncMode::Normal) {
            return Err(Error::Blockchain(
                "Normal company resync uses the durable incoming catch-up pipeline".into(),
            ));
        }
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

                    let replace_from =
                        find_first_difference(existing_chain.blocks(), prepared.chain.blocks());

                    if replace_from == Some(BlockId::first()) {
                        saw_authoritative_genesis_mismatch = true;
                        continue;
                    }

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
                    if saw_authoritative_genesis_mismatch {
                        return Err(Error::Blockchain(
                            "Nostr-authoritative resync could not find a valid company chain with matching genesis".to_string(),
                        ));
                    }
                    debug!(
                        "finished company chain resync for {company_id} - no valid remote chain found"
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

                // persist atomically
                if canonical_chain_changed {
                    let mut tx = self
                        .transaction_mgr
                        .begin()
                        .await
                        .map_err(|e| Error::Persistence(e.to_string()))?;

                    if let Some(replace_from) = replace_from {
                        tx.replace_company_blocks_from_height(
                            company_id,
                            &expected_local_tip,
                            replace_from,
                            &replacement_blocks,
                        )
                        .await
                        .map_err(|e| Error::Persistence(e.to_string()))?;
                    } else {
                        tx.append_company_blocks(
                            company_id,
                            Some(&expected_local_tip),
                            &replacement_blocks,
                        )
                        .await
                        .map_err(|e| Error::Persistence(e.to_string()))?;
                    }

                    // Rebuild company from the winning chain
                    tx.update_company(company_id, &prepared.company)
                        .await
                        .map_err(|e| Error::Persistence(e.to_string()))?;

                    for prepared_block in prepared
                        .blocks
                        .iter()
                        .filter(|prepared_block| prepared_block.block_id >= changed_from)
                    {
                        if let Some(confirmation) = &prepared_block.email_confirmation {
                            tx.set_company_email_confirmation(
                                company_id,
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

                    // file refs outside transaction
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

    async fn persist_invite_keys(&self, company_id: &NodeId, keys: &BcrKeys) -> Result<()> {
        if company_id.network() != self.bitcoin_network
            || *company_id != NodeId::new(keys.pub_key(), self.bitcoin_network)
        {
            return Err(Error::Blockchain(
                "Invalid company invite id or keys".to_string(),
            ));
        }

        let mut tx = self
            .transaction_mgr
            .begin()
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;
        tx.save_company_key_pair(company_id, keys)
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;
        Ok(())
    }

    async fn apply_verified_block(
        &self,
        company_id: &NodeId,
        block: CompanyBlock,
        keys: BcrKeys,
    ) -> Result<IncomingChainApplyResult> {
        if company_id.network() != self.bitcoin_network {
            return Ok(IncomingChainApplyResult::Rejected(
                "Company belongs to another network".into(),
            ));
        }
        if &block.company_id != company_id {
            return classify_verified_application_result(Err(
                InvalidIncomingBlock::WrongChain.into()
            ));
        }
        if let Err(e) = validate_incoming_block_integrity(&block) {
            return classify_verified_application_result(Err(e));
        }
        // get chain
        let existing = match self.blockchain_store.get_chain(company_id).await {
            Ok(chain) => Some(chain),
            Err(PersistenceError::NoSuchEntity(_, _)) => None,
            Err(e) => return Err(Error::Persistence(e.to_string())),
        };
        // calculate status of the block
        let position = block_position(existing.as_ref(), &block);

        // replay child-chain recovery effects
        if position == BlockPosition::AlreadyApplied
            && block.op_code == CompanyOpCode::SignCompanyBill
        {
            let payload = block
                .get_block_data(&keys)
                .map_err(|e| Error::Blockchain(e.to_string()))?;
            self.recover_company_bill_keys(company_id, &payload).await?;
        }

        // if it's not "Next" - return status
        if let Some(outcome) = deferred_position(position) {
            return Ok(outcome);
        }
        // attempt to apply
        let identity = self
            .identity_store
            .get()
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?
            .node_id;
        let result = match existing {
            Some(mut chain) => {
                self.add_company_blocks(company_id, &mut chain, vec![block], &identity)
                    .await
            }
            None => {
                if block.op_code != CompanyOpCode::Create {
                    return classify_verified_application_result(Err(
                        InvalidIncomingBlock::UnexpectedOperation(
                            "Company genesis must be Create".into(),
                        )
                        .into(),
                    ));
                }
                let payload = match block.get_block_data(&keys) {
                    Ok(payload) => payload,
                    Err(e) => {
                        return classify_verified_application_result(Err(
                            map_remote_block_data_error(e),
                        ));
                    }
                };
                match payload {
                    CompanyBlockPayload::Create(data) if &data.id == company_id => {}
                    CompanyBlockPayload::Create(_) => {
                        return classify_verified_application_result(Err(
                            InvalidIncomingBlock::WrongChain.into(),
                        ));
                    }
                    _ => {
                        return classify_verified_application_result(Err(
                            InvalidIncomingBlock::UnexpectedOperation(
                                "Company genesis payload must be Create".into(),
                            )
                            .into(),
                        ));
                    }
                };
                self.add_new_chain(vec![block], &keys, &identity).await
            }
        };
        classify_verified_application_result(result)
    }

    async fn preferred_verified_branch(
        &self,
        company_id: &NodeId,
        blocks: &[(usize, CompanyBlock)],
        keys: &BcrKeys,
    ) -> Result<Vec<usize>> {
        let local = match self.blockchain_store.get_chain(company_id).await {
            Ok(chain) => Some(chain),
            Err(PersistenceError::NoSuchEntity(_, _)) => None,
            Err(e) => return Err(Error::Persistence(e.to_string())),
        };
        let identity = self
            .identity_store
            .get()
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?
            .node_id;
        let company = if local.is_some() {
            Some(
                self.company_store
                    .get(company_id)
                    .await
                    .map_err(|e| Error::Persistence(e.to_string()))?,
            )
        } else {
            None
        };

        preferred_extension::<CompanyBlockchain, _>(local.as_ref(), blocks, |path| {
            std::future::ready(self.verified_extension_len(
                company_id,
                local.as_ref().zip(company.as_ref()),
                &path,
                keys,
                &identity,
            ))
        })
        .await
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
        transaction_mgr: Arc<dyn TransactionManagerApi>,
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
            transaction_mgr,
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

        // persist atomically

        let mut tx = self
            .transaction_mgr
            .begin()
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

        tx.append_company_blocks(&company_id, None, prepared.chain.blocks())
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

        tx.insert_company(&prepared.company).await.map_err(|e| {
            error!("Failed to insert company {company_id}: {e}");
            Error::Persistence(e.to_string())
        })?;

        tx.save_company_key_pair(&company_id, keys)
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

        for prepared_block in &prepared.blocks {
            if let Some(confirmation) = &prepared_block.email_confirmation {
                tx.set_company_email_confirmation(
                    &company_id,
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

        // anchored files from create outside tx
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
    ) -> Result<()> {
        let keys = self
            .company_store
            .get_key_pair(company_id)
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;
        if *company_id != NodeId::new(keys.pub_key(), self.bitcoin_network) {
            return Err(Error::Persistence(format!(
                "Stored keys do not match company {company_id}"
            )));
        }
        let mut company = self
            .company_store
            .get(company_id)
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

        let mut block_height = chain.get_latest_block().id;
        for block in &blocks {
            if block.id <= block_height {
                if chain
                    .blocks()
                    .iter()
                    .any(|existing| existing.id == block.id && existing.hash() == block.hash())
                {
                    continue;
                }
                return Err(Error::Blockchain(format!(
                    "Conflicting company block {} for {company_id}",
                    block.id,
                )));
            }
            self.add_company_block(company_id, &keys, &mut company, chain, block, identity)
                .await?;
            block_height = block.id;
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
        validate_remote_plaintext(block, company_keys)?;
        let company_id = block.company_id.clone();

        // structural validation is only done against the clone
        let mut candidate_chain = chain.clone();

        if !candidate_chain.try_add_block(block.clone()) {
            error!("Received invalid company block");
            return Err(InvalidIncomingBlock::InvalidAction(
                "Received invalid company block".into(),
            )
            .into());
        }

        let verify_and_get_signer = block
            .verify_and_get_signer(company_keys)
            .map_err(map_block_signer_error)?;

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
        .map_err(map_chain_action_validation_error)?;

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
            .map_err(map_remote_block_data_error)?;
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
        let expected_latest = chain.get_latest_block().clone();
        let (prepared, candidate_chain, candidate_company) =
            self.prepare_company_block(chain, company, block, keys, identity_node_id)?;

        // persist atomically

        let mut tx = self
            .transaction_mgr
            .begin()
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

        tx.append_company_blocks(
            company_id,
            Some(&expected_latest),
            std::slice::from_ref(block),
        )
        .await
        .map_err(|e| Error::Persistence(e.to_string()))?;

        if prepared.company_changed {
            tx.update_company(company_id, &candidate_company)
                .await
                .map_err(|e| Error::Persistence(e.to_string()))?;
        }

        if let Some(confirmation) = &prepared.email_confirmation {
            tx.set_company_email_confirmation(company_id, &confirmation.proof, &confirmation.data)
                .await
                .map_err(|e| Error::Persistence(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

        // file refs outside of transaction
        for anchor in &prepared.files_to_anchor {
            anchor_important_file(
                &self.file_reference_store,
                &anchor.file,
                anchor.context.clone(),
            )
            .await?;
        }

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
            CompanyBlockPayload::SignBill(_) => {
                self.recover_company_bill_keys(company_id, payload).await?;
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
        if first_block.op_code != CompanyOpCode::Create {
            return Err(InvalidIncomingBlock::UnexpectedOperation(
                "Company genesis must be Create".into(),
            )
            .into());
        }
        validate_remote_plaintext(first_block, keys)?;
        let chain = CompanyBlockchain::new_from_blocks(vec![first_block.clone()])
            .map_err(map_remote_block_data_error)?;
        if !chain.is_chain_valid() {
            return Err(InvalidIncomingBlock::InvalidAction(
                "Invalid company genesis block".into(),
            )
            .into());
        }
        let payload = first_block
            .get_block_data(keys)
            .map_err(map_remote_block_data_error)?;
        let CompanyBlockPayload::Create(payload) = payload else {
            return Err(InvalidIncomingBlock::UnexpectedOperation(
                "Company genesis payload must be Create".into(),
            )
            .into());
        };
        if payload.id != first_block.company_id {
            return Err(InvalidIncomingBlock::WrongChain.into());
        }
        first_block
            .verify_and_get_signer(keys)
            .map_err(map_block_signer_error)?;
        let company = Company::from_block_data(payload, identity_node_id);
        let company_id = company.id.clone();
        Ok((company_id, company, chain))
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

    /// Validates an extension against copies of the committed chain and company state
    fn verified_extension_len(
        &self,
        company_id: &NodeId,
        existing: Option<(&CompanyBlockchain, &Company)>,
        blocks: &[CompanyBlock],
        keys: &BcrKeys,
        identity: &NodeId,
    ) -> Result<usize> {
        let Some(first) = blocks.first() else {
            return Ok(0);
        };
        let (mut chain, mut company, mut len) = match existing {
            Some((chain, company)) => (chain.clone(), company.clone(), 0),
            None => {
                if first.op_code != CompanyOpCode::Create || &first.company_id != company_id {
                    return Ok(0);
                }
                let Some((id, company, chain)) =
                    valid_fork_step(self.get_valid_chain(first, keys, identity))?
                else {
                    return Ok(0);
                };
                if &id != company_id {
                    return Ok(0);
                }
                (chain, company, 1)
            }
        };
        for block in blocks.iter().skip(len) {
            if &block.company_id != company_id
                || !block.validate_with_previous(chain.get_latest_block())
            {
                break;
            }
            let Some((_, next_chain, next_company)) = valid_fork_step(
                self.prepare_company_block(&chain, &company, block, keys, identity),
            )?
            else {
                break;
            };
            chain = next_chain;
            company = next_company;
            len += 1;
        }
        Ok(len)
    }

    /// Recovers a bill's keys from a committed company block
    async fn recover_company_bill_keys(
        &self,
        company_id: &NodeId,
        payload: &CompanyBlockPayload,
    ) -> Result<()> {
        let CompanyBlockPayload::SignBill(data) = payload else {
            return Ok(());
        };
        if data.operation != BillOpCode::Issue {
            return Ok(());
        }
        let Some(bill_key) = data.bill_key else {
            return Ok(());
        };
        let bill_keys = BcrKeys::from_private_key(&bill_key);
        if data.bill_id != BillId::new(bill_keys.pub_key(), self.bitcoin_network) {
            error!(
                "Cannot recover company bill {}: key does not match bill ID",
                data.bill_id,
            );
            return Ok(());
        }
        info!("Recovering company bill {}", data.bill_id);
        let invite = ChainInvite::bill(data.bill_id.to_string(), bill_keys);
        self.bill_invite_handler
            .handle_event(Event::new_bill(invite).try_into()?, company_id, None, None)
            .await?;
        Ok(())
    }
}

impl ServiceTraitBounds for CompanyChainEventProcessor {}

#[cfg(test)]
#[allow(unused_mut)]
pub mod tests {
    use crate::chain_keys::ChainKeyService;
    use crate::handler::public_chain_helpers::compare_block_chains;
    use crate::handler::{CompanyInviteEventHandler, NotificationHandlerApi};
    use crate::handler::{
        IncomingChainApplication, MockBillChainEventProcessorApi,
        MockIdentityChainEventProcessorApi,
    };
    use crate::incoming_verification::{IncomingPropagationVerifier, VerifiedChainIngestionApi};
    use bcr_common::core::BillId;
    use bcr_common::core::NodeId;
    use bcr_ebill_api::service::transport_service::propagation::RelayQuorumSnapshot;
    use bcr_ebill_api::service::transport_service::{Error, ResyncMode};
    use bcr_ebill_core::protocol::blockchain::Block;
    use bcr_ebill_core::protocol::blockchain::company::CompanyBlockPayload;
    use bcr_ebill_core::protocol::blockchain::company::block::{
        CompanyCreateBlockData, CompanySignatoryAcceptInviteBlockData,
        CompanySignatoryRejectInviteBlockData,
    };
    use bcr_ebill_core::protocol::event::{CompanyBlockEvent, Event, EventEnvelope};
    use bcr_ebill_core::protocol::file_reference::{FileReference, FileReferenceContext};
    use bcr_ebill_core::protocol::{
        BlockId,
        blockchain::{bill::BillOpCode, company::block::CompanySignCompanyBillBlockData},
    };
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
    use bcr_ebill_core::{application::company::CompanyStatus, protocol::event::ChainInvite};
    use bcr_ebill_persistence::NostrChainEventStoreApi;
    use bcr_ebill_persistence::traits::propagation::{
        ApplicationWaitReason, IncomingChainCandidate, IncomingPropagationStoreApi,
    };
    use bcr_ebill_persistence::traits::transaction::TransactionManagerApi;
    use bcr_ebill_persistence::{
        EncryptionContext,
        sqlite::{SqliteConfig, SqlitePersistence},
        traits::company::{CompanyChainStoreApi, CompanyStoreApi},
    };
    use mockall::predicate::eq;
    use nostr::event::FinalizeEvent;
    use std::sync::Arc;
    use std::time::Duration;
    use url::Url;

    use crate::handler::test_utils::{
        MockBillStore, MockNotificationStore, MockPersistenceTransactionApiMock,
        MockTransactionManagerApiMock, get_valid_activated_signatory, node_id_test_another,
        private_key_test, private_key_test_another, transaction_manager_with,
        update_company_block_with_name,
    };
    use crate::handler::{IncomingChainApplyResult, IncomingChainDependency};
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

    fn incoming_company_candidate(
        event: nostr::event::Event,
        company_id: &NodeId,
        snapshot: &RelayQuorumSnapshot,
    ) -> IncomingChainCandidate {
        IncomingChainCandidate {
            event,
            chain_type: "company".into(),
            chain_id: company_id.to_string(),
            relays: snapshot.relays.clone(),
            required_relays: snapshot.required,
            attempts: 0,
            application_attempts: 0,
        }
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

        let expected_company_id = node_id.clone();
        let mut tx = MockPersistenceTransactionApiMock::new();
        tx.expect_append_company_blocks()
            .withf(move |company_id, expected_latest, blocks| {
                company_id == &expected_company_id && expected_latest.is_none() && blocks.len() == 1
            })
            .returning(|_, _, _| Ok(()))
            .once();

        let expected_company = company.clone();
        tx.expect_insert_company()
            .withf(move |company| {
                company.id == expected_company.id && company.name == expected_company.name
            })
            .returning(|_| Ok(()))
            .once();
        tx.expect_save_company_key_pair()
            .returning(|_, _| Ok(()))
            .once();
        tx.expect_commit().return_once(|| Ok(()));
        let transaction_mgr = transaction_manager_with(tx);

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
            Arc::new(transaction_mgr),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let block = get_company_create_block(node_id.clone(), company.clone(), &keys);

        let result = handler
            .apply_verified_block(&node_id, block, keys.clone())
            .await
            .unwrap();

        assert_eq!(result, IncomingChainApplyResult::Applied);
    }

    #[tokio::test]
    async fn test_invited_company_genesis_is_applied_before_membership() {
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

        let mut recipient = get_baseline_identity().identity;
        recipient.node_id = node_id_test_another();

        assert_ne!(recipient.node_id, company.signatories[0].node_id,);

        identity
            .expect_get()
            .return_once(move || Ok(recipient))
            .once();

        contact_store.expect_get().returning(|_| Ok(None));
        contact_store.expect_insert().returning(|_, _| Ok(()));

        let expected_company_id = node_id.clone();
        let mut tx = MockPersistenceTransactionApiMock::new();
        tx.expect_append_company_blocks()
            .withf(move |company_id, expected_latest, blocks| {
                company_id == &expected_company_id && expected_latest.is_none() && blocks.len() == 1
            })
            .returning(|_, _, _| Ok(()))
            .once();

        let expected_company_id = company.id.clone();

        tx.expect_insert_company()
            .withf(move |persisted| {
                persisted.id == expected_company_id
                    && persisted.status == bcr_ebill_core::application::company::CompanyStatus::None
            })
            .returning(|_| Ok(()))
            .once();

        tx.expect_save_company_key_pair()
            .returning(|_, _| Ok(()))
            .once();
        tx.expect_commit().return_once(|| Ok(()));
        let transaction_mgr = transaction_manager_with(tx);

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
            Arc::new(transaction_mgr),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let block = get_company_create_block(node_id.clone(), company.clone(), &keys);

        let result = handler
            .apply_verified_block(&node_id, block, keys.clone())
            .await
            .unwrap();

        assert_eq!(result, IncomingChainApplyResult::Applied);
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
        let keys_clone = keys.clone();
        store
            .expect_get_key_pair()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(keys_clone.clone()))
            .once();

        // get the current company state
        let expected_company = company.clone();
        store
            .expect_get()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(expected_company.clone()))
            .once();

        // no need to ensure contacts in case of an update
        contact
            .expect_ensure_nostr_contact()
            .with(eq(node_id.clone()))
            .returning(|_| ())
            .never();

        let expected_company_id = node_id.clone();
        let expected_hash = update_block.hash.clone();

        let mut tx = MockPersistenceTransactionApiMock::new();
        tx.expect_append_company_blocks()
            .withf(move |company_id, expected_latest, blocks| {
                company_id == &expected_company_id
                    && expected_latest.is_some()
                    && blocks.len() == 1
                    && blocks[0].hash == expected_hash
            })
            .returning(|_, _, _| Ok(()))
            .once();
        let expected_company_id = node_id.clone();
        tx.expect_update_company()
            .withf(move |company_id, company| {
                company_id == &expected_company_id
                    && company.id == expected_company_id
                    && company.name == Name::new("new_name").unwrap()
            })
            .returning(|_, _| Ok(()))
            .once();
        tx.expect_commit().return_once(|| Ok(()));
        let transaction_mgr = transaction_manager_with(tx);

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
            Arc::new(transaction_mgr),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let result = handler
            .apply_verified_block(&node_id, update_block, keys.clone())
            .await
            .unwrap();

        assert_eq!(result, IncomingChainApplyResult::Applied);
    }

    #[tokio::test]
    async fn test_rejects_missing_blocks_without_resync() {
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

        // checks if we already have the chain
        chain_store
            .expect_get_chain()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(skipped_chain.clone()))
            .times(1);

        // we have a chain so get the keys
        let apply_keys = keys.clone();

        transport.expect_resolve_public_chain().never();

        chain_event_store.expect_remove_chain_events().never();
        chain_event_store.expect_add_chain_event().never();

        contact.expect_ensure_nostr_contact().never();

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
            Arc::new(MockTransactionManagerApiMock::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let outcome = handler
            .apply_verified_block(&node_id, update_block, apply_keys)
            .await
            .unwrap();

        assert_eq!(
            outcome,
            IncomingChainApplyResult::Deferred(IncomingChainDependency::MissingPredecessor,),
        );
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
        let keys_clone = keys.clone();
        store
            .expect_get_key_pair()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(keys_clone.clone()))
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

        let mut tx = MockPersistenceTransactionApiMock::new();
        tx.expect_append_company_blocks()
            .returning(|_, _, _| Ok(()))
            .once();

        tx.expect_update_company().returning(|_, _| Ok(())).once();
        tx.expect_commit().return_once(|| Ok(()));
        let transaction_mgr = transaction_manager_with(tx);

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
            Arc::new(transaction_mgr),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let result = handler
            .apply_verified_block(&node_id, update_block, keys.clone())
            .await
            .unwrap();

        assert_eq!(result, IncomingChainApplyResult::Applied);
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
        let keys_clone = keys.clone();
        store
            .expect_get_key_pair()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(keys_clone.clone()))
            .once();

        // get the current company state
        let expected_company = company.clone();
        store
            .expect_get()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(expected_company.clone()))
            .once();

        let mut tx = MockPersistenceTransactionApiMock::new();
        tx.expect_append_company_blocks()
            .returning(|_, _, _| Ok(()))
            .once();

        tx.expect_update_company().returning(|_, _| Ok(())).once();
        tx.expect_commit().return_once(|| Ok(()));
        let transaction_mgr = transaction_manager_with(tx);

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
            Arc::new(transaction_mgr),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let result = handler
            .apply_verified_block(&node_id, update_block, keys.clone())
            .await
            .unwrap();

        assert_eq!(result, IncomingChainApplyResult::Applied);
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
        let keys_clone = keys.clone();
        store
            .expect_get_key_pair()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(keys_clone.clone()))
            .once();

        // get the current company state
        let expected_company = company.clone();
        store
            .expect_get()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(expected_company.clone()))
            .once();

        let mut tx = MockPersistenceTransactionApiMock::new();
        tx.expect_append_company_blocks()
            .returning(|_, _, _| Ok(()))
            .once();

        tx.expect_update_company().returning(|_, _| Ok(())).once();
        tx.expect_commit().return_once(|| Ok(()));
        let transaction_mgr = transaction_manager_with(tx);

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
            Arc::new(transaction_mgr),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let result = handler
            .apply_verified_block(&node_id, update_block, keys.clone())
            .await
            .unwrap();

        assert_eq!(result, IncomingChainApplyResult::Applied);
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
        let keys_clone = keys.clone();
        store
            .expect_get_key_pair()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(keys_clone.clone()))
            .once();

        let expected_company = company.clone();
        store
            .expect_get()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(expected_company.clone()))
            .once();

        let mut tx = MockPersistenceTransactionApiMock::new();
        tx.expect_append_company_blocks()
            .returning(|_, _, _| Ok(()))
            .once();

        tx.expect_update_company().returning(|_, _| Ok(())).once();
        tx.expect_commit().return_once(|| Ok(()));
        let transaction_mgr = transaction_manager_with(tx);

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
            Arc::new(transaction_mgr),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let result = handler
            .apply_verified_block(&node_id, remove_block, keys.clone())
            .await
            .unwrap();

        assert_eq!(result, IncomingChainApplyResult::Applied);
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

        // checks if we already have the chain
        chain_store
            .expect_get_chain()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(chain.clone()))
            .once();

        // we have a chain so get the keys
        let keys_clone = keys.clone();
        store
            .expect_get_key_pair()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(keys_clone.clone()))
            .once();

        // get the current company state
        let expected_company = company.clone();
        store
            .expect_get()
            .with(eq(node_id.clone()))
            .returning(move |_| Ok(expected_company.clone()))
            .once();

        let mut tx = MockPersistenceTransactionApiMock::new();
        tx.expect_append_company_blocks()
            .returning(|_, _, _| Ok(()))
            .once();
        tx.expect_update_company().returning(|_, _| Ok(())).once();
        tx.expect_set_company_email_confirmation()
            .returning(|_, _, _| Ok(()))
            .once();
        tx.expect_commit().return_once(|| Ok(()));
        let transaction_mgr = transaction_manager_with(tx);

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
            Arc::new(transaction_mgr),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let result = handler
            .apply_verified_block(&node_id, update_block, keys.clone())
            .await
            .unwrap();

        assert_eq!(result, IncomingChainApplyResult::Applied);
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
            Arc::new(MockTransactionManagerApiMock::new()),
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

        let mut tx = MockPersistenceTransactionApiMock::new();
        tx.expect_append_company_blocks()
            .returning(|_, _, _| Ok(()))
            .once();
        tx.expect_update_company().returning(|_, _| Ok(())).once();
        tx.expect_commit().return_once(|| Ok(()));
        let transaction_mgr = transaction_manager_with(tx);

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
            Arc::new(transaction_mgr),
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
            Arc::new(MockTransactionManagerApiMock::new()),
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
            Arc::new(MockTransactionManagerApiMock::new()),
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

        // Create + Proof + valid Update may be persisted
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
        let expected_company_id = company_id.clone();
        let expected_name_for_tx = expected_name.clone();
        let create_hash = create_block.hash.clone();
        let proof_hash = proof_block.hash.clone();
        let valid_update_hash = valid_update.hash.clone();
        let invalid_hash = invalid_update.hash.clone();
        let expected_key_pub = keys.pub_key();
        let mut tx = MockPersistenceTransactionApiMock::new();
        tx.expect_append_company_blocks()
            .withf(move |id, expected_latest, blocks| {
                id == &expected_company_id
                    && expected_latest.is_none()
                    && blocks.len() == 3
                    && blocks[0].hash == create_hash
                    && blocks[1].hash == proof_hash
                    && blocks[2].hash == valid_update_hash
                    && blocks.iter().all(|block| block.hash != invalid_hash)
            })
            .once()
            .returning(|_, _, _| Ok(()));
        let expected_company_id = company_id.clone();
        tx.expect_insert_company()
            .withf(move |company| {
                company.id == expected_company_id && company.name == expected_name_for_tx
            })
            .once()
            .returning(|_| Ok(()));
        let expected_company_id = company_id.clone();
        tx.expect_save_company_key_pair()
            .withf(move |id, keys| id == &expected_company_id && keys.pub_key() == expected_key_pub)
            .once()
            .returning(|_, _| Ok(()));
        tx.expect_set_company_email_confirmation()
            .withf({
                let expected_company_id = company_id.clone();
                move |id, _, _| id == &expected_company_id
            })
            .once()
            .returning(|_, _, _| Ok(()));
        tx.expect_update_company().never();
        tx.expect_commit().once().return_once(|| Ok(()));
        let transaction_mgr = transaction_manager_with(tx);

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
            Arc::new(transaction_mgr),
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
        transport
            .expect_resolve_public_chain()
            .with(eq(company_id.to_string()), eq(BlockchainType::Company))
            .once()
            .returning(move |_, _| Ok(nostr_events.clone()));
        chain_event_store
            .expect_remove_chain_events()
            .once()
            .returning(|_, _| Ok(()));

        let expected_company_id = company_id.clone();
        let expected_tip_hash = local_update.hash.clone();
        let valid_4_hash = valid_block_4.hash.clone();
        let valid_5_hash = valid_block_5.hash.clone();
        let invalid_6_hash = invalid_block_6.hash.clone();

        let mut tx = MockPersistenceTransactionApiMock::new();

        tx.expect_append_company_blocks()
            .withf(move |id, expected_latest, blocks| {
                id == &expected_company_id
                    && expected_latest
                        .as_ref()
                        .is_some_and(|block| block.hash == expected_tip_hash)
                    && blocks.len() == 2
                    && blocks[0].hash == valid_4_hash
                    && blocks[1].hash == valid_5_hash
                    && blocks.iter().all(|block| block.hash != invalid_6_hash)
            })
            .once()
            .returning(|_, _, _| Ok(()));

        let expected_company_id = company_id.clone();
        let expected_name = expected_final_name.clone();
        tx.expect_update_company()
            .withf(move |id, company| id == &expected_company_id && company.name == expected_name)
            .once()
            .returning(|_, _| Ok(()));
        tx.expect_set_company_email_confirmation().never();
        tx.expect_save_company_key_pair().never();
        tx.expect_commit().once().return_once(|| Ok(()));
        let transaction_mgr = transaction_manager_with(tx);

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
            Arc::new(transaction_mgr),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .resync_chain(&company_id, ResyncMode::NostrAuthoritative)
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

        let keys_clone = keys.clone();
        store
            .expect_get_key_pair()
            .once()
            .returning(move |_| Ok(keys_clone.clone()));
        identity_store
            .expect_get()
            .once()
            .returning(|| Ok(get_baseline_identity().identity));
        transport
            .expect_resolve_public_chain()
            .once()
            .returning(move |_, _| Ok(nostr_events.clone()));

        chain_event_store
            .expect_remove_chain_events()
            .once()
            .returning(|_, _| Ok(()));

        let expected_company_id = company_id.clone();
        let expected_tip_hash = proof_block.hash.clone();
        let b3_hash = b3.hash.clone();
        let b4_hash = b4.hash.clone();
        let a3_hash = a3.hash.clone();
        let bad4_hash = bad4.hash.clone();
        let bad5_hash = bad5.hash.clone();

        let mut tx = MockPersistenceTransactionApiMock::new();
        tx.expect_append_company_blocks()
            .withf(move |id, expected_latest, blocks| {
                id == &expected_company_id
                    && expected_latest
                        .as_ref()
                        .is_some_and(|block| block.hash == expected_tip_hash)
                    && blocks.len() == 2
                    && blocks[0].hash == b3_hash
                    && blocks[1].hash == b4_hash
                    && blocks.iter().all(|block| {
                        block.hash != a3_hash && block.hash != bad4_hash && block.hash != bad5_hash
                    })
            })
            .once()
            .returning(|_, _, _| Ok(()));

        let expected_company_id = company_id.clone();
        let expected_name_for_tx = expected_name.clone();
        tx.expect_update_company()
            .withf(move |id, company| {
                id == &expected_company_id && company.name == expected_name_for_tx
            })
            .once()
            .returning(|_, _| Ok(()));
        tx.expect_set_company_email_confirmation().never();
        tx.expect_save_company_key_pair().never();
        tx.expect_commit().once().return_once(|| Ok(()));
        let transaction_mgr = transaction_manager_with(tx);

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
            Arc::new(transaction_mgr),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );
        handler
            .resync_chain(&company_id, ResyncMode::NostrAuthoritative)
            .await
            .expect("the longest protocol-valid prefix must win, not the longest raw Nostr branch");
    }

    #[tokio::test]
    async fn test_processor_normal_resync_is_disabled() {
        let (
            chain_store,
            store,
            notification_store,
            contact,
            bill,
            identity_store,
            event_store,
            mut transport,
            push_service,
            contact_store,
        ) = create_mocks();
        transport.expect_resolve_public_chain().never();
        let handler = CompanyChainEventProcessor::new(
            Arc::new(chain_store),
            Arc::new(store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity_store),
            Arc::new(notification_store),
            Arc::new(contact),
            Arc::new(bill),
            Arc::new(push_service),
            Arc::new(event_store),
            Arc::new(transport),
            Arc::new(contact_store),
            Arc::new(MockTransactionManagerApiMock::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );
        let result = handler
            .resync_chain(&node_id_test(), ResyncMode::Normal)
            .await;
        assert!(matches!(result, Err(Error::Blockchain(_))));
    }

    #[tokio::test]
    async fn company_invite_sqlite_genesis_before_membership() {
        // Integration test using SQLITE
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("company-invite.sqlite");
        let db = SqlitePersistence::open(SqliteConfig::new(db_path.clone()))
            .await
            .unwrap();
        let encryption = Arc::new(EncryptionContext::new(BcrKeys::new()));
        let company_store = Arc::new(db.company_store(encryption.clone()));
        let chain_store = Arc::new(db.company_chain_store());
        let incoming_store = Arc::new(db.incoming_propagation_store(encryption.clone()));
        let (company_id, (company, keys)) = get_company_data();
        let recipient_id = node_id_test_another();
        assert_ne!(recipient_id, company.signatories[0].node_id,);

        // The local identity is the invited participant, not the company creator
        let mut recipient = get_baseline_identity().identity;
        recipient.node_id = recipient_id.clone();
        let mut identity_store = MockIdentityStore::new();
        identity_store
            .expect_get()
            .times(3)
            .returning(move || Ok(recipient.clone()));
        let mut transport = MockNotificationJsonTransport::new();
        let expected_company_id = company_id.clone();
        let expected_company_pubkey = keys.pub_key();
        transport
            .expect_add_identity()
            .times(2)
            .withf(move |id, added_keys| {
                id == &expected_company_id && added_keys.pub_key() == expected_company_pubkey
            })
            .returning(|_, _| Ok(()));
        transport.expect_resolve_public_chain().never();
        let transport = Arc::new(transport);
        let mut nostr_contacts = MockNostrContactProcessorApi::new();
        nostr_contacts
            .expect_ensure_nostr_contact()
            .returning(|_| ());
        let mut contacts = MockContactStore::new();
        contacts.expect_get().once().returning(|_| Ok(None));
        contacts.expect_insert().once().returning(|_, _| Ok(()));
        let mut notifications = MockNotificationStore::new();
        notifications
            .expect_get_latest_by_reference_and_node_id()
            .once()
            .returning(|_, _, _| Ok(None));
        notifications
            .expect_add()
            .withf(|n| {
                n.notification_type
                    == bcr_ebill_core::application::notification::NotificationType::Company
            })
            .returning(Ok)
            .once();
        let mut push = MockPushApi::new();
        push.expect_send().once().returning(|_| ());
        let processor = Arc::new(CompanyChainEventProcessor::new(
            chain_store.clone(),
            company_store.clone(),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity_store),
            Arc::new(notifications),
            Arc::new(nostr_contacts),
            Arc::new(MockNotificationHandlerApi::new()),
            Arc::new(push),
            Arc::new(MockNostrChainEventStore::new()),
            transport.clone(),
            Arc::new(contacts),
            Arc::new(db.transaction_mgr(encryption.clone())),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        ));

        // 1. Process private company invitation
        let (hint_tx, mut hint_rx) = tokio::sync::broadcast::channel(8);
        let invite_handler =
            CompanyInviteEventHandler::new(transport, processor.clone(), incoming_store)
                .with_catchup_hints(hint_tx);
        let envelope: EventEnvelope =
            Event::new_company_invite(ChainInvite::company(company_id.to_string(), keys.clone()))
                .try_into()
                .unwrap();
        invite_handler
            .handle_event(envelope, &recipient_id, None, None)
            .await
            .unwrap();

        // The company keys are persisted before the company blockchain has been initialized
        let persisted_keys = company_store.get_key_pair(&company_id).await.unwrap();
        assert_eq!(persisted_keys.pub_key(), keys.pub_key());
        assert!(matches!(
            chain_store.get_chain(&company_id).await,
            Err(bcr_ebill_persistence::Error::NoSuchEntity(_, _))
        ));
        // The invitation requests immediate public chain catch-up
        let hint = hint_rx.try_recv().unwrap();
        assert_eq!(hint.chain_type, BlockchainType::Company);
        assert_eq!(hint.chain_id, company_id.to_string());

        // 2. Build the protocol-valid company history
        // Create -> Creator Identity Proof -> Invite Signatory
        let genesis = get_company_create_block(company_id.clone(), company, &keys);
        let chain = CompanyBlockchain::new_from_blocks(vec![genesis]).unwrap();
        let chain = add_creator_identity_proof_block(chain);
        let chain = add_invite_signatory_block(chain);
        let blocks = chain.blocks().clone();
        assert_eq!(blocks.len(), 3);

        // 3. invitation block cannot apply before genesis
        assert_eq!(
            processor
                .apply_verified_block(&company_id, blocks[2].clone(), keys.clone(),)
                .await
                .unwrap(),
            IncomingChainApplyResult::Deferred(IncomingChainDependency::ChainNotInitialized,),
        );

        // 4. Genesis is allowed even though the local user is not a company signatory yet
        assert_eq!(
            processor
                .apply_verified_block(&company_id, blocks[0].clone(), keys.clone(),)
                .await
                .unwrap(),
            IncomingChainApplyResult::Applied,
        );
        assert_eq!(
            company_store.get(&company_id).await.unwrap().status,
            CompanyStatus::None,
        );
        assert_eq!(
            chain_store
                .get_chain(&company_id)
                .await
                .unwrap()
                .blocks()
                .len(),
            1,
        );
        // 5. Apply the creator identity proof
        assert_eq!(
            processor
                .apply_verified_block(&company_id, blocks[1].clone(), keys.clone(),)
                .await
                .unwrap(),
            IncomingChainApplyResult::Applied,
        );

        assert_eq!(
            company_store.get(&company_id).await.unwrap().status,
            CompanyStatus::None,
        );

        // 6. Only the later InviteSignatory block changes the local status to Invited
        assert_eq!(
            processor
                .apply_verified_block(&company_id, blocks[2].clone(), keys.clone(),)
                .await
                .unwrap(),
            IncomingChainApplyResult::Applied,
        );
        assert_eq!(
            company_store.get(&company_id).await.unwrap().status,
            CompanyStatus::Invited,
        );
        assert_eq!(
            chain_store
                .get_chain(&company_id)
                .await
                .unwrap()
                .blocks()
                .len(),
            3,
        );

        // 7. Replaying the same blocks does not apply them again
        for block in &blocks {
            assert_eq!(
                processor
                    .apply_verified_block(&company_id, block.clone(), keys.clone(),)
                    .await
                    .unwrap(),
                IncomingChainApplyResult::AlreadyApplied,
            );
        }

        // 8. Simulate reinitialization with a new SQLite pool - state must survive the process boundary
        let reopened = SqlitePersistence::open(SqliteConfig::new(db_path))
            .await
            .unwrap();
        let reopened_company_store = reopened.company_store(encryption);
        assert_eq!(
            reopened_company_store
                .get(&company_id)
                .await
                .unwrap()
                .status,
            CompanyStatus::Invited,
        );
        assert_eq!(
            reopened
                .company_chain_store()
                .get_chain(&company_id)
                .await
                .unwrap()
                .blocks()
                .len(),
            3,
        );
    }

    #[tokio::test]
    async fn company_invite_sqlite_verified_out_of_order_recovery() {
        // Integration test using real SQLITE
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("company-invite.sqlite");
        let db = SqlitePersistence::open(SqliteConfig::new(db_path.clone()))
            .await
            .unwrap();
        let encryption = Arc::new(EncryptionContext::new(BcrKeys::new()));
        let company_store = Arc::new(db.company_store(encryption.clone()));
        let chain_store = Arc::new(db.company_chain_store());
        let incoming_store = Arc::new(db.incoming_propagation_store(encryption.clone()));
        let (company_id, (company, keys)) = get_company_data();
        let recipient_id = node_id_test_another();
        let chain_event_store = Arc::new(db.nostr_chain_event_store());
        assert_ne!(recipient_id, company.signatories[0].node_id,);

        // The local identity is the invited participant, not the company creator
        let mut recipient = get_baseline_identity().identity;
        recipient.node_id = recipient_id.clone();
        let mut identity_store = MockIdentityStore::new();
        identity_store
            .expect_get()
            .times(3)
            .returning(move || Ok(recipient.clone()));
        let mut transport = MockNotificationJsonTransport::new();
        let expected_company_id = company_id.clone();
        let expected_company_pubkey = keys.pub_key();
        transport
            .expect_add_identity()
            .times(2)
            .withf(move |id, added_keys| {
                id == &expected_company_id && added_keys.pub_key() == expected_company_pubkey
            })
            .returning(|_, _| Ok(()));
        transport
            .expect_event_available_on_relay()
            .times(9)
            .returning(|_, relay| match relay.host_str() {
                Some("r1.example" | "r2.example") => Ok(true),
                Some("r3.example") => Ok(false),
                other => panic!("Unexpected relay: {other:?}"),
            });
        transport
            .expect_has_connected_read_relay()
            .returning(|| true);
        transport
            .expect_fetch_event_from_relay()
            .returning(|_, _| Ok(None));
        transport.expect_resolve_public_chain().never();
        let transport = Arc::new(transport);
        let mut nostr_contacts = MockNostrContactProcessorApi::new();
        nostr_contacts
            .expect_ensure_nostr_contact()
            .returning(|_| ());
        let mut contacts = MockContactStore::new();
        contacts.expect_get().once().returning(|_| Ok(None));
        contacts.expect_insert().once().returning(|_, _| Ok(()));
        let mut notifications = MockNotificationStore::new();
        notifications
            .expect_get_latest_by_reference_and_node_id()
            .once()
            .returning(|_, _, _| Ok(None));
        notifications
            .expect_add()
            .withf(|n| {
                n.notification_type
                    == bcr_ebill_core::application::notification::NotificationType::Company
            })
            .returning(Ok)
            .once();
        let mut push = MockPushApi::new();
        push.expect_send().once().returning(|_| ());
        let processor = Arc::new(CompanyChainEventProcessor::new(
            chain_store.clone(),
            company_store.clone(),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity_store),
            Arc::new(notifications),
            Arc::new(nostr_contacts),
            Arc::new(MockNotificationHandlerApi::new()),
            Arc::new(push),
            chain_event_store.clone(),
            transport.clone(),
            Arc::new(contacts),
            Arc::new(db.transaction_mgr(encryption.clone())),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        ));

        let (hint_tx, mut hint_rx) = tokio::sync::broadcast::channel(8);
        let invite_handler = CompanyInviteEventHandler::new(
            transport.clone(),
            processor.clone(),
            incoming_store.clone(),
        )
        .with_catchup_hints(hint_tx);
        let envelope: EventEnvelope =
            Event::new_company_invite(ChainInvite::company(company_id.to_string(), keys.clone()))
                .try_into()
                .unwrap();
        invite_handler
            .handle_event(envelope, &recipient_id, None, None)
            .await
            .unwrap();

        // The company keys are persisted before the company blockchain has been initialized
        let persisted_keys = company_store.get_key_pair(&company_id).await.unwrap();
        assert_eq!(persisted_keys.pub_key(), keys.pub_key());
        assert!(matches!(
            chain_store.get_chain(&company_id).await,
            Err(bcr_ebill_persistence::Error::NoSuchEntity(_, _))
        ));
        let chain_keys = Arc::new(ChainKeyService::new(
            Arc::new(MockBillStore::new()),
            company_store.clone(),
            Arc::new(MockIdentityStore::new()),
            bitcoin::Network::Testnet,
        ));

        let application = Arc::new(IncomingChainApplication::new(
            chain_keys,
            Arc::new(MockBillChainEventProcessorApi::new()),
            processor.clone(),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            chain_event_store.clone(),
        ));

        let verifier = IncomingPropagationVerifier::new(
            incoming_store.clone(),
            transport.clone(),
            application,
        );

        let snapshot = RelayQuorumSnapshot {
            relays: vec![
                Url::parse("wss://r1.example").unwrap(),
                Url::parse("wss://r2.example").unwrap(),
                Url::parse("wss://r3.example").unwrap(),
            ],
            required: 2,
        };

        // The invitation requests immediate public chain catch-up
        let hint = hint_rx.try_recv().unwrap();
        assert_eq!(hint.chain_type, BlockchainType::Company);
        assert_eq!(hint.chain_id, company_id.to_string());

        // 2. Build the protocol-valid company history
        // Create -> Creator Identity Proof -> Invite Signatory
        let genesis = get_company_create_block(company_id.clone(), company, &keys);
        let chain = CompanyBlockchain::new_from_blocks(vec![genesis]).unwrap();
        let chain = add_creator_identity_proof_block(chain);
        let chain = add_invite_signatory_block(chain);
        let blocks = chain.blocks().clone();
        assert_eq!(blocks.len(), 3);

        let genesis_event = generate_test_event(
            &keys,
            None,
            None,
            as_event_payload(&company_id, &blocks[0]),
            &company_id,
        );

        let proof_event = generate_test_event(
            &keys,
            Some(genesis_event.clone()),
            Some(genesis_event.clone()),
            as_event_payload(&company_id, &blocks[1]),
            &company_id,
        );

        let invite_event = generate_test_event(
            &keys,
            Some(proof_event.clone()),
            Some(genesis_event.clone()),
            as_event_payload(&company_id, &blocks[2]),
            &company_id,
        );

        let genesis = incoming_company_candidate(genesis_event.clone(), &company_id, &snapshot);
        let proof = incoming_company_candidate(proof_event.clone(), &company_id, &snapshot);
        let invite = incoming_company_candidate(invite_event.clone(), &company_id, &snapshot);

        // deliver invite block without predecessors
        incoming_store
            .upsert_candidate(&invite, Timestamp::zero())
            .await
            .unwrap();
        assert_eq!(verifier.verify_due_once().await.unwrap(), 1,);
        assert_eq!(verifier.apply_due_once().await.unwrap(), 1,);

        // verified but not applied
        assert!(
            chain_store.get_chain(&company_id).await.is_err(),
            "Invitation must not create the company before genesis",
        );
        let waiting = incoming_store
            .get_verified_candidates(Timestamp::now() + Duration::from_secs(61), 10)
            .await
            .unwrap();
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].event.id, invite_event.id);

        // deliver genesis and proof
        for candidate in [&genesis, &proof] {
            incoming_store
                .upsert_candidate(candidate, Timestamp::zero())
                .await
                .unwrap();
        }
        assert_eq!(verifier.verify_due_once().await.unwrap(), 2,);

        // run application passes
        for _ in 0..3 {
            verifier.apply_due_once().await.unwrap();
        }
        assert_eq!(
            company_store.get(&company_id).await.unwrap().status,
            CompanyStatus::Invited,
        );

        // final state - company is created, we're invited
        let persisted_chain = chain_store.get_chain(&company_id).await.unwrap();
        assert_eq!(persisted_chain.blocks().len(), 3);
        for (stored, expected) in persisted_chain.blocks().iter().zip(blocks.iter()) {
            assert_eq!(stored.hash(), expected.hash());
        }

        // chain events were persisted
        let chain_events = chain_event_store
            .find_chain_events(&company_id.to_string(), BlockchainType::Company)
            .await
            .unwrap();
        assert_eq!(chain_events.len(), 3);

        // duplicate delivery does nothing
        for candidate in [&genesis, &proof, &invite] {
            incoming_store
                .upsert_candidate(candidate, Timestamp::zero())
                .await
                .unwrap();
        }
        assert_eq!(verifier.verify_due_once().await.unwrap(), 0);
        assert_eq!(verifier.apply_due_once().await.unwrap(), 0);
        // no outstanding work in the queues
        assert!(
            incoming_store
                .get_due_candidates(Timestamp::now() + Duration::from_secs(600), 10,)
                .await
                .unwrap()
                .is_empty(),
        );
        assert!(
            incoming_store
                .get_verified_candidates(Timestamp::now() + Duration::from_secs(600), 10,)
                .await
                .unwrap()
                .is_empty(),
        );

        // re-init DB, state was durable
        let reopened = SqlitePersistence::open(SqliteConfig::new(db_path))
            .await
            .unwrap();
        assert_eq!(
            reopened
                .company_store(encryption.clone())
                .get(&company_id)
                .await
                .unwrap()
                .status,
            CompanyStatus::Invited,
        );
        assert_eq!(
            reopened
                .company_chain_store()
                .get_chain(&company_id)
                .await
                .unwrap()
                .blocks()
                .len(),
            3,
        );
    }

    #[tokio::test]
    async fn company_invite_wakes_sqlite_candidates_waiting_for_keys() {
        // Integration test using real SQLITE
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("company-invite.sqlite");
        let db = SqlitePersistence::open(SqliteConfig::new(db_path.clone()))
            .await
            .unwrap();
        let encryption = Arc::new(EncryptionContext::new(BcrKeys::new()));
        let company_store = Arc::new(db.company_store(encryption.clone()));
        let chain_store = Arc::new(db.company_chain_store());
        let incoming_store = Arc::new(db.incoming_propagation_store(encryption.clone()));
        let (company_id, (company, keys)) = get_company_data();
        let recipient_id = node_id_test_another();
        let chain_event_store = Arc::new(db.nostr_chain_event_store());
        assert_ne!(recipient_id, company.signatories[0].node_id,);

        // The local identity is the invited participant, not the company creator
        let mut recipient = get_baseline_identity().identity;
        recipient.node_id = recipient_id.clone();
        let mut identity_store = MockIdentityStore::new();
        identity_store
            .expect_get()
            .times(3)
            .returning(move || Ok(recipient.clone()));
        let mut transport = MockNotificationJsonTransport::new();
        let expected_company_id = company_id.clone();
        let expected_company_pubkey = keys.pub_key();
        transport
            .expect_add_identity()
            .times(2)
            .withf(move |id, added_keys| {
                id == &expected_company_id && added_keys.pub_key() == expected_company_pubkey
            })
            .returning(|_, _| Ok(()));
        transport
            .expect_event_available_on_relay()
            .times(9)
            .returning(|_, relay| match relay.host_str() {
                Some("r1.example" | "r2.example") => Ok(true),
                Some("r3.example") => Ok(false),
                other => panic!("Unexpected relay: {other:?}"),
            });
        transport
            .expect_has_connected_read_relay()
            .returning(|| true);
        transport
            .expect_fetch_event_from_relay()
            .returning(|_, _| Ok(None));
        transport.expect_resolve_public_chain().never();
        let transport = Arc::new(transport);
        let mut nostr_contacts = MockNostrContactProcessorApi::new();
        nostr_contacts
            .expect_ensure_nostr_contact()
            .returning(|_| ());
        let mut contacts = MockContactStore::new();
        contacts.expect_get().once().returning(|_| Ok(None));
        contacts.expect_insert().once().returning(|_, _| Ok(()));
        let mut notifications = MockNotificationStore::new();
        notifications
            .expect_get_latest_by_reference_and_node_id()
            .once()
            .returning(|_, _, _| Ok(None));
        notifications
            .expect_add()
            .withf(|n| {
                n.notification_type
                    == bcr_ebill_core::application::notification::NotificationType::Company
            })
            .returning(Ok)
            .once();
        let mut push = MockPushApi::new();
        push.expect_send().once().returning(|_| ());
        let processor = Arc::new(CompanyChainEventProcessor::new(
            chain_store.clone(),
            company_store.clone(),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity_store),
            Arc::new(notifications),
            Arc::new(nostr_contacts),
            Arc::new(MockNotificationHandlerApi::new()),
            Arc::new(push),
            chain_event_store.clone(),
            transport.clone(),
            Arc::new(contacts),
            Arc::new(db.transaction_mgr(encryption.clone())),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        ));

        let (hint_tx, mut hint_rx) = tokio::sync::broadcast::channel(8);
        let invite_handler = CompanyInviteEventHandler::new(
            transport.clone(),
            processor.clone(),
            incoming_store.clone(),
        )
        .with_catchup_hints(hint_tx);
        assert!(matches!(
            company_store.get_key_pair(&company_id).await,
            Err(bcr_ebill_persistence::Error::NoSuchEntity(_, _))
        ));

        assert!(matches!(
            chain_store.get_chain(&company_id).await,
            Err(bcr_ebill_persistence::Error::NoSuchEntity(_, _))
        ));
        let envelope: EventEnvelope =
            Event::new_company_invite(ChainInvite::company(company_id.to_string(), keys.clone()))
                .try_into()
                .unwrap();

        let chain_keys = Arc::new(ChainKeyService::new(
            Arc::new(MockBillStore::new()),
            company_store.clone(),
            Arc::new(MockIdentityStore::new()),
            bitcoin::Network::Testnet,
        ));

        let application = Arc::new(IncomingChainApplication::new(
            chain_keys,
            Arc::new(MockBillChainEventProcessorApi::new()),
            processor.clone(),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            chain_event_store.clone(),
        ));

        let verifier = IncomingPropagationVerifier::new(
            incoming_store.clone(),
            transport.clone(),
            application,
        );

        let snapshot = RelayQuorumSnapshot {
            relays: vec![
                Url::parse("wss://r1.example").unwrap(),
                Url::parse("wss://r2.example").unwrap(),
                Url::parse("wss://r3.example").unwrap(),
            ],
            required: 2,
        };

        // 2. Build the protocol-valid company history
        // Create -> Creator Identity Proof -> Invite Signatory
        let genesis = get_company_create_block(company_id.clone(), company, &keys);
        let chain = CompanyBlockchain::new_from_blocks(vec![genesis]).unwrap();
        let chain = add_creator_identity_proof_block(chain);
        let chain = add_invite_signatory_block(chain);
        let blocks = chain.blocks().clone();
        assert_eq!(blocks.len(), 3);

        let genesis_event = generate_test_event(
            &keys,
            None,
            None,
            as_event_payload(&company_id, &blocks[0]),
            &company_id,
        );

        let proof_event = generate_test_event(
            &keys,
            Some(genesis_event.clone()),
            Some(genesis_event.clone()),
            as_event_payload(&company_id, &blocks[1]),
            &company_id,
        );

        let invite_event = generate_test_event(
            &keys,
            Some(proof_event.clone()),
            Some(genesis_event.clone()),
            as_event_payload(&company_id, &blocks[2]),
            &company_id,
        );

        let genesis = incoming_company_candidate(genesis_event.clone(), &company_id, &snapshot);
        let proof = incoming_company_candidate(proof_event.clone(), &company_id, &snapshot);
        let invite = incoming_company_candidate(invite_event.clone(), &company_id, &snapshot);

        // 1. The public company history arrives before its private invite
        // All three candidates are queued
        for candidate in [&genesis, &proof, &invite] {
            incoming_store
                .upsert_candidate(candidate, Timestamp::zero())
                .await
                .unwrap();
        }

        // 2. All three events pass 2-of-3 relay quorum
        assert_eq!(verifier.verify_due_once().await.unwrap(), 3);
        // 3. None can apply without the company keys
        assert_eq!(verifier.apply_due_once().await.unwrap(), 3);
        assert!(
            chain_store.get_chain(&company_id).await.is_err(),
            "Verified blocks must not initialize a company without keys",
        );
        // No block metadata should be written either
        assert!(
            chain_event_store
                .find_chain_events(&company_id.to_string(), BlockchainType::Company,)
                .await
                .unwrap()
                .is_empty(),
        );

        // Candidates remain verified and durable, scheduled for a missing-keys retry rather than being rejected
        let waiting = incoming_store
            .get_verified_candidates(Timestamp::now() + Duration::from_secs(301), 10)
            .await
            .unwrap();
        assert_eq!(waiting.len(), 3);
        for event in [&genesis_event, &proof_event, &invite_event] {
            assert!(
                waiting
                    .iter()
                    .any(|candidate| candidate.event.id == event.id),
                "Candidate {} must remain queued while keys are missing",
                event.id,
            );
        }

        // 4. Now the private company invitation arrives
        // This persists the company keys and wakes all verified candidates waiting for them
        invite_handler
            .handle_event(envelope, &recipient_id, None, None)
            .await
            .unwrap();

        let persisted_keys = company_store.get_key_pair(&company_id).await.unwrap();
        assert_eq!(persisted_keys.pub_key(), keys.pub_key());
        // Confirm the immediate public catch-up hint was emitted
        let hint = hint_rx.try_recv().unwrap();
        assert_eq!(hint.chain_type, BlockchainType::Company);
        assert_eq!(hint.chain_id, company_id.to_string());
        // 5. All three candidates should now be due immediately
        let ready = incoming_store
            .get_verified_candidates(Timestamp::now(), 10)
            .await
            .unwrap();
        assert_eq!(
            ready.len(),
            3,
            "Company invite must wake every missing-keys candidate",
        );

        // These events are already verified. We dont repeat relay availability checks after receiving the keys
        assert_eq!(verifier.verify_due_once().await.unwrap(), 0);

        // 6. Apply in the normal verifier loop
        // If blocks arrive out of order, predecessor application wakes the dependent blocks
        for _ in 0..3 {
            verifier.apply_due_once().await.unwrap();
        }

        // 7. The complete company chain is now initialized and our local identity has been invited
        assert_eq!(
            company_store.get(&company_id).await.unwrap().status,
            CompanyStatus::Invited,
        );
        let stored_chain = chain_store.get_chain(&company_id).await.unwrap();
        assert_eq!(stored_chain.blocks().len(), 3);
        for (actual, expected) in stored_chain.blocks().iter().zip(blocks.iter()) {
            assert_eq!(actual.hash(), expected.hash());
        }
        // Metadata is also persisted through IncomingChainApplication
        let chain_events = chain_event_store
            .find_chain_events(&company_id.to_string(), BlockchainType::Company)
            .await
            .unwrap();
        assert_eq!(chain_events.len(), 3);

        // 8. No verified work remains
        assert!(
            incoming_store
                .get_due_candidates(Timestamp::now() + Duration::from_secs(600), 10,)
                .await
                .unwrap()
                .is_empty(),
        );
        assert!(
            incoming_store
                .get_verified_candidates(Timestamp::now() + Duration::from_secs(600), 10,)
                .await
                .unwrap()
                .is_empty(),
        );
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ForkChoiceCase {
        LateFork,
        BothVerified,
        ForegroundIngestion,
        ForegroundMissingQuorum,
    }

    #[tokio::test]
    async fn company_verified_competing_forks_never_replace_sqlite_chain() {
        company_fork_choice_case(ForkChoiceCase::LateFork).await;
    }

    #[tokio::test]
    async fn company_best_verified_fork_wins_before_commit() {
        company_fork_choice_case(ForkChoiceCase::BothVerified).await;
    }

    #[tokio::test]
    async fn company_foreground_ingestion_selects_best_verified_fork() {
        company_fork_choice_case(ForkChoiceCase::ForegroundIngestion).await;
    }

    #[tokio::test]
    async fn company_foreground_ingestion_ignores_nonquorum_tail() {
        company_fork_choice_case(ForkChoiceCase::ForegroundMissingQuorum).await;
    }

    async fn company_fork_choice_case(case: ForkChoiceCase) {
        // Integration test using real SQLITE
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("company-invite.sqlite");
        let db = SqlitePersistence::open(SqliteConfig::new(db_path.clone()))
            .await
            .unwrap();
        let encryption = Arc::new(EncryptionContext::new(BcrKeys::new()));
        let company_store = Arc::new(db.company_store(encryption.clone()));
        let chain_store = Arc::new(db.company_chain_store());
        let incoming_store = Arc::new(db.incoming_propagation_store(encryption.clone()));
        let (company_id, (company, keys)) = get_company_data();
        let recipient_id = node_id_test_another();
        let chain_event_store = Arc::new(db.nostr_chain_event_store());
        assert_ne!(recipient_id, company.signatories[0].node_id,);

        // The local identity is the invited participant, not the company creator
        let mut recipient = get_baseline_identity().identity;
        recipient.node_id = recipient_id.clone();
        let mut identity_store = MockIdentityStore::new();
        identity_store
            .expect_get()
            .returning(move || Ok(recipient.clone()));

        let unavailable_on_second_relay =
            Arc::new(std::sync::Mutex::new(Vec::<nostr::event::EventId>::new()));
        let unavailable = unavailable_on_second_relay.clone();

        let mut transport = MockNotificationJsonTransport::new();
        let expected_company_id = company_id.clone();
        let expected_company_pubkey = keys.pub_key();
        transport
            .expect_add_identity()
            .times(2)
            .withf(move |id, added_keys| {
                id == &expected_company_id && added_keys.pub_key() == expected_company_pubkey
            })
            .returning(|_, _| Ok(()));
        transport
            .expect_event_available_on_relay()
            .times(18)
            .returning(move |id, relay| match relay.host_str() {
                Some("r1.example") => Ok(true),
                Some("r2.example") => Ok(!unavailable.lock().unwrap().contains(&id)),
                Some("r3.example") => Ok(false),
                other => panic!("Unexpected relay: {other:?}"),
            });

        transport
            .expect_has_connected_read_relay()
            .returning(|| true);
        transport
            .expect_fetch_event_from_relay()
            .returning(|_, _| Ok(None));
        transport.expect_resolve_public_chain().never();
        let transport = Arc::new(transport);
        let mut nostr_contacts = MockNostrContactProcessorApi::new();
        nostr_contacts
            .expect_ensure_nostr_contact()
            .returning(|_| ());
        let mut contacts = MockContactStore::new();
        contacts.expect_get().once().returning(|_| Ok(None));
        contacts.expect_insert().once().returning(|_, _| Ok(()));
        let mut notifications = MockNotificationStore::new();
        notifications
            .expect_get_latest_by_reference_and_node_id()
            .once()
            .returning(|_, _, _| Ok(None));
        notifications
            .expect_add()
            .withf(|n| {
                n.notification_type
                    == bcr_ebill_core::application::notification::NotificationType::Company
            })
            .returning(Ok)
            .once();
        let mut push = MockPushApi::new();
        push.expect_send().once().returning(|_| ());
        let processor = Arc::new(CompanyChainEventProcessor::new(
            chain_store.clone(),
            company_store.clone(),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(identity_store),
            Arc::new(notifications),
            Arc::new(nostr_contacts),
            Arc::new(MockNotificationHandlerApi::new()),
            Arc::new(push),
            chain_event_store.clone(),
            transport.clone(),
            Arc::new(contacts),
            Arc::new(db.transaction_mgr(encryption.clone())),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        ));

        let (hint_tx, mut hint_rx) = tokio::sync::broadcast::channel(8);
        let invite_handler = CompanyInviteEventHandler::new(
            transport.clone(),
            processor.clone(),
            incoming_store.clone(),
        )
        .with_catchup_hints(hint_tx);
        let envelope: EventEnvelope =
            Event::new_company_invite(ChainInvite::company(company_id.to_string(), keys.clone()))
                .try_into()
                .unwrap();
        invite_handler
            .handle_event(envelope, &recipient_id, None, None)
            .await
            .unwrap();

        // The company keys are persisted before the company blockchain has been initialized
        let persisted_keys = company_store.get_key_pair(&company_id).await.unwrap();
        assert_eq!(persisted_keys.pub_key(), keys.pub_key());
        assert!(matches!(
            chain_store.get_chain(&company_id).await,
            Err(bcr_ebill_persistence::Error::NoSuchEntity(_, _))
        ));
        let chain_keys = Arc::new(ChainKeyService::new(
            Arc::new(MockBillStore::new()),
            company_store.clone(),
            Arc::new(MockIdentityStore::new()),
            bitcoin::Network::Testnet,
        ));

        let application = Arc::new(IncomingChainApplication::new(
            chain_keys,
            Arc::new(MockBillChainEventProcessorApi::new()),
            processor.clone(),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            chain_event_store.clone(),
        ));

        let verifier = IncomingPropagationVerifier::new(
            incoming_store.clone(),
            transport.clone(),
            application,
        );

        let snapshot = RelayQuorumSnapshot {
            relays: vec![
                Url::parse("wss://r1.example").unwrap(),
                Url::parse("wss://r2.example").unwrap(),
                Url::parse("wss://r3.example").unwrap(),
            ],
            required: 2,
        };

        // The invitation requests immediate public chain catch-up
        let hint = hint_rx.try_recv().unwrap();
        assert_eq!(hint.chain_type, BlockchainType::Company);
        assert_eq!(hint.chain_id, company_id.to_string());

        // 2. Build the protocol-valid company history
        // Create -> Creator Identity Proof -> Invite Signatory
        let genesis = get_company_create_block(company_id.clone(), company, &keys);
        let chain = CompanyBlockchain::new_from_blocks(vec![genesis]).unwrap();
        let chain = add_creator_identity_proof_block(chain);
        let chain = add_invite_signatory_block(chain);
        let blocks = chain.blocks().clone();
        assert_eq!(blocks.len(), 3);

        let genesis_event = generate_test_event(
            &keys,
            None,
            None,
            as_event_payload(&company_id, &blocks[0]),
            &company_id,
        );

        let proof_event = generate_test_event(
            &keys,
            Some(genesis_event.clone()),
            Some(genesis_event.clone()),
            as_event_payload(&company_id, &blocks[1]),
            &company_id,
        );

        let invite_event = generate_test_event(
            &keys,
            Some(proof_event.clone()),
            Some(genesis_event.clone()),
            as_event_payload(&company_id, &blocks[2]),
            &company_id,
        );

        let genesis = incoming_company_candidate(genesis_event.clone(), &company_id, &snapshot);
        let proof = incoming_company_candidate(proof_event.clone(), &company_id, &snapshot);
        let invite = incoming_company_candidate(invite_event.clone(), &company_id, &snapshot);

        // deliver invite block without predecessors
        if matches!(
            case,
            ForkChoiceCase::LateFork | ForkChoiceCase::BothVerified
        ) {
            incoming_store
                .upsert_candidate(&invite, Timestamp::zero())
                .await
                .unwrap();
            assert_eq!(verifier.verify_due_once().await.unwrap(), 1,);
            assert_eq!(verifier.apply_due_once().await.unwrap(), 1,);

            // verified but not applied
            assert!(
                chain_store.get_chain(&company_id).await.is_err(),
                "Invitation must not create the company before genesis",
            );
            let waiting = incoming_store
                .get_verified_candidates(Timestamp::now() + Duration::from_secs(61), 10)
                .await
                .unwrap();
            assert_eq!(waiting.len(), 1);
            assert_eq!(waiting[0].event.id, invite_event.id);

            // deliver genesis and proof
            for candidate in [&genesis, &proof] {
                incoming_store
                    .upsert_candidate(candidate, Timestamp::zero())
                    .await
                    .unwrap();
            }
            assert_eq!(verifier.verify_due_once().await.unwrap(), 2,);

            // run application passes
            for _ in 0..3 {
                verifier.apply_due_once().await.unwrap();
            }
            assert_eq!(
                company_store.get(&company_id).await.unwrap().status,
                CompanyStatus::Invited,
            );

            // final state - company is created, we're invited
            let persisted_chain = chain_store.get_chain(&company_id).await.unwrap();
            assert_eq!(persisted_chain.blocks().len(), 3);
            for (stored, expected) in persisted_chain.blocks().iter().zip(blocks.iter()) {
                assert_eq!(stored.hash(), expected.hash());
            }
        }
        // Common history: Create -> Proof -> Invite (height 3)
        let previous = &blocks[2];
        let creator_keys = BcrKeys::from_private_key(&private_key_test());
        // Branch A: the block we want to keep
        let a4_data = update_company_block_with_name(Some(Name::new("Accepted branch").unwrap()));
        let a4 =
            get_company_update_block(company_id.clone(), previous, &creator_keys, &keys, &a4_data);
        // Branch B: a different, independently valid block at height 4
        let b4_data =
            update_company_block_with_name(Some(Name::new("Alternative branch").unwrap()));
        let b4 =
            get_company_update_block(company_id.clone(), previous, &creator_keys, &keys, &b4_data);
        let (a4, b4) =
            if compare_block_chains(std::slice::from_ref(&a4), std::slice::from_ref(&b4)).is_gt() {
                (b4, a4)
            } else {
                (a4, b4)
            };
        // Extend branch B, making it longer than branch A
        let b5_data =
            update_company_block_with_name(Some(Name::new("Alternative extension").unwrap()));
        let b5 = get_company_update_block(company_id.clone(), &b4, &creator_keys, &keys, &b5_data);
        assert_ne!(a4.hash(), b4.hash());
        // Both alternatives are structurally valid independent chains
        let mut branch_a = chain.clone();
        assert!(branch_a.try_add_block(a4.clone()));
        assert!(branch_a.is_chain_valid());
        let mut branch_b = chain.clone();
        assert!(branch_b.try_add_block(b4.clone()));
        assert!(branch_b.try_add_block(b5.clone()));
        assert!(branch_b.is_chain_valid());

        let a4_event = generate_test_event(
            &keys,
            Some(invite_event.clone()),
            Some(genesis_event.clone()),
            as_event_payload(&company_id, &a4),
            &company_id,
        );
        let b4_event = generate_test_event(
            &keys,
            Some(invite_event.clone()),
            Some(genesis_event.clone()),
            as_event_payload(&company_id, &b4),
            &company_id,
        );
        let b5_event = generate_test_event(
            &keys,
            Some(b4_event.clone()),
            Some(genesis_event.clone()),
            as_event_payload(&company_id, &b5),
            &company_id,
        );
        let candidate_a4 = incoming_company_candidate(a4_event.clone(), &company_id, &snapshot);
        let candidate_b4 = incoming_company_candidate(b4_event.clone(), &company_id, &snapshot);
        let candidate_b5 = incoming_company_candidate(b5_event.clone(), &company_id, &snapshot);

        match case {
            ForkChoiceCase::LateFork => {
                // A is the only continuation at application time
                incoming_store
                    .upsert_candidate(&candidate_a4, Timestamp::zero())
                    .await
                    .unwrap();
                assert_eq!(verifier.verify_due_once().await.unwrap(), 1,);
                assert_eq!(verifier.apply_due_once().await.unwrap(), 1,);
                let persisted = chain_store.get_chain(&company_id).await.unwrap();
                assert_eq!(persisted.get_latest_block().hash(), a4.hash(),);
                // B and C arrive only after A committed.
                for candidate in [&candidate_b4, &candidate_b5] {
                    incoming_store
                        .upsert_candidate(candidate, Timestamp::zero())
                        .await
                        .unwrap();
                }
                assert_eq!(verifier.verify_due_once().await.unwrap(), 2,);
                verifier.apply_due_once().await.unwrap();
            }
            ForkChoiceCase::BothVerified => {
                // Every competing event is verified before any of them is applied
                for candidate in [&candidate_a4, &candidate_b4, &candidate_b5] {
                    incoming_store
                        .upsert_candidate(candidate, Timestamp::zero())
                        .await
                        .unwrap();
                }
                assert_eq!(verifier.verify_due_once().await.unwrap(), 3,);
                // Force A to be the only currently due candidate
                // The chain-scoped selection query must still see B/C
                let future = Timestamp::now() + Duration::from_secs(600);
                incoming_store
                    .mark_application_deferred(
                        &candidate_b4.event.id.to_string(),
                        Some(future),
                        ApplicationWaitReason::Transient,
                        "B is not currently due",
                    )
                    .await
                    .unwrap();
                incoming_store
                    .mark_application_deferred(
                        &candidate_b5.event.id.to_string(),
                        Some(future),
                        ApplicationWaitReason::MissingPredecessor,
                        "Waiting for B",
                    )
                    .await
                    .unwrap();
                assert_eq!(verifier.apply_due_once().await.unwrap(), 1,);
                // A was due, but B -> C was preferred
                // Therefore A must not have committed
                let persisted = chain_store.get_chain(&company_id).await.unwrap();
                assert_eq!(persisted.blocks().len(), 3);
                assert_eq!(persisted.get_latest_block().hash(), blocks[2].hash(),);

                let status = incoming_store
                    .get_chain_queue_status("company", &company_id.to_string())
                    .await
                    .unwrap();
                assert_eq!(status.verified, 3);
                assert_eq!(status.conflicting_forks, 0);
                // A must not continuously occupy the due batch
                assert!(
                    incoming_store
                        .get_verified_candidates(Timestamp::now(), 16,)
                        .await
                        .unwrap()
                        .is_empty(),
                );
                // Make B due, but leave C waiting for its predecessor
                incoming_store
                    .mark_application_deferred(
                        &candidate_b4.event.id.to_string(),
                        Some(Timestamp::zero()),
                        ApplicationWaitReason::Transient,
                        "Retry preferred branch",
                    )
                    .await
                    .unwrap();
                verifier.apply_due_once().await.unwrap();
                let persisted = chain_store.get_chain(&company_id).await.unwrap();
                assert_eq!(persisted.blocks().len(), 4);
                assert_eq!(persisted.get_latest_block().hash(), b4.hash(),);
                // B's application should wake C
                assert!(
                    incoming_store
                        .get_verified_candidates(Timestamp::now(), 16,)
                        .await
                        .unwrap()
                        .iter()
                        .any(|candidate| { candidate.event.id == candidate_b5.event.id }),
                );
                verifier.apply_due_once().await.unwrap();
            }
            ForkChoiceCase::ForegroundIngestion | ForkChoiceCase::ForegroundMissingQuorum => {
                if case == ForkChoiceCase::ForegroundMissingQuorum {
                    // B5 exists but does not reach relay quorum
                    unavailable_on_second_relay
                        .lock()
                        .unwrap()
                        .push(b5_event.id);
                }
                let progress = verifier
                    .ingest_verified_chain(
                        BlockchainType::Company,
                        &company_id.to_string(),
                        vec![
                            genesis_event.clone(),
                            proof_event.clone(),
                            invite_event.clone(),
                            a4_event.clone(),
                            b4_event.clone(),
                            b5_event.clone(),
                        ],
                        snapshot.clone(),
                    )
                    .await
                    .unwrap();
                assert_eq!(progress.enqueued, 6);
                let expected_applied = if case == ForkChoiceCase::ForegroundIngestion {
                    5
                } else {
                    4
                };
                assert_eq!(progress.applied_prefix, expected_applied,);
            }
        }

        let longer_branch_wins = matches!(
            case,
            ForkChoiceCase::BothVerified | ForkChoiceCase::ForegroundIngestion
        );
        // Make the losing candidate immediately due so we dont need to sleep for the fork-selection retry interval
        let losing_candidate = match case {
            ForkChoiceCase::BothVerified | ForkChoiceCase::ForegroundIngestion => {
                Some(&candidate_a4)
            }
            ForkChoiceCase::ForegroundMissingQuorum => Some(&candidate_b4),
            ForkChoiceCase::LateFork => None,
        };

        if let Some(candidate) = losing_candidate {
            incoming_store
                .mark_application_deferred(
                    &candidate.event.id.to_string(),
                    Some(Timestamp::zero()),
                    ApplicationWaitReason::Transient,
                    "Recheck losing branch after winner committed",
                )
                .await
                .unwrap();

            verifier.apply_due_once().await.unwrap();
        }
        let (expected_height, expected_tip) = if longer_branch_wins {
            (5, b5.hash())
        } else {
            (4, a4.hash())
        };
        let persisted = chain_store.get_chain(&company_id).await.unwrap();
        assert_eq!(persisted.blocks().len(), expected_height,);
        assert_eq!(persisted.get_latest_block().hash(), expected_tip,);
        assert_eq!(
            company_store.get(&company_id).await.unwrap().status,
            CompanyStatus::Invited,
        );
        // Only the committed branch has application metadata
        let events = chain_event_store
            .find_chain_events(&company_id.to_string(), BlockchainType::Company)
            .await
            .unwrap();
        assert_eq!(events.len(), expected_height);
        assert_eq!(
            events.iter().any(|e| &e.block_hash == a4.hash()),
            !longer_branch_wins,
        );
        assert_eq!(
            events.iter().any(|e| &e.block_hash == b4.hash()),
            longer_branch_wins,
        );
        assert_eq!(
            events.iter().any(|e| &e.block_hash == b5.hash()),
            longer_branch_wins,
        );
        let status = incoming_store
            .get_chain_queue_status("company", &company_id.to_string())
            .await
            .unwrap();
        assert_eq!(status.applied, expected_height as u64);
        match case {
            ForkChoiceCase::LateFork => {
                assert_eq!(status.conflicting_forks, 2);
                assert_eq!(status.pending, 0);
            }
            ForkChoiceCase::BothVerified | ForkChoiceCase::ForegroundIngestion => {
                assert_eq!(status.conflicting_forks, 1);
                assert_eq!(status.pending, 0);
            }
            ForkChoiceCase::ForegroundMissingQuorum => {
                assert_eq!(status.conflicting_forks, 1);
                assert_eq!(status.pending, 1);
            }
        }
        // No ordinary application work remains due, even in the future. The losing forks have been parked
        assert!(
            incoming_store
                .get_verified_candidates(Timestamp::now() + Duration::from_secs(600), 16,)
                .await
                .unwrap()
                .is_empty(),
        );
        // Reopen SQLite and prove the selected branch is durable
        let reopened = SqlitePersistence::open(SqliteConfig::new(db_path))
            .await
            .unwrap();
        let persisted = reopened
            .company_chain_store()
            .get_chain(&company_id)
            .await
            .unwrap();
        assert_eq!(persisted.blocks().len(), expected_height,);
        assert_eq!(persisted.get_latest_block().hash(), expected_tip,);
    }

    #[tokio::test]
    async fn company_bill_recovery_survives_post_commit_failure() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("company-bill-recovery.sqlite");
        let db = SqlitePersistence::open(SqliteConfig::new(db_path.clone()))
            .await
            .unwrap();
        let encryption = Arc::new(EncryptionContext::new(BcrKeys::new()));
        let network = bitcoin::Network::Testnet;
        let (company_id, (company, keys)) = get_company_data();
        let genesis = get_company_create_block(company_id.clone(), company.clone(), &keys);
        let chain = CompanyBlockchain::new_from_blocks(vec![genesis]).unwrap();
        let chain = add_creator_identity_proof_block(chain);
        assert_eq!(chain.blocks().len(), 2);
        let mut tx = db
            .transaction_mgr(encryption.clone())
            .begin()
            .await
            .unwrap();
        tx.append_company_blocks(&company_id, None, chain.blocks())
            .await
            .unwrap();
        tx.insert_company(&company).await.unwrap();
        tx.save_company_key_pair(&company_id, &keys).await.unwrap();
        tx.commit().await.unwrap();

        let bill_keys = BcrKeys::new();
        let bill_id = BillId::new(bill_keys.pub_key(), network);
        let block = CompanyBlock::create_block_for_sign_company_bill(
            company_id.clone(),
            chain.get_latest_block(),
            &CompanySignCompanyBillBlockData {
                bill_id: bill_id.clone(),
                block_id: BlockId::first(),
                block_hash: Sha256Hash::new("bill genesis"),
                operation: BillOpCode::Issue,
                bill_key: Some(bill_keys.get_private_key()),
            },
            &BcrKeys::from_private_key(&private_key_test()),
            &keys,
            test_ts(),
        )
        .unwrap();
        let expected_hash = block.hash().clone();
        let mut bill_invite = MockNotificationHandlerApi::new();
        let mut attempts = 0;
        let expected_company_id = company_id.clone();
        bill_invite
            .expect_handle_event()
            .times(2)
            .returning(move |envelope, recipient, _, _| {
                assert_eq!(recipient, &expected_company_id);
                let event = Event::<ChainInvite>::try_from(envelope).unwrap();
                assert_eq!(event.data.chain_type, BlockchainType::Bill,);
                assert_eq!(event.data.chain_id, bill_id.to_string(),);
                assert_eq!(event.data.keys.private_key, bill_keys.get_private_key(),);
                attempts += 1;
                if attempts == 1 {
                    Err(Error::Persistence(
                        "Could not persist bill invitation".into(),
                    ))
                } else {
                    Ok(())
                }
            });

        let bill_invite = Arc::new(bill_invite);
        let make_processor = |db: &SqlitePersistence| {
            let mut identity_store = MockIdentityStore::new();
            identity_store
                .expect_get()
                .returning(|| Ok(get_baseline_identity().identity));
            CompanyChainEventProcessor::new(
                Arc::new(db.company_chain_store()),
                Arc::new(db.company_store(encryption.clone())),
                Arc::new(MockFileReferenceStore::new()),
                Arc::new(identity_store),
                Arc::new(MockNotificationStore::new()),
                Arc::new(MockNostrContactProcessorApi::new()),
                bill_invite.clone(),
                Arc::new(MockPushApi::new()),
                Arc::new(db.nostr_chain_event_store()),
                Arc::new(MockNotificationJsonTransport::new()),
                Arc::new(MockContactStore::new()),
                Arc::new(db.transaction_mgr(encryption.clone())),
                network,
                Arc::new(test_cfg()),
            )
        };

        let processor = make_processor(&db);
        // Real business validation and transaction succeed
        // But the invitation effect fails
        let result = processor
            .apply_verified_block(&company_id, block.clone(), keys.clone())
            .await;
        assert!(matches!(result, Err(Error::Persistence(_))));
        let persisted = db
            .company_chain_store()
            .get_chain(&company_id)
            .await
            .unwrap();
        assert_eq!(persisted.blocks().len(), 3);
        assert_eq!(persisted.get_latest_block().hash(), &expected_hash,);
        // Simulate shutdown and reopening the same database
        drop(processor);
        db.close().await;
        let reopened = SqlitePersistence::open(SqliteConfig::new(db_path))
            .await
            .unwrap();
        let processor = make_processor(&reopened);

        // parent block is already committed, but its key-recovery effect must still be attempted
        assert_eq!(
            processor
                .apply_verified_block(&company_id, block, keys,)
                .await
                .unwrap(),
            IncomingChainApplyResult::AlreadyApplied,
        );
        let persisted = reopened
            .company_chain_store()
            .get_chain(&company_id)
            .await
            .unwrap();

        // No duplicate block or chain replacement
        assert_eq!(persisted.blocks().len(), 3);
        assert_eq!(persisted.get_latest_block().hash(), &expected_hash,);
    }
}
