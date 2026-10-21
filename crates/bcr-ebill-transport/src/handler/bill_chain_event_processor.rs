use crate::handler::public_chain_helpers::{
    BlockData, EventContainer, chain_matches_local, compare_block_chains, find_first_difference,
    is_fork_block, resolve_event_chains, resolve_fork,
};
use crate::{Error, Result};
use async_trait::async_trait;
use bcr_common::core::BillId;
use bcr_ebill_api::Config;
use bcr_ebill_api::external::mint::MintClientApi;
use bcr_ebill_api::service::transport_service::ResyncMode;
use bcr_ebill_api::service::transport_service::transport_client::TransportClientApi;
use bcr_ebill_core::application::ServiceTraitBounds;
use bcr_ebill_core::protocol::Validate;
use bcr_ebill_core::protocol::blockchain::bill::BillOpCode;
use bcr_ebill_core::protocol::blockchain::bill::block::{
    BillIssueBlockData, BillOfferToSellBlockData, BillRequestRecourseBlockData,
    BillRequestToPayBlockData,
};
use bcr_ebill_core::protocol::blockchain::bill::participant::BillParticipant;
use bcr_ebill_core::protocol::blockchain::bill::{BillBlock, BillBlockchain};
use bcr_ebill_core::protocol::blockchain::bill::{
    BillValidateActionData, BillValidationActionMode,
};
use bcr_ebill_core::protocol::blockchain::{Block, Blockchain, BlockchainType};
use bcr_ebill_core::protocol::crypto::{BcrKeys, btc};
use bcr_ebill_core::protocol::{BitcoinAddress, BlockId, Sha256Hash};
use bcr_ebill_persistence::{
    FileReferenceStoreApi, NostrChainEventStoreApi, traits::bill::BillChainStoreApi,
    traits::bill::BillStoreApi,
};
use bitcoin::secp256k1::PublicKey;
use log::{debug, error, info, warn};
use std::collections::HashSet;
use std::sync::Arc;

use super::inbound_file_anchor::{anchor_important_file, bill_file_context};
use super::{BillChainEventProcessorApi, NostrContactProcessorApi};

impl ServiceTraitBounds for BillChainEventProcessor {}

#[async_trait]
impl BillChainEventProcessorApi for BillChainEventProcessor {
    async fn process_chain_data(
        &self,
        bill_id: &BillId,
        blocks: Vec<BillBlock>,
        keys: Option<BcrKeys>,
    ) -> Result<()> {
        // check that incoming bills are of the same network that we use
        if bill_id.network() != self.bitcoin_network {
            warn!("Received bill blocks for bill {bill_id} for a different network");
            return Err(Error::Blockchain(format!(
                "Received bill blocks for bill {bill_id} for a different network"
            )));
        }

        if let Ok(existing_chain) = self.bill_blockchain_store.get_chain(bill_id).await {
            self.add_bill_blocks(bill_id, existing_chain, blocks, false)
                .await
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
        sender: nostr::key::PublicKey,
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
                .collect::<Vec<nostr::key::PublicKey>>();

            Ok(participants.contains(&sender))
        } else {
            Ok(false)
        }
    }

    async fn resolve_chain(
        &self,
        bill_id: &BillId,
        bill_keys: &BcrKeys,
    ) -> Result<Vec<Vec<EventContainer>>> {
        resolve_event_chains(
            self.transport.clone(),
            &bill_id.to_string(),
            BlockchainType::Bill,
            &Some(bill_keys.to_owned()),
        )
        .await
    }

    async fn resync_chain(
        &self,
        bill_id: &BillId,
        from_nostr: bool,
        mode: ResyncMode,
    ) -> Result<()> {
        if !from_nostr {
            debug!("invalidating cache for {bill_id} without Nostr refetch");
            return self.invalidate_cache_for_bill(bill_id).await;
        }

        match (
            self.bill_blockchain_store.get_chain(bill_id).await,
            self.bill_store.get_keys(bill_id).await,
        ) {
            (Ok(existing_chain), Ok(bill_keys)) => {
                debug!("starting bill chain resync for {bill_id} with mode {mode:?}");
                let bcr_keys = BcrKeys::from_private_key(&bill_keys.get_private_key());
                // Pre-fetch validation data needed for all chain candidates
                let is_paid = self.bill_store.is_paid(bill_id).await.map_err(|e| {
                    error!("Could not resync bill {bill_id} because getting paid status failed");
                    Error::Persistence(e.to_string())
                })?;
                let bill_first_version = existing_chain
                    .get_first_version_bill(&bill_keys)
                    .map_err(|e| {
                        error!("Could not resync bill {bill_id} because getting first version bill data failed");
                        Error::Blockchain(e.to_string())
                    })?;

                let expected_local_tip = existing_chain.get_latest_block().clone();

                let Ok(chain_data) = resolve_event_chains(
                    self.transport.clone(),
                    &bill_id.to_string(),
                    BlockchainType::Bill,
                    &Some(bcr_keys.to_owned()),
                )
                .await
                else {
                    let message = format!("Could not refetch chain data from Nostr for {bill_id}");
                    error!("{message}");
                    return Err(Error::Network(message));
                };

                // In this mode, we don't care about local, or remote chain divergences, we're just adding missing metadata for local, unpublished blocks
                if let ResyncMode::OnlyMissingMetadata { ref up_to_hash } = mode {
                    let Some(local_chain_end) = existing_chain
                        .blocks()
                        .iter()
                        .position(|block| block.hash() == up_to_hash)
                    else {
                        return Err(Error::Blockchain(format!(
                            "Could not restore Nostr metadata for bill {bill_id}: block with hash {up_to_hash} does not exist in the local chain"
                        )));
                    };
                    let local_blocks = &existing_chain.blocks()[..=local_chain_end];
                    for data in chain_data.iter() {
                        let blocks: Vec<BillBlock> = data
                            .iter()
                            .filter_map(|d| match d.block.clone() {
                                BlockData::Bill(block) => Some(block),
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
                            .find_chain_events(&bill_id.to_string(), BlockchainType::Bill)
                            .await
                        {
                            Ok(ev) => ev,
                            Err(e) => {
                                error!("Failed to fetch chain events for bill {bill_id}: {e}");
                                return Err(Error::Persistence(format!(
                                    "Failed to fetch chain events for bill {bill_id}: {e}"
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
                                    matches!(event_container.block, BlockData::Bill(_))
                                }))
                        {
                            let BlockData::Bill(remote_block) = &event_container.block else {
                                continue;
                            };

                            // if we have the block as a chain event - continue
                            if existing_block_hashes.contains(&local_block.hash) {
                                continue;
                            }

                            // otherwise, add it
                            let event = event_container.as_chain_store_event(
                                &bill_id.to_string(),
                                BlockchainType::Bill,
                                remote_block.id.inner() as usize,
                            );

                            self.chain_event_store
                                            .add_chain_event(event)
                                            .await
                                            .map_err(|e| {
                                                error!(
                                                    "Failed to restore missing chain event for bill {bill_id}, block {}: {e}",
                                                    local_block.id
                                                );

                                                Error::Persistence(format!(
                                                        "Failed to restore missing chain event for bill {bill_id}, block {}: {e}",
                                                        local_block.id
                                                ))
                                            })?;

                            events_added += 1;
                        }

                        if events_added > 0 {
                            info!(
                                "Restored {events_added} missing Nostr chain event(s) for bill {bill_id} up to block hash {up_to_hash}"
                            );
                        }

                        return Ok(());
                    }

                    let message = format!(
                        "Could not restore Nostr metadata for bill {bill_id}: no Nostr chain matches the local bill chain"
                    );
                    error!("{message}");
                    return Err(Error::Blockchain(message));
                }

                let mut candidates: Vec<(usize, BillBlockchain, Option<BlockId>)> = Vec::new();
                let mut saw_authoritative_genesis_mismatch = false;

                for (data_index, data) in chain_data.iter().enumerate() {
                    let blocks: Vec<BillBlock> = data
                        .iter()
                        .filter_map(|d| match d.block.clone() {
                            BlockData::Bill(block) => Some(block),
                            _ => None,
                        })
                        .collect();
                    if blocks.is_empty() {
                        continue;
                    }
                    let Some(remote_genesis) = blocks.first() else {
                        continue;
                    };
                    let local_genesis = existing_chain.get_first_block();
                    if remote_genesis.id != local_genesis.id
                        || remote_genesis.hash != local_genesis.hash
                    {
                        if matches!(mode, ResyncMode::NostrAuthoritative) {
                            saw_authoritative_genesis_mismatch = true;
                        }
                        continue;
                    }

                    let prepared_chain = match self
                        .prepare_bill_resync_valid_prefix(
                            bill_id,
                            &existing_chain,
                            &blocks,
                            &bill_keys,
                            &bill_first_version,
                            is_paid,
                        )
                        .await
                    {
                        Ok(chain) => chain,
                        Err(e) => {
                            debug!(
                                "Bill chain candidate could not produce a valid prefix for {bill_id}: {e}"
                            );
                            continue;
                        }
                    };

                    let replace_from = match mode {
                        ResyncMode::Normal => {
                            let (is_preferred, fork_point) =
                                resolve_fork(existing_chain.blocks(), prepared_chain.blocks());

                            if !is_preferred {
                                continue;
                            }

                            fork_point
                        }
                        ResyncMode::NostrAuthoritative => {
                            let difference = find_first_difference(
                                existing_chain.blocks(),
                                prepared_chain.blocks(),
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

                    candidates.push((data_index, prepared_chain, replace_from));
                }

                // sort candidates by their protocol-valid chains
                candidates
                    .sort_by(|(_, a, _), (_, b, _)| compare_block_chains(a.blocks(), b.blocks()));

                // select the best chain
                let Some((selected_data_index, prepared_chain, replace_from)) =
                    candidates.into_iter().next()
                else {
                    if matches!(mode, ResyncMode::NostrAuthoritative)
                        && saw_authoritative_genesis_mismatch
                    {
                        return Err(Error::Blockchain("Nostr-authoritative resync could not find a valid bill chain with matching genesis".to_string()));
                    }
                    debug!(
                        "finished bill chain resync for {bill_id} - no preferred valid remote chain found"
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

                let replacement_blocks: Vec<BillBlock> = prepared_chain
                    .blocks()
                    .iter()
                    .filter(|block| block.id >= changed_from)
                    .cloned()
                    .collect();

                let canonical_chain_changed = replace_from.is_some()
                    || prepared_chain.blocks().len() != existing_chain.blocks().len();

                // persist - TODO (tx): make transactional

                if canonical_chain_changed {
                    if let Some(replace_from) = replace_from {
                        self.bill_blockchain_store
                            .remove_blocks_from_height(bill_id, replace_from)
                            .await
                            .map_err(|e| Error::Persistence(e.to_string()))?;
                    }
                    for block in &replacement_blocks {
                        self.save_block(bill_id, block).await?;
                    }
                }

                // nostr-event updates
                let accepted_block_count = prepared_chain.blocks().len();
                if let Err(e) = self
                    .chain_event_store
                    .remove_chain_events(&bill_id.to_string(), BlockchainType::Bill)
                    .await
                {
                    error!("Failed to invalidate old bill chain events during resync: {e}");
                }

                // only save nostr events up to the last valid event
                for event_container in data
                    .iter()
                    .filter(|event_container| matches!(event_container.block, BlockData::Bill(_)))
                    .take(accepted_block_count)
                {
                    let event = event_container.as_chain_store_event(
                        &bill_id.to_string(),
                        BlockchainType::Bill,
                        event_container.block.get_block_height() as usize,
                    );
                    if let Err(e) = self.chain_event_store.add_chain_event(event).await {
                        error!("Failed to store bill chain event during resync: {e}");
                    }
                }

                // effects

                if let Err(e) = self.invalidate_cache_for_bill(bill_id).await {
                    error!("Failed to invalidate cache for bill {bill_id}: {e}");
                }

                if canonical_chain_changed {
                    for node_id in prepared_chain
                        .get_all_nodes_from_bill(&bill_keys)
                        .unwrap_or_default()
                    {
                        self.nostr_contact_processor
                            .ensure_nostr_contact(&node_id)
                            .await;
                    }
                }

                debug!(
                    "finished bill chain resync for {bill_id} to valid remote block height {} from {} raw remote events",
                    prepared_chain.get_latest_block().id,
                    data.len(),
                );
                Ok(())
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

    async fn invalidate_cache_for_bill(&self, bill_id: &BillId) -> Result<()> {
        if let Err(e) = self.bill_store.invalidate_bill_in_cache(bill_id).await {
            error!("Failed to invalidate cache for bill {bill_id}: {e}");
            return Err(Error::Persistence(
                "Failed to invalidate cache for bill".to_string(),
            ));
        }
        Ok(())
    }

    async fn valid_chain_prefix_len(
        &self,
        bill_id: &BillId,
        blocks: &[BillBlock],
        keys: &BcrKeys,
    ) -> Result<usize> {
        let prepared = self.prepare_bill_chain_valid_prefix(blocks, keys).await?;
        if &prepared.bill_id != bill_id {
            return Err(Error::Blockchain(format!(
                "Bill chain belongs to {}, expected {}",
                prepared.bill_id, bill_id,
            )));
        }
        Ok(prepared.chain.blocks().len())
    }
}

#[derive(Clone)]
pub struct BillChainEventProcessor {
    bill_blockchain_store: Arc<dyn BillChainStoreApi>,
    bill_store: Arc<dyn BillStoreApi>,
    file_reference_store: Arc<dyn FileReferenceStoreApi>,
    nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
    chain_event_store: Arc<dyn NostrChainEventStoreApi>,
    transport: Arc<dyn TransportClientApi>,
    mint_client: Arc<dyn MintClientApi>,
    bitcoin_network: bitcoin::Network,
    config: Arc<Config>,
}

#[derive(Debug, Clone)]
struct PreparedBillChain {
    bill_id: BillId,
    bill_first_version: BillIssueBlockData,
    chain: BillBlockchain,
}

impl BillChainEventProcessor {
    pub fn new(
        bill_blockchain_store: Arc<dyn BillChainStoreApi>,
        bill_store: Arc<dyn BillStoreApi>,
        file_reference_store: Arc<dyn FileReferenceStoreApi>,
        nostr_contact_processor: Arc<dyn NostrContactProcessorApi>,
        chain_event_store: Arc<dyn NostrChainEventStoreApi>,
        transport: Arc<dyn TransportClientApi>,
        mint_client: Arc<dyn MintClientApi>,
        bitcoin_network: bitcoin::Network,
        config: Arc<Config>,
    ) -> Self {
        Self {
            bill_blockchain_store,
            bill_store,
            file_reference_store,
            nostr_contact_processor,
            chain_event_store,
            transport,
            mint_client,
            bitcoin_network,
            config,
        }
    }

    async fn add_bill_blocks(
        &self,
        bill_id: &BillId,
        existing: BillBlockchain,
        blocks: Vec<BillBlock>,
        from_resync: bool,
    ) -> Result<()> {
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

        let mut block_added = false;
        for block in &blocks {
            let current_height = chain.get_latest_block().id;
            if block.id <= current_height {
                if blocks.len() == 1 && !from_resync {
                    let latest = chain.get_latest_block();
                    if is_fork_block(latest, block) {
                        info!(
                            "Split chain detected for bill {bill_id} at height {} - resyncing",
                            block.id
                        );
                        self.resync_chain(bill_id, true, ResyncMode::Normal).await?;
                        // resync potentially changed the complete chain - don't continue
                        return Ok(());
                    }
                }
                continue;
            }
            match self
                .validate_block_for_chain(
                    bill_id,
                    &chain,
                    &bill_first_version,
                    &bill_keys,
                    block,
                    is_paid,
                )
                .await
            {
                Ok(candidate_chain) => {
                    self.save_block(bill_id, block).await?;
                    chain = candidate_chain;
                    block_added = true;
                }
                Err(e) => {
                    if blocks.len() == 1
                        && !from_resync
                        && BlockId::next_from_previous_block_id(&chain.get_latest_block().id)
                            < block.id
                    {
                        info!(
                            "Received invalid block {} for bill {bill_id} - missing blocks - try to resync",
                            block.id
                        );
                        self.resync_chain(bill_id, true, ResyncMode::Normal).await?;
                        // resync potentially changed the complete chain - don't continue
                        return Ok(());
                    }
                    return Err(e);
                }
            }
        }

        // if the bill was changed, we invalidate the cache
        if block_added {
            // re-anchor files
            for file in &bill_first_version.files {
                anchor_important_file(
                    &self.file_reference_store,
                    file,
                    bill_file_context(bill_id, "files"),
                )
                .await?;
            }
            if let Err(e) = self.invalidate_cache_for_bill(bill_id).await {
                error!("Failed to invalidate cache for bill {bill_id}: {e}");
            }
            // ensure that we have all nostr contacts for the bill participants
            for node_id in chain
                .get_all_nodes_from_bill(&bill_keys)
                .unwrap_or_default()
            {
                self.nostr_contact_processor
                    .ensure_nostr_contact(&node_id)
                    .await;
            }
        }

        Ok(())
    }

    /// Validates a single block for a chain.
    /// Returns true if the block was validated and added to the in-memory chain.
    /// Returns false if the block should be skipped (already exists, etc.).
    async fn validate_block_for_chain(
        &self,
        bill_id: &BillId,
        chain: &BillBlockchain,
        bill_first_version: &BillIssueBlockData,
        bill_keys: &BcrKeys,
        block: &BillBlock,
        is_paid: bool,
    ) -> Result<BillBlockchain> {
        let block_id = block.id;

        if block.op_code == BillOpCode::Issue {
            return Err(Error::Blockchain(format!(
                "Received unexpected Issue block {block_id} for existing bill {bill_id}"
            )));
        }

        // validate plaintext hash
        if !block.validate_plaintext_hash(&bill_keys.get_private_key()) {
            error!("Received invalid block {block_id} for bill {bill_id} - invalid plaintext hash");
            return Err(Error::Blockchain(format!(
                "Received invalid block {block_id} for bill {bill_id} - invalid plaintext hash"
            )));
        }

        // keep chain before this block for validation
        let chain_before = chain.clone();

        let holder_is_mint_for_validation = match chain_before.holder_is_mint(bill_keys) {
            Ok(h) => h,
            Err(e) => {
                error!(
                    "Received invalid block {block_id} for bill {bill_id} - could not check if holder is mint for bill {bill_id}"
                );
                return Err(Error::Blockchain(e.to_string()));
            }
        };
        let latest_block_before_add = chain_before.get_latest_block();

        // validation happens against a candidate
        let mut candidate_chain = chain_before.clone();
        if !candidate_chain.try_add_block(block.clone()) {
            error!("Received invalid block {block_id} for bill {bill_id}");
            return Err(Error::Blockchain(format!(
                "Received invalid block {block_id} for bill {bill_id}"
            )));
        }

        let (signer, bill_action) = match block.verify_and_get_signer(bill_keys) {
            Ok(signer) => signer,
            Err(e) => {
                error!(
                    "Received invalid block {block_id} for bill {bill_id} - could not verify signature from block data signer"
                );
                return Err(Error::Blockchain(e.to_string()));
            }
        };

        // validate payment address for payment requests
        match block.op_code() {
            BillOpCode::RequestToPay => {
                let data: BillRequestToPayBlockData = block
                    .get_decrypted_block(bill_keys)
                    .map_err(|e| Error::Blockchain(e.to_string()))?;
                self.validate_payment_address_for_payment_request(
                    bill_id,
                    block.op_code().to_owned(),
                    &block.id(),
                    latest_block_before_add.hash(),
                    &bill_keys.pub_key(),
                    &signer.pub_key(),
                    self.config.bitcoin_network(),
                    &data.payment_data.payment_address,
                    &holder_is_mint_for_validation,
                )
                .await
                .map_err(|e| Error::Blockchain(e.to_string()))?;
            }
            BillOpCode::OfferToSell => {
                let data: BillOfferToSellBlockData = block
                    .get_decrypted_block(bill_keys)
                    .map_err(|e| Error::Blockchain(e.to_string()))?;
                self.validate_payment_address_for_payment_request(
                    bill_id,
                    block.op_code().to_owned(),
                    &block.id(),
                    latest_block_before_add.hash(),
                    &bill_keys.pub_key(),
                    &signer.pub_key(),
                    self.config.bitcoin_network(),
                    &data.payment_data.payment_address,
                    &None,
                )
                .await
                .map_err(|e| Error::Blockchain(e.to_string()))?;
            }
            BillOpCode::RequestRecourse => {
                let data: BillRequestRecourseBlockData = block
                    .get_decrypted_block(bill_keys)
                    .map_err(|e| Error::Blockchain(e.to_string()))?;
                self.validate_payment_address_for_payment_request(
                    bill_id,
                    block.op_code().to_owned(),
                    &block.id(),
                    latest_block_before_add.hash(),
                    &bill_keys.pub_key(),
                    &signer.pub_key(),
                    self.config.bitcoin_network(),
                    &data.payment_data.payment_address,
                    &None,
                )
                .await
                .map_err(|e| Error::Blockchain(e.to_string()))?;
            }
            _ => {} // nothing to do for non-payment-requests
        };

        // then, validate the bill action
        let bill_parties = chain_before
            .get_bill_parties(bill_keys, bill_first_version)
            .map_err(|e| {
                error!("Received invalid block {block_id} for bill {bill_id}: {e}");
                Error::Blockchain(
                    "Received invalid block for bill - couldn't get bill parties".to_string(),
                )
            })?;

        if let Err(e) = (BillValidateActionData {
            blockchain: chain_before,
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
        })
        .validate()
        {
            error!(
                "Received invalid block {block_id} for bill {bill_id}, bill action validation failed: {e}"
            );
            return Err(Error::Blockchain(e.to_string()));
        }

        Ok(candidate_chain)
    }

    /// Calculates the payment address with the given values and validates it against the given address
    async fn validate_payment_address_for_payment_request(
        &self,
        bill_id: &BillId,
        payment_op: BillOpCode,
        block_id: &BlockId,
        previous_hash: &Sha256Hash,
        bill_pub_key: &PublicKey,
        caller_pub_key: &PublicKey,
        btc_network: bitcoin::Network,
        address_to_check: &BitcoinAddress,
        holder_is_mint: &Option<BillParticipant>,
    ) -> Result<()> {
        if let Some(_mint_holder) = holder_is_mint
            && matches!(payment_op, BillOpCode::RequestToPay)
        {
            if !address_to_check.is_valid_for_network(btc_network) {
                return Err(Error::Crypto(
                    "Wrong Network for mint payment address".to_owned(),
                ));
            }

            self.mint_client
                .validate_payment_address_from_mint(
                    &self.config.mint_config.default_mint_url,
                    address_to_check,
                    bill_id,
                    *block_id,
                    previous_hash,
                )
                .await
                .map_err(|e| {
                    error!("Invalid mint payment address: {e}");
                    Error::Crypto("Invalid mint payment address".to_owned())
                })?;
            Ok(())
        } else {
            let addr = btc::get_address_to_pay(
                bill_pub_key,
                caller_pub_key,
                &btc::calculate_tweak_hash_for_payment_request(
                    payment_op,
                    block_id,
                    previous_hash,
                )?,
                btc_network,
            )?;
            if &addr != address_to_check {
                Err(Error::Crypto(format!(
                    "Payment Addresses don't match - derived: {}, to check: {}",
                    addr.assume_checked(),
                    address_to_check.clone().assume_checked(),
                )))
            } else {
                Ok(())
            }
        }
    }

    async fn add_new_chain(&self, blocks: Vec<BillBlock>, keys: &BcrKeys) -> Result<()> {
        let prepared = self.prepare_bill_chain_valid_prefix(&blocks, keys).await?;
        let bill_id = prepared.bill_id.clone();
        debug!(
            "adding new valid bill chain prefix for {bill_id} with {} blocks",
            prepared.chain.blocks().len(),
        );

        // persist - TODO (tx): make transactional

        for block in prepared.chain.blocks() {
            self.save_block(&bill_id, block).await?;
        }
        self.save_keys(&bill_id, keys).await?;
        for file in &prepared.bill_first_version.files {
            anchor_important_file(
                &self.file_reference_store,
                file,
                bill_file_context(&bill_id, "files"),
            )
            .await?;
        }

        // effects

        // ensure that we have all nostr contacts for the bill participants
        for node_id in prepared
            .chain
            .get_all_nodes_from_bill(keys)
            .unwrap_or_default()
        {
            self.nostr_contact_processor
                .ensure_nostr_contact(&node_id)
                .await;
        }

        Ok(())
    }

    fn prepare_bill_issue(
        &self,
        issue_block: &BillBlock,
        keys: &BcrKeys,
    ) -> Result<PreparedBillChain> {
        // make sure first block is of type Issue
        if issue_block.op_code != BillOpCode::Issue {
            error!("Newly received chain is not valid - first block is not an Issue block");
            return Err(Error::Blockchain(
                "Newly received chain is not valid - first block is not an Issue block".to_string(),
            ));
        }

        if !issue_block.validate_plaintext_hash(&keys.get_private_key()) {
            return Err(Error::Blockchain(
                "Newly received bill Issue block has invalid plaintext hash".to_string(),
            ));
        }

        let chain = BillBlockchain::new_from_blocks(vec![issue_block.clone()])
            .map_err(|e| Error::Blockchain(e.to_string()))?;

        if !chain.is_chain_valid() {
            error!("Newly received chain is not valid");
            return Err(Error::Blockchain(
                "Newly received bill Issue block is invalid".to_string(),
            ));
        }

        let bill_first_version = chain
            .get_first_version_bill(keys)
            .map_err(|e| Error::Crypto(format!("Failed to decrypt new bill Issue block: {e}")))?;

        issue_block
        .verify_and_get_signer(keys)
        .map_err(|e| {
            error!(
                "Received invalid block for bill {} - could not verify signature from block data signer",
                bill_first_version.id
            );
            Error::Blockchain(e.to_string())
        })?;

        Ok(PreparedBillChain {
            bill_id: bill_first_version.id.clone(),
            bill_first_version,
            chain,
        })
    }

    async fn prepare_bill_chain_valid_prefix(
        &self,
        blocks: &[BillBlock],
        keys: &BcrKeys,
    ) -> Result<PreparedBillChain> {
        let Some(issue_block) = blocks.first() else {
            return Err(Error::Blockchain("Received empty bill chain".to_string()));
        };
        let mut prepared = self.prepare_bill_issue(issue_block, keys)?;
        for block in blocks.iter().skip(1) {
            match self
                .validate_block_for_chain(
                    &prepared.bill_id,
                    &prepared.chain,
                    &prepared.bill_first_version,
                    keys,
                    block,
                    false,
                )
                .await
            {
                Ok(candidate_chain) => {
                    prepared.chain = candidate_chain;
                }
                Err(e) => {
                    debug!(
                        "Ignoring invalid bill chain tail starting at block {} for {}: {e}",
                        block.id, prepared.bill_id,
                    );
                    break;
                }
            }
        }
        Ok(prepared)
    }

    async fn prepare_bill_resync_valid_prefix(
        &self,
        bill_id: &BillId,
        existing_chain: &BillBlockchain,
        remote_blocks: &[BillBlock],
        bill_keys: &BcrKeys,
        bill_first_version: &BillIssueBlockData,
        is_paid: bool,
    ) -> Result<BillBlockchain> {
        let Some(remote_genesis) = remote_blocks.first() else {
            return Err(Error::Blockchain(
                "Received empty remote bill chain".to_string(),
            ));
        };
        let local_genesis = existing_chain.get_first_block();
        if remote_genesis.id != local_genesis.id || remote_genesis.hash != local_genesis.hash {
            return Err(Error::Blockchain(
                "Remote bill chain has different genesis".to_string(),
            ));
        }
        let first_difference = find_first_difference(existing_chain.blocks(), remote_blocks);
        let mut candidate_chain = existing_chain.clone();

        let start_index = if let Some(difference) = first_difference {
            let index = existing_chain
                .blocks()
                .iter()
                .position(|block| block.id == difference)
                .ok_or_else(|| {
                    Error::Blockchain(format!(
                        "Could not find bill fork point {difference} in local chain for {bill_id}"
                    ))
                })?;
            candidate_chain.truncate_from(difference);
            index
        } else {
            // remote is just an extension of local
            existing_chain.blocks().len()
        };

        // start iterating from the divergence position
        for block in remote_blocks.iter().skip(start_index) {
            match self
                .validate_block_for_chain(
                    bill_id,
                    &candidate_chain,
                    bill_first_version,
                    bill_keys,
                    block,
                    is_paid,
                )
                .await
            {
                Ok(next_chain) => {
                    candidate_chain = next_chain;
                }
                Err(e) => {
                    debug!(
                        "Ignoring invalid remote bill chain tail starting at block {} for {bill_id}: {e}",
                        block.id
                    );
                    break;
                }
            }
        }
        Ok(candidate_chain)
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

    async fn save_keys(&self, bill_id: &BillId, keys: &BcrKeys) -> Result<()> {
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
    use bcr_ebill_core::protocol::{
        File, Name, Sha256Hash, Timestamp,
        blockchain::bill::{
            block::{
                BillAcceptBlockData, BillEndorseBlockData, BillParticipantBlockData,
                BillRejectBlockData, BillRequestToAcceptBlockData,
            },
            participant::BillIdentParticipant,
        },
        constants::ACCEPT_DEADLINE_SECONDS,
        crypto::BcrKeys,
        event::{BillBlockEvent, Event, EventEnvelope},
        file_reference::{FileReference, FileReferenceContext},
    };
    use bitcoin::PrivateKey;
    use bitcoin::secp256k1::{SECP256K1, SecretKey};
    use mockall::predicate::{always, eq};
    use nostr::event::FinalizeEvent;
    use std::str::FromStr;

    use crate::{
        handler::{
            MockNostrContactProcessorApi,
            test_utils::{
                MockBillChainStore, MockBillStore, MockMintClient, MockNostrChainEventStore,
                bill_id_test, empty_address, get_baseline_bill, get_baseline_identity,
                get_bill_keys, get_genesis_chain, get_test_bitcredit_bill, node_id_test_other,
                private_key_test,
            },
        },
        test_utils::{
            MockFileReferenceStore, MockNotificationJsonTransport, signed_identity_proof_test,
            test_cfg, valid_payment_address_testnet,
        },
        transport::create_public_chain_event,
    };

    use super::*;

    #[tokio::test]
    async fn test_create_event_handler() {
        let (bill_chain_store, bill_store, contact, transport, chain_event_store) = create_mocks();
        BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );
    }

    #[tokio::test]
    async fn test_validate_chain_event_and_sender_invalid_on_no_keys_or_chain() {
        let keys = BcrKeys::new().get_nostr_keys();
        let (mut bill_chain_store, mut bill_store, contact, transport, _) = create_mocks();

        bill_store
            .expect_get_keys()
            .with(eq(bill_id_test()))
            .returning(move |_| {
                Err(bcr_ebill_persistence::Error::NoSuchEntity(
                    "bill block".to_string(),
                    bill_id_test().to_string(),
                ))
            });

        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id_test()))
            .returning(move |_| {
                Err(bcr_ebill_persistence::Error::NoSuchEntity(
                    "bill block".to_string(),
                    bill_id_test().to_string(),
                ))
            });

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let valid = handler
            .validate_chain_event_and_sender(&bill_id_test(), keys.public_key())
            .await
            .expect("Event should be handled");
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_validate_chain_event_and_sender_valid() {
        let baseline = get_baseline_identity();
        let npub = baseline.key_pair.get_nostr_keys().public_key();
        let (mut bill_chain_store, mut bill_store, contact, transport, _) = create_mocks();

        let payer = BillIdentParticipant::new(baseline.identity.clone()).unwrap();
        let payee = BillIdentParticipant::new(baseline.identity.clone()).unwrap();
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);

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
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
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

        let (mut bill_chain_store, mut bill_store, mut contact, transport, _) = create_mocks();

        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id_test()))
            .times(1)
            .returning(move |_| {
                Err(bcr_ebill_persistence::Error::NoSuchEntity(
                    "bill block".to_string(),
                    bill_id_test().to_string(),
                ))
            });
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
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
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
                signer_identity_proof: Some(signed_identity_proof_test().into()),
            },
            &BcrKeys::from_private_key(&private_key_test()),
            None,
            &BcrKeys::from_private_key(&private_key_test()),
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();

        let (mut bill_chain_store, mut bill_store, mut contact, transport, _) = create_mocks();

        let chain_clone = chain.clone();
        bill_store
            .expect_invalidate_bill_in_cache()
            .returning(|_| Ok(()));
        bill_store.expect_is_paid().returning(|_| Ok(false));
        bill_store
            .expect_get_keys()
            .returning(|_| Ok(BcrKeys::from_private_key(&private_key_test())));
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
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
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
        let bcr_keys = BcrKeys::from_private_key(&private_key_test());
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
                signer_identity_proof: Some(signed_identity_proof_test().into()),
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
                signer_identity_proof: signed_identity_proof_test().into(),
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

        let (
            mut bill_chain_store,
            mut bill_store,
            mut contact,
            mut transport,
            mut chain_event_store,
        ) = create_mocks();

        let chain_clone = chain.clone();
        bill_store
            .expect_invalidate_bill_in_cache()
            .returning(|_| Ok(()));
        bill_store
            .expect_is_paid()
            .times(2)
            .returning(|_| Ok(false));
        bill_store
            .expect_get_keys()
            .times(2)
            .returning(move |_| Ok(BcrKeys::from_private_key(&private_key_test())));

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

        chain_event_store
            .expect_remove_chain_events()
            .returning(|_, _| Ok(()));

        // issue -> block1 -> block2
        chain_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()))
            .times(3);

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
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
        previous: Option<nostr::event::Event>,
        root: Option<nostr::event::Event>,
        data: EventEnvelope,
        bill_id: &BillId,
    ) -> nostr::event::Event {
        create_public_chain_event(
            &bill_id.to_string(),
            data,
            Timestamp::new(1000).unwrap(),
            BlockchainType::Bill,
            previous,
            root,
        )
        .expect("could not create chain event")
        .finalize(&keys.get_nostr_keys())
        .expect("could not sign event")
    }

    #[tokio::test]
    async fn test_add_new_chain_persists_valid_prefix_before_invalid_tail() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let mut payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        payee.node_id = node_id_test_other();
        let drawer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, Some(&drawer), None);
        let mut chain = get_genesis_chain(Some(bill));
        let keys = get_bill_keys();

        // appendable, but invalid bill action
        let invalid_block = BillBlock::create_block_for_reject_to_pay(
            bill_id_test(),
            chain.get_latest_block(),
            &BillRejectBlockData {
                rejecter: payer.clone().into(),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1000,
                signing_address: empty_address(),
                signer_identity_proof: signed_identity_proof_test().into(),
            },
            &BcrKeys::from_private_key(&private_key_test()),
            None,
            &BcrKeys::from_private_key(&private_key_test()),
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();
        assert!(chain.try_add_block(invalid_block.clone()));
        let issue_block = chain.get_first_block().clone();
        let (mut bill_chain_store, mut bill_store, mut contact, transport, _) = create_mocks();
        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id_test()))
            .once()
            .returning(move |_| {
                Err(bcr_ebill_persistence::Error::NoSuchEntity(
                    "bill block".to_string(),
                    bill_id_test().to_string(),
                ))
            });

        // only the valid Issue is persisted
        bill_chain_store
            .expect_add_block()
            .with(eq(bill_id_test()), eq(issue_block))
            .once()
            .returning(|_, _| Ok(()));

        // valid issue is accepted, so keys are persisted as well
        bill_store
            .expect_save_keys()
            .with(eq(bill_id_test()), always())
            .once()
            .returning(|_, _| Ok(()));
        contact.expect_ensure_nostr_contact().returning(|_| ());
        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );
        let result = handler
            .process_chain_data(&bill_id_test(), chain.blocks().clone(), Some(keys))
            .await;
        assert!(
            result.is_ok(),
            "invalid tail must not poison a valid bill prefix"
        );
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

        let (mut bill_chain_store, mut bill_store, contact, transport, _) = create_mocks();

        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id_test()))
            .times(1)
            .returning(move |_| {
                Err(bcr_ebill_persistence::Error::NoSuchEntity(
                    "bill block".to_string(),
                    bill_id_test().to_string(),
                ))
            });
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
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
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
                signer_identity_proof: signed_identity_proof_test().into(),
            },
            &BcrKeys::from_private_key(&private_key_test()),
            None,
            &BcrKeys::from_private_key(&private_key_test()),
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();

        let (mut bill_chain_store, mut bill_store, contact, transport, _) = create_mocks();

        let chain_clone = chain.clone();
        bill_store
            .expect_get_keys()
            .returning(|_| Ok(BcrKeys::from_private_key(&private_key_test())));

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
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
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
                signer_identity_proof: Some(signed_identity_proof_test().into()),
            },
            &BcrKeys::from_private_key(&private_key_test()),
            None,
            &BcrKeys::from_private_key(&private_key_test()),
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();

        let (mut bill_chain_store, mut bill_store, contact, transport, _) = create_mocks();

        let chain_clone = chain.clone();
        bill_store
            .expect_get_keys()
            .returning(|_| Ok(BcrKeys::from_private_key(&private_key_test())));

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
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
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
                signer_identity_proof: Some(signed_identity_proof_test().into()),
            },
            &BcrKeys::from_private_key(&private_key_test()),
            None,
            &BcrKeys::from_private_key(&private_key_test()),
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();

        let (mut bill_chain_store, bill_store, contact, transport, _) = create_mocks();

        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id_test()))
            .times(1)
            .returning(move |_| {
                Err(bcr_ebill_persistence::Error::NoSuchEntity(
                    "bill block".to_string(),
                    bill_id_test().to_string(),
                ))
            });

        bill_chain_store.expect_add_block().never();

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let result = handler
            .process_chain_data(&bill_id_test(), vec![block.clone()], None)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fails_to_add_block_for_bill_id_from_different_network() {
        let (bill_chain_store, bill_store, contact, transport, _) = create_mocks();
        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );
        let mainnet_bill_id = BillId::new(BcrKeys::new().pub_key(), bitcoin::Network::Bitcoin);

        let result = handler
            .process_chain_data(&mainnet_bill_id, vec![], None)
            .await;

        assert!(result.is_err());
        assert!(result.as_ref().unwrap_err().to_string().contains("network"));
    }

    #[tokio::test]
    async fn test_from_resync_prevents_recursive_resync_on_split_chain() {
        // Setup: Create a scenario where a single block would trigger split chain detection
        // When from_resync=false, it would trigger resync_chain
        // When from_resync=true, it should NOT trigger resync_chain (preventing loop)
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let chain = get_genesis_chain(Some(bill.clone()));

        // Create a valid block first
        let mut split_block = BillBlock::create_block_for_request_to_accept(
            bill_id_test(),
            chain.get_latest_block(),
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1000,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: chain.get_latest_block().timestamp
                    + 1000
                    + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &BcrKeys::from_private_key(&private_key_test()),
            None,
            &BcrKeys::from_private_key(&private_key_test()),
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();

        // Manually modify the block to simulate split chain conditions:
        // Same height as latest, different hash, earlier timestamp
        split_block.id = chain.get_latest_block().id; // Same height
        split_block.timestamp = chain.get_latest_block().timestamp - 1000; // Earlier timestamp
        split_block.hash = Sha256Hash::new("different_hash"); // Different hash

        let (mut bill_chain_store, mut bill_store, contact, mut transport, _) = create_mocks();

        // Setup existing chain
        let chain_clone = chain.clone();
        bill_store
            .expect_get_keys()
            .returning(|_| Ok(BcrKeys::from_private_key(&private_key_test())));
        bill_store.expect_is_paid().returning(|_| Ok(false));
        bill_chain_store
            .expect_get_chain()
            .returning(move |_| Ok(chain_clone.clone()));

        // CRITICAL: transport.resolve_public_chain should NEVER be called when from_resync=true
        // This would indicate a resync is being triggered
        transport
            .expect_resolve_public_chain()
            .times(0)
            .returning(|_, _| Ok(vec![]));

        // Block should NOT be added (it's rejected due to split detection, but no resync)
        bill_chain_store.expect_add_block().times(0);

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        // Call add_bill_blocks with from_resync=true
        // Should return Ok without calling resync_chain even though conditions would normally trigger it
        let result = handler
            .add_bill_blocks(&bill_id_test(), chain, vec![split_block], true)
            .await;

        // Should succeed without triggering resync (block is skipped/ignored)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_from_resync_prevents_recursive_resync_on_missing_blocks() {
        // Setup: Create a scenario where validation fails due to missing predecessor
        // When from_resync=false, it would trigger resync_chain
        // When from_resync=true, it should return error without resync
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let chain = get_genesis_chain(Some(bill.clone()));

        // Create a block at height 2 (we only have block 1, so gap of 1 block)
        // Create an intermediate block first to establish proper chain
        let prev_block = chain.get_latest_block();
        let intermediate_block = BillBlock::create_block_for_request_to_accept(
            bill_id_test(),
            prev_block,
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: prev_block.timestamp + 500,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: prev_block.timestamp
                    + 500
                    + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &BcrKeys::from_private_key(&private_key_test()),
            None,
            &BcrKeys::from_private_key(&private_key_test()),
            prev_block.timestamp + 500,
        )
        .unwrap();

        // Now create a gapped block at height 3, but we'll try to add it without intermediate_block
        // This creates a gap (we have block 1, but trying to add block 3)
        let gapped_block = BillBlock::create_block_for_accept(
            bill_id_test(),
            &intermediate_block,
            &BillAcceptBlockData {
                accepter: payer.clone().into(),
                signatory: None,
                signing_timestamp: intermediate_block.timestamp + 1000,
                signing_address: empty_address(),
                signer_identity_proof: signed_identity_proof_test().into(),
            },
            &BcrKeys::from_private_key(&private_key_test()),
            None,
            &BcrKeys::from_private_key(&private_key_test()),
            intermediate_block.timestamp + 1000,
        )
        .unwrap();

        let (mut bill_chain_store, mut bill_store, contact, mut transport, _) = create_mocks();

        // Setup existing chain
        let chain_clone = chain.clone();
        bill_store
            .expect_get_keys()
            .returning(|_| Ok(BcrKeys::from_private_key(&private_key_test())));
        bill_store.expect_is_paid().returning(|_| Ok(false));
        bill_chain_store
            .expect_get_chain()
            .returning(move |_| Ok(chain_clone.clone()));

        // CRITICAL: transport.resolve_public_chain should NEVER be called when from_resync=true
        transport
            .expect_resolve_public_chain()
            .times(0)
            .returning(|_, _| Ok(vec![]));

        // Block should NOT be added
        bill_chain_store.expect_add_block().times(0);

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        // Call add_bill_blocks with from_resync=true and a gapped block
        // Should return error, NOT call resync_chain
        let result = handler
            .add_bill_blocks(&bill_id_test(), chain, vec![gapped_block], true)
            .await;

        // Should return an error (validation failed), but NOT trigger resync
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resync_chain_selects_best_valid_prefix_not_longest_raw_branch() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bcr_keys = BcrKeys::from_private_key(&private_key_test());
        let bill_id = BillId::new(bcr_keys.pub_key(), bitcoin::Network::Testnet);
        let bill = get_test_bitcredit_bill(&bill_id, &payer, &payee, None, None);
        let genesis_chain = get_genesis_chain(Some(bill));
        let genesis = genesis_chain.get_first_block().clone();

        // Candidate A
        // raw:   1 A2 A2 A2
        // valid: 1 A2
        let a_ts = genesis.timestamp + 1000;
        let a2 = BillBlock::create_block_for_request_to_accept(
            bill_id.clone(),
            &genesis,
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: a_ts,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: a_ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &bcr_keys,
            None,
            &bcr_keys,
            a_ts,
        )
        .unwrap();

        // Candidate B
        // raw + valid: 1 B2 B3
        let b_ts = genesis.timestamp + 2000;
        let b2 = BillBlock::create_block_for_request_to_accept(
            bill_id.clone(),
            &genesis,
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: b_ts,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: b_ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &bcr_keys,
            None,
            &bcr_keys,
            b_ts,
        )
        .unwrap();
        let b3 = BillBlock::create_block_for_accept(
            bill_id.clone(),
            &b2,
            &BillAcceptBlockData {
                accepter: payer.clone().into(),
                signatory: None,
                signing_timestamp: b2.timestamp + 1000,
                signing_address: empty_address(),
                signer_identity_proof: signed_identity_proof_test().into(),
            },
            &bcr_keys,
            None,
            &bcr_keys,
            b2.timestamp + 1000,
        )
        .unwrap();
        let root = generate_test_event(
            &bcr_keys,
            None,
            None,
            as_event_payload(&bill_id, &genesis),
            &bill_id,
        );
        // longer RAW branch A
        let event_a2 = generate_test_event(
            &bcr_keys,
            Some(root.clone()),
            Some(root.clone()),
            as_event_payload(&bill_id, &a2),
            &bill_id,
        );
        let event_bad_a3 = generate_test_event(
            &bcr_keys,
            Some(event_a2.clone()),
            Some(root.clone()),
            // A2 is replayed
            as_event_payload(&bill_id, &a2),
            &bill_id,
        );
        let event_bad_a4 = generate_test_event(
            &bcr_keys,
            Some(event_bad_a3.clone()),
            Some(root.clone()),
            as_event_payload(&bill_id, &a2),
            &bill_id,
        );
        // shorter RAW but longer VALID branch B
        let event_b2 = generate_test_event(
            &bcr_keys,
            Some(root.clone()),
            Some(root.clone()),
            as_event_payload(&bill_id, &b2),
            &bill_id,
        );
        let event_b3 = generate_test_event(
            &bcr_keys,
            Some(event_b2.clone()),
            Some(root.clone()),
            as_event_payload(&bill_id, &b3),
            &bill_id,
        );
        let nostr_events = vec![
            root.clone(),
            event_a2,
            event_bad_a3,
            event_bad_a4,
            event_b2,
            event_b3,
        ];
        let (
            mut bill_chain_store,
            mut bill_store,
            mut contact,
            mut transport,
            mut chain_event_store,
        ) = create_mocks();

        let local_chain = genesis_chain.clone();
        bill_chain_store
            .expect_get_chain()
            .once()
            .returning(move |_| Ok(local_chain.clone()));

        let keys = bcr_keys.clone();
        bill_store
            .expect_get_keys()
            .once()
            .returning(move |_| Ok(keys.clone()));
        bill_store.expect_is_paid().once().returning(|_| Ok(false));
        bill_store
            .expect_invalidate_bill_in_cache()
            .once()
            .returning(|_| Ok(()));
        transport
            .expect_resolve_public_chain()
            .with(eq(bill_id.to_string()), eq(BlockchainType::Bill))
            .once()
            .returning(move |_, _| Ok(nostr_events.clone()));
        bill_chain_store.expect_remove_blocks_from_height().times(0);

        let b2_hash = b2.hash.clone();
        let b3_hash = b3.hash.clone();
        bill_chain_store
            .expect_add_block()
            .withf(move |_, block| block.hash == b2_hash || block.hash == b3_hash)
            .times(2)
            .returning(|_, _| Ok(()));
        contact.expect_ensure_nostr_contact().returning(|_| ());
        chain_event_store
            .expect_remove_chain_events()
            .once()
            .returning(|_, _| Ok(()));

        let selected_hashes = [genesis.hash.clone(), b2.hash.clone(), b3.hash.clone()];
        chain_event_store
            .expect_add_chain_event()
            .withf(move |event| selected_hashes.contains(&event.block_hash))
            .times(3)
            .returning(|_| Ok(()));
        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );
        handler
            .resync_chain(&bill_id, true, ResyncMode::Normal)
            .await
            .expect("best protocol-valid prefix must win");
    }

    #[tokio::test]
    async fn test_resync_chain_recovers_valid_prefix_and_does_not_store_repeated_tip_event() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bcr_keys = BcrKeys::from_private_key(&private_key_test());
        let bill_id = BillId::new(bcr_keys.pub_key(), bitcoin::Network::Testnet);
        let bill = get_test_bitcredit_bill(&bill_id, &payer, &payee, None, None);
        let local_chain = get_genesis_chain(Some(bill));
        let genesis = local_chain.get_first_block().clone();
        let ts = genesis.timestamp + 1000;
        let block2 = BillBlock::create_block_for_request_to_accept(
            bill_id.clone(),
            &genesis,
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &bcr_keys,
            None,
            &bcr_keys,
            ts,
        )
        .unwrap();

        let block3 = BillBlock::create_block_for_accept(
            bill_id.clone(),
            &block2,
            &BillAcceptBlockData {
                accepter: payer.clone().into(),
                signatory: None,
                signing_timestamp: block2.timestamp + 1000,
                signing_address: empty_address(),
                signer_identity_proof: signed_identity_proof_test().into(),
            },
            &bcr_keys,
            None,
            &bcr_keys,
            block2.timestamp + 1000,
        )
        .unwrap();

        let event1 = generate_test_event(
            &bcr_keys,
            None,
            None,
            as_event_payload(&bill_id, &genesis),
            &bill_id,
        );
        let event2 = generate_test_event(
            &bcr_keys,
            Some(event1.clone()),
            Some(event1.clone()),
            as_event_payload(&bill_id, &block2),
            &bill_id,
        );
        let event3 = generate_test_event(
            &bcr_keys,
            Some(event2.clone()),
            Some(event1.clone()),
            as_event_payload(&bill_id, &block3),
            &bill_id,
        );

        // Invalid tail: replay block #3 as a child of accepted block #3
        let replay_event = generate_test_event(
            &bcr_keys,
            Some(event3.clone()),
            Some(event1.clone()),
            as_event_payload(&bill_id, &block3),
            &bill_id,
        );

        let replay_event_id = replay_event.id.to_string();
        let nostr_events = vec![event1, event2, event3, replay_event];
        let (
            mut bill_chain_store,
            mut bill_store,
            mut contact,
            mut transport,
            mut chain_event_store,
        ) = create_mocks();

        let chain_clone = local_chain.clone();
        bill_chain_store
            .expect_get_chain()
            .once()
            .returning(move |_| Ok(chain_clone.clone()));
        let keys = bcr_keys.clone();
        bill_store
            .expect_get_keys()
            .once()
            .returning(move |_| Ok(keys.clone()));
        bill_store.expect_is_paid().once().returning(|_| Ok(false));
        bill_store
            .expect_invalidate_bill_in_cache()
            .once()
            .returning(|_| Ok(()));
        transport
            .expect_resolve_public_chain()
            .once()
            .returning(move |_, _| Ok(nostr_events.clone()));
        bill_chain_store.expect_remove_blocks_from_height().times(0);
        let block2_hash = block2.hash.clone();
        let block3_hash = block3.hash.clone();
        bill_chain_store
            .expect_add_block()
            .withf(move |_, block| block.hash == block2_hash || block.hash == block3_hash)
            .times(2)
            .returning(|_, _| Ok(()));
        contact.expect_ensure_nostr_contact().returning(|_| ());
        chain_event_store
            .expect_remove_chain_events()
            .once()
            .returning(|_, _| Ok(()));

        // only 3 accepted events - check by id, because valid and invalid #3 have same hash
        chain_event_store
            .expect_add_chain_event()
            .withf(move |event| event.event_id != replay_event_id)
            .times(3)
            .returning(|_| Ok(()));
        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );
        handler
            .resync_chain(&bill_id, true, ResyncMode::Normal)
            .await
            .expect("invalid tail must not poison valid bill prefix");
    }

    #[tokio::test]
    async fn test_failed_bill_block_does_not_mutate_chain() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bill = get_test_bitcredit_bill(&bill_id_test(), &payer, &payee, None, None);
        let chain = get_genesis_chain(Some(bill));
        let bill_keys = BcrKeys::from_private_key(&private_key_test());
        let bill_first_version = chain.get_first_version_bill(&bill_keys).unwrap();
        let invalid_block = BillBlock::create_block_for_reject_to_pay(
            bill_id_test(),
            chain.get_latest_block(),
            &BillRejectBlockData {
                rejecter: payer.into(),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1000,
                signing_address: empty_address(),
                signer_identity_proof: signed_identity_proof_test().into(),
            },
            &bill_keys,
            None,
            &bill_keys,
            chain.get_latest_block().timestamp + 1000,
        )
        .unwrap();

        let before_len = chain.blocks().len();
        let before_tip = chain.get_latest_block().hash.clone();
        let handler = BillChainEventProcessor::new(
            Arc::new(MockBillChainStore::new()),
            Arc::new(MockBillStore::new()),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockNotificationJsonTransport::new()),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let result = handler
            .validate_block_for_chain(
                &bill_id_test(),
                &chain,
                &bill_first_version,
                &bill_keys,
                &invalid_block,
                false,
            )
            .await;

        assert!(result.is_err());
        assert_eq!(chain.blocks().len(), before_len,);
        assert_eq!(chain.get_latest_block().hash, before_tip,);
    }

    #[tokio::test]
    async fn test_resync_chain_resolves_fork_with_truncation() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bcr_keys = BcrKeys::from_private_key(&private_key_test());
        let bill_id = BillId::new(bcr_keys.pub_key(), bitcoin::Network::Testnet);
        let bill = get_test_bitcredit_bill(&bill_id, &payer, &payee, None, None);

        let genesis_chain = get_genesis_chain(Some(bill.clone()));

        let ts = genesis_chain.get_latest_block().timestamp + 1000;

        let local_block = BillBlock::create_block_for_request_to_accept(
            bill_id.clone(),
            genesis_chain.get_latest_block(),
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &bcr_keys,
            None,
            &bcr_keys,
            ts + 2000,
        )
        .unwrap();

        let mut local_chain = genesis_chain.clone();
        local_chain.try_add_block(local_block.clone());

        let remote_block = BillBlock::create_block_for_request_to_accept(
            bill_id.clone(),
            genesis_chain.get_latest_block(),
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &bcr_keys,
            None,
            &bcr_keys,
            ts + 1000,
        )
        .unwrap();

        let mut remote_chain = genesis_chain.clone();
        remote_chain.try_add_block(remote_block.clone());

        let fork_height = local_block.id;

        let event0 = generate_test_event(
            &bcr_keys,
            None,
            None,
            as_event_payload(&bill_id, genesis_chain.get_latest_block()),
            &bill_id,
        );

        let event_remote = generate_test_event(
            &bcr_keys,
            Some(event0.clone()),
            Some(event0.clone()),
            as_event_payload(&bill_id, &remote_block),
            &bill_id,
        );

        let nostr_events = vec![event0.clone(), event_remote.clone()];

        let (
            mut bill_chain_store,
            mut bill_store,
            mut contact,
            mut transport,
            mut chain_event_store,
        ) = create_mocks();

        bill_store
            .expect_invalidate_bill_in_cache()
            .returning(|_| Ok(()));
        bill_store.expect_is_paid().returning(|_| Ok(false));
        bill_store
            .expect_get_keys()
            .returning(move |_| Ok(bcr_keys.clone()));

        let local_chain_clone = local_chain.clone();
        bill_chain_store
            .expect_get_chain()
            .returning(move |_| Ok(local_chain_clone.clone()));

        transport
            .expect_resolve_public_chain()
            .with(eq(bill_id.to_string()), eq(BlockchainType::Bill))
            .returning(move |_, _| Ok(nostr_events.clone()))
            .once();

        bill_chain_store
            .expect_remove_blocks_from_height()
            .with(eq(bill_id.clone()), eq(fork_height))
            .times(1)
            .returning(|_, _| Ok(()));

        bill_chain_store
            .expect_add_block()
            .with(eq(bill_id.clone()), eq(remote_block.clone()))
            .times(1)
            .returning(|_, _| Ok(()));

        contact.expect_ensure_nostr_contact().returning(|_| ());

        chain_event_store
            .expect_remove_chain_events()
            .returning(|_, _| Ok(()));

        chain_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()))
            .times(0..);

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .resync_chain(&bill_id, true, ResyncMode::Normal)
            .await
            .expect("resync should succeed with fork resolution");
    }

    #[tokio::test]
    async fn test_resync_chain_skips_non_preferred_chain() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bcr_keys = BcrKeys::from_private_key(&private_key_test());
        let bill_id = BillId::new(bcr_keys.pub_key(), bitcoin::Network::Testnet);
        let bill = get_test_bitcredit_bill(&bill_id, &payer, &payee, None, None);

        let genesis_chain = get_genesis_chain(Some(bill.clone()));

        let ts = genesis_chain.get_latest_block().timestamp + 1000;

        let local_block = BillBlock::create_block_for_request_to_accept(
            bill_id.clone(),
            genesis_chain.get_latest_block(),
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &bcr_keys,
            None,
            &bcr_keys,
            ts + 1000,
        )
        .unwrap();

        let mut local_chain = genesis_chain.clone();
        local_chain.try_add_block(local_block.clone());

        let remote_block = BillBlock::create_block_for_request_to_accept(
            bill_id.clone(),
            genesis_chain.get_latest_block(),
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &bcr_keys,
            None,
            &bcr_keys,
            ts + 2000,
        )
        .unwrap();

        let event0 = generate_test_event(
            &bcr_keys,
            None,
            None,
            as_event_payload(&bill_id, genesis_chain.get_latest_block()),
            &bill_id,
        );

        let event_remote = generate_test_event(
            &bcr_keys,
            Some(event0.clone()),
            Some(event0.clone()),
            as_event_payload(&bill_id, &remote_block),
            &bill_id,
        );

        let nostr_events = vec![event0.clone(), event_remote.clone()];

        let (mut bill_chain_store, mut bill_store, contact, mut transport, mut chain_event_store) =
            create_mocks();

        bill_store
            .expect_invalidate_bill_in_cache()
            .returning(|_| Ok(()));
        bill_store.expect_is_paid().returning(|_| Ok(false));
        bill_store
            .expect_get_keys()
            .returning(move |_| Ok(bcr_keys.clone()));

        let local_chain_clone = local_chain.clone();
        bill_chain_store
            .expect_get_chain()
            .returning(move |_| Ok(local_chain_clone.clone()));

        transport
            .expect_resolve_public_chain()
            .with(eq(bill_id.to_string()), eq(BlockchainType::Bill))
            .returning(move |_, _| Ok(nostr_events.clone()))
            .once();

        bill_chain_store.expect_remove_blocks_from_height().times(0);

        bill_chain_store.expect_add_block().times(0);

        chain_event_store
            .expect_remove_chain_events()
            .returning(|_, _| Ok(()));

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let result = handler
            .resync_chain(&bill_id, true, ResyncMode::Normal)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_resync_chain_nostr_authoritative_removes_local_only_block() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bcr_keys = BcrKeys::from_private_key(&private_key_test());
        let bill_id = BillId::new(bcr_keys.pub_key(), bitcoin::Network::Testnet);
        let bill = get_test_bitcredit_bill(&bill_id, &payer, &payee, None, None);

        let genesis_chain = get_genesis_chain(Some(bill.clone()));

        // Local chain has a block that was not published to Nostr
        let ts = genesis_chain.get_latest_block().timestamp + 1000;
        let local_only_block = BillBlock::create_block_for_request_to_accept(
            bill_id.clone(),
            genesis_chain.get_latest_block(),
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &bcr_keys,
            None,
            &bcr_keys,
            ts,
        )
        .unwrap();

        let mut local_chain = genesis_chain.clone();
        assert!(local_chain.try_add_block(local_only_block.clone()));

        let event0 = generate_test_event(
            &bcr_keys,
            None,
            None,
            as_event_payload(&bill_id, genesis_chain.get_latest_block()),
            &bill_id,
        );
        let nostr_events = vec![event0];

        let (
            mut bill_chain_store,
            mut bill_store,
            mut contact,
            mut transport,
            mut chain_event_store,
        ) = create_mocks();
        contact.expect_ensure_nostr_contact().returning(|_| ());

        bill_store
            .expect_get_keys()
            .returning(move |_| Ok(bcr_keys.clone()));

        bill_store.expect_is_paid().returning(|_| Ok(false));

        bill_store
            .expect_invalidate_bill_in_cache()
            .times(1)
            .returning(|_| Ok(()));

        let local_chain_clone = local_chain.clone();
        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id.clone()))
            .returning(move |_| Ok(local_chain_clone.clone()));

        transport
            .expect_resolve_public_chain()
            .with(eq(bill_id.to_string()), eq(BlockchainType::Bill))
            .returning(move |_, _| Ok(nostr_events.clone()))
            .once();

        // local-only block is removed
        bill_chain_store
            .expect_remove_blocks_from_height()
            .with(eq(bill_id.clone()), eq(local_only_block.id))
            .times(1)
            .returning(|_, _| Ok(()));

        bill_chain_store.expect_add_block().times(0);

        chain_event_store
            .expect_remove_chain_events()
            .with(eq(bill_id.to_string()), eq(BlockchainType::Bill))
            .times(1)
            .returning(|_, _| Ok(()));

        chain_event_store
            .expect_add_chain_event()
            .times(1)
            .returning(|_| Ok(()));

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .resync_chain(&bill_id, true, ResyncMode::NostrAuthoritative)
            .await
            .expect("Nostr-authoritative resync should remove local-only blocks");
    }

    #[tokio::test]
    async fn test_resync_chain_nostr_authoritative_rebuilds_chain_events_with_identical_blocks() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bcr_keys = BcrKeys::from_private_key(&private_key_test());
        let bill_id = BillId::new(bcr_keys.pub_key(), bitcoin::Network::Testnet);
        let bill = get_test_bitcredit_bill(&bill_id, &payer, &payee, None, None);

        let local_chain = get_genesis_chain(Some(bill.clone()));

        let event0 = generate_test_event(
            &bcr_keys,
            None,
            None,
            as_event_payload(&bill_id, local_chain.get_latest_block()),
            &bill_id,
        );
        let nostr_events = vec![event0];

        let (mut bill_chain_store, mut bill_store, contact, mut transport, mut chain_event_store) =
            create_mocks();

        bill_store
            .expect_get_keys()
            .returning(move |_| Ok(bcr_keys.clone()));

        bill_store.expect_is_paid().returning(|_| Ok(false));

        bill_store
            .expect_invalidate_bill_in_cache()
            .times(1)
            .returning(|_| Ok(()));

        let local_chain_clone = local_chain.clone();
        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id.clone()))
            .returning(move |_| Ok(local_chain_clone.clone()));

        transport
            .expect_resolve_public_chain()
            .with(eq(bill_id.to_string()), eq(BlockchainType::Bill))
            .returning(move |_, _| Ok(nostr_events.clone()))
            .once();

        bill_chain_store.expect_remove_blocks_from_height().times(0);

        bill_chain_store.expect_add_block().times(0);

        // Chain events ARE refreshed, even if the chain doesn't change
        chain_event_store
            .expect_remove_chain_events()
            .with(eq(bill_id.to_string()), eq(BlockchainType::Bill))
            .times(1)
            .returning(|_, _| Ok(()));

        chain_event_store
            .expect_add_chain_event()
            .times(1)
            .returning(|_| Ok(()));

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .resync_chain(&bill_id, true, ResyncMode::NostrAuthoritative)
            .await
            .expect("Nostr-authoritative resync should rebuild chain events");
    }

    #[tokio::test]
    async fn test_resync_chain_nostr_authoritative_adds_remote_blocks() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bcr_keys = BcrKeys::from_private_key(&private_key_test());
        let bill_id = BillId::new(bcr_keys.pub_key(), bitcoin::Network::Testnet);
        let bill = get_test_bitcredit_bill(&bill_id, &payer, &payee, None, None);

        let local_chain = get_genesis_chain(Some(bill.clone()));

        let ts = local_chain.get_latest_block().timestamp + 1000;
        let remote_block = BillBlock::create_block_for_request_to_accept(
            bill_id.clone(),
            local_chain.get_latest_block(),
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &bcr_keys,
            None,
            &bcr_keys,
            ts,
        )
        .unwrap();

        let event0 = generate_test_event(
            &bcr_keys,
            None,
            None,
            as_event_payload(&bill_id, local_chain.get_latest_block()),
            &bill_id,
        );

        let event1 = generate_test_event(
            &bcr_keys,
            Some(event0.clone()),
            Some(event0.clone()),
            as_event_payload(&bill_id, &remote_block),
            &bill_id,
        );

        let nostr_events = vec![event0, event1];

        let (
            mut bill_chain_store,
            mut bill_store,
            mut contact,
            mut transport,
            mut chain_event_store,
        ) = create_mocks();

        bill_store
            .expect_get_keys()
            .returning(move |_| Ok(bcr_keys.clone()));

        bill_store.expect_is_paid().returning(|_| Ok(false));

        bill_store
            .expect_invalidate_bill_in_cache()
            .returning(|_| Ok(()));

        let local_chain_clone = local_chain.clone();
        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id.clone()))
            .returning(move |_| Ok(local_chain_clone.clone()));

        transport
            .expect_resolve_public_chain()
            .with(eq(bill_id.to_string()), eq(BlockchainType::Bill))
            .returning(move |_, _| Ok(nostr_events.clone()))
            .once();

        // nothing removed, because first blocks are identical
        bill_chain_store.expect_remove_blocks_from_height().times(0);

        // new blocks are added
        bill_chain_store
            .expect_add_block()
            .with(eq(bill_id.clone()), eq(remote_block.clone()))
            .times(1)
            .returning(|_, _| Ok(()));

        contact.expect_ensure_nostr_contact().returning(|_| ());

        chain_event_store
            .expect_remove_chain_events()
            .with(eq(bill_id.to_string()), eq(BlockchainType::Bill))
            .times(1)
            .returning(|_, _| Ok(()));

        // new chain events are added
        chain_event_store
            .expect_add_chain_event()
            .times(2)
            .returning(|_| Ok(()));

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .resync_chain(&bill_id, true, ResyncMode::NostrAuthoritative)
            .await
            .expect("Nostr-authoritative resync should append missing remote blocks");
    }

    #[tokio::test]
    async fn test_resync_chain_nostr_authoritative_replaces_non_preferred_remote_fork() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let bcr_keys = BcrKeys::from_private_key(&private_key_test());
        let bill_id = BillId::new(bcr_keys.pub_key(), bitcoin::Network::Testnet);
        let bill = get_test_bitcredit_bill(&bill_id, &payer, &payee, None, None);

        let genesis_chain = get_genesis_chain(Some(bill.clone()));
        let ts = genesis_chain.get_latest_block().timestamp + 1000;

        // Local block has the earlier timestamp and would therefore normally win
        let local_block = BillBlock::create_block_for_request_to_accept(
            bill_id.clone(),
            genesis_chain.get_latest_block(),
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &bcr_keys,
            None,
            &bcr_keys,
            ts + 1000,
        )
        .unwrap();

        let mut local_chain = genesis_chain.clone();
        assert!(local_chain.try_add_block(local_block.clone()));

        // Remote fork has a later timestamp, so Normal mode would reject it
        let remote_block = BillBlock::create_block_for_request_to_accept(
            bill_id.clone(),
            genesis_chain.get_latest_block(),
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &bcr_keys,
            None,
            &bcr_keys,
            ts + 2000,
        )
        .unwrap();

        let event0 = generate_test_event(
            &bcr_keys,
            None,
            None,
            as_event_payload(&bill_id, genesis_chain.get_latest_block()),
            &bill_id,
        );

        let event_remote = generate_test_event(
            &bcr_keys,
            Some(event0.clone()),
            Some(event0.clone()),
            as_event_payload(&bill_id, &remote_block),
            &bill_id,
        );

        let nostr_events = vec![event0, event_remote];

        let (
            mut bill_chain_store,
            mut bill_store,
            mut contact,
            mut transport,
            mut chain_event_store,
        ) = create_mocks();

        bill_store
            .expect_get_keys()
            .returning(move |_| Ok(bcr_keys.clone()));

        bill_store.expect_is_paid().returning(|_| Ok(false));

        bill_store
            .expect_invalidate_bill_in_cache()
            .returning(|_| Ok(()));

        let local_chain_clone = local_chain.clone();
        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id.clone()))
            .returning(move |_| Ok(local_chain_clone.clone()));

        transport
            .expect_resolve_public_chain()
            .with(eq(bill_id.to_string()), eq(BlockchainType::Bill))
            .returning(move |_, _| Ok(nostr_events.clone()))
            .once();

        // replace local blocks from fork height
        bill_chain_store
            .expect_remove_blocks_from_height()
            .with(eq(bill_id.clone()), eq(local_block.id))
            .times(1)
            .returning(|_, _| Ok(()));

        bill_chain_store
            .expect_add_block()
            .with(eq(bill_id.clone()), eq(remote_block.clone()))
            .times(1)
            .returning(|_, _| Ok(()));

        contact.expect_ensure_nostr_contact().returning(|_| ());

        chain_event_store
            .expect_remove_chain_events()
            .with(eq(bill_id.to_string()), eq(BlockchainType::Bill))
            .times(1)
            .returning(|_, _| Ok(()));

        chain_event_store
            .expect_add_chain_event()
            .times(2)
            .returning(|_| Ok(()));

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .resync_chain(&bill_id, true, ResyncMode::NostrAuthoritative)
            .await
            .expect("Nostr-authoritative resync should replace local fork");
    }

    #[tokio::test]
    async fn test_add_new_chain_anchors_inbound_bill_files() {
        let mut bill = get_baseline_bill(&bill_id_test());
        let attachment = File {
            name: Name::new("attachment.pdf").unwrap(),
            hash: Sha256Hash::new("bill_attachment_file_hash_1234567890"),
            nostr_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .parse()
                .unwrap(),
        };
        bill.files = vec![attachment.clone()];

        let chain = get_genesis_chain(Some(bill));
        let issue_block = chain.get_first_block().clone();
        let keys = get_bill_keys();

        let mut bill_chain_store = MockBillChainStore::new();
        let mut bill_store = MockBillStore::new();
        let mut file_reference_store = MockFileReferenceStore::new();
        let mut contact = MockNostrContactProcessorApi::new();

        bill_chain_store
            .expect_add_block()
            .with(eq(bill_id_test()), always())
            .returning(|_, _| Ok(()))
            .once();
        bill_store
            .expect_save_keys()
            .returning(|_, _| Ok(()))
            .once();
        contact
            .expect_ensure_nostr_contact()
            .returning(|_| ())
            .times(2);

        file_reference_store
            .expect_upsert()
            .withf(
                move |hash: &Sha256Hash,
                      _nostr_hash: &bitcoin::hashes::sha256::Hash,
                      name: &Option<Name>,
                      server_urls: &Vec<url::Url>,
                      is_important: &Option<bool>,
                      context: &Vec<FileReferenceContext>| {
                    *hash == attachment.hash
                        && *name == Some(attachment.name.clone())
                        && server_urls.is_empty()
                        && *is_important == Some(true)
                        && context
                            == &vec![FileReferenceContext::Bill {
                                bill_id: bill_id_test().to_string(),
                                field: "files".to_string(),
                            }]
                },
            )
            .returning(
                |hash: &Sha256Hash,
                 nostr_hash: &bitcoin::hashes::sha256::Hash,
                 name: Option<Name>,
                 _: Vec<url::Url>,
                 is_important: Option<bool>,
                 context: Vec<FileReferenceContext>| {
                    let mut file_ref = FileReference::new(hash.clone(), *nostr_hash, name);
                    file_ref.is_important = is_important.unwrap_or(false);
                    file_ref.context = context;
                    Ok(file_ref)
                },
            )
            .once();

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(file_reference_store),
            Arc::new(contact),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockNotificationJsonTransport::new()),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let result = handler.add_new_chain(vec![issue_block], &keys).await;

        assert!(result.is_ok());
    }

    fn create_mocks() -> (
        MockBillChainStore,
        MockBillStore,
        MockNostrContactProcessorApi,
        MockNotificationJsonTransport,
        MockNostrChainEventStore,
    ) {
        (
            MockBillChainStore::new(),
            MockBillStore::new(),
            MockNostrContactProcessorApi::new(),
            MockNotificationJsonTransport::new(),
            MockNostrChainEventStore::new(),
        )
    }

    fn test_privkeys(network: bitcoin::Network) -> (PrivateKey, PrivateKey) {
        let sk1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk2 = SecretKey::from_slice(&[2u8; 32]).unwrap();

        (PrivateKey::new(sk1, network), PrivateKey::new(sk2, network))
    }

    fn test_pubkeys(network: bitcoin::Network) -> (PublicKey, PublicKey) {
        let (pk1, pk2) = test_privkeys(network);
        (
            pk1.public_key(SECP256K1).inner,
            pk2.public_key(SECP256K1).inner,
        )
    }

    #[tokio::test]
    async fn test_validate_payment_address_accepts_matching_address() {
        let (bill_chain_store, _, _, _, _) = create_mocks();
        let network = bitcoin::Network::Testnet;
        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(MockBillStore::new()),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockNotificationJsonTransport::new()),
            Arc::new(MockMintClient::new()),
            network,
            Arc::new(test_cfg()),
        );

        let block_id = BlockId::first().add(6);
        let previous_hash =
            Sha256Hash::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let (bill_pub, holder_pub) = test_pubkeys(network);

        let tweak_hash = btc::calculate_tweak_hash_for_payment_request(
            BillOpCode::RequestToPay,
            &block_id,
            &previous_hash,
        )
        .unwrap();

        let address =
            btc::get_address_to_pay(&bill_pub, &holder_pub, &tweak_hash, network).unwrap();

        let result = handler
            .validate_payment_address_for_payment_request(
                &bill_id_test(),
                BillOpCode::RequestToPay,
                &block_id,
                &previous_hash,
                &bill_pub,
                &holder_pub,
                network,
                &address,
                &None,
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_payment_address_mint_case() {
        let (bill_chain_store, _, _, _, _) = create_mocks();
        let network = bitcoin::Network::Testnet;
        let mut mock_mint_client = MockMintClient::new();
        mock_mint_client
            .expect_validate_payment_address_from_mint()
            .returning(|_, _, _, _, _| Ok(()))
            .times(1);
        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(MockBillStore::new()),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockNotificationJsonTransport::new()),
            Arc::new(mock_mint_client),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        let block_id = BlockId::first().add(6);
        let previous_hash =
            Sha256Hash::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let (bill_pub, holder_pub) = test_pubkeys(network);

        let address = valid_payment_address_testnet();

        let result = handler
            .validate_payment_address_for_payment_request(
                &bill_id_test(),
                BillOpCode::RequestToPay,
                &block_id,
                &previous_hash,
                &bill_pub,
                &holder_pub,
                network,
                &address,
                &Some(BillParticipant::Ident(
                    BillIdentParticipant::new(get_baseline_identity().identity).unwrap(),
                )),
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_payment_address_rejects_non_matching_address() {
        let (bill_chain_store, _, _, _, _) = create_mocks();
        let network = bitcoin::Network::Testnet;
        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(MockBillStore::new()),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockNotificationJsonTransport::new()),
            Arc::new(MockMintClient::new()),
            network,
            Arc::new(test_cfg()),
        );

        let block_id = BlockId::first().add(6);
        let previous_hash =
            Sha256Hash::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let (bill_pub, holder_pub) = test_pubkeys(network);

        let wrong_address = BitcoinAddress::from_str(
            "tb1p98hgytlecct3qzfmd9qnf05q03ql032xvpdg9kpwfftej2t95t8s0eyx5k",
        )
        .unwrap();

        let err = handler
            .validate_payment_address_for_payment_request(
                &bill_id_test(),
                BillOpCode::RequestToPay,
                &block_id,
                &previous_hash,
                &bill_pub,
                &holder_pub,
                network,
                &wrong_address,
                &None,
            )
            .await
            .expect_err("wrong address should fail");

        match err {
            Error::Crypto(msg) => assert!(msg.contains("don't match")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_validate_payment_address_rejects_when_op_changes() {
        let (bill_chain_store, _, _, _, _) = create_mocks();
        let network = bitcoin::Network::Testnet;
        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(MockBillStore::new()),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(MockNostrContactProcessorApi::new()),
            Arc::new(MockNostrChainEventStore::new()),
            Arc::new(MockNotificationJsonTransport::new()),
            Arc::new(MockMintClient::new()),
            network,
            Arc::new(test_cfg()),
        );

        let block_id = BlockId::first().add(6);
        let previous_hash =
            Sha256Hash::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let (bill_pub, holder_pub) = test_pubkeys(network);

        let tweak_hash = btc::calculate_tweak_hash_for_payment_request(
            BillOpCode::RequestToPay,
            &block_id,
            &previous_hash,
        )
        .unwrap();

        let address =
            btc::get_address_to_pay(&bill_pub, &holder_pub, &tweak_hash, network).unwrap();

        let err = handler
            .validate_payment_address_for_payment_request(
                &bill_id_test(),
                BillOpCode::OfferToSell,
                &block_id,
                &previous_hash,
                &bill_pub,
                &holder_pub,
                network,
                &address,
                &None,
            )
            .await
            .expect_err("different op should fail");

        match err {
            Error::Crypto(msg) => assert!(msg.contains("don't match")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_resync_chain_only_missing_metadata_restores_missing_event() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();

        let bcr_keys = BcrKeys::from_private_key(&private_key_test());
        let bill_id = BillId::new(bcr_keys.pub_key(), bitcoin::Network::Testnet);
        let bill = get_test_bitcredit_bill(&bill_id, &payer, &payee, None, None);

        let genesis_chain = get_genesis_chain(Some(bill));

        let ts = genesis_chain.get_latest_block().timestamp + 1000;
        let block1 = BillBlock::create_block_for_request_to_accept(
            bill_id.clone(),
            genesis_chain.get_latest_block(),
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &bcr_keys,
            None,
            &bcr_keys,
            ts,
        )
        .unwrap();

        let mut local_chain = genesis_chain.clone();
        assert!(local_chain.try_add_block(block1.clone()));

        let genesis_block = genesis_chain.get_latest_block().clone();

        let event0 = generate_test_event(
            &bcr_keys,
            None,
            None,
            as_event_payload(&bill_id, &genesis_block),
            &bill_id,
        );

        let event1 = generate_test_event(
            &bcr_keys,
            Some(event0.clone()),
            Some(event0.clone()),
            as_event_payload(&bill_id, &block1),
            &bill_id,
        );

        let nostr_events = vec![event0.clone(), event1.clone()];

        // Genesis metadata already exists locally.
        let existing_genesis_event = EventContainer::new(
            event0.clone(),
            None,
            None,
            BlockData::Bill(genesis_block.clone()),
        )
        .as_chain_store_event(
            &bill_id.to_string(),
            BlockchainType::Bill,
            genesis_block.id.inner() as usize,
        );

        let (mut bill_chain_store, mut bill_store, contact, mut transport, mut chain_event_store) =
            create_mocks();

        let local_chain_clone = local_chain.clone();
        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id.clone()))
            .times(1)
            .returning(move |_| Ok(local_chain_clone.clone()));

        // Metadata-only sync must never alter the bill blockchain
        bill_chain_store.expect_remove_blocks_from_height().times(0);

        bill_chain_store.expect_add_block().times(0);

        let keys_for_store = bcr_keys.clone();
        bill_store
            .expect_get_keys()
            .times(1)
            .returning(move |_| Ok(keys_for_store.clone()));

        bill_store
            .expect_is_paid()
            .times(1)
            .returning(|_| Ok(false));

        // Metadata changes don't affect cached bill state
        bill_store.expect_invalidate_bill_in_cache().times(0);

        transport
            .expect_resolve_public_chain()
            .with(eq(bill_id.to_string()), eq(BlockchainType::Bill))
            .times(1)
            .returning(move |_, _| Ok(nostr_events.clone()));

        chain_event_store
            .expect_find_chain_events()
            .with(eq(bill_id.to_string()), eq(BlockchainType::Bill))
            .times(1)
            .returning(move |_, _| Ok(vec![existing_genesis_event.clone()]));

        // Metadata-only recovery never clear existing metadata
        chain_event_store.expect_remove_chain_events().times(0);

        let expected_hash = block1.hash.clone();
        let expected_height = block1.id.inner() as usize;

        chain_event_store
            .expect_add_chain_event()
            .withf(move |event| {
                event.block_hash == expected_hash && event.block_height == expected_height
            })
            .times(1)
            .returning(|_| Ok(()));

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .resync_chain(
                &bill_id,
                true,
                ResyncMode::OnlyMissingMetadata {
                    up_to_hash: local_chain.get_latest_block().hash().to_owned(),
                },
            )
            .await
            .expect("missing Nostr metadata should be restored");
    }

    #[tokio::test]
    async fn test_resync_chain_only_missing_metadata_does_not_rewrite_existing_event() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();

        let bcr_keys = BcrKeys::from_private_key(&private_key_test());
        let bill_id = BillId::new(bcr_keys.pub_key(), bitcoin::Network::Testnet);
        let bill = get_test_bitcredit_bill(&bill_id, &payer, &payee, None, None);

        let local_chain = get_genesis_chain(Some(bill));
        let genesis = local_chain.get_latest_block().clone();

        let event0 = generate_test_event(
            &bcr_keys,
            None,
            None,
            as_event_payload(&bill_id, &genesis),
            &bill_id,
        );

        let existing_event =
            EventContainer::new(event0.clone(), None, None, BlockData::Bill(genesis.clone()))
                .as_chain_store_event(
                    &bill_id.to_string(),
                    BlockchainType::Bill,
                    genesis.id.inner() as usize,
                );

        let (mut bill_chain_store, mut bill_store, contact, mut transport, mut chain_event_store) =
            create_mocks();

        let local_chain_clone = local_chain.clone();
        bill_chain_store
            .expect_get_chain()
            .times(1)
            .returning(move |_| Ok(local_chain_clone.clone()));

        bill_chain_store.expect_add_block().times(0);
        bill_chain_store.expect_remove_blocks_from_height().times(0);

        let keys_for_store = bcr_keys.clone();
        bill_store
            .expect_get_keys()
            .times(1)
            .returning(move |_| Ok(keys_for_store.clone()));

        bill_store.expect_is_paid().returning(|_| Ok(false));
        bill_store.expect_invalidate_bill_in_cache().times(0);

        transport
            .expect_resolve_public_chain()
            .returning(move |_, _| Ok(vec![event0.clone()]))
            .times(1);

        chain_event_store
            .expect_find_chain_events()
            .times(1)
            .returning(move |_, _| Ok(vec![existing_event.clone()]));

        chain_event_store.expect_add_chain_event().times(0);

        chain_event_store.expect_remove_chain_events().times(0);

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .resync_chain(
                &bill_id,
                true,
                ResyncMode::OnlyMissingMetadata {
                    up_to_hash: genesis.hash().to_owned(),
                },
            )
            .await
            .expect("should be a no-op");
    }

    #[tokio::test]
    async fn test_resync_chain_only_missing_metadata_ignores_remote_tail() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();

        let bcr_keys = BcrKeys::from_private_key(&private_key_test());
        let bill_id = BillId::new(bcr_keys.pub_key(), bitcoin::Network::Testnet);
        let bill = get_test_bitcredit_bill(&bill_id, &payer, &payee, None, None);

        let local_chain = get_genesis_chain(Some(bill));
        let genesis = local_chain.get_latest_block().clone();

        let ts = genesis.timestamp + 1000;
        let remote_block = BillBlock::create_block_for_request_to_accept(
            bill_id.clone(),
            &genesis,
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &bcr_keys,
            None,
            &bcr_keys,
            ts,
        )
        .unwrap();

        let event0 = generate_test_event(
            &bcr_keys,
            None,
            None,
            as_event_payload(&bill_id, &genesis),
            &bill_id,
        );

        let event1 = generate_test_event(
            &bcr_keys,
            Some(event0.clone()),
            Some(event0.clone()),
            as_event_payload(&bill_id, &remote_block),
            &bill_id,
        );

        let (mut bill_chain_store, mut bill_store, contact, mut transport, mut chain_event_store) =
            create_mocks();

        let local_chain_clone = local_chain.clone();
        bill_chain_store
            .expect_get_chain()
            .times(1)
            .returning(move |_| Ok(local_chain_clone.clone()));

        bill_chain_store.expect_add_block().times(0);
        bill_chain_store.expect_remove_blocks_from_height().times(0);

        let keys_for_store = bcr_keys.clone();
        bill_store
            .expect_get_keys()
            .times(1)
            .returning(move |_| Ok(keys_for_store.clone()));

        bill_store.expect_is_paid().returning(|_| Ok(false));
        bill_store.expect_invalidate_bill_in_cache().times(0);

        transport
            .expect_resolve_public_chain()
            .returning(move |_, _| Ok(vec![event0.clone(), event1.clone()]))
            .times(1);

        chain_event_store
            .expect_find_chain_events()
            .times(1)
            .returning(|_, _| Ok(vec![]));

        chain_event_store.expect_remove_chain_events().times(0);

        let genesis_hash = genesis.hash.clone();

        // The remote-only second block must not be added
        chain_event_store
            .expect_add_chain_event()
            .withf(move |event| event.block_hash == genesis_hash)
            .times(1)
            .returning(|_| Ok(()));

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .resync_chain(
                &bill_id,
                true,
                ResyncMode::OnlyMissingMetadata {
                    up_to_hash: local_chain.get_latest_block().hash().to_owned(),
                },
            )
            .await
            .expect("works");
    }

    #[tokio::test]
    async fn test_resync_chain_only_missing_metadata_skips_non_matching_candidate() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();

        let bcr_keys = BcrKeys::from_private_key(&private_key_test());
        let bill_id = BillId::new(bcr_keys.pub_key(), bitcoin::Network::Testnet);
        let bill = get_test_bitcredit_bill(&bill_id, &payer, &payee, None, None);

        let genesis_chain = get_genesis_chain(Some(bill));
        let genesis = genesis_chain.get_latest_block().clone();

        // Invalid chain - local branch has later timestamp
        let matching_ts = genesis.timestamp + 2000;
        let matching_block = BillBlock::create_block_for_request_to_accept(
            bill_id.clone(),
            &genesis,
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: matching_ts,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: matching_ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &bcr_keys,
            None,
            &bcr_keys,
            matching_ts,
        )
        .unwrap();

        let mut local_chain = genesis_chain.clone();
        assert!(local_chain.try_add_block(matching_block.clone()));

        // Remote Nostr branch sorts before the matching branch because
        // its tip timestamp is earlier
        let competing_ts = genesis.timestamp + 1000;
        let competing_block = BillBlock::create_block_for_request_to_accept(
            bill_id.clone(),
            &genesis,
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: competing_ts,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: competing_ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &bcr_keys,
            None,
            &bcr_keys,
            competing_ts,
        )
        .unwrap();

        let event0 = generate_test_event(
            &bcr_keys,
            None,
            None,
            as_event_payload(&bill_id, &genesis),
            &bill_id,
        );

        let competing_event = generate_test_event(
            &bcr_keys,
            Some(event0.clone()),
            Some(event0.clone()),
            as_event_payload(&bill_id, &competing_block),
            &bill_id,
        );

        let matching_event = generate_test_event(
            &bcr_keys,
            Some(event0.clone()),
            Some(event0.clone()),
            as_event_payload(&bill_id, &matching_block),
            &bill_id,
        );

        let existing_genesis =
            EventContainer::new(event0.clone(), None, None, BlockData::Bill(genesis.clone()))
                .as_chain_store_event(
                    &bill_id.to_string(),
                    BlockchainType::Bill,
                    genesis.id.inner() as usize,
                );

        let (mut bill_chain_store, mut bill_store, contact, mut transport, mut chain_event_store) =
            create_mocks();

        let local_chain_clone = local_chain.clone();
        bill_chain_store
            .expect_get_chain()
            .times(1)
            .returning(move |_| Ok(local_chain_clone.clone()));

        bill_chain_store.expect_add_block().times(0);
        bill_chain_store.expect_remove_blocks_from_height().times(0);

        let keys_for_store = bcr_keys.clone();
        bill_store
            .expect_get_keys()
            .times(1)
            .returning(move |_| Ok(keys_for_store.clone()));

        bill_store.expect_is_paid().returning(|_| Ok(false));
        bill_store.expect_invalidate_bill_in_cache().times(0);

        transport
            .expect_resolve_public_chain()
            .returning(move |_, _| {
                Ok(vec![
                    event0.clone(),
                    competing_event.clone(),
                    matching_event.clone(),
                ])
            })
            .times(1);

        // once, because non-matching candidate gets skipped
        chain_event_store
            .expect_find_chain_events()
            .times(1)
            .returning(move |_, _| Ok(vec![existing_genesis.clone()]));

        let matching_hash = matching_block.hash.clone();

        chain_event_store
            .expect_add_chain_event()
            .withf(move |event| event.block_hash == matching_hash)
            .times(1)
            .returning(|_| Ok(()));

        chain_event_store.expect_remove_chain_events().times(0);

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .resync_chain(
                &bill_id,
                true,
                ResyncMode::OnlyMissingMetadata {
                    up_to_hash: local_chain.get_latest_block().hash().to_owned(),
                },
            )
            .await
            .expect("matching Nostr branch should be found");
    }

    #[tokio::test]
    async fn test_resync_chain_only_missing_metadata_matches_up_to_hash() {
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let payee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();

        let bcr_keys = BcrKeys::from_private_key(&private_key_test());
        let bill_id = BillId::new(bcr_keys.pub_key(), bitcoin::Network::Testnet);
        let bill = get_test_bitcredit_bill(&bill_id, &payer, &payee, None, None);

        let genesis_chain = get_genesis_chain(Some(bill));
        let genesis = genesis_chain.get_latest_block().clone();

        // #2: this is the missing block whose Nostr metadata we want to recover
        let ts = genesis.timestamp + 1000;
        let predecessor = BillBlock::create_block_for_request_to_accept(
            bill_id.clone(),
            &genesis,
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.clone().into()),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &bcr_keys,
            None,
            &bcr_keys,
            ts,
        )
        .unwrap();

        // #3: already persisted locally, but not published to Nostr yet
        let new_local_block = BillBlock::create_block_for_accept(
            bill_id.clone(),
            &predecessor,
            &BillAcceptBlockData {
                accepter: payer.clone().into(),
                signatory: None,
                signing_timestamp: ts + 1000,
                signing_address: empty_address(),
                signer_identity_proof: signed_identity_proof_test().into(),
            },
            &bcr_keys,
            None,
            &bcr_keys,
            ts + 1000,
        )
        .unwrap();

        let mut local_chain = genesis_chain.clone();
        assert!(local_chain.try_add_block(predecessor.clone()));
        assert!(local_chain.try_add_block(new_local_block.clone()));

        // Nostr only has #1 and #2
        let event0 = generate_test_event(
            &bcr_keys,
            None,
            None,
            as_event_payload(&bill_id, &genesis),
            &bill_id,
        );

        let event1 = generate_test_event(
            &bcr_keys,
            Some(event0.clone()),
            Some(event0.clone()),
            as_event_payload(&bill_id, &predecessor),
            &bill_id,
        );

        let nostr_events = vec![event0.clone(), event1];

        let existing_genesis_event = EventContainer {
            event: event0,
            block: BlockData::Bill(genesis.clone()),
            root_id: None,
            reply_id: None,
            children: vec![],
            block_height: 1,
        }
        .as_chain_store_event(
            &bill_id.to_string(),
            BlockchainType::Bill,
            genesis.id.inner() as usize,
        );

        let (mut bill_chain_store, mut bill_store, contact, mut transport, mut chain_event_store) =
            create_mocks();

        let local_chain_clone = local_chain.clone();
        bill_chain_store
            .expect_get_chain()
            .with(eq(bill_id.clone()))
            .times(1)
            .returning(move |_| Ok(local_chain_clone.clone()));

        // Metadata-only recovery must not mutate the bill chain.
        bill_chain_store.expect_remove_blocks_from_height().times(0);

        bill_chain_store.expect_add_block().times(0);

        let keys = bcr_keys.clone();
        bill_store
            .expect_get_keys()
            .times(1)
            .returning(move |_| Ok(keys.clone()));

        bill_store
            .expect_is_paid()
            .times(1)
            .returning(|_| Ok(false));

        bill_store.expect_invalidate_bill_in_cache().times(0);

        transport
            .expect_resolve_public_chain()
            .with(eq(bill_id.to_string()), eq(BlockchainType::Bill))
            .times(1)
            .returning(move |_, _| Ok(nostr_events.clone()));

        // Genesis metadata exists, prev block metadata is missing
        chain_event_store
            .expect_find_chain_events()
            .with(eq(bill_id.to_string()), eq(BlockchainType::Bill))
            .times(1)
            .returning(move |_, _| Ok(vec![existing_genesis_event.clone()]));

        chain_event_store.expect_remove_chain_events().times(0);

        let predecessor_hash = predecessor.hash.clone();
        let new_local_block_hash = new_local_block.hash.clone();

        // Only #2 should be restored, #3 should not be considered since it's only local
        chain_event_store
            .expect_add_chain_event()
            .withf(move |event| {
                event.block_hash == predecessor_hash && event.block_hash != new_local_block_hash
            })
            .times(1)
            .returning(|_| Ok(()));

        let handler = BillChainEventProcessor::new(
            Arc::new(bill_chain_store),
            Arc::new(bill_store),
            Arc::new(MockFileReferenceStore::new()),
            Arc::new(contact),
            Arc::new(chain_event_store),
            Arc::new(transport),
            Arc::new(MockMintClient::new()),
            bitcoin::Network::Testnet,
            Arc::new(test_cfg()),
        );

        handler
            .resync_chain(
                &bill_id,
                true,
                ResyncMode::OnlyMissingMetadata {
                    up_to_hash: predecessor.hash.clone(),
                },
            )
            .await
            .expect(
                "metadata recovery should only compare the local chain \
             through the requested predecessor",
            );
    }
}
