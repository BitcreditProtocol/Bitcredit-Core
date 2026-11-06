use crate::handler::public_chain_helpers::{BlockData, resolve_event_chains};
use crate::handler::{
    BillChainEventProcessorApi, CompanyChainEventProcessorApi, IdentityChainEventProcessorApi,
};
use crate::nostr_transport::NostrTransportService;
use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_api::Config;
use bcr_ebill_api::service::transport_service::{BlockTransportServiceApi, ResyncMode};
use bcr_ebill_api::service::transport_service::{Error, Result};
use bcr_ebill_core::application::nostr::ResendQueueEntry;
use bcr_ebill_core::application::{ServiceTraitBounds, ValidationError};
use bcr_ebill_core::protocol::blockchain::BlockchainType;
use bcr_ebill_core::protocol::blockchain::bill::BillBlock;
use bcr_ebill_core::protocol::event::{
    BillChainEvent, CompanyChainEvent, EventEnvelope, IdentityChainEvent,
};
use bcr_ebill_core::protocol::{Sha256Hash, Timestamp};
use bcr_ebill_persistence::traits::nostr::NostrChainEvent;
use bcr_ebill_persistence::traits::propagation::PreparedPropagationMessage;
use bitcoin::base58;
use log::{debug, error};
use std::str::FromStr;
use std::sync::Arc;

#[derive(Clone)]
pub struct BlockTransportService {
    nostr_transport: Arc<NostrTransportService>,
    bill_chain_event_processor: Arc<dyn BillChainEventProcessorApi>,
    company_chain_event_processor: Arc<dyn CompanyChainEventProcessorApi>,
    identity_chain_event_processor: Arc<dyn IdentityChainEventProcessorApi>,
    config: Arc<Config>,
}

impl BlockTransportService {
    pub fn new(
        nostr_transport: Arc<NostrTransportService>,
        bill_chain_event_processor: Arc<dyn BillChainEventProcessorApi>,
        company_chain_event_processor: Arc<dyn CompanyChainEventProcessorApi>,
        identity_chain_event_processor: Arc<dyn IdentityChainEventProcessorApi>,
        config: Arc<Config>,
    ) -> Self {
        Self {
            nostr_transport,
            bill_chain_event_processor,
            company_chain_event_processor,
            identity_chain_event_processor,
            config,
        }
    }
}

impl ServiceTraitBounds for BlockTransportService {}

impl BlockTransportService {
    /// Validates that a previous block event exists before publishing.
    /// If no previous event is found and the block is not genesis,
    /// returns an error to prevent publishing an orphaned block.
    async fn validate_previous_event_exists(
        &self,
        previous_hash: &Sha256Hash,
        chain_id: &str,
        chain_type: BlockchainType,
        block_height: usize,
    ) -> Result<(Option<NostrChainEvent>, Option<NostrChainEvent>)> {
        if block_height == 0 {
            return Err(Error::Blockchain("Invalid block height 0".to_owned()));
        }
        if block_height == 1 {
            return Ok((None, None));
        }

        let (previous, root) = self
            .nostr_transport
            .find_root_and_previous_event(previous_hash, chain_id, chain_type)
            .await?;

        if Self::validate_predecessor_metadata(
            previous_hash,
            chain_id,
            chain_type,
            block_height,
            &previous,
            &root,
        )
        .is_ok()
        {
            return Ok((previous, root));
        }

        log::warn!(
            "Missing or inconsistent Nostr chain metadata for {chain_type:?} chain {chain_id} at height {block_height}; attempting resync"
        );

        // if we're missing the previous event, we attempt to fetch the missing metadata
        self.resync_missing_chain_metadata(previous_hash, chain_id, chain_type)
            .await?;

        let (previous, root) = self
            .nostr_transport
            .find_root_and_previous_event(previous_hash, chain_id, chain_type)
            .await?;

        Self::validate_predecessor_metadata(
            previous_hash,
            chain_id,
            chain_type,
            block_height,
            &previous,
            &root,
        )
        .map_err(|e| {
            Error::Blockchain(format!("Nostr preflight failed after metadata resync: {e}"))
        })?;

        Ok((previous, root))
    }

    fn validate_predecessor_metadata(
        previous_hash: &Sha256Hash,
        chain_id: &str,
        chain_type: BlockchainType,
        block_height: usize,
        previous: &Option<NostrChainEvent>,
        root: &Option<NostrChainEvent>,
    ) -> Result<()> {
        if block_height == 0 {
            return Err(Error::Blockchain("Invalid block height 0".to_owned()));
        }
        if block_height == 1 {
            return Ok(());
        }

        let previous = previous.as_ref().ok_or_else(|| {
            Error::Blockchain(format!(
                "Cannot publish block: missing previous block for {chain_type:?} chain {chain_id} at height {block_height}"
            ))
        })?;
        if previous.chain_id != chain_id
            || previous.chain_type != chain_type
            || &previous.block_hash != previous_hash
            || previous.block_height.checked_add(1) != Some(block_height)
        {
            return Err(Error::Blockchain(format!(
                "Invalid previous Nostr event metadata for {chain_type:?} chain {chain_id} at height {block_height}"
            )));
        }

        let root = root.as_ref().ok_or_else(|| {
            Error::Blockchain(format!(
                "Cannot publish block: missing root event for {chain_type:?} chain {chain_id}"
            ))
        })?;
        if root.chain_id != chain_id
            || root.chain_type != chain_type
            || root.block_height != 1
            || !root.is_root_event()
            || previous.root_id != root.event_id
        {
            return Err(Error::Blockchain(format!(
                "Invalid root Nostr event metadata for {chain_type:?} chain {chain_id}"
            )));
        }
        Ok(())
    }

    async fn resync_missing_chain_metadata(
        &self,
        previous_hash: &Sha256Hash,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> Result<()> {
        let mode = ResyncMode::OnlyMissingMetadata {
            up_to_hash: previous_hash.clone(),
        };
        match chain_type {
            BlockchainType::Bill => {
                let bill_id = BillId::from_str(chain_id)
                    .map_err(|_| Error::Blockchain(format!("Invalid bill chain ID {chain_id}")))?;
                self.bill_chain_event_processor
                    .resync_chain(&bill_id, true, mode)
                    .await?;
            }
            BlockchainType::Company => {
                let company_id = NodeId::from_str(chain_id).map_err(|_| {
                    Error::Blockchain(format!("Invalid company chain ID {chain_id}"))
                })?;
                self.company_chain_event_processor
                    .resync_chain(&company_id, mode)
                    .await?;
            }
            BlockchainType::Identity => {
                self.identity_chain_event_processor
                    .resync_chain(mode)
                    .await?;
            }
        }
        Ok(())
    }

    async fn send_prepared_public_chain_event(
        &self,
        sender: &NodeId,
        prepared: NostrChainEvent,
    ) -> Result<()> {
        let node = self.nostr_transport.get_node_transport(sender);
        let threshold = node.relay_ack_threshold();
        if let Err(e) = node
            .broadcast_event_optimistic(&prepared.payload, threshold)
            .await
        {
            error!(
                "Failed to broadcast {} chain event: {e}",
                prepared.chain_type
            );
            let payload = serde_json::to_string(&prepared.payload)?;
            self.nostr_transport
                .queue_retry_message_and_trigger(sender, None, payload)
                .await?;
        }
        self.nostr_transport.add_chain_event(prepared).await?;
        Ok(())
    }

    /// prepare a batch of chain events, for when we publish multiple consecutive blocks
    /// and at preparation time don't have the chain events in persistent storage yet
    async fn prepare_chain_event_batch(
        &self,
        inputs: Vec<ChainEventToPrepare>,
    ) -> Result<Vec<NostrChainEvent>> {
        let mut prepared: Vec<NostrChainEvent> = Vec::with_capacity(inputs.len());
        let mut batch_root: Option<NostrChainEvent> = None;
        for input in inputs {
            let (previous, root) = if let Some(last) = prepared.last() {
                if input.block_height <= 1 {
                    return Err(Error::Blockchain(
                        "Invalid block order in Nostr preparation batch".into(),
                    ));
                }
                let root = batch_root.as_ref().ok_or_else(|| {
                    Error::Blockchain("Missing root in Nostr preparation batch".into())
                })?;
                Self::validate_predecessor_metadata(
                    &input.previous_hash,
                    &input.chain_id,
                    input.chain_type,
                    input.block_height,
                    &Some(last.clone()),
                    &Some(root.clone()),
                )?;
                (Some(last.clone()), Some(root.clone()))
            } else {
                // Only the first block needs a DB lookup and potentially a metadata resync
                // the others are only in-memory for now
                self.validate_previous_event_exists(
                    &input.previous_hash,
                    &input.chain_id,
                    input.chain_type,
                    input.block_height,
                )
                .await?
            };

            let node = self.nostr_transport.get_node_transport(&input.sender);
            let signed = node
                .build_public_chain_event(
                    &input.sender,
                    &input.chain_id,
                    input.chain_type,
                    input.block_time,
                    input.envelope,
                    previous.as_ref().map(|e| e.payload.clone()),
                    root.as_ref().map(|e| e.payload.clone()),
                )
                .await?;

            let event_id = signed.id.to_string();
            let time: Timestamp = signed.created_at.into();
            let chain_event = NostrChainEvent {
                event_id: event_id.clone(),
                root_id: root
                    .as_ref()
                    .map(|e| e.event_id.clone())
                    .unwrap_or_else(|| event_id.clone()),
                reply_id: previous.as_ref().map(|e| e.event_id.clone()),
                author: signed.pubkey.to_string(),
                chain_id: input.chain_id,
                chain_type: input.chain_type,
                block_height: input.block_height,
                block_hash: input.block_hash,
                received: time,
                time,
                payload: signed,
            };
            if batch_root.is_none() {
                // Existing chain: retain the DB-resolved root
                // Genesis: the first signed event is the root
                batch_root = Some(root.unwrap_or_else(|| chain_event.clone()));
            }
            prepared.push(chain_event);
        }
        Ok(prepared)
    }
}

#[derive(Clone, Debug)]
struct ChainEventToPrepare {
    sender: NodeId,
    chain_id: String,
    chain_type: BlockchainType,
    block_height: usize,
    block_hash: Sha256Hash,
    previous_hash: Sha256Hash,
    block_time: Timestamp,
    envelope: EventEnvelope,
}

impl ChainEventToPrepare {
    fn identity(events: &IdentityChainEvent) -> Result<Self> {
        let event = events
            .generate_blockchain_message()
            .ok_or_else(|| Error::Message("Identity chain event has no new block".into()))?;
        Ok(Self {
            sender: events.sender(),
            chain_id: event.data.node_id.to_string(),
            chain_type: BlockchainType::Identity,
            block_height: event.data.block.id.inner() as usize,
            block_hash: event.data.block.hash.clone(),
            previous_hash: event.data.block.previous_hash.clone(),
            block_time: event.data.block.timestamp,
            envelope: event.try_into()?,
        })
    }

    fn company(events: &CompanyChainEvent) -> Result<Self> {
        let event = events
            .generate_blockchain_message()
            .ok_or_else(|| Error::Message("Company chain event has no new block".into()))?;
        Ok(Self {
            sender: events.sender(),
            chain_id: event.data.node_id.to_string(),
            chain_type: BlockchainType::Company,
            block_height: event.data.block.id.inner() as usize,
            block_hash: event.data.block.hash.clone(),
            previous_hash: event.data.block.previous_hash.clone(),
            block_time: event.data.block.timestamp,
            envelope: event.try_into()?,
        })
    }

    fn bill(events: &BillChainEvent) -> Result<Self> {
        let event = events
            .generate_blockchain_message()
            .ok_or_else(|| Error::Message("Bill chain event has no new block".into()))?;
        Ok(Self {
            sender: events.sender(),
            chain_id: event.data.bill_id.to_string(),
            chain_type: BlockchainType::Bill,
            block_height: event.data.block.id.inner() as usize,
            block_hash: event.data.block.hash.clone(),
            previous_hash: event.data.block.previous_hash.clone(),
            block_time: event.data.block.timestamp,
            envelope: event.try_into()?,
        })
    }
}

#[async_trait]
impl BlockTransportServiceApi for BlockTransportService {
    async fn prepare_identity_chain_events(
        &self,
        events: &[IdentityChainEvent],
    ) -> Result<Vec<NostrChainEvent>> {
        let inputs = events
            .iter()
            .map(ChainEventToPrepare::identity)
            .collect::<Result<Vec<_>>>()?;
        self.prepare_chain_event_batch(inputs).await
    }

    async fn prepare_company_chain_events(
        &self,
        events: &[CompanyChainEvent],
    ) -> Result<Vec<NostrChainEvent>> {
        let inputs = events
            .iter()
            .map(ChainEventToPrepare::company)
            .collect::<Result<Vec<_>>>()?;
        self.prepare_chain_event_batch(inputs).await
    }

    async fn prepare_bill_chain_events(
        &self,
        events: &[BillChainEvent],
    ) -> Result<Vec<NostrChainEvent>> {
        let inputs = events
            .iter()
            .map(ChainEventToPrepare::bill)
            .collect::<Result<Vec<_>>>()?;
        self.prepare_chain_event_batch(inputs).await
    }

    async fn prepare_identity_chain_event(
        &self,
        event: &IdentityChainEvent,
    ) -> Result<Option<NostrChainEvent>> {
        if event.generate_blockchain_message().is_none() {
            return Ok(None);
        }
        Ok(self
            .prepare_identity_chain_events(std::slice::from_ref(event))
            .await?
            .into_iter()
            .next())
    }

    async fn prepare_company_chain_event(
        &self,
        event: &CompanyChainEvent,
    ) -> Result<Option<NostrChainEvent>> {
        if event.generate_blockchain_message().is_none() {
            return Ok(None);
        }
        Ok(self
            .prepare_company_chain_events(std::slice::from_ref(event))
            .await?
            .into_iter()
            .next())
    }

    async fn prepare_bill_chain_event(
        &self,
        event: &BillChainEvent,
    ) -> Result<Option<NostrChainEvent>> {
        if event.generate_blockchain_message().is_none() {
            return Ok(None);
        }
        Ok(self
            .prepare_bill_chain_events(std::slice::from_ref(event))
            .await?
            .into_iter()
            .next())
    }

    /// Sent when an identity chain is created or updated
    async fn send_identity_chain_events(&self, events: IdentityChainEvent) -> Result<()> {
        debug!(
            "sending identity chain events for node: {}",
            events.identity_id
        );
        if let Some(prepared) = self.prepare_identity_chain_event(&events).await? {
            self.send_prepared_public_chain_event(&events.sender(), prepared)
                .await?;
        }
        Ok(())
    }

    /// Sent when a company chain is created or updated
    async fn send_company_chain_events(&self, events: CompanyChainEvent) -> Result<()> {
        debug!(
            "sending company chain events for company id: {}",
            events.company_id
        );
        let sender = events.sender();
        let node = self.nostr_transport.get_node_transport(&sender);
        if let Some(prepared) = self.prepare_company_chain_event(&events).await? {
            self.send_prepared_public_chain_event(&sender, prepared)
                .await?;
        }

        // handle potential invite for new signatory
        if let Some((recipient, invite)) = events.generate_company_invite_message()
            && let Some(identity) = self.nostr_transport.resolve_identity(&recipient).await
        {
            let message: EventEnvelope = invite.try_into()?;
            if let Err(e) = node
                .send_private_event(&events.sender(), &identity, message.clone())
                .await
            {
                error!("Failed to send company invite, queuing for retry: {e}");
                self.nostr_transport
                    .queue_retry_message_and_trigger(
                        &events.sender(),
                        Some(&recipient),
                        base58::encode(&borsh::to_vec(&message)?),
                    )
                    .await?;
            }
        }

        Ok(())
    }

    /// Sent when a bill chain is created or updated
    async fn send_bill_chain_events(&self, events: BillChainEvent) -> Result<()> {
        debug!("sending bill chain events for bill id: {}", events.bill.id);
        let sender = events.sender();
        let node = self.nostr_transport.get_node_transport(&sender);
        if let Some(prepared) = self.prepare_bill_chain_event(&events).await? {
            self.send_prepared_public_chain_event(&sender, prepared)
                .await?;
        }

        // handle potential invite for new endorsee
        let invites = events.generate_bill_invite_events();
        if !invites.is_empty() {
            for (recipient, event) in invites {
                if let Some(identity) = self.nostr_transport.resolve_identity(&recipient).await {
                    let message: EventEnvelope = event.try_into()?;
                    if let Err(e) = node
                        .send_private_event(&events.sender(), &identity, message.clone())
                        .await
                    {
                        error!("Failed to send bill invite, queuing for retry: {e}");
                        self.nostr_transport
                            .queue_retry_message_and_trigger(
                                &events.sender(),
                                Some(&recipient),
                                base58::encode(&borsh::to_vec(&message)?),
                            )
                            .await?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Resync bill chain. If `from_nostr` is true, fetches missing blocks from Nostr first.
    /// If false, only invalidates the local cache.
    async fn resync_bill_chain(
        &self,
        bill_id: &BillId,
        from_nostr: bool,
        mode: ResyncMode,
    ) -> Result<()> {
        // if dev mode is off - we return an error
        if matches!(mode, ResyncMode::NostrAuthoritative) && !self.config.dev_mode_config.on {
            error!("Called dev mode operation with dev mode disabled - please enable!");
            return Err(Error::Validation(ValidationError::InvalidOperation));
        }

        self.bill_chain_event_processor
            .resync_chain(bill_id, from_nostr, mode)
            .await?;
        Ok(())
    }

    /// Resync company chain
    async fn resync_company_chain(&self, company_id: &NodeId, mode: ResyncMode) -> Result<()> {
        // if dev mode is off - we return an error
        if matches!(mode, ResyncMode::NostrAuthoritative) && !self.config.dev_mode_config.on {
            error!("Called dev mode operation with dev mode disabled - please enable!");
            return Err(Error::Validation(ValidationError::InvalidOperation));
        }

        self.company_chain_event_processor
            .resync_chain(company_id, mode)
            .await?;
        Ok(())
    }

    /// Resync identity chain
    async fn resync_identity_chain(&self, mode: ResyncMode) -> Result<()> {
        // if dev mode is off - we return an error
        if matches!(mode, ResyncMode::NostrAuthoritative) && !self.config.dev_mode_config.on {
            error!("Called dev mode operation with dev mode disabled - please enable!");
            return Err(Error::Validation(ValidationError::InvalidOperation));
        }

        self.identity_chain_event_processor
            .resync_chain(mode)
            .await?;
        Ok(())
    }

    /// Fetch all chains for this bill id from nostr and attempt to find one which exactly matches the given blocks
    async fn validate_bill_blocks_exist_on_nostr_chain(
        &self,
        bill_id: &BillId,
        blocks: &[BillBlock],
    ) -> Result<bool> {
        if blocks.is_empty() {
            return Ok(true);
        }
        let mut sorted_blocks = blocks.to_vec();
        sorted_blocks.sort_by(|x, y| x.bill_id.cmp(&y.bill_id).then_with(|| x.id.cmp(&y.id)));

        let transport = self.nostr_transport.get_first_transport();
        // chains are sorted by longest first, so we start there and move down until we have a success
        let chains =
            resolve_event_chains(transport, &bill_id.to_string(), BlockchainType::Bill, &None)
                .await?;
        for chain in chains.iter() {
            // ignore empty chains
            if chain.is_empty() {
                continue;
            }

            let mut chain_blocks: Vec<BillBlock> = chain
                .iter()
                .filter_map(|d| match d.block.clone() {
                    BlockData::Bill(block) => Some(block),
                    _ => None,
                })
                .collect();
            chain_blocks.sort_by(|x, y| x.bill_id.cmp(&y.bill_id).then_with(|| x.id.cmp(&y.id)));

            // ignore chains with no bill blocks
            if chain_blocks.is_empty() {
                continue;
            }

            // chain has to match exactly
            if chain_blocks.len() != sorted_blocks.len() {
                continue;
            }

            // if it matches exactly, it's valid
            if sorted_blocks == chain_blocks {
                return Ok(true);
            }
        }
        // didn't find all blocks exactly in any chain - invalid
        Ok(false)
    }

    async fn fetch_resend_queue_entries(&self) -> Result<Vec<ResendQueueEntry>> {
        self.nostr_transport.fetch_resend_queue_entries().await
    }

    async fn requeue_resend_queue_entry(&self, id: &str) -> Result<()> {
        self.nostr_transport.requeue_resend_queue_entry(id).await
    }

    async fn prepare_bill_chain_invites(
        &self,
        events: &BillChainEvent,
    ) -> Result<Vec<PreparedPropagationMessage>> {
        let sender = events.sender();
        let mut invites = events
            .generate_bill_invite_events()
            .into_iter()
            .collect::<Vec<_>>();
        invites.sort_by_key(|(a, _)| a.to_string());
        let mut prepared = Vec::with_capacity(invites.len());
        for (recipient_id, event) in invites {
            let envelope: EventEnvelope = event.try_into()?;
            let message = self
                .nostr_transport
                .prepare_private_propagation_message(&sender, &recipient_id, envelope)
                .await?;
            prepared.push(message);
        }
        Ok(prepared)
    }

    async fn prepare_company_chain_invites(
        &self,
        events: &CompanyChainEvent,
    ) -> Result<Vec<PreparedPropagationMessage>> {
        let Some((recipient_id, event)) = events.generate_company_invite_message() else {
            return Ok(Vec::new());
        };
        let envelope: EventEnvelope = event.try_into()?;
        let message = self
            .nostr_transport
            .prepare_private_propagation_message(&events.sender(), &recipient_id, envelope)
            .await?;
        Ok(vec![message])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::{
        MockBillChainEventProcessorApi, MockCompanyChainEventProcessorApi,
        MockIdentityChainEventProcessorApi,
    };
    use crate::test_utils::{
        MockContactStore, MockNostrChainEventStore, MockNostrContactStore,
        MockNostrQueuedMessageStore, MockNotificationJsonTransport, bill_id_test,
        get_genesis_chain, get_nostr_transport, get_test_company_chain_event,
        get_test_identity_chain_event, private_key_test, test_cfg,
    };
    use crate::transport::create_public_chain_event;
    use bcr_ebill_core::protocol::blockchain::{Blockchain, BlockchainType};
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use bcr_ebill_core::protocol::event::{BillBlockEvent, Event};
    use bcr_ebill_core::protocol::{BlockId, Sha256Hash, Timestamp};
    use bcr_ebill_persistence::traits::nostr::NostrChainEvent;
    use nostr::event::FinalizeEvent;

    fn create_test_chain_event(
        chain_id: &str,
        chain_type: BlockchainType,
        block_height: usize,
        block_hash: Sha256Hash,
    ) -> NostrChainEvent {
        NostrChainEvent {
            event_id: format!("test_event_{block_height}"),
            root_id: "test_event_1".to_string(),
            reply_id: if block_height > 1 {
                Some(format!("test_event_{}", block_height - 1))
            } else {
                None
            },
            author: "test_author".to_string(),
            chain_id: chain_id.to_string(),
            chain_type,
            block_height,
            block_hash,
            received: bcr_ebill_core::protocol::Timestamp::now(),
            time: bcr_ebill_core::protocol::Timestamp::now(),
            payload: nostr::event::EventBuilder::new(nostr::event::Kind::TextNote, "test")
                .finalize(&nostr::key::Keys::generate())
                .unwrap(),
        }
    }

    fn get_service_with_transport(
        mock_transport: MockNotificationJsonTransport,
        chain_event_store: MockNostrChainEventStore,
    ) -> BlockTransportService {
        BlockTransportService::new(
            Arc::new(get_nostr_transport(
                mock_transport,
                MockContactStore::new(),
                MockNostrContactStore::new(),
                MockNostrQueuedMessageStore::new(),
                chain_event_store,
            )),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(test_cfg()),
        )
    }

    fn get_service(chain_event_store: MockNostrChainEventStore) -> BlockTransportService {
        get_service_with_transport(MockNotificationJsonTransport::new(), chain_event_store)
    }

    fn get_service_with_bill_chain_event_processor(
        bill_chain_event_processor: MockBillChainEventProcessorApi,
        chain_event_store: MockNostrChainEventStore,
    ) -> BlockTransportService {
        BlockTransportService::new(
            Arc::new(get_nostr_transport(
                MockNotificationJsonTransport::new(),
                MockContactStore::new(),
                MockNostrContactStore::new(),
                MockNostrQueuedMessageStore::new(),
                chain_event_store,
            )),
            Arc::new(bill_chain_event_processor),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(test_cfg()),
        )
    }

    #[tokio::test]
    async fn test_validate_previous_event_exists_allows_genesis() {
        let mut chain_event_store = MockNostrChainEventStore::new();
        // No previous event in store for genesis block
        chain_event_store
            .expect_find_by_block_hash()
            .returning(|_| Ok(None));

        let service = get_service(chain_event_store);
        let result = service
            .validate_previous_event_exists(
                &Sha256Hash::new("genesis"),
                "test_chain",
                BlockchainType::Bill,
                1,
            )
            .await;

        assert!(result.is_ok());
        let (previous, root) = result.unwrap();
        assert!(previous.is_none());
        assert!(root.is_none());
    }

    #[tokio::test]
    async fn test_validate_previous_event_exists_rejects_missing() {
        let mut chain_event_store = MockNostrChainEventStore::new();
        // No previous event in store for non-genesis block
        chain_event_store
            .expect_find_by_block_hash()
            .returning(|_| Ok(None));

        let mut bill_chain_event_processor = MockBillChainEventProcessorApi::new();
        bill_chain_event_processor
            .expect_resync_chain()
            .returning(|_, _, _| Ok(()));

        let service = get_service_with_bill_chain_event_processor(
            bill_chain_event_processor,
            chain_event_store,
        );
        let result = service
            .validate_previous_event_exists(
                &Sha256Hash::new("missing_hash"),
                &bill_id_test().to_string(),
                BlockchainType::Bill,
                2,
            )
            .await;

        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Cannot publish block"));
        assert!(err_msg.contains("missing previous block"));
    }

    #[tokio::test]
    async fn test_validate_previous_event_exists_accepts_with_previous() {
        let mut chain_event_store = MockNostrChainEventStore::new();
        let previous_hash = Sha256Hash::new("previous_hash");
        let previous_event =
            create_test_chain_event("test_chain", BlockchainType::Bill, 1, previous_hash.clone());

        chain_event_store
            .expect_find_by_block_hash()
            .returning(move |_| Ok(Some(previous_event.clone())));

        let service = get_service(chain_event_store);
        let result = service
            .validate_previous_event_exists(&previous_hash, "test_chain", BlockchainType::Bill, 2)
            .await;

        assert!(result.is_ok());
        let (previous, root) = result.unwrap();
        assert!(previous.is_some());
        assert!(root.is_some());
    }

    #[tokio::test]
    async fn test_identity_chain_event_uses_optimistic_broadcast() {
        let signed_event =
            nostr::event::EventBuilder::new(nostr::event::Kind::TextNote, "identity chain event")
                .finalize(&nostr::key::Keys::generate())
                .unwrap();
        let mut transport = MockNotificationJsonTransport::new();
        transport
            .expect_build_public_chain_event()
            .returning(move |_, _, _, _, _, _, _| Ok(signed_event.clone()));
        transport.expect_relay_ack_threshold().returning(|| 1);
        transport
            .expect_broadcast_event_optimistic()
            .withf(|_event, min_acks| *min_acks == 1)
            .returning(|_, _| Ok(()));

        let mut chain_event_store = MockNostrChainEventStore::new();
        chain_event_store
            .expect_find_by_block_hash()
            .returning(|_| Ok(None));
        chain_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()));

        let service = get_service_with_transport(transport, chain_event_store);
        let event = get_test_identity_chain_event();

        let result = service.send_identity_chain_events(event).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_company_chain_event_uses_optimistic_broadcast() {
        let signed_event =
            nostr::event::EventBuilder::new(nostr::event::Kind::TextNote, "company chain event")
                .finalize(&nostr::key::Keys::generate())
                .unwrap();
        let mut transport = MockNotificationJsonTransport::new();
        transport
            .expect_build_public_chain_event()
            .returning(move |_, _, _, _, _, _, _| Ok(signed_event.clone()));
        transport.expect_relay_ack_threshold().returning(|| 1);
        transport
            .expect_broadcast_event_optimistic()
            .withf(|_event, min_acks| *min_acks == 1)
            .returning(|_, _| Ok(()));

        let mut chain_event_store = MockNostrChainEventStore::new();
        chain_event_store
            .expect_find_by_block_hash()
            .returning(|_| Ok(None));
        chain_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()));

        let service = get_service_with_transport(transport, chain_event_store);
        let event = get_test_company_chain_event();

        let result = service.send_company_chain_events(event).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_broadcast_error_triggers_full_message_retry() {
        let signed_event =
            nostr::event::EventBuilder::new(nostr::event::Kind::TextNote, "retry event")
                .finalize(&nostr::key::Keys::generate())
                .unwrap();
        let mut transport = MockNotificationJsonTransport::new();
        transport
            .expect_build_public_chain_event()
            .returning(move |_, _, _, _, _, _, _| Ok(signed_event.clone()));
        transport.expect_relay_ack_threshold().returning(|| 1);
        transport
            .expect_broadcast_event_optimistic()
            .withf(|_event, min_acks| *min_acks == 1)
            .returning(|_, _| Err(Error::Network("relay failed".to_string())));

        let mut chain_event_store = MockNostrChainEventStore::new();
        chain_event_store
            .expect_find_by_block_hash()
            .returning(|_| Ok(None));
        chain_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()));

        let mut queued_message_store = MockNostrQueuedMessageStore::new();
        queued_message_store
            .expect_add_message()
            .times(1)
            .returning(|_, _| Ok(()));
        queued_message_store
            .expect_get_retry_messages()
            .returning(|_| Ok(vec![]));

        let service = BlockTransportService::new(
            Arc::new(get_nostr_transport(
                transport,
                MockContactStore::new(),
                MockNostrContactStore::new(),
                queued_message_store,
                chain_event_store,
            )),
            Arc::new(MockBillChainEventProcessorApi::new()),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(test_cfg()),
        );
        let event = get_test_identity_chain_event();

        let result = service.send_identity_chain_events(event).await;
        assert!(result.is_ok());
    }

    fn generate_test_event(
        previous: Option<nostr::event::Event>,
        root: Option<nostr::event::Event>,
        height: usize,
        block: BillBlock,
    ) -> nostr::event::Event {
        let keys = BcrKeys::from_private_key(&private_key_test());
        let block_event = Event::new_bill_chain(BillBlockEvent {
            bill_id: bill_id_test(),
            block: block.clone(),
            block_height: height,
        })
        .try_into()
        .expect("could not create envelope");
        create_public_chain_event(
            &bill_id_test().to_string(),
            block_event,
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
    async fn test_validate_bill_blocks_exist_on_nostr_chain_empty() {
        let mut transport = MockNotificationJsonTransport::new();
        transport.expect_resolve_public_chain().never();
        let service = get_service_with_transport(transport, MockNostrChainEventStore::new());
        let bill_id = bill_id_test();

        let res = service
            .validate_bill_blocks_exist_on_nostr_chain(&bill_id, &[])
            .await;
        assert!(res.unwrap());
    }

    #[tokio::test]
    async fn test_validate_bill_blocks_exist_on_nostr_chain_invalid() {
        let mut transport = MockNotificationJsonTransport::new();
        // create a block
        let block = get_genesis_chain(None)
            .blocks()
            .first()
            .expect("could not get block")
            .clone();
        transport
            .expect_resolve_public_chain()
            .times(1)
            .returning(move |_, _| Ok(vec![generate_test_event(None, None, 1, block.clone())]));
        let service = get_service_with_transport(transport, MockNostrChainEventStore::new());
        let bill_id = bill_id_test();

        // create a different block
        let block = get_genesis_chain(None)
            .blocks()
            .first()
            .expect("could not get block")
            .clone();

        let res = service
            .validate_bill_blocks_exist_on_nostr_chain(&bill_id, &[block])
            .await;
        assert!(!res.unwrap());
    }

    #[tokio::test]
    async fn test_validate_bill_blocks_exist_on_nostr_chain_valid() {
        // create a block
        let block = get_genesis_chain(None)
            .blocks()
            .first()
            .expect("could not get block")
            .clone();
        let mut transport = MockNotificationJsonTransport::new();
        let block_clone = block.clone();
        transport
            .expect_resolve_public_chain()
            .times(1)
            .returning(move |_, _| {
                Ok(vec![generate_test_event(
                    None,
                    None,
                    1,
                    block_clone.clone(),
                )])
            });
        let service = get_service_with_transport(transport, MockNostrChainEventStore::new());
        let bill_id = bill_id_test();

        let res = service
            .validate_bill_blocks_exist_on_nostr_chain(&bill_id, &[block])
            .await;
        assert!(res.unwrap());
    }

    #[tokio::test]
    async fn test_validate_bill_blocks_exist_on_nostr_chain_multi() {
        // create a block
        let block = get_genesis_chain(None)
            .blocks()
            .first()
            .expect("could not get block")
            .clone();
        // create another block
        let mut block_2 = get_genesis_chain(None)
            .blocks()
            .first()
            .expect("could not get block")
            .clone();
        block_2.id = BlockId::first().add(1);
        let mut transport = MockNotificationJsonTransport::new();
        let block_clone = block.clone();
        let block_2_clone = block_2.clone();
        transport
            .expect_resolve_public_chain()
            .times(1)
            .returning(move |_, _| {
                let first_event = generate_test_event(None, None, 1, block_clone.clone());
                let second_event = generate_test_event(
                    Some(first_event.clone()),
                    Some(first_event.clone()),
                    2,
                    block_2_clone.clone(),
                );
                Ok(vec![first_event, second_event])
            });
        let service = get_service_with_transport(transport, MockNostrChainEventStore::new());
        let bill_id = bill_id_test();

        // works if it's not sorted correctly as well
        let res = service
            .validate_bill_blocks_exist_on_nostr_chain(&bill_id, &[block_2, block])
            .await;
        assert!(res.unwrap());
    }

    #[tokio::test]
    async fn prepare_identity_chain_event_does_not_publish() {
        let signed_event = nostr::event::EventBuilder::new(
            nostr::event::Kind::TextNote,
            "prepared identity chain event",
        )
        .finalize(&nostr::key::Keys::generate())
        .unwrap();
        let expected_event_id = signed_event.id.to_string();
        let mut transport = MockNotificationJsonTransport::new();
        transport
            .expect_build_public_chain_event()
            .times(1)
            .returning(move |_, _, _, _, _, _, _| Ok(signed_event.clone()));
        transport.expect_broadcast_event_optimistic().never();
        transport.expect_broadcast_event().never();
        let mut chain_event_store = MockNostrChainEventStore::new();
        chain_event_store.expect_add_chain_event().never();
        let service = get_service_with_transport(transport, chain_event_store);
        let identity_event = get_test_identity_chain_event();
        let prepared = service
            .prepare_identity_chain_event(&identity_event)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(prepared.event_id, expected_event_id);
        assert_eq!(prepared.payload.id.to_string(), expected_event_id);
        assert_eq!(prepared.root_id, expected_event_id);
        assert!(prepared.reply_id.is_none());
        assert_eq!(prepared.chain_type, BlockchainType::Identity);
        assert_eq!(prepared.block_height, 1);
    }

    #[test]
    fn predecessor_metadata_must_match_chain() {
        let hash = Sha256Hash::new("previous_hash");
        let previous = create_test_chain_event("bill-123", BlockchainType::Bill, 1, hash.clone());
        let root = previous.clone();
        assert!(
            BlockTransportService::validate_predecessor_metadata(
                &hash,
                "bill-123",
                BlockchainType::Bill,
                2,
                &Some(previous.clone()),
                &Some(root.clone()),
            )
            .is_ok()
        );
        // wrong chain
        assert!(
            BlockTransportService::validate_predecessor_metadata(
                &hash,
                "other-bill",
                BlockchainType::Bill,
                2,
                &Some(previous.clone()),
                &Some(root.clone()),
            )
            .is_err()
        );
        // wrong height
        assert!(
            BlockTransportService::validate_predecessor_metadata(
                &hash,
                "bill-123",
                BlockchainType::Bill,
                3,
                &Some(previous.clone()),
                &Some(root.clone()),
            )
            .is_err()
        );
        // missing root
        assert!(
            BlockTransportService::validate_predecessor_metadata(
                &hash,
                "bill-123",
                BlockchainType::Bill,
                2,
                &Some(previous),
                &None,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn missing_root_after_resync_fails_preflight() {
        let bill_id = bill_id_test();
        let chain_id = bill_id.to_string();
        let previous_hash = Sha256Hash::new("previous_hash");
        let previous =
            create_test_chain_event(&chain_id, BlockchainType::Bill, 2, previous_hash.clone());
        let mut store = MockNostrChainEventStore::new();
        store
            .expect_find_by_block_hash()
            .returning(move |_| Ok(Some(previous.clone())));
        store.expect_find_root_event().returning(|_, _| Ok(None));
        let mut processor = MockBillChainEventProcessorApi::new();
        processor
            .expect_resync_chain()
            .times(1)
            .returning(|_, _, _| Ok(()));
        let service = get_service_with_bill_chain_event_processor(processor, store);
        let result = service
            .validate_previous_event_exists(&previous_hash, &chain_id, BlockchainType::Bill, 3)
            .await;

        let error = result.unwrap_err().to_string();
        assert!(error.contains("preflight failed"));
        assert!(error.contains("missing root event"));
    }
}
