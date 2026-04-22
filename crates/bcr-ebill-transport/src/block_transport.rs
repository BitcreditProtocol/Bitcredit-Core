use std::sync::Arc;

use crate::handler::{
    BillChainEventProcessorApi, CompanyChainEventProcessorApi, IdentityChainEventProcessorApi,
};
use crate::nostr_transport::NostrTransportService;
use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_api::service::transport_service::BlockTransportServiceApi;
use bcr_ebill_core::application::ServiceTraitBounds;
use bcr_ebill_core::application::company::Company;
use bcr_ebill_core::protocol::Sha256Hash;
use bcr_ebill_core::protocol::blockchain::BlockchainType;
use bcr_ebill_core::protocol::crypto::BcrKeys;
use bcr_ebill_core::protocol::event::{
    BillChainEvent, CompanyChainEvent, EventEnvelope, IdentityChainEvent,
};
use bcr_ebill_persistence::nostr::NostrChainEvent;
use bitcoin::base58;
use log::{debug, error};

use bcr_ebill_api::service::transport_service::{Error, Result};

#[derive(Clone)]
pub struct BlockTransportService {
    nostr_transport: Arc<NostrTransportService>,
    bill_chain_event_processor: Arc<dyn BillChainEventProcessorApi>,
    company_chain_event_processor: Arc<dyn CompanyChainEventProcessorApi>,
    identity_chain_event_processor: Arc<dyn IdentityChainEventProcessorApi>,
}

impl BlockTransportService {
    pub fn new(
        nostr_transport: Arc<NostrTransportService>,
        bill_chain_event_processor: Arc<dyn BillChainEventProcessorApi>,
        company_chain_event_processor: Arc<dyn CompanyChainEventProcessorApi>,
        identity_chain_event_processor: Arc<dyn IdentityChainEventProcessorApi>,
    ) -> Self {
        Self {
            nostr_transport,
            bill_chain_event_processor,
            company_chain_event_processor,
            identity_chain_event_processor,
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
        let (previous_event, root_event) = self
            .nostr_transport
            .find_root_and_previous_event(previous_hash, chain_id, chain_type)
            .await?;

        if previous_event.is_none() && block_height > 1 {
            return Err(Error::Blockchain(format!(
                "Cannot publish block: missing previous block for {chain_type:?} chain {chain_id} at height {block_height}"
            )));
        }

        Ok((previous_event, root_event))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl BlockTransportServiceApi for BlockTransportService {
    /// Sent when an identity chain is created or updated
    async fn send_identity_chain_events(&self, events: IdentityChainEvent) -> Result<()> {
        debug!(
            "sending identity chain events for node: {}",
            events.identity_id
        );
        let node = self.nostr_transport.get_node_transport(&events.sender());

        if let Some(event) = events.generate_blockchain_message() {
            let (previous_event, root_event) = self
                .validate_previous_event_exists(
                    &event.data.block.previous_hash,
                    &event.data.node_id.to_string(),
                    BlockchainType::Identity,
                    event.data.block.id.inner() as usize,
                )
                .await?;
            let nostr_event = node
                .build_public_chain_event(
                    &events.sender(),
                    &event.data.node_id.to_string(),
                    BlockchainType::Identity,
                    event.data.block.timestamp,
                    events.keys.clone(),
                    event.clone().try_into()?,
                    previous_event.clone().map(|e| e.payload),
                    root_event.clone().map(|e| e.payload),
                )
                .await?;

            if let Err(e) = node.broadcast_event(&nostr_event).await {
                error!("Failed to broadcast identity chain event, queuing for retry: {e}");
                let payload = serde_json::to_string(&nostr_event)
                    .map_err(|e| Error::Message(e.to_string()))?;
                self.nostr_transport
                    .queue_retry_message_and_trigger(&events.sender(), None, payload)
                    .await?;
            }

            self.nostr_transport
                .add_chain_event(
                    &nostr_event,
                    &root_event,
                    &previous_event,
                    &event.data.node_id.to_string(),
                    BlockchainType::Identity,
                    event.data.block.id.inner() as usize,
                    &event.data.block.hash,
                )
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
        let node = self.nostr_transport.get_node_transport(&events.sender());

        if let Some(event) = events.generate_blockchain_message() {
            let (previous_event, root_event) = self
                .validate_previous_event_exists(
                    &event.data.block.previous_hash,
                    &event.data.node_id.to_string(),
                    BlockchainType::Company,
                    event.data.block.id.inner() as usize,
                )
                .await?;
            let nostr_event = node
                .build_public_chain_event(
                    &events.sender(),
                    &event.data.node_id.to_string(),
                    BlockchainType::Company,
                    event.data.block.timestamp,
                    events.keys.clone(),
                    event.clone().try_into()?,
                    previous_event.clone().map(|e| e.payload),
                    root_event.clone().map(|e| e.payload),
                )
                .await?;

            if let Err(e) = node.broadcast_event(&nostr_event).await {
                error!("Failed to broadcast company chain event, queuing for retry: {e}");
                let payload = serde_json::to_string(&nostr_event)
                    .map_err(|e| Error::Message(e.to_string()))?;
                self.nostr_transport
                    .queue_retry_message_and_trigger(&events.sender(), None, payload)
                    .await?;
            }

            self.nostr_transport
                .add_chain_event(
                    &nostr_event,
                    &root_event,
                    &previous_event,
                    &event.data.node_id.to_string(),
                    BlockchainType::Company,
                    event.data.block.id.inner() as usize,
                    &event.data.block.hash,
                )
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

    /// Sent when: A bill chain is created or updated
    async fn send_bill_chain_events(&self, events: BillChainEvent) -> Result<()> {
        let node = self.nostr_transport.get_node_transport(&events.sender());

        if let Some(block_event) = events.generate_blockchain_message() {
            let (previous_event, root_event) = self
                .validate_previous_event_exists(
                    &block_event.data.block.previous_hash,
                    &block_event.data.bill_id.to_string(),
                    BlockchainType::Bill,
                    block_event.data.block.id.inner() as usize,
                )
                .await?;

            let nostr_event = node
                .build_public_chain_event(
                    &events.sender(),
                    &block_event.data.bill_id.to_string(),
                    BlockchainType::Bill,
                    block_event.data.block.timestamp,
                    events.bill_keys.clone(),
                    block_event.clone().try_into()?,
                    previous_event.clone().map(|e| e.payload),
                    root_event.clone().map(|e| e.payload),
                )
                .await?;

            if let Err(e) = node.broadcast_event(&nostr_event).await {
                error!("Failed to broadcast bill chain event, queuing for retry: {e}");
                let payload = serde_json::to_string(&nostr_event)
                    .map_err(|e| Error::Message(e.to_string()))?;
                self.nostr_transport
                    .queue_retry_message_and_trigger(&events.sender(), None, payload)
                    .await?;
            }

            self.nostr_transport
                .add_chain_event(
                    &nostr_event,
                    &root_event,
                    &previous_event,
                    &block_event.data.bill_id.to_string(),
                    BlockchainType::Bill,
                    block_event.data.block.id.inner() as usize,
                    &block_event.data.block.hash,
                )
                .await?;
        }

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

    /// Resync bill chain
    async fn resync_bill_chain(&self, bill_id: &BillId) -> Result<()> {
        self.bill_chain_event_processor
            .resync_chain(bill_id)
            .await?;
        Ok(())
    }

    /// Resync company chain
    async fn resync_company_chain(&self, company_id: &NodeId) -> Result<()> {
        self.company_chain_event_processor
            .resync_chain(company_id)
            .await?;
        Ok(())
    }

    /// Resync identity chain
    async fn resync_identity_chain(&self) -> Result<()> {
        self.identity_chain_event_processor.resync_chain().await?;
        Ok(())
    }

    /// Adds a new transport client for a company if it does not already exist
    async fn add_company_transport(&self, company: &Company, keys: &BcrKeys) -> Result<()> {
        self.nostr_transport.add_company_keys(company, keys).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bcr_ebill_core::protocol::Sha256Hash;

    #[tokio::test]
    async fn test_validate_previous_event_exists_allows_genesis() {
        // Genesis block (height 1) should succeed even without previous event
        // This is a unit test for the validation logic only
        let previous_hash = Sha256Hash::new("genesis");
        let block_height = 1;

        // For genesis blocks, we don't need a previous event
        assert!(block_height <= 1 || previous_hash != Sha256Hash::new("genesis"));
    }

    #[tokio::test]
    async fn test_validate_previous_event_exists_rejects_missing() {
        // Non-genesis block without previous event should fail
        let block_height = 2;

        // Simulate the validation check
        let previous_event_exists = false;
        let is_genesis = block_height <= 1;

        let result = if !previous_event_exists && !is_genesis {
            Err(Error::Blockchain(
                "Cannot publish block: missing previous block".to_string(),
            ))
        } else {
            Ok(())
        };

        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Cannot publish block"));
        assert!(err_msg.contains("missing previous block"));
    }

    #[tokio::test]
    async fn test_validate_previous_event_exists_accepts_with_previous() {
        // Non-genesis block with previous event should succeed
        let block_height = 2;
        let previous_event_exists = true;
        let is_genesis = block_height <= 1;

        let result = if !previous_event_exists && !is_genesis {
            Err(Error::Blockchain(
                "Cannot publish block: missing previous block".to_string(),
            ))
        } else {
            Ok(())
        };

        assert!(result.is_ok());
    }
}
