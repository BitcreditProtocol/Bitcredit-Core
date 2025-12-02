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
use bcr_ebill_core::protocol::blockchain::BlockchainType;
use bcr_ebill_core::protocol::crypto::BcrKeys;
use bcr_ebill_core::protocol::event::{BillChainEvent, CompanyChainEvent, IdentityChainEvent};
use log::debug;

use bcr_ebill_api::service::transport_service::Result;

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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl BlockTransportServiceApi for BlockTransportService {
    /// Sent when an identity chain is created or updated
    async fn send_identity_chain_events(&self, events: IdentityChainEvent) -> Result<()> {
        debug!(
            "sending identity chain events for node: {}",
            events.identity_id
        );
        let node = self
            .nostr_transport
            .get_node_transport(&events.sender());
        
            if let Some(event) = events.generate_blockchain_message() {
                let (previous_event, root_event) = self
                    .nostr_transport
                    .find_root_and_previous_event(
                        &event.data.block.previous_hash,
                        &event.data.node_id.to_string(),
                        BlockchainType::Identity,
                    )
                    .await?;
                // send the event
                let nostr_event = node
                    .send_public_chain_event(
                        &event.data.node_id.to_string(),
                        BlockchainType::Identity,
                        event.data.block.timestamp,
                        events.keys.clone(),
                        event.clone().try_into()?,
                        previous_event.clone().map(|e| e.payload),
                        root_event.clone().map(|e| e.payload),
                    )
                    .await?;
                // and store the event locally
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
        let node = self
            .nostr_transport
            .get_node_transport(&events.sender());
        
            if let Some(event) = events.generate_blockchain_message() {
                let (previous_event, root_event) = self
                    .nostr_transport
                    .find_root_and_previous_event(
                        &event.data.block.previous_hash,
                        &event.data.node_id.to_string(),
                        BlockchainType::Company,
                    )
                    .await?;
                // send the event
                let nostr_event = node
                    .send_public_chain_event(
                        &event.data.node_id.to_string(),
                        BlockchainType::Company,
                        event.data.block.timestamp,
                        events.keys.clone(),
                        event.clone().try_into()?,
                        previous_event.clone().map(|e| e.payload),
                        root_event.clone().map(|e| e.payload),
                    )
                    .await?;
                // and store the event locally
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
                node.send_private_event(&events.sender(), &identity, invite.try_into()?)
                    .await?;
            }

        Ok(())
    }

    /// Sent when: A bill chain is created or updated
    async fn send_bill_chain_events(&self, events: BillChainEvent) -> Result<()> {
        let node = self
            .nostr_transport
            .get_node_transport(&events.sender());
        
        if let Some(block_event) = events.generate_blockchain_message() {
                let (previous_event, root_event) = self
                    .nostr_transport
                    .find_root_and_previous_event(
                        &block_event.data.block.previous_hash,
                        &block_event.data.bill_id.to_string(),
                        BlockchainType::Bill,
                    )
                    .await?;

                // now send the event
                let event = node
                    .send_public_chain_event(
                        &block_event.data.bill_id.to_string(),
                        BlockchainType::Bill,
                        block_event.data.block.timestamp,
                        events.bill_keys.clone(),
                        block_event.clone().try_into()?,
                        previous_event.clone().map(|e| e.payload),
                        root_event.clone().map(|e| e.payload),
                    )
                    .await?;

                self.nostr_transport
                    .add_chain_event(
                        &event,
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
                if let Some(identity) = self.nostr_transport.resolve_identity(&recipient).await
                {
                    node.send_private_event(&events.sender(), &identity, event.try_into()?)
                        .await?;
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
        self.nostr_transport.add_company_client(company, keys).await
    }
}
