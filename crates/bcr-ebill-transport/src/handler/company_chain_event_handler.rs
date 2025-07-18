use std::sync::Arc;

use async_trait::async_trait;
use bcr_ebill_core::{NodeId, ServiceTraitBounds, blockchain::BlockchainType, util::date::now};
use bcr_ebill_persistence::{
    NostrChainEventStoreApi, company::CompanyStoreApi, nostr::NostrChainEvent,
};
use log::{debug, error, trace, warn};

use crate::{
    Event, EventEnvelope, EventType, Result, event::blockchain_event::CompanyBlockEvent,
    transport::root_and_reply_id,
};

use super::{CompanyChainEventProcessorApi, NotificationHandlerApi};

pub struct CompanyChainEventHandler {
    company_store: Arc<dyn CompanyStoreApi>,
    processor: Arc<dyn CompanyChainEventProcessorApi>,
    chain_event_store: Arc<dyn NostrChainEventStoreApi>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationHandlerApi for CompanyChainEventHandler {
    fn handles_event(&self, event_type: &EventType) -> bool {
        event_type == &EventType::CompanyChain
    }

    async fn handle_event(
        &self,
        event: EventEnvelope,
        node_id: &NodeId,
        original_event: Box<nostr::Event>,
    ) -> Result<()> {
        debug!("incoming company chain event for {node_id}");
        if let Ok(decoded) = Event::<CompanyBlockEvent>::try_from(event.clone()) {
            if let Ok(keys) = self.company_store.get_key_pair(&decoded.data.node_id).await {
                let valid = self
                    .processor
                    .process_chain_data(
                        &decoded.data.node_id,
                        vec![decoded.data.block.clone()],
                        Some(keys.clone()),
                    )
                    .await
                    .inspect_err(|e| error!("Received invalid block {e}"))
                    .is_ok();

                self.store_event(
                    original_event,
                    decoded.data.block_height,
                    &decoded.data.block.hash,
                    &decoded.data.node_id.to_string(),
                    valid,
                )
                .await?;
            } else {
                trace!("no keys for incoming company block {node_id}");
            }
        } else {
            warn!("Could not decode event to CompanyBlockEvent {event:?}");
        }
        Ok(())
    }
}
impl ServiceTraitBounds for CompanyChainEventHandler {}

impl CompanyChainEventHandler {
    pub fn new(
        company_store: Arc<dyn CompanyStoreApi>,
        processor: Arc<dyn CompanyChainEventProcessorApi>,
        chain_event_store: Arc<dyn NostrChainEventStoreApi>,
    ) -> Self {
        Self {
            company_store,
            processor,
            chain_event_store,
        }
    }
    async fn store_event(
        &self,
        event: Box<nostr::Event>,
        block_height: usize,
        block_hash: &str,
        chain_id: &str,
        valid: bool,
    ) -> Result<()> {
        let (root, reply) = root_and_reply_id(&event);
        if let Err(e) = self
            .chain_event_store
            .add_chain_event(NostrChainEvent {
                event_id: event.id.to_string(),
                root_id: root
                    .map(|id| id.to_string())
                    .unwrap_or(event.id.to_string()),
                reply_id: reply.map(|id| id.to_string()),
                author: event.pubkey.to_string(),
                chain_id: chain_id.to_string(),
                chain_type: BlockchainType::Bill,
                block_height,
                block_hash: block_hash.to_string(),
                received: now().timestamp() as u64,
                time: event.created_at.as_u64(),
                payload: *event.clone(),
                valid,
            })
            .await
        {
            error!("Failed to store bill chain nostr event into event store {e}");
        }
        Ok(())
    }
}
