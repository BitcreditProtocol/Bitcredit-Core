use std::sync::Arc;

use async_trait::async_trait;
use bcr_ebill_core::{
    ServiceTraitBounds,
    bill::BillKeys,
    blockchain::{BlockchainType, bill::BillBlock},
    util::BcrKeys,
};
use log::{debug, error, info, warn};

use crate::{
    Event, EventEnvelope, EventType, NotificationJsonTransportApi, Result,
    event::bill_blockchain_event::BillBlockEvent,
    event::bill_blockchain_event::ChainInvite,
    transport::{decrypt_public_chain_event, unwrap_public_chain_event},
};

use super::{BillChainEventProcessorApi, NotificationHandlerApi};

pub struct BillInviteEventHandler {
    transport: Arc<dyn NotificationJsonTransportApi>,
    processor: Arc<dyn BillChainEventProcessorApi>,
}

impl BillInviteEventHandler {
    pub fn new(
        transport: Arc<dyn NotificationJsonTransportApi>,
        processor: Arc<dyn BillChainEventProcessorApi>,
    ) -> Self {
        Self {
            transport,
            processor,
        }
    }
}

impl ServiceTraitBounds for BillInviteEventHandler {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationHandlerApi for BillInviteEventHandler {
    fn handles_event(&self, event_type: &EventType) -> bool {
        event_type == &EventType::BillChain
    }

    async fn handle_event(&self, event: EventEnvelope, node_id: &str) -> Result<()> {
        debug!("incoming bill chain event for {node_id}");
        if let Ok(decoded) = Event::<ChainInvite>::try_from(event.clone()) {
            debug!("Received chain invite {:?}", decoded.data);
            if let Ok(keys) = BcrKeys::from_private_key(&decoded.data.keys.private_key) {
                let data = self
                    .transport
                    .resolve_public_chain(&decoded.data.chain_id, decoded.data.chain_type)
                    .await?;
                if let Ok(blocks) = extract_blocks(
                    &data,
                    &keys,
                    &decoded.data.chain_id,
                    decoded.data.chain_type,
                ) {
                    if !blocks.is_empty() {
                        info!("extracted blocks {blocks:?}");
                        self.processor
                            .process_chain_data(
                                &decoded.data.chain_id,
                                blocks,
                                Some(BillKeys {
                                    public_key: decoded.data.keys.public_key,
                                    private_key: decoded.data.keys.private_key,
                                }),
                            )
                            .await?;
                    }
                }
                debug!("Resolved chain data for bill chain {data:?}");
            } else {
                error!(
                    "Received invalid chain keys for chain {} {}",
                    &decoded.data.chain_id, &decoded.data.chain_type
                );
            }
        } else {
            warn!("Could not decode event to ChainInvite {event:?}");
        }
        Ok(())
    }
}

fn extract_blocks(
    events: &[nostr_sdk::Event],
    keys: &BcrKeys,
    chain_id: &str,
    chain_type: BlockchainType,
) -> Result<Vec<BillBlock>> {
    let mut result = Vec::new();
    for event in events {
        if let Ok(Some(payload)) = unwrap_public_chain_event(Box::new(event.clone())) {
            if (payload.id == chain_id) && (payload.chain_type == chain_type) {
                if let Ok(decrypted) = decrypt_public_chain_event(&payload.payload, keys) {
                    let event: BillBlockEvent = serde_json::from_value(decrypted.data)?;
                    result.push(event.block);
                }
            }
        }
    }
    Ok(result)
}
