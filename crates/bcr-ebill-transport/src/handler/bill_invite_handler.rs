use std::sync::Arc;

use async_trait::async_trait;
use bcr_ebill_core::ServiceTraitBounds;
use log::{debug, warn};

use crate::{
    Event, EventEnvelope, EventType, NotificationJsonTransportApi, Result,
    event::bill_blockchain_event::ChainInvite,
};

use super::NotificationHandlerApi;

pub struct BillInviteEventHandler {
    _transport: Arc<dyn NotificationJsonTransportApi>,
}

impl BillInviteEventHandler {
    pub fn new(transport: Arc<dyn NotificationJsonTransportApi>) -> Self {
        Self {
            _transport: transport,
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
            let data = self
                ._transport
                .resolve_public_chain(&decoded.data.chain_id, decoded.data.chain_type)
                .await?;
            debug!("Resolved chain data for bill chain {data:?}");
        } else {
            warn!("Could not decode event to ChainInvite {event:?}");
        }
        Ok(())
    }
}
