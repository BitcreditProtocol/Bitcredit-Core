use async_trait::async_trait;
use bcr_ebill_core::{
    ServiceTraitBounds, blockchain::bill::block::NodeId, contact::BillParticipant,
};
use log::info;

#[cfg(test)]
use mockall::automock;

use crate::{Result, event::EventEnvelope};

#[cfg(test)]
impl ServiceTraitBounds for MockNotificationJsonTransportApi {}

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait NotificationJsonTransportApi: ServiceTraitBounds {
    fn get_sender_key(&self) -> String;
    async fn send(&self, recipient: &BillParticipant, event: EventEnvelope) -> Result<()>;
}

/// A dummy transport that logs all events that are sent as json.
pub struct LoggingNotificationJsonTransport;

impl ServiceTraitBounds for LoggingNotificationJsonTransport {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationJsonTransportApi for LoggingNotificationJsonTransport {
    fn get_sender_key(&self) -> String {
        "log_sender".to_string()
    }
    async fn send(&self, recipient: &BillParticipant, event: EventEnvelope) -> Result<()> {
        info!(
            "Sending json event: {:?}({}) with payload: {:?} to peer: {}",
            event.event_type,
            event.version,
            event.data,
            recipient.node_id()
        );
        Ok(())
    }
}
