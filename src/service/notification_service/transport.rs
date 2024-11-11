use super::{EventEnvelope, Result};
use async_trait::async_trait;
use log::info;
#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock)]
#[async_trait]
pub trait NotificationJsonTransportApi: Send + Sync {
    async fn send(&self, event: EventEnvelope) -> Result<()>;
}

/// A dummy transport that logs all events that are sent as json.
pub struct LoggingNotificationJsonTransport;

#[async_trait]
impl NotificationJsonTransportApi for LoggingNotificationJsonTransport {
    async fn send(&self, event: EventEnvelope) -> Result<()> {
        info!(
            "Sending json event: {:?}({}) with payload: {:?} to peer: {}",
            event.event_type, event.version, event.data, event.peer_id
        );
        Ok(())
    }
}
