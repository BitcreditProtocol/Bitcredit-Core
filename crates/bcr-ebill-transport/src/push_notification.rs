use async_trait::async_trait;
use bcr_ebill_core::ServiceTraitBounds;
use log::trace;
use std::sync::Arc;

use async_broadcast::{InactiveReceiver, Receiver, Sender};
#[cfg(test)]
use mockall::automock;
use serde_json::Value;

#[cfg(test)]
impl ServiceTraitBounds for MockPushApi {}

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait PushApi: ServiceTraitBounds {
    /// Push a json message to the client
    async fn send(&self, value: Value);
    /// Subscribe to the message stream.
    async fn subscribe(&self) -> Receiver<Value>;
}

pub struct PushService {
    sender: Arc<Sender<Value>>,
    _receiver: InactiveReceiver<Value>, // keep receiver around, so channel doesn't get closed
}

impl PushService {
    pub fn new() -> Self {
        let (mut tx, rx) = async_broadcast::broadcast::<Value>(5);
        tx.set_overflow(true);
        tx.set_await_active(false);
        let inactive = rx.deactivate();
        Self {
            sender: Arc::new(tx),
            _receiver: inactive,
        }
    }
}

impl Default for PushService {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceTraitBounds for PushService {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl PushApi for PushService {
    async fn send(&self, value: Value) {
        match self.sender.broadcast(value).await {
            Ok(_) => {}
            Err(err) => {
                trace!("Error sending push message: {err}");
            }
        }
    }

    async fn subscribe(&self) -> Receiver<Value> {
        self.sender.new_receiver()
    }
}
