use bcr_ebill_core::util::{self, crypto};
use thiserror::Error;

pub mod chain_keys;
pub mod email;
pub mod event;
pub mod handler;
pub mod notification_service;
pub mod push_notification;
pub mod transport;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    /// Errors stemming from the transport layer that are Network related
    #[error("Network error: {0}")]
    Network(String),

    /// Errors layer that are serialization related, serde will be auto transformed
    #[error("Message serialization error: {0}")]
    Message(String),

    /// Errors that are storage related
    #[error("Persistence error: {0}")]
    Persistence(String),

    /// Errors that are related to a blockchain
    #[error("BlockChain error: {0}")]
    Blockchain(String),

    /// Errors that are related to crypto (keys, encryption, etc.)
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// errors that stem from validation in core
    #[error("Validation Error: {0}")]
    Validation(#[from] bcr_ebill_core::ValidationError),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Message(format!("Failed to serialize/unserialize json message: {e}"))
    }
}

impl From<crypto::Error> for Error {
    fn from(e: crypto::Error) -> Self {
        Error::Crypto(format!("Failed crypto operation: {e}"))
    }
}

impl From<util::Error> for Error {
    fn from(e: util::Error) -> Self {
        Error::Crypto(format!("Failed base58 operation: {e}"))
    }
}
pub use async_broadcast::Receiver;
pub use event::bill_events::{BillChainEvent, BillChainEventPayload};
pub use event::{Event, EventEnvelope, EventType};
pub use notification_service::NotificationServiceApi;
pub use push_notification::{PushApi, PushService};
pub use transport::{NotificationJsonTransportApi, bcr_nostr_tag};
