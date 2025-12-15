pub mod bill;
pub mod company;
pub mod constants;
pub mod contact;
pub mod db;
pub mod file_upload;
pub mod identity;
pub mod mint;
pub mod nostr;
pub mod notification;
#[cfg(test)]
mod tests;

use bcr_ebill_core::protocol;
use thiserror::Error;

/// Generic persistence result type
pub type Result<T> = std::result::Result<T, Error>;

/// Generic persistence error type
#[derive(Debug, Error)]
pub enum Error {
    #[error("io error {0}")]
    Io(#[from] std::io::Error),

    #[error("SurrealDB error {0}")]
    SurrealConnection(String),

    #[error("Failed to insert into database: {0}")]
    InsertFailed(String),

    #[error("Resource already exists: {0}")]
    Conflict(String),

    #[error("no such {0} entity {1}")]
    NoSuchEntity(String, String),

    #[error("Cryptography error: {0}")]
    CryptoUtil(#[from] protocol::crypto::Error),

    #[error("Protocol error: {0}")]
    Protocol(#[from] bcr_ebill_core::protocol::ProtocolError),

    #[error("Network does not match")]
    NetworkDoesNotMatch,

    #[error("Public Key does not match")]
    PublicKeyDoesNotMatch,

    #[error("Error with encoding, or decoding")]
    EncodingError,

    #[error("Persistence error: {0}")]
    Persistence(String),
}

impl From<surrealdb::Error> for Error {
    fn from(e: surrealdb::Error) -> Self {
        Error::SurrealConnection(format!("SurrealDB connection error: {e}"))
    }
}

pub use contact::ContactStoreApi;
pub use db::file_upload::FileUploadStore;
#[cfg(not(target_arch = "wasm32"))]
pub use db::get_surreal_db;
pub use db::{
    SurrealDbConfig, bill::SurrealBillStore, bill_chain::SurrealBillChainStore,
    company::SurrealCompanyStore, company_chain::SurrealCompanyChainStore,
    contact::SurrealContactStore, identity::SurrealIdentityStore,
    identity_chain::SurrealIdentityChainStore, nostr_chain_event::SurrealNostrChainEventStore,
    nostr_contact_store::SurrealNostrStore, nostr_event_offset::SurrealNostrEventOffsetStore,
    notification::SurrealNotificationStore,
};
// Backwards compatibility alias
pub use db::nostr_contact_store::SurrealNostrStore as SurrealNostrContactStore;
pub use nostr::{
    NostrChainEventStoreApi, NostrEventOffset, NostrEventOffsetStoreApi,
    NostrQueuedMessageStoreApi, NostrStoreApi, PendingContactShare, RelaySyncRetry,
    RelaySyncStatus, ShareDirection, SyncStatus,
};
// Backwards compatibility alias
pub use nostr::NostrStoreApi as NostrContactStoreApi;
pub use notification::NotificationStoreApi;
