#![recursion_limit = "256"]
pub mod constants;
pub mod db;
pub mod file_upload;
#[cfg(test)]
mod tests;
pub mod traits;

#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "sqlite")]
pub mod sqlite;

mod sql;

use std::path::PathBuf;

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

    #[error("Migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("Initialization error: {0}")]
    Init(String),

    #[error("Invalid Data error: {0}")]
    InvalidData(String),

    #[error("Json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Sqlx query error: {0}")]
    SqlxQuery(#[from] sqlx::Error),
}

impl From<surrealdb::Error> for Error {
    fn from(e: surrealdb::Error) -> Self {
        Error::SurrealConnection(format!("SurrealDB connection error: {e}"))
    }
}

#[derive(Clone, Debug)]
pub struct DbConfig {
    pub connection_string: String,
    pub temp_files_path: PathBuf,
}

#[cfg(feature = "sqlite")]
pub async fn get_sqlite_db(config: &DbConfig) -> Result<sqlite::SqlitePersistence> {
    use std::str::FromStr;
    let db = sqlite::SqlitePersistence::open(sqlite::SqliteConfig::new(
        std::path::PathBuf::from_str(&config.connection_string)
            .map_err(|e| Error::Init(format!("Invalid Sqlite folder: {e}")))?,
    ))
    .await?;
    Ok(db)
}

#[cfg(feature = "postgres")]
pub async fn get_postgres_db(config: &DbConfig) -> Result<postgres::PostgresPersistence> {
    use crate::postgres::{PostgresConfig, PostgresPersistence};
    let db =
        PostgresPersistence::connect(PostgresConfig::new(config.connection_string.clone())).await?;
    Ok(db)
}

pub use db::file_reference::SurrealFileReferenceStore;
pub use db::file_upload::FileUploadStore;
pub use db::get_surreal_db;
pub use db::{
    SurrealDbConfig, bill::SurrealBillStore, bill_chain::SurrealBillChainStore,
    company::SurrealCompanyStore, company_chain::SurrealCompanyChainStore,
    contact::SurrealContactStore, identity::SurrealIdentityStore,
    identity_chain::SurrealIdentityChainStore, nostr_chain_event::SurrealNostrChainEventStore,
    nostr_contact_store::SurrealNostrStore, nostr_event_offset::SurrealNostrEventOffsetStore,
    notification::SurrealNotificationStore,
};
pub use traits::contact::ContactStoreApi;
pub use traits::file_reference::FileReferenceStoreApi;
// Backwards compatibility alias
pub use db::nostr_contact_store::SurrealNostrStore as SurrealNostrContactStore;
pub use traits::nostr::{
    NostrChainEventStoreApi, NostrEventOffset, NostrEventOffsetStoreApi,
    NostrQueuedMessageStoreApi, NostrStoreApi, PendingContactShare, RelaySyncRetry,
    RelaySyncStatus, ShareDirection, SyncStatus,
};
// Backwards compatibility alias
pub use traits::nostr::NostrStoreApi as NostrContactStoreApi;
pub use traits::notification::NotificationStoreApi;
