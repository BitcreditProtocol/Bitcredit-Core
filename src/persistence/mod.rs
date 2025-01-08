pub mod bill;
pub mod company;
pub mod contact;
pub mod db;
pub mod file_upload;
pub mod identity;
pub mod identity_chain;
pub mod nostr;
pub mod notification;

use crate::util;
use bill::FileBasedBillStore;
use db::{
    company::SurrealCompanyStore, contact::SurrealContactStore, get_surreal_db,
    identity::SurrealIdentityStore, identity_chain::SurrealIdentityChainStore,
    nostr_event_offset::SurrealNostrEventOffsetStore, notification::SurrealNotificationStore,
    SurrealDbConfig,
};
use log::error;
use notification::NotificationStoreApi;
use std::{path::Path, sync::Arc};
use thiserror::Error;

/// Generic persistence result type
pub type Result<T> = std::result::Result<T, Error>;

/// Generic persistence error type
#[derive(Debug, Error)]
pub enum Error {
    #[error("io error {0}")]
    Io(#[from] std::io::Error),

    #[error("SurrealDB connection error {0}")]
    SurrealConnection(#[from] surrealdb::Error),

    #[error("Failed to insert into database: {0}")]
    InsertFailed(String),

    #[error("unable to serialize/deserialize to/from JSON {0}")]
    Json(#[from] serde_json::Error),

    #[error("unable to serialize/deserialize PeerId {0}")]
    PeerId(#[from] libp2p::multihash::Error),

    #[error("unable to serialize/deserialize Keypair {0}")]
    Keypair(#[from] libp2p::identity::DecodingError),

    #[error("no such {0} entity {1}")]
    NoSuchEntity(String, String),

    #[error("Identity Block could not be added: {0}")]
    AddIdentityBlock(String),

    #[error("identity chain was invalid: {0}")]
    InvalidIdentityChain(String),

    #[error("no identity block found")]
    NoIdentityBlock,

    #[error("no identity found")]
    NoIdentity,

    #[error("no node id found")]
    NoNodeId,

    #[error("no identity key found")]
    NoIdentityKey,

    #[allow(dead_code)]
    #[error("Failed to convert integer {0}")]
    FromInt(#[from] std::num::TryFromIntError),

    #[error("Cryptography error: {0}")]
    CryptoUtil(#[from] util::crypto::Error),

    #[error("Blockchain error: {0}")]
    Blockchain(#[from] blockchain::Error),

    #[error("parse bytes to string error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}

pub use contact::ContactStoreApi;
pub use nostr::{NostrEventOffset, NostrEventOffsetStoreApi};

use crate::{blockchain, config::Config};
use file_upload::FileUploadStore;

/// Given a base path and a directory path, ensures that the directory
/// exists and returns the full path.
pub async fn file_storage_path(data_dir: &str, path: &str) -> Result<String> {
    let directory = format!("{}/{}", data_dir, path);
    if !Path::new(&directory).exists() {
        tokio::fs::create_dir_all(&directory).await?;
    }
    Ok(directory)
}

/// A container for all persistence related dependencies.
#[derive(Clone)]
pub struct DbContext {
    pub contact_store: Arc<dyn ContactStoreApi>,
    pub bill_store: Arc<dyn bill::BillStoreApi>,
    pub identity_store: Arc<dyn identity::IdentityStoreApi>,
    pub identity_chain_store: Arc<dyn identity_chain::IdentityChainStoreApi>,
    pub company_store: Arc<dyn company::CompanyStoreApi>,
    pub file_upload_store: Arc<dyn file_upload::FileUploadStoreApi>,
    pub nostr_event_offset_store: Arc<dyn nostr::NostrEventOffsetStoreApi>,
    pub notification_store: Arc<dyn NotificationStoreApi>,
}

/// Creates a new instance of the DbContext with the given SurrealDB configuration.
pub async fn get_db_context(conf: &Config) -> Result<DbContext> {
    let surreal_db_config = SurrealDbConfig::new(&conf.surreal_db_connection);
    let db = get_surreal_db(&surreal_db_config).await?;

    let company_store = Arc::new(SurrealCompanyStore::new(db.clone()));
    let file_upload_store =
        Arc::new(FileUploadStore::new(&conf.data_dir, "files", "temp_upload").await?);

    if let Err(e) = file_upload_store.cleanup_temp_uploads().await {
        error!("Error cleaning up temp upload folder for bill: {e}");
    }

    let contact_store = Arc::new(SurrealContactStore::new(db.clone()));

    let bill_store =
        Arc::new(FileBasedBillStore::new(&conf.data_dir, "bills", "bills_keys").await?);

    let identity_store = Arc::new(SurrealIdentityStore::new(db.clone()));
    let identity_chain_store = Arc::new(SurrealIdentityChainStore::new(db.clone()));

    let nostr_event_offset_store = Arc::new(SurrealNostrEventOffsetStore::new(db.clone()));
    let notification_store = Arc::new(SurrealNotificationStore::new(db.clone()));

    Ok(DbContext {
        contact_store,
        bill_store,
        identity_store,
        identity_chain_store,
        company_store,
        file_upload_store,
        nostr_event_offset_store,
        notification_store,
    })
}
