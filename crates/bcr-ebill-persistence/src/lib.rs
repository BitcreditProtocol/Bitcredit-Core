pub mod backup;
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

use bcr_ebill_core::util;
use log::error;
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

    #[error("no such {0} entity {1}")]
    NoSuchEntity(String, String),

    #[error("Company Block could not be added: {0}")]
    AddCompanyBlock(String),

    #[error("Bill Block could not be added: {0}")]
    AddBillBlock(String),

    #[error("company chain was invalid: {0}")]
    InvalidCompanyChain(String),

    #[error("no company block found")]
    NoCompanyBlock,

    #[error("no bill block found")]
    NoBillBlock,

    #[error("There is already an offer for the given request to mint")]
    MintOfferAlreadyExists,

    #[error("The offer for the given request to mint already has proofs set")]
    MintOfferAlreadyHasProofs,

    #[error("There is no offer for the given request to mint")]
    MintOfferDoesNotExist,

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
    Blockchain(#[from] bcr_ebill_core::blockchain::Error),

    #[error("parse bytes to string error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("No seed phrase available")]
    NoSeedPhrase,

    #[error("Error with encoding, or decoding")]
    EncodingError,
}

impl From<surrealdb::Error> for Error {
    fn from(e: surrealdb::Error) -> Self {
        Error::SurrealConnection(format!("SurrealDB connection error: {}", e))
    }
}

pub use backup::BackupStoreApi;
pub use contact::ContactStoreApi;
#[cfg(target_arch = "wasm32")]
pub use db::file_upload::FileUploadStore;
#[cfg(not(target_arch = "wasm32"))]
pub use db::get_surreal_db;
pub use db::{
    SurrealDbConfig, backup::SurrealBackupStore, bill::SurrealBillStore,
    bill_chain::SurrealBillChainStore, company::SurrealCompanyStore,
    company_chain::SurrealCompanyChainStore, contact::SurrealContactStore,
    identity::SurrealIdentityStore, identity_chain::SurrealIdentityChainStore,
    nostr_chain_event::SurrealNostrChainEventStore,
    nostr_event_offset::SurrealNostrEventOffsetStore, notification::SurrealNotificationStore,
};
#[cfg(not(target_arch = "wasm32"))]
pub use file_upload::FileUploadStore;
pub use nostr::{NostrChainEventStoreApi, NostrEventOffset, NostrEventOffsetStoreApi};
pub use notification::NotificationStoreApi;
