use crate::{external, util};
use bcr_ebill_core::util::crypto;

pub mod chain_keys;
pub mod event;
pub mod restore;
mod service;
pub mod transport;

use log::error;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use bcr_ebill_core::NodeId;
use bcr_ebill_core::util::BcrKeys;
use nostr::{
    nips::{nip01::Metadata, nip19::ToBech32},
    types::RelayUrl,
};
use std::time::Duration;

#[cfg(test)]
pub use service::MockNotificationServiceApi;
pub use service::NotificationServiceApi;

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

    #[error("External API error: {0}")]
    ExternalApi(#[from] external::Error),

    /// errors if something couldn't be found
    #[error("not found")]
    NotFound,
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

/// A container for collecting contact data from nostr
#[derive(Debug, Clone)]
pub struct NostrContactData {
    pub metadata: Metadata,
    pub relays: Vec<RelayUrl>,
}

impl NostrContactData {
    pub fn new(name: &str, relays: Vec<String>, bcr_data: BcrMetadata) -> Self {
        // At some point we might want to add more metadata like payment info
        let mut metadata = Metadata::new().name(name).display_name(name);
        if let Ok(custom) = serde_json::to_value(bcr_data) {
            metadata = metadata.custom_field("bcr", custom);
        }

        Self {
            metadata,
            relays: relays.into_iter().filter_map(|r| r.parse().ok()).collect(),
        }
    }
}

/// Our custom data on nostr Metadata messages
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BcrMetadata {
    /// Encrypted private contact data for sharing with trusted contacts
    pub contact_data: String,
}

#[derive(Clone, Debug)]
pub struct NostrConfig {
    pub keys: BcrKeys,
    pub relays: Vec<String>,
    pub default_timeout: Duration,
    pub is_primary: bool,
    pub node_id: NodeId,
}

impl NostrConfig {
    pub fn new(keys: BcrKeys, relays: Vec<String>, is_primary: bool, node_id: NodeId) -> Self {
        assert!(!relays.is_empty());
        Self {
            keys,
            relays,
            default_timeout: Duration::from_secs(20),
            is_primary,
            node_id,
        }
    }

    pub fn get_npub(&self) -> String {
        self.keys
            .get_nostr_keys()
            .public_key()
            .to_bech32()
            .expect("checked conversion")
    }

    pub fn get_relay(&self) -> String {
        self.relays[0].clone()
    }
}
