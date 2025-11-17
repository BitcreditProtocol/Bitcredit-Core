pub mod bill_service;
pub mod company_service;
pub mod contact_service;
pub mod file_upload_service;
pub mod identity_service;
pub mod search_service;
pub mod transport_service;

use crate::external;
use bcr_ebill_core::{application::ValidationError, protocol::ProtocolValidationError};
use thiserror::Error;

/// Generic result type
pub type Result<T> = std::result::Result<T, Error>;

/// Generic error type
#[derive(Debug, Error)]
pub enum Error {
    /// all errors originating from the persistence layer
    #[error("Persistence error: {0}")]
    Persistence(#[from] bcr_ebill_persistence::Error),

    /// errors stemming from resources that were not found
    #[error("not found")]
    NotFound,

    /// errors stemming from sending or receiving notifications
    #[error("Notification service error: {0}")]
    TransportService(#[from] transport_service::Error),

    /// errors stemming from handling bills
    #[error("Bill service error: {0}")]
    BillService(#[from] bill_service::Error),

    /// errors stemming from crypto utils
    #[error("Crypto util error: {0}")]
    CryptoUtil(#[from] bcr_ebill_core::protocol::crypto::Error),

    /// errors that stem from validation in core
    #[error("Validation Error: {0}")]
    Validation(#[from] ValidationError),

    #[error("External API error: {0}")]
    ExternalApi(#[from] external::Error),

    /// errors that stem from interacting with a blockchain
    #[error("Blockchain error: {0}")]
    Protocol(#[from] bcr_ebill_core::protocol::ProtocolError),

    #[error("Json error: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<ProtocolValidationError> for Error {
    fn from(value: ProtocolValidationError) -> Self {
        Self::Validation(ValidationError::Protocol(value))
    }
}
