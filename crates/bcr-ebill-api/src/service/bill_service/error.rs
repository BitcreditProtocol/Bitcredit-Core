use crate::{external, service::transport_service};
use bcr_ebill_core::{
    application::ValidationError,
    protocol::{ProtocolValidationError, crypto},
};
use thiserror::Error;

/// Generic error type
#[derive(Debug, Error)]
pub enum Error {
    /// errors stemming from resources that were not found
    #[error("not found")]
    NotFound,

    /// all errors originating from the persistence layer
    #[error("Persistence error: {0}")]
    Persistence(#[from] bcr_ebill_persistence::Error),

    /// all errors originating from external APIs
    #[error("External API error: {0}")]
    ExternalApi(#[from] external::Error),

    /// Errors stemming from cryptography, such as converting keys, encryption and decryption
    #[error("Cryptography error: {0}")]
    Cryptography(#[from] crypto::Error),

    #[error("Notification error: {0}")]
    Notification(#[from] transport_service::Error),

    #[error("Protocol error: {0}")]
    Protocol(#[from] bcr_ebill_core::protocol::ProtocolError),

    /// errors that stem from bill validation errors
    #[error("bill validation error {0}")]
    Validation(#[from] ValidationError),
}

impl From<ProtocolValidationError> for Error {
    fn from(value: ProtocolValidationError) -> Self {
        Self::Validation(ValidationError::Protocol(value))
    }
}
