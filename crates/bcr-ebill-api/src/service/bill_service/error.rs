use crate::{blockchain, external, persistence, util};
use thiserror::Error;

/// Generic error type
#[derive(Debug, Error)]
pub enum Error {
    /// errors that currently return early http status code Status::NotFound
    #[error("not found")]
    NotFound,

    /// errors stemming from trying to do invalid operations
    #[error("invalid operation")]
    InvalidOperation,

    /// error returned if the given file upload id is not a temp file we have
    #[error("No file found for file upload id")]
    NoFileForFileUploadId,

    /// errors that stem from interacting with a blockchain
    #[error("Blockchain error: {0}")]
    Blockchain(#[from] blockchain::Error),

    /// all errors originating from the persistence layer
    #[error("Persistence error: {0}")]
    Persistence(#[from] persistence::Error),

    /// all errors originating from external APIs
    #[error("External API error: {0}")]
    ExternalApi(#[from] external::Error),

    /// Errors stemming from cryptography, such as converting keys, encryption and decryption
    #[error("Cryptography error: {0}")]
    Cryptography(#[from] util::crypto::Error),

    #[error("Notification error: {0}")]
    Notification(#[from] bcr_ebill_transport::Error),

    #[error("io error {0}")]
    Io(#[from] std::io::Error),

    /// errors that stem from drawee identity not being in the contacts
    #[error("Can not get drawee identity from contacts.")]
    DraweeNotInContacts,

    /// errors that stem from payee identity not being in the contacts
    #[error("Can not get payee identity from contacts.")]
    PayeeNotInContacts,

    /// errors that stem from buyer identity not being in the contacts
    #[error("Can not get buyer identity from contacts.")]
    BuyerNotInContacts,

    /// errors that stem from endorsee identity not being in the contacts
    #[error("Can not get endorsee identity from contacts.")]
    EndorseeNotInContacts,

    /// errors that stem from mint identity not being in the contacts
    #[error("Can not get mint identity from contacts.")]
    MintNotInContacts,

    /// errors that stem from recoursee identity not being in the contacts
    #[error("Can not get recoursee identity from contacts.")]
    RecourseeNotInContacts,

    /// errors that stem from trying to cancel a mint request that's not pending
    #[error("Mint request can only be cancelled if it's pending.")]
    CancelMintRequestNotPending,

    /// errors that stem from trying to reject a mint request that's not offered
    #[error("Mint request can only be rejected if it's offered.")]
    RejectMintRequestNotOffered,

    /// errors that stem from trying to accept a mint request that's not offered
    #[error("Mint request can only be accepted if it's offered.")]
    AcceptMintRequestNotOffered,

    /// errors that stem from trying to accept a mint request that's expired
    #[error("Mint request can only be accepted if it's not expired.")]
    AcceptMintOfferExpired,

    /// errors that stem from bill validation errors
    #[error("bill validation error {0}")]
    Validation(#[from] bcr_ebill_core::ValidationError),
}
