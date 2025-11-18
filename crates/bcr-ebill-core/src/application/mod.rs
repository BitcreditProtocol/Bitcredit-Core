use bill::LightBitcreditBillResult;
use company::Company;
use contact::Contact;
use thiserror::Error;
use uuid::Uuid;

pub mod bill;
pub mod company;
pub mod contact;
mod event;
pub mod identity;
pub mod nostr_contact;
pub mod notification;

pub use event::ContactShareEvent;

/// This is needed, so we can have our services be used both in a single threaded (wasm32) and in a
/// multi-threaded (e.g. web) environment without issues.
#[cfg(not(target_arch = "wasm32"))]
pub trait ServiceTraitBounds: Send + Sync {}

#[cfg(target_arch = "wasm32")]
pub trait ServiceTraitBounds {}

#[derive(Debug)]
pub struct GeneralSearchResult {
    pub bills: Vec<LightBitcreditBillResult>,
    pub contacts: Vec<Contact>,
    pub companies: Vec<Company>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum GeneralSearchFilterItemType {
    Company,
    Bill,
    Contact,
}

#[derive(Debug)]
pub struct UploadFileResult {
    pub file_upload_id: Uuid,
}

use crate::protocol::ProtocolValidationError;

/// Generic validation error type
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ValidationError {
    /// error from protocol validation
    #[error("Protocol validation: {0}")]
    Protocol(#[from] ProtocolValidationError),

    /// error returned if the contact is invalid, e.g. a non-anon contact with no address
    #[error("The contact {0} is invalid")]
    InvalidContact(String),

    /// error returned if the mint is invalid
    #[error("The mint {0} is invalid")]
    InvalidMint(String),

    /// error returned if there is already a request to mint for this bill and mint
    #[error("There is already a request to mint for this bill and mint")]
    RequestToMintForBillAndMintAlreadyActive,

    /// error returned if an anonymous contact is used in place where only an identified can't be used
    #[error("The contact {0} is anonymous, but an identified contact is needed")]
    ContactIsAnonymous(String),

    /// error returned if the signatory is not in the contacts
    #[error("Node Id {0} is not a person in the contacts.")]
    SignatoryNotInContacts(String),

    /// errors stemming from providing an invalid bill type
    #[error("Invalid bill type")]
    InvalidBillType,

    /// error returned if the signatory is not a signatory of the company
    #[error("Caller must be signatory for company")]
    CallerMustBeSignatory,

    /// error returned if the given node is not a local one (company or identity)
    #[error("The provided node_id: {0} is not a valid company id, or personal node_id")]
    UnknownNodeId(String),

    /// errors that stem from interacting with a blockchain
    #[error("Blockchain error: {0}")]
    Blockchain(String),

    /// error returned if the identity proof status was invalid
    #[error("Invalid identity proof status: {0}")]
    InvalidIdentityProofStatus(String),

    /// errors stemming from trying to do invalid operations
    #[error("invalid operation")]
    InvalidOperation,

    /// error returned if the given file upload id is not a temp file we have
    #[error("No file found for file upload id")]
    NoFileForFileUploadId,

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

    /// errors that stem from trying to create, or deanonymize an identity without a confirmed email
    #[error("Ident identity can only be created with a confirmed email.")]
    NoConfirmedEmailForIdentIdentity,
}
