use thiserror::Error;

mod base;
pub mod blockchain;
pub mod constants;
pub mod crypto;
pub mod event;
pub mod mint;
pub mod serialization;
/// Test helpers
#[cfg(test)]
pub mod tests;

// base types
pub use base::BitcoinAddress;
pub use base::DateTimeUtc;
pub use base::File;
pub use base::OptionalPostalAddress;
pub use base::PostalAddress;
pub use base::address::Address;
pub use base::block_id::BlockId;
pub use base::city::City;
pub use base::country::Country;
pub use base::date::Date;
pub use base::email::Email;
pub use base::hash::Sha256Hash;
pub use base::identification::Identification;
pub use base::identity_proof::{SignedEmailIdentityData, SignedIdentityProof};
pub use base::name::Name;
pub use base::signature::SchnorrSignature;
pub use base::sum::Currency;
pub use base::sum::Sum;
pub use base::timestamp::Timestamp;
pub use base::zip::Zip;
// re-export key types
pub use bitcoin::secp256k1::{PublicKey, SecretKey};

pub type Result<T> = std::result::Result<T, ProtocolError>;

pub trait Validate {
    fn validate(&self) -> std::result::Result<(), ProtocolValidationError>;
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Errors stemming from cryptography, such as converting keys, encryption and decryption
    #[error("Cryptography error: {0}")]
    Crypto(#[from] crypto::Error),

    /// Errors stemming from blockchain operations
    #[error("Blockchain error: {0}")]
    Blockchain(#[from] blockchain::Error),

    /// Errors stemming from validation
    #[error("validation error: {0}")]
    Validation(#[from] ProtocolValidationError),
}

impl From<serde_json::Error> for ProtocolError {
    fn from(e: serde_json::Error) -> Self {
        ProtocolError::Serialization(format!("JSON error: {e}"))
    }
}

impl From<std::io::Error> for ProtocolError {
    fn from(e: std::io::Error) -> Self {
        ProtocolError::Serialization(format!("IO error: {e}"))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Field {
    Country,
    City,
    Zip,
    Address,
    Name,
    Email,
    Id,
    CountryOfIssuing,
    CityOfIssuing,
    CountryOfPayment,
    CityOfPayment,
    Identification,
}

/// Generic validation error type
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProtocolValidationError {
    /// error returned if a field that is not allowed to be empty is empty
    #[error("Field {0:?} can't be empty")]
    FieldEmpty(Field),

    /// error returned if a field has invalid data
    #[error("Field {0:?} has invalid data")]
    FieldInvalid(Field),

    /// error returned if the sum was invalid
    #[error("Invalid sum")]
    InvalidSum,

    /// error returned if the date was invalid
    #[error("Invalid date")]
    InvalidDate,

    /// error returned if the country was invalid
    #[error("Invalid country")]
    InvalidCountry,

    /// error returned if the given deadline is before the minimum deadline
    #[error("The given deadline is before the minimum deadline")]
    DeadlineBeforeMinimum,

    /// error returned if the timestamp was invalid
    #[error("Invalid timestamp")]
    InvalidTimestamp,

    /// error returned if the signer for a certain action is not allowed to be anonymous
    #[error("The signer can't be anonymous")]
    SignerCantBeAnon,

    /// error returned if the identity for a certain action is not allowed to be anonymous
    #[error("The identity can't be anonymous")]
    IdentityCantBeAnon,

    /// error returned if the maturity date is in the past
    #[error("Maturity date can't be in the past")]
    MaturityDateInThePast,

    /// error returned if the issue date is after the maturity date
    #[error("Issue date after maturity date")]
    IssueDateAfterMaturityDate,

    /// error returned if the currency was invalid
    #[error("Invalid currency")]
    InvalidCurrency,

    /// error returned if the file upload id was invalid
    #[error("Invalid file upload id")]
    InvalidFileUploadId,

    /// errors stemming from providing an invalid bill id
    #[error("Invalid bill id")]
    InvalidBillId,

    /// errors stemming from when the drawee is the payee
    #[error("Drawee can't be Payee at the same time")]
    DraweeCantBePayee,

    /// errors stemming from when the endorser is the endorsee
    #[error("Endorser can't be Endorsee at the same time")]
    EndorserCantBeEndorsee,

    /// errors stemming from when the buyer is the seller
    #[error("Buyer can't be Seller at the same time")]
    BuyerCantBeSeller,

    /// errors stemming from when the recourser is the recoursee
    #[error("Recourser can't be Recoursee at the same time")]
    RecourserCantBeRecoursee,

    /// error returned if a bill was already accepted and is attempted to be accepted again
    #[error("Bill was already accepted")]
    BillAlreadyAccepted,

    /// error returned if the caller of an operation is not the drawee, but would have to be for it
    /// to be valid, e.g. accepting a  bill
    #[error("Caller is not drawee")]
    CallerIsNotDrawee,

    /// error returned if the caller of an operation is not the holder, but would have to be for it
    /// to be valid, e.g. requesting payment
    #[error("Caller is not holder")]
    CallerIsNotHolder,

    /// error returned if the given recoursee is not a past holder of the bill
    #[error("The given recoursee is not a past holder of the bill")]
    RecourseeNotPastHolder,

    /// error returned if a bill was already requested to accept
    #[error("Bill was already requested to accept")]
    BillAlreadyRequestedToAccept,

    /// error returned if a bill was not accepted yet
    #[error("Bill was not yet accepted")]
    BillNotAccepted,

    /// error returned if a bill was rejected to pay
    #[error("Bill was rejected to pay")]
    BillWasRejectedToPay,

    /// error returned if a bill payment expired
    #[error("Bill payment expired")]
    BillPaymentExpired,

    /// error returned if a bill was rejected to accept
    #[error("Bill was rejected to accept")]
    BillWasRejectedToAccept,

    /// error returned if a bill acceptance expired
    #[error("Bill acceptance expired")]
    BillAcceptanceExpired,

    /// error returned if a bill was recoursed to the end
    #[error("Bill was recoursed to the end")]
    BillWasRecoursedToTheEnd,

    /// error returned if the caller of a reject operation is not the recoursee
    #[error("Caller is not the recoursee and can't reject")]
    CallerIsNotRecoursee,

    /// error returned if the caller of a reject buy operation is not the buyer
    #[error("Caller is not the buyer and can't reject to buy")]
    CallerIsNotBuyer,

    /// error returned if the operation was already rejected
    #[error("The request was already rejected")]
    RequestAlreadyRejected,

    /// error returned if the bill was already paid and hence can't be rejected to be paid
    #[error("The bill was already paid")]
    BillAlreadyPaid,

    /// error returned if the bill is self drafted and blank (anon payee) - because it doesn't make
    /// sense as the drawer is identified already
    #[error("A self-drafted bill can't be blank")]
    SelfDraftedBillCantBeBlank,

    /// error returned if the bill was not requested to pay, e.g. when rejecting to pay
    #[error("Bill was not requested to pay")]
    BillWasNotRequestedToPay,

    /// error returned if the bill was not offered to sell, e.g. when rejecting to buy
    #[error("Bill was not offered to sell")]
    BillWasNotOfferedToSell,

    /// error returned if someone wants to request acceptance recourse, but the request to accept did
    /// not expire and was not rejected
    #[error("Bill request to accept did not expire and was not rejected")]
    BillRequestToAcceptDidNotExpireAndWasNotRejected,

    /// error returned if someone wants to request payment recourse, but the request to pay did
    /// not expire and was not rejected
    #[error("Bill request to pay did not expire and was not rejected")]
    BillRequestToPayDidNotExpireAndWasNotRejected,

    /// error returned if the bill was not requester to recourse, e.g. when rejecting to pay for
    /// recourse
    #[error("Bill was not requested to recourse")]
    BillWasNotRequestedToRecourse,

    /// error returned if the bill is not requested to recourse and is waiting for payment
    #[error("Bill is not waiting for recourse payment")]
    BillIsNotRequestedToRecourseAndWaitingForPayment,

    /// error returned if the bill is not currently an offer to sell waiting for payment
    #[error("Bill is not offer to sell waiting for payment")]
    BillIsNotOfferToSellWaitingForPayment,

    /// error returned if the selling data of selling a bill does not match the waited for offer to
    /// sell
    #[error("Sell data does not match offer to sell")]
    BillSellDataInvalid,

    /// error returned if the selling data of recoursing a bill does not match the request to
    /// recourse
    #[error("Recourse data does not match request to recourse")]
    BillRecourseDataInvalid,

    /// error returned if the bill is requested to pay and waiting for payment
    #[error("Bill is requested to pay and waiting for payment")]
    BillIsRequestedToPayAndWaitingForPayment,

    /// error returned if the bill is offered to sell and waiting for payment
    #[error("Bill is offered to sell and waiting for payment")]
    BillIsOfferedToSellAndWaitingForPayment,

    /// error returned if the bill is in recourse and waiting for payment
    #[error("Bill is in recourse and waiting for payment")]
    BillIsInRecourseAndWaitingForPayment,

    /// error returned if the signatory is already a signatory
    #[error("Node Id {0} is already a signatory.")]
    SignatoryAlreadySignatory(String),

    /// error returned if the last signatory is about to be removed
    #[error("Can't remove last signatory")]
    CantRemoveLastSignatory,

    /// error returned if the signatory to be removed is not a signatory
    #[error("Node id {0} is not a signatory.")]
    NotASignatory(String),

    /// error returned if the file is too big
    #[error("Maximum file size for this file type is {0} bytes")]
    FileIsTooBig(usize),

    /// error returned if the file is empty
    #[error("File is empty (0 bytes)")]
    FileIsEmpty,

    /// error returned if there are too many bill files
    #[error("Too many files")]
    TooManyFiles,

    /// error returned if the file name is wrong
    #[error("File name needs to have between 1 and {0} characters")]
    InvalidFileName(usize),

    /// error returned if the file has an invalid, or unknown content type
    #[error("Invalid content type")]
    InvalidContentType,

    /// error returned if the node id is not valid
    #[error("Invalid node id")]
    InvalidNodeId,

    /// error returned if the identity type is not valid
    #[error("Invalid identity type")]
    InvalidIdentityType,

    /// errors that stem from interacting with a blockchain
    #[error("Blockchain error: {0}")]
    Blockchain(String),

    /// error returned if the relay url was invalid
    #[error("Invalid relay url")]
    InvalidRelayUrl,

    /// error returned if the string is not a valid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// error returned if the string is not a valid hash
    #[error("Invalid hash")]
    InvalidHash,

    /// error returned if the string is not a valid url
    #[error("Invalid url")]
    InvalidUrl,

    /// error returned if the mint request id was invalid
    #[error("Invalid mint request id")]
    InvalidMintRequestId,

    /// error returned if the given bill action was invalid
    #[error("Invalid bill action")]
    InvalidBillAction,

    /// error returned if the contact type is not valid
    #[error("Invalid contact type")]
    InvalidContactType,
}

impl From<bcr_common::core::Error> for ProtocolValidationError {
    fn from(err: bcr_common::core::Error) -> Self {
        match err {
            bcr_common::core::Error::InvalidNodeId => ProtocolValidationError::InvalidNodeId,
            bcr_common::core::Error::InvalidBillId => ProtocolValidationError::InvalidBillId,
        }
    }
}
