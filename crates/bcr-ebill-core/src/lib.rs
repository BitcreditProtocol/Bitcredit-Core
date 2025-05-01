use bill::LightBitcreditBillResult;
use borsh_derive::{BorshDeserialize, BorshSerialize};
use company::Company;
use contact::Contact;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use util::is_blank;

pub mod bill;
pub mod blockchain;
pub mod company;
pub mod constants;
pub mod contact;
pub mod identity;
pub mod notification;
#[cfg(test)]
mod tests;
pub mod util;

/// This is needed, so we can have our services be used both in a single threaded (wasm32) and in a
/// multi-threaded (e.g. web) environment without issues.
#[cfg(not(target_arch = "wasm32"))]
pub trait ServiceTraitBounds: Send + Sync {}

#[cfg(target_arch = "wasm32")]
pub trait ServiceTraitBounds {}

pub trait Validate {
    fn validate(&self) -> Result<(), ValidationError>;
}

#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default,
)]
pub struct PostalAddress {
    pub country: String,
    pub city: String,
    pub zip: Option<String>,
    pub address: String,
}

impl Validate for PostalAddress {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.country.trim().is_empty() {
            return Err(ValidationError::FieldEmpty(Field::Country));
        }

        if self.city.trim().is_empty() {
            return Err(ValidationError::FieldEmpty(Field::City));
        }

        if is_blank(&self.zip) {
            return Err(ValidationError::FieldEmpty(Field::Zip));
        }

        if self.address.trim().is_empty() {
            return Err(ValidationError::FieldEmpty(Field::Address));
        }
        Ok(())
    }
}

impl fmt::Display for PostalAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.zip {
            Some(ref zip) => {
                write!(
                    f,
                    "{}, {} {}, {}",
                    self.address, zip, self.city, self.country
                )
            }
            None => {
                write!(f, "{}, {}, {}", self.address, self.city, self.country)
            }
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OptionalPostalAddress {
    pub country: Option<String>,
    pub city: Option<String>,
    pub zip: Option<String>,
    pub address: Option<String>,
}

impl Validate for OptionalPostalAddress {
    fn validate(&self) -> Result<(), ValidationError> {
        if is_blank(&self.country) {
            return Err(ValidationError::FieldEmpty(Field::Country));
        }

        if is_blank(&self.city) {
            return Err(ValidationError::FieldEmpty(Field::City));
        }

        if is_blank(&self.zip) {
            return Err(ValidationError::FieldEmpty(Field::Zip));
        }

        if is_blank(&self.address) {
            return Err(ValidationError::FieldEmpty(Field::Address));
        }
        Ok(())
    }
}

impl OptionalPostalAddress {
    pub fn is_fully_set(&self) -> bool {
        self.country.is_some() && self.city.is_some() && self.address.is_some()
    }

    pub fn to_full_postal_address(&self) -> Option<PostalAddress> {
        if self.is_fully_set() {
            return Some(PostalAddress {
                country: self.country.clone().expect("checked above"),
                city: self.city.clone().expect("checked above"),
                zip: self.zip.clone(),
                address: self.address.clone().expect("checked above"),
            });
        }
        None
    }
}

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

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub name: String,
    pub hash: String,
}

#[derive(Debug)]
pub struct UploadFileResult {
    pub file_upload_id: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Field {
    Country,
    City,
    Zip,
    Address,
    Name,
    Id,
    CountryOfIssuing,
    CityOfIssuing,
    CountryOfPayment,
    CityOfPayment,
    Language,
}

/// Generic validation error type
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ValidationError {
    /// error returned if a field that is not allowed to be empty is empty
    #[error("Field {0:?} can't be empty")]
    FieldEmpty(Field),

    /// error returned if the sum was invalid
    #[error("invalid sum")]
    InvalidSum,

    /// error returned if the date was invalid
    #[error("invalid date")]
    InvalidDate,

    /// error returned if the maturity date is in the past
    #[error("maturity date can't be in the past")]
    MaturityDateInThePast,

    /// error returned if the issue date is after the maturity date
    #[error("issue date after maturity date")]
    IssueDateAfterMaturityDate,

    /// error returned if the currency was invalid
    #[error("invalid currency")]
    InvalidCurrency,

    /// error returned if the bitcoin address
    #[error("invalid payment address")]
    InvalidPaymentAddress,

    /// error returned if the file upload id was invalid
    #[error("invalid file upload id")]
    InvalidFileUploadId,

    /// errors stemming from providing an invalid bill type
    #[error("invalid bill type")]
    InvalidBillType,

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

    /// error returned if a bill was rejected to recourse
    #[error("Bill was rejected to recourse")]
    BillWasRejectedToRecourse,

    /// error returned if a bill request to recourse expired
    #[error("Bill request to recourse expired")]
    BillRequestToRecourseExpired,

    /// error returned if a bill was recoursed to the end
    #[error("Bill was recoursed to the end")]
    BillWasRecoursedToTheEnd,

    /// error returned if the caller of a reject operation is not the recoursee
    #[error("Caller is not the recoursee and can't reject")]
    CallerIsNotRecoursee,

    /// error returned if the caller of a reject buy operation is not the buyer
    #[error("Caller is not the buyer and can't reject to buy")]
    CallerIsNotBuyer,

    /// error returned if the caller of a reject operation trys to reject a request that is already
    /// expired
    #[error("The request already expired")]
    RequestAlreadyExpired,

    /// error returned if the operation was already rejected
    #[error("The request was already rejected")]
    RequestAlreadyRejected,

    /// error returned if the bill was already paid and hence can't be rejected to be paid
    #[error("The bill was already paid")]
    BillAlreadyPaid,

    /// error returned if the bill was not requested to accept, e.g. when rejecting to accept
    #[error("Bill was not requested to accept")]
    BillWasNotRequestedToAccept,

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

    /// error returned if the bill was requested to pay
    #[error("Bill was requested to pay")]
    BillWasRequestedToPay,

    /// error returned if the signatory is not a signatory of the company
    #[error("Caller must be signatory for company")]
    CallerMustBeSignatory,

    /// error returned if the drawer is not a bill issuer
    #[error("Drawer is not a bill issuer - does not have a postal address set")]
    DrawerIsNotBillIssuer,

    /// error returned if the signatory is not in the contacts
    #[error("Node Id {0} is not a person in the contacts.")]
    SignatoryNotInContacts(String),

    /// error returned if the signatory is already a signatory
    #[error("Node Id {0} is already a signatory.")]
    SignatoryAlreadySignatory(String),

    /// error returned if the last signatory is about to be removed
    #[error("Can't remove last signatory")]
    CantRemoveLastSignatory,

    /// error returned if the signatory to be removed is not a signatory
    #[error("Node id {0} is not a signatory.")]
    NotASignatory(String),

    /// error returned if the given secp256k1 key is not valid
    #[error("Not a valid secp256k1 key: {0}")]
    InvalidSecp256k1Key(String),

    /// error returned if the file is too big
    #[error("Maximum file size is {0} bytes")]
    FileIsTooBig(usize),

    /// error returned if the file name is wrong
    #[error("File name needs to have between 1 and {0} characters")]
    InvalidFileName(usize),

    /// error returned if the file has an invalid, or unknown content type
    #[error("Invalid content type")]
    InvalidContentType,

    /// error returned if the contact type is not valid
    #[error("Invalid contact type")]
    InvalidContactType,

    /// error returned if the given node is not a local one (company or identity)
    #[error("The provided node_id: {0} is not a valid company id, or personal node_id")]
    UnknownNodeId(String),

    /// error returned if the given surrealdb connection doesn't support backup
    #[error("Backup not supported for given SurrealDB connection")]
    BackupNotSupported,

    /// errors that stem from interacting with a blockchain
    #[error("Blockchain error: {0}")]
    Blockchain(String),
}

impl From<crate::blockchain::Error> for ValidationError {
    fn from(e: crate::blockchain::Error) -> Self {
        ValidationError::Blockchain(format!("Blockchain error: {}", e))
    }
}
