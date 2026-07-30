use bcr_ebill_api::service::bill_service::Error as BillServiceError;
use bcr_ebill_api::service::{
    Error as ServiceError, transport_service::Error as NotificationServiceError,
};
use bcr_ebill_core::application::ValidationError;
use bcr_ebill_core::protocol::{ProtocolValidationError, crypto};
use log::error;

#[derive(Debug, Clone)]
pub struct EbillFfiError {
    pub kind: EbillFfiErrorKind,
    pub code: EbillFfiErrorCode,
    pub msg: String,
}

#[derive(Debug, Clone)]
pub enum EbillFfiErrorKind {
    BadRequest,
    NotFound,
    Network,
    Internal,
    Initialization,
    Unavailable,
    Unsupported,
}

#[derive(Debug, Clone)]
pub enum EbillFfiErrorCode {
    FieldEmpty,
    FieldInvalid,
    InvalidSum,
    InvalidCurrency,
    InvalidBitcoinAddress,
    InvalidBitcoinDescriptor,
    InvalidContentType,
    IdentityCantBeAnon,
    InvalidContactType,
    InvalidIdentityType,
    InvalidDate,
    InvalidCountry,
    InvalidTimestamp,
    DeadlineBeforeMinimum,
    SelfDraftedBillCantBeBlank,
    RequestToMintForBillAndMintAlreadyActive,
    SignerCantBeAnon,
    ContactIsAnonymous,
    InvalidContact,
    InvalidMint,
    IssueDateAfterMaturityDate,
    MaturityDateInThePast,
    RequestToPayBeforeMaturityDate,
    InvalidFileUploadId,
    InvalidNodeId,
    InvalidBillId,
    InvalidBillType,
    DraweeCantBePayee,
    EndorserCantBeEndorsee,
    BuyerCantBeSeller,
    RecourserCantBeRecoursee,
    DraweeNotInContacts,
    PayeeNotInContacts,
    MintNotInContacts,
    BuyerNotInContacts,
    EndorseeNotInContacts,
    RecourseeNotInContacts,
    NoPaymentForSweep,
    CancelMintRequestNotPending,
    RejectMintRequestNotOffered,
    AcceptMintRequestNotOffered,
    AcceptMintOfferExpired,
    NoConfirmedEmailForIdentIdentity,
    NoFileForFileUploadId,
    NotFound,
    ExternalApi,
    Crypto,
    Persistence,
    Blockchain,
    Protocol,
    InvalidRelayUrl,
    Serialization,
    Init,
    // notification
    NotificationNetwork,
    NotificationMessage,
    //bill
    InvalidOperation,
    BillAlreadyAccepted,
    BillWasRejectedToAccept,
    BillAcceptanceExpired,
    BillWasRejectedToPay,
    BillPaymentExpired,
    BillWasRecoursedToTheEnd,
    BillAlreadyRequestedToAccept,
    BillNotAccepted,
    CallerIsNotDrawee,
    CallerIsNotHolder,
    CallerIsNotRecoursee,
    CallerIsNotBuyer,
    RequestAlreadyRejected,
    BillAlreadyPaid,
    BillWasNotRequestedToPay,
    BillWasNotOfferedToSell,
    BillRequestToAcceptDidNotExpireAndWasNotRejected,
    BillRequestToPayDidNotExpireAndWasNotRejected,
    RecourseeNotPastHolder,
    BillWasNotRequestedToRecourse,
    BillIsNotRequestedToRecourseAndWaitingForPayment,
    BillIsNotOfferToSellWaitingForPayment,
    BillSellDataInvalid,
    BillRecourseDataInvalid,
    BillIsRequestedToPayAndWaitingForPayment,
    BillIsOfferedToSellAndWaitingForPayment,
    BillIsInRecourseAndWaitingForPayment,
    // general
    SignatoryNotInContacts,
    SignatoryAlreadySignatory,
    CantRemoveLastSignatory,
    NotASignatory,
    NotARemovedOrRejectedSignatory,
    NotInvitedAsSignatory,
    NoSignerIdentityProof,
    FileIsTooBig,
    FileIsEmpty,
    TooManyFiles,
    InvalidFileName,
    UnknownNodeId,
    CallerMustBeSignatory,
    CallerMustBeCreator,
    CallerMustBeIdentifiedCreator,
    InvalidIdentityProof,
    InvalidReferenceBlock,
    MintRequestToPayWithoutCustomAddress,
    InvalidSignature,
    InvalidHash,
    InvalidUrl,
    InvalidIdentityProofStatus,
    Json,
    InvalidBillAction,
    InvalidCompanyAction,
    InvalidIdentityAction,
    CompanySignerCreatorMismatch,
    InvalidMintRequestId,
}

impl From<ServiceError> for EbillFfiError {
    fn from(value: ServiceError) -> Self {
        error!("Service Error: {value}");
        match value {
            ServiceError::NotFound => err_404(value, EbillFfiErrorCode::NotFound),
            ServiceError::TransportService(e) => notification_service_error_data(e),
            ServiceError::BillService(e) => bill_service_error_data(e),
            ServiceError::Validation(e) => validation_error_data(e),
            ServiceError::ExternalApi(e) => err_500(e, EbillFfiErrorCode::ExternalApi),
            ServiceError::CryptoUtil(e) => err_500(e, EbillFfiErrorCode::Crypto),
            ServiceError::Persistence(e) => err_500(e, EbillFfiErrorCode::Persistence),
            ServiceError::Protocol(e) => err_500(e, EbillFfiErrorCode::Protocol),
            ServiceError::Json(e) => err_500(e, EbillFfiErrorCode::Json),
        }
    }
}

impl From<BillServiceError> for EbillFfiError {
    fn from(value: BillServiceError) -> Self {
        error!("Bill Service Error: {value}");
        bill_service_error_data(value)
    }
}

impl From<NotificationServiceError> for EbillFfiError {
    fn from(value: NotificationServiceError) -> Self {
        error!("Notification Service Error: {value}");
        notification_service_error_data(value)
    }
}

impl From<crypto::Error> for EbillFfiError {
    fn from(value: crypto::Error) -> Self {
        error!("Crypto Error: {value}");
        err_500(value, EbillFfiErrorCode::Crypto)
    }
}

impl From<bcr_ebill_persistence::Error> for EbillFfiError {
    fn from(value: bcr_ebill_persistence::Error) -> Self {
        error!("Persistence Error: {value}");
        err_500(value, EbillFfiErrorCode::Persistence)
    }
}

impl From<anyhow::Error> for EbillFfiError {
    fn from(value: anyhow::Error) -> Self {
        error!("Init Error: {value}");
        err_500(value, EbillFfiErrorCode::Init)
    }
}

impl From<ValidationError> for EbillFfiError {
    fn from(value: ValidationError) -> Self {
        error!("Validation Error: {value}");
        validation_error_data(value)
    }
}

impl From<ProtocolValidationError> for EbillFfiError {
    fn from(value: ProtocolValidationError) -> Self {
        error!("Protocol Validation Error: {value}");
        protocol_validation_error_data(value)
    }
}

fn notification_service_error_data(e: NotificationServiceError) -> EbillFfiError {
    match e {
        NotificationServiceError::Network(e) => err_500(e, EbillFfiErrorCode::NotificationNetwork),
        NotificationServiceError::Message(e) => err_500(e, EbillFfiErrorCode::NotificationMessage),
        NotificationServiceError::Persistence(e) => err_500(e, EbillFfiErrorCode::Persistence),
        NotificationServiceError::Crypto(e) => err_500(e, EbillFfiErrorCode::Crypto),
        NotificationServiceError::Blockchain(e) => err_500(e, EbillFfiErrorCode::Blockchain),
        NotificationServiceError::Validation(e) => validation_error_data(e),
        NotificationServiceError::ExternalApi(e) => err_500(e, EbillFfiErrorCode::ExternalApi),
        NotificationServiceError::NotFound => err_404(e, EbillFfiErrorCode::NotFound),
    }
}

fn bill_service_error_data(e: BillServiceError) -> EbillFfiError {
    match e {
        BillServiceError::Validation(e) => validation_error_data(e),
        BillServiceError::NotFound => err_404(e, EbillFfiErrorCode::NotFound),
        BillServiceError::Persistence(e) => err_500(e, EbillFfiErrorCode::Persistence),
        BillServiceError::ExternalApi(e) => err_500(e, EbillFfiErrorCode::ExternalApi),
        BillServiceError::Protocol(e) => err_500(e, EbillFfiErrorCode::Protocol),
        BillServiceError::Cryptography(e) => err_500(e, EbillFfiErrorCode::Crypto),
        BillServiceError::Notification(e) => notification_service_error_data(e),
        BillServiceError::Json(e) => err_500(e, EbillFfiErrorCode::Serialization),
    }
}

fn validation_error_data(e: ValidationError) -> EbillFfiError {
    match e {
        ValidationError::Protocol(e) => protocol_validation_error_data(e),
        ValidationError::RequestToMintForBillAndMintAlreadyActive => err_400(
            e,
            EbillFfiErrorCode::RequestToMintForBillAndMintAlreadyActive,
        ),
        ValidationError::ContactIsAnonymous(_) => err_400(e, EbillFfiErrorCode::ContactIsAnonymous),
        ValidationError::InvalidContact(_) => err_400(e, EbillFfiErrorCode::InvalidContact),
        ValidationError::InvalidMint(_) => err_400(e, EbillFfiErrorCode::InvalidMint),
        ValidationError::InvalidBillType => err_400(e, EbillFfiErrorCode::InvalidBillType),
        ValidationError::SignatoryNotInContacts(_) => {
            err_400(e, EbillFfiErrorCode::SignatoryNotInContacts)
        }
        ValidationError::UnknownNodeId(_) => err_400(e, EbillFfiErrorCode::UnknownNodeId),
        ValidationError::Blockchain(e) => err_500(e, EbillFfiErrorCode::Blockchain),
        ValidationError::InvalidIdentityProofStatus(_) => {
            err_400(e, EbillFfiErrorCode::InvalidIdentityProofStatus)
        }
        ValidationError::InvalidOperation => err_400(e, EbillFfiErrorCode::InvalidOperation),
        ValidationError::NoFileForFileUploadId => {
            err_400(e, EbillFfiErrorCode::NoFileForFileUploadId)
        }
        ValidationError::DraweeNotInContacts => err_400(e, EbillFfiErrorCode::DraweeNotInContacts),
        ValidationError::PayeeNotInContacts => err_400(e, EbillFfiErrorCode::PayeeNotInContacts),
        ValidationError::BuyerNotInContacts => err_400(e, EbillFfiErrorCode::BuyerNotInContacts),
        ValidationError::EndorseeNotInContacts => {
            err_400(e, EbillFfiErrorCode::EndorseeNotInContacts)
        }
        ValidationError::MintNotInContacts => err_400(e, EbillFfiErrorCode::MintNotInContacts),
        ValidationError::RecourseeNotInContacts => {
            err_400(e, EbillFfiErrorCode::RecourseeNotInContacts)
        }
        ValidationError::NoPaymentForSweep => err_400(e, EbillFfiErrorCode::NoPaymentForSweep),
        ValidationError::CancelMintRequestNotPending => {
            err_400(e, EbillFfiErrorCode::CancelMintRequestNotPending)
        }
        ValidationError::RejectMintRequestNotOffered => {
            err_400(e, EbillFfiErrorCode::RejectMintRequestNotOffered)
        }
        ValidationError::AcceptMintRequestNotOffered => {
            err_400(e, EbillFfiErrorCode::AcceptMintRequestNotOffered)
        }
        ValidationError::AcceptMintOfferExpired => {
            err_400(e, EbillFfiErrorCode::AcceptMintOfferExpired)
        }
        ValidationError::NoConfirmedEmailForIdentIdentity => {
            err_400(e, EbillFfiErrorCode::NoConfirmedEmailForIdentIdentity)
        }
    }
}

fn protocol_validation_error_data(e: ProtocolValidationError) -> EbillFfiError {
    match e {
        ProtocolValidationError::FieldEmpty(_) => err_400(e, EbillFfiErrorCode::FieldEmpty),
        ProtocolValidationError::FieldInvalid(_) => err_400(e, EbillFfiErrorCode::FieldInvalid),
        ProtocolValidationError::InvalidSum => err_400(e, EbillFfiErrorCode::InvalidSum),
        ProtocolValidationError::InvalidBitcoinAddress => {
            err_400(e, EbillFfiErrorCode::InvalidBitcoinAddress)
        }
        ProtocolValidationError::InvalidBitcoinDescriptor => {
            err_400(e, EbillFfiErrorCode::InvalidBitcoinDescriptor)
        }
        ProtocolValidationError::InvalidCurrency => err_400(e, EbillFfiErrorCode::InvalidCurrency),
        ProtocolValidationError::InvalidContactType => {
            err_400(e, EbillFfiErrorCode::InvalidContactType)
        }
        ProtocolValidationError::InvalidIdentityType => {
            err_400(e, EbillFfiErrorCode::InvalidIdentityType)
        }
        ProtocolValidationError::InvalidContentType => {
            err_400(e, EbillFfiErrorCode::InvalidContentType)
        }
        ProtocolValidationError::InvalidDate => err_400(e, EbillFfiErrorCode::InvalidDate),
        ProtocolValidationError::InvalidCountry => err_400(e, EbillFfiErrorCode::InvalidCountry),
        ProtocolValidationError::InvalidTimestamp => {
            err_400(e, EbillFfiErrorCode::InvalidTimestamp)
        }
        ProtocolValidationError::DeadlineBeforeMinimum => {
            err_400(e, EbillFfiErrorCode::DeadlineBeforeMinimum)
        }
        ProtocolValidationError::SelfDraftedBillCantBeBlank => {
            err_400(e, EbillFfiErrorCode::SelfDraftedBillCantBeBlank)
        }
        ProtocolValidationError::IdentityCantBeAnon => {
            err_400(e, EbillFfiErrorCode::IdentityCantBeAnon)
        }
        ProtocolValidationError::SignerCantBeAnon => {
            err_400(e, EbillFfiErrorCode::SignerCantBeAnon)
        }
        ProtocolValidationError::MaturityDateInThePast => {
            err_400(e, EbillFfiErrorCode::MaturityDateInThePast)
        }
        ProtocolValidationError::IssueDateAfterMaturityDate => {
            err_400(e, EbillFfiErrorCode::IssueDateAfterMaturityDate)
        }
        ProtocolValidationError::RequestToPayBeforeMaturityDate => {
            err_400(e, EbillFfiErrorCode::RequestToPayBeforeMaturityDate)
        }
        ProtocolValidationError::InvalidFileUploadId => {
            err_400(e, EbillFfiErrorCode::InvalidFileUploadId)
        }
        ProtocolValidationError::InvalidNodeId => err_400(e, EbillFfiErrorCode::InvalidNodeId),
        ProtocolValidationError::InvalidBillId => err_400(e, EbillFfiErrorCode::InvalidBillId),
        ProtocolValidationError::DraweeCantBePayee => {
            err_400(e, EbillFfiErrorCode::DraweeCantBePayee)
        }
        ProtocolValidationError::EndorserCantBeEndorsee => {
            err_400(e, EbillFfiErrorCode::EndorserCantBeEndorsee)
        }
        ProtocolValidationError::BuyerCantBeSeller => {
            err_400(e, EbillFfiErrorCode::BuyerCantBeSeller)
        }
        ProtocolValidationError::RecourserCantBeRecoursee => {
            err_400(e, EbillFfiErrorCode::RecourserCantBeRecoursee)
        }
        ProtocolValidationError::BillAlreadyAccepted => {
            err_400(e, EbillFfiErrorCode::BillAlreadyAccepted)
        }
        ProtocolValidationError::BillWasRejectedToAccept => {
            err_400(e, EbillFfiErrorCode::BillWasRejectedToAccept)
        }
        ProtocolValidationError::BillAcceptanceExpired => {
            err_400(e, EbillFfiErrorCode::BillAcceptanceExpired)
        }
        ProtocolValidationError::BillWasRejectedToPay => {
            err_400(e, EbillFfiErrorCode::BillWasRejectedToPay)
        }
        ProtocolValidationError::BillPaymentExpired => {
            err_400(e, EbillFfiErrorCode::BillPaymentExpired)
        }
        ProtocolValidationError::BillWasRecoursedToTheEnd => {
            err_400(e, EbillFfiErrorCode::BillWasRecoursedToTheEnd)
        }
        ProtocolValidationError::BillWasNotOfferedToSell => {
            err_400(e, EbillFfiErrorCode::BillWasNotOfferedToSell)
        }
        ProtocolValidationError::BillWasNotRequestedToPay => {
            err_400(e, EbillFfiErrorCode::BillWasNotRequestedToPay)
        }
        ProtocolValidationError::BillWasNotRequestedToRecourse => {
            err_400(e, EbillFfiErrorCode::BillWasNotRequestedToRecourse)
        }
        ProtocolValidationError::BillIsNotOfferToSellWaitingForPayment => {
            err_400(e, EbillFfiErrorCode::BillIsNotOfferToSellWaitingForPayment)
        }
        ProtocolValidationError::BillIsOfferedToSellAndWaitingForPayment => err_400(
            e,
            EbillFfiErrorCode::BillIsOfferedToSellAndWaitingForPayment,
        ),
        ProtocolValidationError::BillIsInRecourseAndWaitingForPayment => {
            err_400(e, EbillFfiErrorCode::BillIsInRecourseAndWaitingForPayment)
        }
        ProtocolValidationError::BillRequestToAcceptDidNotExpireAndWasNotRejected => err_400(
            e,
            EbillFfiErrorCode::BillRequestToAcceptDidNotExpireAndWasNotRejected,
        ),
        ProtocolValidationError::BillRequestToPayDidNotExpireAndWasNotRejected => err_400(
            e,
            EbillFfiErrorCode::BillRequestToPayDidNotExpireAndWasNotRejected,
        ),
        ProtocolValidationError::BillIsNotRequestedToRecourseAndWaitingForPayment => err_400(
            e,
            EbillFfiErrorCode::BillIsNotRequestedToRecourseAndWaitingForPayment,
        ),
        ProtocolValidationError::BillSellDataInvalid => {
            err_400(e, EbillFfiErrorCode::BillSellDataInvalid)
        }
        ProtocolValidationError::BillAlreadyPaid => err_400(e, EbillFfiErrorCode::BillAlreadyPaid),
        ProtocolValidationError::BillNotAccepted => err_400(e, EbillFfiErrorCode::BillNotAccepted),
        ProtocolValidationError::BillAlreadyRequestedToAccept => {
            err_400(e, EbillFfiErrorCode::BillAlreadyRequestedToAccept)
        }
        ProtocolValidationError::BillIsRequestedToPayAndWaitingForPayment => err_400(
            e,
            EbillFfiErrorCode::BillIsRequestedToPayAndWaitingForPayment,
        ),
        ProtocolValidationError::BillRecourseDataInvalid => {
            err_400(e, EbillFfiErrorCode::BillRecourseDataInvalid)
        }
        ProtocolValidationError::RecourseeNotPastHolder => {
            err_400(e, EbillFfiErrorCode::RecourseeNotPastHolder)
        }
        ProtocolValidationError::CallerIsNotDrawee => {
            err_400(e, EbillFfiErrorCode::CallerIsNotDrawee)
        }
        ProtocolValidationError::CallerIsNotBuyer => {
            err_400(e, EbillFfiErrorCode::CallerIsNotBuyer)
        }
        ProtocolValidationError::CallerIsNotRecoursee => {
            err_400(e, EbillFfiErrorCode::CallerIsNotRecoursee)
        }
        ProtocolValidationError::RequestAlreadyRejected => {
            err_400(e, EbillFfiErrorCode::RequestAlreadyRejected)
        }
        ProtocolValidationError::CallerIsNotHolder => {
            err_400(e, EbillFfiErrorCode::CallerIsNotHolder)
        }
        ProtocolValidationError::SignatoryAlreadySignatory(_) => {
            err_400(e, EbillFfiErrorCode::SignatoryAlreadySignatory)
        }
        ProtocolValidationError::CantRemoveLastSignatory => {
            err_400(e, EbillFfiErrorCode::CantRemoveLastSignatory)
        }
        ProtocolValidationError::NotASignatory(_) => err_400(e, EbillFfiErrorCode::NotASignatory),
        ProtocolValidationError::NotARemovedOrRejectedSignatory => {
            err_400(e, EbillFfiErrorCode::NotARemovedOrRejectedSignatory)
        }
        ProtocolValidationError::NotInvitedAsSignatory => {
            err_400(e, EbillFfiErrorCode::NotInvitedAsSignatory)
        }
        ProtocolValidationError::NoSignerIdentityProof => {
            err_400(e, EbillFfiErrorCode::NoSignerIdentityProof)
        }
        ProtocolValidationError::FileIsTooBig(_) => err_400(e, EbillFfiErrorCode::FileIsTooBig),
        ProtocolValidationError::FileIsEmpty => err_400(e, EbillFfiErrorCode::FileIsEmpty),
        ProtocolValidationError::TooManyFiles => err_400(e, EbillFfiErrorCode::TooManyFiles),
        ProtocolValidationError::InvalidFileName(_) => {
            err_400(e, EbillFfiErrorCode::InvalidFileName)
        }
        ProtocolValidationError::Blockchain(e) => err_500(e, EbillFfiErrorCode::Blockchain),
        ProtocolValidationError::InvalidRelayUrl => err_400(e, EbillFfiErrorCode::InvalidRelayUrl),
        ProtocolValidationError::InvalidSignature => {
            err_400(e, EbillFfiErrorCode::InvalidSignature)
        }
        ProtocolValidationError::InvalidHash => err_400(e, EbillFfiErrorCode::InvalidHash),
        ProtocolValidationError::InvalidUrl => err_400(e, EbillFfiErrorCode::InvalidUrl),
        ProtocolValidationError::InvalidBillAction => {
            err_400(e, EbillFfiErrorCode::InvalidBillAction)
        }
        ProtocolValidationError::InvalidCompanyAction => {
            err_400(e, EbillFfiErrorCode::InvalidCompanyAction)
        }
        ProtocolValidationError::InvalidIdentityAction => {
            err_400(e, EbillFfiErrorCode::InvalidIdentityAction)
        }
        ProtocolValidationError::CompanySignerCreatorMismatch => {
            err_400(e, EbillFfiErrorCode::CompanySignerCreatorMismatch)
        }
        ProtocolValidationError::InvalidMintRequestId => {
            err_400(e, EbillFfiErrorCode::InvalidMintRequestId)
        }
        ProtocolValidationError::CallerMustBeSignatory => {
            err_400(e, EbillFfiErrorCode::CallerMustBeSignatory)
        }
        ProtocolValidationError::CallerMustBeCreator => {
            err_400(e, EbillFfiErrorCode::CallerMustBeCreator)
        }
        ProtocolValidationError::CallerMustBeIdentifiedCreator => {
            err_400(e, EbillFfiErrorCode::CallerMustBeIdentifiedCreator)
        }
        ProtocolValidationError::InvalidIdentityProof => {
            err_400(e, EbillFfiErrorCode::InvalidIdentityProof)
        }
        ProtocolValidationError::InvalidReferenceBlock => {
            err_400(e, EbillFfiErrorCode::InvalidReferenceBlock)
        }
        ProtocolValidationError::MintRequestToPayWithoutCustomAddress => {
            err_400(e, EbillFfiErrorCode::MintRequestToPayWithoutCustomAddress)
        }
    }
}

fn err_400<E: ToString>(e: E, code: EbillFfiErrorCode) -> EbillFfiError {
    EbillFfiError {
        kind: EbillFfiErrorKind::BadRequest,
        code,
        msg: e.to_string(),
    }
}

fn err_404<E: ToString>(e: E, code: EbillFfiErrorCode) -> EbillFfiError {
    EbillFfiError {
        kind: EbillFfiErrorKind::NotFound,
        code,
        msg: e.to_string(),
    }
}

fn err_500<E: ToString>(e: E, code: EbillFfiErrorCode) -> EbillFfiError {
    EbillFfiError {
        kind: EbillFfiErrorKind::Internal,
        code,
        msg: e.to_string(),
    }
}
