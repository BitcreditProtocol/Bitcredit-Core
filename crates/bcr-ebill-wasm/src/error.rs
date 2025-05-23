use bcr_ebill_api::service::Error as ServiceError;
use bcr_ebill_api::service::bill_service::Error as BillServiceError;
use bcr_ebill_api::util::{self, ValidationError};
use bcr_ebill_transport::Error as NotificationServiceError;
use log::error;
use serde::Serialize;
use thiserror::Error;
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Debug, Error)]
pub enum WasmError {
    #[error("service error: {0}")]
    Service(#[from] ServiceError),

    #[error("bill service error: {0}")]
    BillService(#[from] BillServiceError),

    #[error("notification service error: {0}")]
    NotificationService(#[from] NotificationServiceError),

    #[error("wasm serialization error: {0}")]
    WasmSerialization(#[from] serde_wasm_bindgen::Error),

    #[error("crypto error: {0}")]
    Crypto(#[from] util::crypto::Error),

    #[error("persistence error: {0}")]
    Persistence(#[from] bcr_ebill_api::PersistenceError),

    #[error("api init error: {0}")]
    Init(#[from] anyhow::Error),

    #[error("Validation error: {0}")]
    Validation(#[from] bcr_ebill_api::util::ValidationError),
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
enum JsErrorType {
    FieldEmpty,
    InvalidSum,
    InvalidCurrency,
    InvalidPaymentAddress,
    InvalidContentType,
    IdentityCantBeAnon,
    IdentityIsNotBillIssuer,
    InvalidContactType,
    InvalidIdentityType,
    InvalidDate,
    SelfDraftedBillCantBeBlank,
    RequestToMintForBillAndMintAlreadyActive,
    SignerCantBeAnon,
    ContactIsAnonymous,
    InvalidContact,
    InvalidMint,
    IssueDateAfterMaturityDate,
    MaturityDateInThePast,
    InvalidFileUploadId,
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
    CancelMintRequestNotPending,
    NoFileForFileUploadId,
    NotFound,
    ExternalApi,
    Io,
    Crypto,
    Persistence,
    Blockchain,
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
    BillWasRejectedToRecourse,
    BillRequestToRecourseExpired,
    BillWasRecoursedToTheEnd,
    BillAlreadyRequestedToAccept,
    BillNotAccepted,
    CallerIsNotDrawee,
    CallerIsNotHolder,
    CallerIsNotRecoursee,
    CallerIsNotBuyer,
    RequestAlreadyExpired,
    RequestAlreadyRejected,
    BillAlreadyPaid,
    BillWasNotRequestedToAccept,
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
    BillWasRequestedToPay,
    // general
    DrawerIsNotBillIssuer,
    SignatoryNotInContacts,
    SignatoryAlreadySignatory,
    CantRemoveLastSignatory,
    NotASignatory,
    InvalidSecp256k1Key,
    FileIsTooBig,
    InvalidFileName,
    UnknownNodeId,
    BackupNotSupported,
    CallerMustBeSignatory,
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
struct JsErrorData {
    error: JsErrorType,
    message: String,
    code: u16,
}
impl From<WasmError> for JsValue {
    fn from(error: WasmError) -> JsValue {
        error!("{error}");
        let js_error_data = match error {
            WasmError::Service(e) => match e {
                ServiceError::NoFileForFileUploadId => {
                    err_400(e, JsErrorType::NoFileForFileUploadId)
                }
                ServiceError::NotFound => err_404(e, JsErrorType::NotFound),
                ServiceError::NotificationService(e) => notification_service_error_data(e),
                ServiceError::BillService(e) => bill_service_error_data(e),
                ServiceError::Validation(e) => validation_error_data(e),
                ServiceError::ExternalApi(e) => err_500(e, JsErrorType::ExternalApi),
                ServiceError::Io(e) => err_500(e, JsErrorType::Io),
                ServiceError::CryptoUtil(e) => err_500(e, JsErrorType::Crypto),
                ServiceError::Persistence(e) => err_500(e, JsErrorType::Persistence),
                ServiceError::Blockchain(e) => err_500(e, JsErrorType::Blockchain),
            },
            WasmError::BillService(e) => bill_service_error_data(e),
            WasmError::Validation(e) => validation_error_data(e),
            WasmError::NotificationService(e) => notification_service_error_data(e),
            WasmError::WasmSerialization(e) => err_500(e, JsErrorType::Serialization),
            WasmError::Crypto(e) => err_500(e, JsErrorType::Crypto),
            WasmError::Persistence(e) => err_500(e, JsErrorType::Persistence),
            WasmError::Init(e) => err_500(e, JsErrorType::Init),
        };
        serde_wasm_bindgen::to_value(&js_error_data).expect("can serialize error")
    }
}
fn notification_service_error_data(e: NotificationServiceError) -> JsErrorData {
    match e {
        NotificationServiceError::Network(e) => err_500(e, JsErrorType::NotificationNetwork),
        NotificationServiceError::Message(e) => err_500(e, JsErrorType::NotificationMessage),
        NotificationServiceError::Persistence(e) => err_500(e, JsErrorType::Persistence),
        NotificationServiceError::Crypto(e) => err_500(e, JsErrorType::Crypto),
        NotificationServiceError::Blockchain(e) => err_500(e, JsErrorType::Blockchain),
    }
}

fn bill_service_error_data(e: BillServiceError) -> JsErrorData {
    match e {
        BillServiceError::DraweeNotInContacts => err_400(e, JsErrorType::DraweeNotInContacts),
        BillServiceError::PayeeNotInContacts => err_400(e, JsErrorType::PayeeNotInContacts),
        BillServiceError::BuyerNotInContacts => err_400(e, JsErrorType::BuyerNotInContacts),
        BillServiceError::EndorseeNotInContacts => err_400(e, JsErrorType::EndorseeNotInContacts),
        BillServiceError::MintNotInContacts => err_400(e, JsErrorType::MintNotInContacts),
        BillServiceError::RecourseeNotInContacts => err_400(e, JsErrorType::RecourseeNotInContacts),
        BillServiceError::CancelMintRequestNotPending => {
            err_400(e, JsErrorType::CancelMintRequestNotPending)
        }
        BillServiceError::NoFileForFileUploadId => err_400(e, JsErrorType::NoFileForFileUploadId),
        BillServiceError::InvalidOperation => err_400(e, JsErrorType::InvalidOperation),
        BillServiceError::Validation(e) => validation_error_data(e),
        BillServiceError::NotFound => err_404(e, JsErrorType::NotFound),
        BillServiceError::Io(e) => err_500(e, JsErrorType::Io),
        BillServiceError::Persistence(e) => err_500(e, JsErrorType::Persistence),
        BillServiceError::ExternalApi(e) => err_500(e, JsErrorType::ExternalApi),
        BillServiceError::Blockchain(e) => err_500(e, JsErrorType::Blockchain),
        BillServiceError::Cryptography(e) => err_500(e, JsErrorType::Crypto),
        BillServiceError::Notification(e) => notification_service_error_data(e),
    }
}

fn validation_error_data(e: ValidationError) -> JsErrorData {
    match e {
        ValidationError::FieldEmpty(_) => err_400(e, JsErrorType::FieldEmpty),
        ValidationError::InvalidSum => err_400(e, JsErrorType::InvalidSum),
        ValidationError::InvalidCurrency => err_400(e, JsErrorType::InvalidCurrency),
        ValidationError::InvalidPaymentAddress => err_400(e, JsErrorType::InvalidPaymentAddress),
        ValidationError::InvalidContactType => err_400(e, JsErrorType::InvalidContactType),
        ValidationError::InvalidIdentityType => err_400(e, JsErrorType::InvalidIdentityType),
        ValidationError::InvalidContentType => err_400(e, JsErrorType::InvalidContentType),
        ValidationError::InvalidDate => err_400(e, JsErrorType::InvalidDate),
        ValidationError::SelfDraftedBillCantBeBlank => {
            err_400(e, JsErrorType::SelfDraftedBillCantBeBlank)
        }
        ValidationError::IdentityCantBeAnon => err_400(e, JsErrorType::IdentityCantBeAnon),
        ValidationError::IdentityIsNotBillIssuer => {
            err_400(e, JsErrorType::IdentityIsNotBillIssuer)
        }
        ValidationError::SignerCantBeAnon => err_400(e, JsErrorType::SignerCantBeAnon),
        ValidationError::RequestToMintForBillAndMintAlreadyActive => {
            err_400(e, JsErrorType::RequestToMintForBillAndMintAlreadyActive)
        }
        ValidationError::ContactIsAnonymous(_) => err_400(e, JsErrorType::ContactIsAnonymous),
        ValidationError::InvalidContact(_) => err_400(e, JsErrorType::InvalidContact),
        ValidationError::InvalidMint(_) => err_400(e, JsErrorType::InvalidMint),
        ValidationError::MaturityDateInThePast => err_400(e, JsErrorType::MaturityDateInThePast),
        ValidationError::IssueDateAfterMaturityDate => {
            err_400(e, JsErrorType::IssueDateAfterMaturityDate)
        }
        ValidationError::InvalidFileUploadId => err_400(e, JsErrorType::InvalidFileUploadId),
        ValidationError::InvalidBillType => err_400(e, JsErrorType::InvalidBillType),
        ValidationError::DraweeCantBePayee => err_400(e, JsErrorType::DraweeCantBePayee),
        ValidationError::EndorserCantBeEndorsee => err_400(e, JsErrorType::EndorserCantBeEndorsee),
        ValidationError::BuyerCantBeSeller => err_400(e, JsErrorType::BuyerCantBeSeller),
        ValidationError::RecourserCantBeRecoursee => {
            err_400(e, JsErrorType::RecourserCantBeRecoursee)
        }
        ValidationError::RequestAlreadyExpired => err_400(e, JsErrorType::RequestAlreadyExpired),
        ValidationError::BillAlreadyAccepted => err_400(e, JsErrorType::BillAlreadyAccepted),
        ValidationError::BillWasRejectedToAccept => {
            err_400(e, JsErrorType::BillWasRejectedToAccept)
        }
        ValidationError::BillAcceptanceExpired => err_400(e, JsErrorType::BillAcceptanceExpired),
        ValidationError::BillWasRejectedToPay => err_400(e, JsErrorType::BillWasRejectedToPay),
        ValidationError::BillPaymentExpired => err_400(e, JsErrorType::BillPaymentExpired),
        ValidationError::BillWasRejectedToRecourse => {
            err_400(e, JsErrorType::BillWasRejectedToRecourse)
        }
        ValidationError::BillRequestToRecourseExpired => {
            err_400(e, JsErrorType::BillRequestToRecourseExpired)
        }
        ValidationError::BillWasRecoursedToTheEnd => {
            err_400(e, JsErrorType::BillWasRecoursedToTheEnd)
        }
        ValidationError::BillWasNotOfferedToSell => {
            err_400(e, JsErrorType::BillWasNotOfferedToSell)
        }
        ValidationError::BillWasNotRequestedToPay => {
            err_400(e, JsErrorType::BillWasNotRequestedToPay)
        }
        ValidationError::BillWasNotRequestedToAccept => {
            err_400(e, JsErrorType::BillWasNotRequestedToAccept)
        }
        ValidationError::BillWasNotRequestedToRecourse => {
            err_400(e, JsErrorType::BillWasNotRequestedToRecourse)
        }
        ValidationError::BillIsNotOfferToSellWaitingForPayment => {
            err_400(e, JsErrorType::BillIsNotOfferToSellWaitingForPayment)
        }
        ValidationError::BillIsOfferedToSellAndWaitingForPayment => {
            err_400(e, JsErrorType::BillIsOfferedToSellAndWaitingForPayment)
        }
        ValidationError::BillWasRequestedToPay => err_400(e, JsErrorType::BillWasRequestedToPay),
        ValidationError::BillIsInRecourseAndWaitingForPayment => {
            err_400(e, JsErrorType::BillIsInRecourseAndWaitingForPayment)
        }
        ValidationError::BillRequestToAcceptDidNotExpireAndWasNotRejected => err_400(
            e,
            JsErrorType::BillRequestToAcceptDidNotExpireAndWasNotRejected,
        ),
        ValidationError::BillRequestToPayDidNotExpireAndWasNotRejected => err_400(
            e,
            JsErrorType::BillRequestToPayDidNotExpireAndWasNotRejected,
        ),
        ValidationError::BillIsNotRequestedToRecourseAndWaitingForPayment => err_400(
            e,
            JsErrorType::BillIsNotRequestedToRecourseAndWaitingForPayment,
        ),
        ValidationError::BillSellDataInvalid => err_400(e, JsErrorType::BillSellDataInvalid),
        ValidationError::BillAlreadyPaid => err_400(e, JsErrorType::BillAlreadyPaid),
        ValidationError::BillNotAccepted => err_400(e, JsErrorType::BillNotAccepted),
        ValidationError::BillAlreadyRequestedToAccept => {
            err_400(e, JsErrorType::BillAlreadyRequestedToAccept)
        }
        ValidationError::BillIsRequestedToPayAndWaitingForPayment => {
            err_400(e, JsErrorType::BillIsRequestedToPayAndWaitingForPayment)
        }
        ValidationError::BillRecourseDataInvalid => {
            err_400(e, JsErrorType::BillRecourseDataInvalid)
        }
        ValidationError::RecourseeNotPastHolder => err_400(e, JsErrorType::RecourseeNotPastHolder),
        ValidationError::CallerIsNotDrawee => err_400(e, JsErrorType::CallerIsNotDrawee),
        ValidationError::CallerIsNotBuyer => err_400(e, JsErrorType::CallerIsNotBuyer),
        ValidationError::CallerIsNotRecoursee => err_400(e, JsErrorType::CallerIsNotRecoursee),
        ValidationError::RequestAlreadyRejected => err_400(e, JsErrorType::RequestAlreadyRejected),
        ValidationError::CallerIsNotHolder => err_400(e, JsErrorType::CallerIsNotHolder),
        ValidationError::DrawerIsNotBillIssuer => err_400(e, JsErrorType::DrawerIsNotBillIssuer),
        ValidationError::CallerMustBeSignatory => err_400(e, JsErrorType::CallerMustBeSignatory),
        ValidationError::SignatoryNotInContacts(_) => {
            err_400(e, JsErrorType::SignatoryNotInContacts)
        }
        ValidationError::SignatoryAlreadySignatory(_) => {
            err_400(e, JsErrorType::SignatoryAlreadySignatory)
        }
        ValidationError::CantRemoveLastSignatory => {
            err_400(e, JsErrorType::CantRemoveLastSignatory)
        }
        ValidationError::NotASignatory(_) => err_400(e, JsErrorType::NotASignatory),
        ValidationError::InvalidSecp256k1Key(_) => err_400(e, JsErrorType::InvalidSecp256k1Key),
        ValidationError::FileIsTooBig(_) => err_400(e, JsErrorType::FileIsTooBig),
        ValidationError::InvalidFileName(_) => err_400(e, JsErrorType::InvalidFileName),
        ValidationError::UnknownNodeId(_) => err_400(e, JsErrorType::UnknownNodeId),
        ValidationError::BackupNotSupported => err_400(e, JsErrorType::BackupNotSupported),
        ValidationError::Blockchain(e) => err_500(e, JsErrorType::Blockchain),
    }
}

fn err_400<E: ToString>(e: E, t: JsErrorType) -> JsErrorData {
    JsErrorData {
        error: t,
        message: e.to_string(),
        code: 400,
    }
}

fn err_404<E: ToString>(e: E, t: JsErrorType) -> JsErrorData {
    JsErrorData {
        error: t,
        message: e.to_string(),
        code: 404,
    }
}

fn err_500<E: ToString>(e: E, t: JsErrorType) -> JsErrorData {
    JsErrorData {
        error: t,
        message: e.to_string(),
        code: 500,
    }
}
