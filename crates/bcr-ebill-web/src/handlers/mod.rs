use crate::CONFIG;
use crate::data::{
    BalanceResponse, CurrenciesResponse, CurrencyResponse, FromWeb, GeneralSearchFilterPayload,
    GeneralSearchResponse, IntoWeb, OverviewBalanceResponse, OverviewResponse, StatusResponse,
    SuccessResponse,
};
use crate::router::ErrorResponse;
use crate::service_context::ServiceContext;
use bcr_ebill_api::{
    data::GeneralSearchFilterItemType,
    service::{Error, bill_service},
    util::VALID_CURRENCIES,
    util::file::detect_content_type_for_bytes,
};
use bill::get_current_identity_node_id;
use log::error;
use rocket::Response;
use rocket::{Shutdown, State, fs::NamedFile, get, http::ContentType, post, serde::json::Json};
use rocket::{http::Status, response::Responder};
use std::io::Cursor;
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, crate::error::Error>;

pub mod bill;
pub mod company;
pub mod contacts;
pub mod identity;
pub mod middleware;
pub mod notifications;
pub mod quotes;

// Lowest prio, fall back to index.html if nothing matches
#[get("/<_..>", rank = 10)]
pub async fn serve_frontend() -> Option<NamedFile> {
    NamedFile::open(Path::new(&CONFIG.frontend_serve_folder).join("index.html"))
        .await
        .ok()
}

// Higher prio than file server and index.html fallback
#[get("/<path..>", rank = 3)]
pub async fn default_api_error_catcher(path: PathBuf) -> Json<ErrorResponse> {
    Json(ErrorResponse::new(
        "not_found",
        format!("We couldn't find the requested path '{}'", path.display()),
        404,
    ))
}

#[get("/")]
pub async fn status() -> Result<Json<StatusResponse>> {
    Ok(Json(StatusResponse {
        bitcoin_network: CONFIG.bitcoin_network.clone(),
        app_version: std::env::var("CARGO_PKG_VERSION").unwrap_or(String::from("unknown")),
    }))
}

#[get("/")]
pub async fn exit(
    shutdown: Shutdown,
    state: &State<ServiceContext>,
) -> Result<Json<SuccessResponse>> {
    log::info!("Exit called - shutting down...");
    shutdown.notify();
    state.shutdown();
    Ok(Json(SuccessResponse::new()))
}

#[get("/")]
pub async fn currencies(_state: &State<ServiceContext>) -> Result<Json<CurrenciesResponse>> {
    Ok(Json(CurrenciesResponse {
        currencies: VALID_CURRENCIES
            .iter()
            .map(|vc| CurrencyResponse {
                code: vc.to_string(),
            })
            .collect(),
    }))
}

#[get("/<file_upload_id>")]
pub async fn get_temp_file(
    state: &State<ServiceContext>,
    file_upload_id: &str,
) -> Result<(ContentType, Vec<u8>)> {
    if file_upload_id.is_empty() {
        return Err(
            Error::Validation(bcr_ebill_api::util::ValidationError::InvalidFileUploadId).into(),
        );
    }
    match state
        .file_upload_service
        .get_temp_file(file_upload_id)
        .await
    {
        Ok(Some((_file_name, file_bytes))) => {
            let content_type = match detect_content_type_for_bytes(&file_bytes) {
                None => None,
                Some(t) => ContentType::parse_flexible(&t),
            }
            .ok_or(Error::Validation(
                bcr_ebill_api::util::ValidationError::InvalidContentType,
            ))?;
            Ok((content_type, file_bytes))
        }
        _ => Err(Error::NotFound.into()),
    }
}

#[get("/?<currency>")]
pub async fn overview(
    currency: &str,
    state: &State<ServiceContext>,
) -> Result<Json<OverviewResponse>> {
    if !VALID_CURRENCIES.contains(&currency) {
        return Err(
            Error::Validation(bcr_ebill_api::util::ValidationError::InvalidCurrency).into(),
        );
    }
    let result = state
        .bill_service
        .get_bill_balances(currency, &get_current_identity_node_id(state).await)
        .await?;

    Ok(Json(OverviewResponse {
        currency: currency.to_owned(),
        balances: OverviewBalanceResponse {
            payee: BalanceResponse {
                sum: result.payee.sum,
            },
            payer: BalanceResponse {
                sum: result.payer.sum,
            },
            contingent: BalanceResponse {
                sum: result.contingent.sum,
            },
        },
    }))
}

#[utoipa::path(
    tag = "General Search",
    path = "/search",
    description = "Search bills, contacts and companies",
    responses(
        (status = 200, description = "Search Result", body = GeneralSearchResponse)
    )
)]
#[post("/", format = "json", data = "<search_filter>")]
pub async fn search(
    state: &State<ServiceContext>,
    search_filter: Json<GeneralSearchFilterPayload>,
) -> Result<Json<GeneralSearchResponse>> {
    let filters: Vec<GeneralSearchFilterItemType> = search_filter
        .filter
        .clone()
        .item_types
        .into_iter()
        .map(GeneralSearchFilterItemType::from_web)
        .collect();
    let result = state
        .search_service
        .search(
            &search_filter.filter.search_term,
            &search_filter.filter.currency,
            &filters,
            &get_current_identity_node_id(state).await,
        )
        .await?;

    Ok(Json(result.into_web()))
}

impl<'r, 'o: 'r> Responder<'r, 'o> for crate::error::Error {
    fn respond_to(self, req: &rocket::Request) -> rocket::response::Result<'o> {
        match self {
            crate::error::Error::Service(e) => ServiceError(e).respond_to(req),
            crate::error::Error::BillService(e) => BillServiceError(e).respond_to(req),
            crate::error::Error::NotificationService(e) => ServiceError(e.into()).respond_to(req),
            crate::error::Error::Validation(e) => ValidationError(e).respond_to(req),
        }
    }
}

pub struct ServiceError(Error);

impl<'r, 'o: 'r> Responder<'r, 'o> for ServiceError {
    fn respond_to(self, req: &rocket::Request) -> rocket::response::Result<'o> {
        match self.0 {
            Error::NoFileForFileUploadId => {
                let body =
                    ErrorResponse::new("bad_request", self.0.to_string(), 400).to_json_string();
                Response::build()
                    .status(Status::BadRequest)
                    .header(ContentType::JSON)
                    .sized_body(body.len(), Cursor::new(body))
                    .ok()
            }
            Error::NotFound => {
                let body =
                    ErrorResponse::new("not_found", "not found".to_string(), 404).to_json_string();
                Response::build()
                    .status(Status::NotFound)
                    .header(ContentType::JSON)
                    .sized_body(body.len(), Cursor::new(body))
                    .ok()
            }
            Error::NotificationService(_) => Status::InternalServerError.respond_to(req),
            Error::BillService(e) => BillServiceError(e).respond_to(req),
            Error::Validation(e) => ValidationError(e).respond_to(req),
            // If an external API errors, we can only tell the caller that something went wrong on
            // our end
            Error::ExternalApi(e) => {
                error!("{e}");
                Status::InternalServerError.respond_to(req)
            }
            Error::Io(e) => {
                error!("{e}");
                Status::InternalServerError.respond_to(req)
            }
            Error::CryptoUtil(e) => {
                error!("{e}");
                Status::InternalServerError.respond_to(req)
            }
            // for now handle all persistence errors as InternalServerError, there
            // will be cases where we want to handle them differently (eg. 409 Conflict)
            Error::Persistence(e) => {
                error!("{e}");
                Status::InternalServerError.respond_to(req)
            }
            Error::Blockchain(e) => {
                error!("{e}");
                Status::InternalServerError.respond_to(req)
            }
        }
    }
}

pub struct BillServiceError(bill_service::Error);

impl<'r, 'o: 'r> Responder<'r, 'o> for BillServiceError {
    fn respond_to(self, req: &rocket::Request) -> rocket::response::Result<'o> {
        match self.0 {
            bill_service::Error::NoFileForFileUploadId
            | bill_service::Error::DraweeNotInContacts
            | bill_service::Error::BuyerNotInContacts
            | bill_service::Error::EndorseeNotInContacts
            | bill_service::Error::MintNotInContacts
            | bill_service::Error::RecourseeNotInContacts
            | bill_service::Error::PayeeNotInContacts
            | bill_service::Error::InvalidOperation => {
                let body =
                    ErrorResponse::new("bad_request", self.0.to_string(), 400).to_json_string();
                Response::build()
                    .status(Status::BadRequest)
                    .header(ContentType::JSON)
                    .sized_body(body.len(), Cursor::new(body))
                    .ok()
            }
            bill_service::Error::Validation(validation_err) => {
                ValidationError(validation_err).respond_to(req)
            }
            bill_service::Error::NotFound => {
                let body =
                    ErrorResponse::new("not_found", "not found".to_string(), 404).to_json_string();
                Response::build()
                    .status(Status::NotFound)
                    .header(ContentType::JSON)
                    .sized_body(body.len(), Cursor::new(body))
                    .ok()
            }
            bill_service::Error::Io(e) => {
                error!("{e}");
                Status::InternalServerError.respond_to(req)
            }
            bill_service::Error::Persistence(e) => {
                error!("{e}");
                Status::InternalServerError.respond_to(req)
            }
            bill_service::Error::ExternalApi(e) => {
                error!("{e}");
                Status::InternalServerError.respond_to(req)
            }
            bill_service::Error::Blockchain(e) => {
                error!("{e}");
                Status::InternalServerError.respond_to(req)
            }
            bill_service::Error::Cryptography(e) => {
                error!("{e}");
                Status::InternalServerError.respond_to(req)
            }
            bill_service::Error::Notification(e) => {
                error!("{e}");
                Status::InternalServerError.respond_to(req)
            }
        }
    }
}

pub struct ValidationError(bcr_ebill_api::util::ValidationError);

impl<'r, 'o: 'r> Responder<'r, 'o> for ValidationError {
    fn respond_to(self, req: &rocket::Request) -> rocket::response::Result<'o> {
        match self.0 {
            bcr_ebill_api::util::ValidationError::RequestAlreadyExpired
                | bcr_ebill_api::util::ValidationError::FieldEmpty(_)
                | bcr_ebill_api::util::ValidationError::InvalidSum
                | bcr_ebill_api::util::ValidationError::InvalidCurrency
                | bcr_ebill_api::util::ValidationError::InvalidPaymentAddress
                | bcr_ebill_api::util::ValidationError::InvalidDate
                | bcr_ebill_api::util::ValidationError::IdentityCantBeAnon
                | bcr_ebill_api::util::ValidationError::IdentityIsNotBillIssuer
                | bcr_ebill_api::util::ValidationError::InvalidContact(_)
                | bcr_ebill_api::util::ValidationError::ContactIsAnonymous(_)
                | bcr_ebill_api::util::ValidationError::SignerCantBeAnon
                | bcr_ebill_api::util::ValidationError::IssueDateAfterMaturityDate
                | bcr_ebill_api::util::ValidationError::MaturityDateInThePast
                | bcr_ebill_api::util::ValidationError::InvalidFileUploadId
                | bcr_ebill_api::util::ValidationError::InvalidBillType
                | bcr_ebill_api::util::ValidationError::InvalidContentType
                | bcr_ebill_api::util::ValidationError::InvalidContactType
                | bcr_ebill_api::util::ValidationError::InvalidIdentityType
                | bcr_ebill_api::util::ValidationError::SelfDraftedBillCantBeBlank
                | bcr_ebill_api::util::ValidationError::DraweeCantBePayee
                | bcr_ebill_api::util::ValidationError::EndorserCantBeEndorsee
                | bcr_ebill_api::util::ValidationError::BuyerCantBeSeller
                | bcr_ebill_api::util::ValidationError::RecourserCantBeRecoursee
                | bcr_ebill_api::util::ValidationError::BillAlreadyAccepted
                | bcr_ebill_api::util::ValidationError::BillWasRejectedToAccept
                | bcr_ebill_api::util::ValidationError::BillAcceptanceExpired
                | bcr_ebill_api::util::ValidationError::BillWasRejectedToPay
                | bcr_ebill_api::util::ValidationError::BillPaymentExpired
                | bcr_ebill_api::util::ValidationError::BillWasRejectedToRecourse
                | bcr_ebill_api::util::ValidationError::BillRequestToRecourseExpired
                | bcr_ebill_api::util::ValidationError::BillWasRecoursedToTheEnd
                | bcr_ebill_api::util::ValidationError::BillWasNotOfferedToSell
                | bcr_ebill_api::util::ValidationError::BillWasNotRequestedToPay
                | bcr_ebill_api::util::ValidationError::BillWasNotRequestedToAccept
                | bcr_ebill_api::util::ValidationError::BillWasNotRequestedToRecourse
                | bcr_ebill_api::util::ValidationError::BillIsNotOfferToSellWaitingForPayment
                | bcr_ebill_api::util::ValidationError::BillIsOfferedToSellAndWaitingForPayment
                | bcr_ebill_api::util::ValidationError::BillWasRequestedToPay
                | bcr_ebill_api::util::ValidationError::BillIsInRecourseAndWaitingForPayment
                | bcr_ebill_api::util::ValidationError::BillRequestToAcceptDidNotExpireAndWasNotRejected
                | bcr_ebill_api::util::ValidationError::BillRequestToPayDidNotExpireAndWasNotRejected
                | bcr_ebill_api::util::ValidationError::BillIsNotRequestedToRecourseAndWaitingForPayment
                | bcr_ebill_api::util::ValidationError::BillSellDataInvalid
                | bcr_ebill_api::util::ValidationError::BillAlreadyPaid
                | bcr_ebill_api::util::ValidationError::BillNotAccepted
                | bcr_ebill_api::util::ValidationError::BillAlreadyRequestedToAccept
                | bcr_ebill_api::util::ValidationError::BillIsRequestedToPayAndWaitingForPayment
                | bcr_ebill_api::util::ValidationError::BillRecourseDataInvalid
                | bcr_ebill_api::util::ValidationError::RecourseeNotPastHolder
                | bcr_ebill_api::util::ValidationError::CallerIsNotDrawee
                | bcr_ebill_api::util::ValidationError::CallerIsNotBuyer
                | bcr_ebill_api::util::ValidationError::CallerIsNotRecoursee
                | bcr_ebill_api::util::ValidationError::RequestAlreadyRejected
                | bcr_ebill_api::util::ValidationError::BackupNotSupported
                | bcr_ebill_api::util::ValidationError::UnknownNodeId(_)
                | bcr_ebill_api::util::ValidationError::InvalidFileName(_)
                | bcr_ebill_api::util::ValidationError::FileIsTooBig(_)
                | bcr_ebill_api::util::ValidationError::InvalidSecp256k1Key(_)
                | bcr_ebill_api::util::ValidationError::NotASignatory(_)
                | bcr_ebill_api::util::ValidationError::SignatoryAlreadySignatory(_)
                | bcr_ebill_api::util::ValidationError::SignatoryNotInContacts(_)
                | bcr_ebill_api::util::ValidationError::CantRemoveLastSignatory
                | bcr_ebill_api::util::ValidationError::DrawerIsNotBillIssuer
                | bcr_ebill_api::util::ValidationError::CallerMustBeSignatory
                | bcr_ebill_api::util::ValidationError::CallerIsNotHolder

                => {
                    let body =
                        ErrorResponse::new("bad_request", self.0.to_string(), 400).to_json_string();
                    Response::build()
                        .status(Status::BadRequest)
                        .header(ContentType::JSON)
                        .sized_body(body.len(), Cursor::new(body))
                        .ok()
                },
            bcr_ebill_api::util::ValidationError::Blockchain(e) => {
                error!("{e}");
                Status::InternalServerError.respond_to(req)
            }
        }
    }
}
