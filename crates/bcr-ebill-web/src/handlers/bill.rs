use super::Result;
use super::middleware::IdentityCheck;
use crate::data::{
    AcceptBitcreditBillPayload, BillCombinedBitcoinKeyWeb, BillId, BillNumbersToWordsForSum,
    BillsResponse, BillsSearchFilterPayload, BitcreditBillPayload, BitcreditBillWeb,
    EndorseBitcreditBillPayload, EndorsementsResponse, FromWeb, IntoWeb, LightBitcreditBillWeb,
    MintBitcreditBillPayload, OfferToSellBitcreditBillPayload, PastEndorseesResponse,
    RejectActionBillPayload, RequestRecourseForAcceptancePayload, RequestRecourseForPaymentPayload,
    RequestToAcceptBitcreditBillPayload, RequestToMintBitcreditBillPayload,
    RequestToPayBitcreditBillPayload, SuccessResponse, TempFileWrapper, UploadFileForm,
    UploadFileResponse,
};
use crate::service_context::ServiceContext;
use bcr_ebill_api::data::bill::BillIssueData;
use bcr_ebill_api::data::contact::BillParticipant;
use bcr_ebill_api::data::{
    bill::{BillAction, BillsFilterRole, LightBitcreditBillResult, RecourseReason},
    contact::BillIdentParticipant,
};
use bcr_ebill_api::service::bill_service::error::Error as BillServiceError;
use bcr_ebill_api::util::file::{UploadFileHandler, detect_content_type_for_bytes};
use bcr_ebill_api::util::{self, BcrKeys, ValidationError, currency};
use bcr_ebill_api::{external, service};
use log::{error, info};
use rocket::form::Form;
use rocket::http::ContentType;
use rocket::serde::json::Json;
use rocket::{State, get, post, put};

pub async fn get_current_identity_node_id(state: &State<ServiceContext>) -> String {
    let current_identity = state.get_current_identity().await;
    match current_identity.company {
        None => current_identity.personal,
        Some(company_node_id) => company_node_id,
    }
}

pub async fn get_signer_public_data_and_keys(
    state: &State<ServiceContext>,
) -> Result<(BillIdentParticipant, BcrKeys)> {
    let current_identity = state.get_current_identity().await;
    let local_node_id = current_identity.personal;
    let (signer_public_data, signer_keys) = match current_identity.company {
        None => {
            let identity = state.identity_service.get_full_identity().await?;
            match BillIdentParticipant::new(identity.identity) {
                Some(identity_public_data) => (identity_public_data, identity.key_pair),
                None => {
                    return Err(
                        service::Error::Validation(ValidationError::DrawerIsNotBillIssuer).into(),
                    );
                }
            }
        }
        Some(company_node_id) => {
            let (company, keys) = state
                .company_service
                .get_company_and_keys_by_id(&company_node_id)
                .await?;
            if !company.signatories.contains(&local_node_id) {
                return Err(service::Error::Validation(ValidationError::NotASignatory(
                    local_node_id.to_owned(),
                ))
                .into());
            }
            (
                BillIdentParticipant::from(company),
                BcrKeys::from_private_key(&keys.private_key).map_err(service::Error::CryptoUtil)?,
            )
        }
    };
    Ok((signer_public_data, signer_keys))
}

#[utoipa::path(
    tag = "Endorsements",
    path = "/bill/endorsements/{id}",
    description = "Get endorsements of the given bill",
    responses(
        (status = 200, description = "Endorsements", body = EndorsementsResponse)
    )
)]
#[get("/endorsements/<id>")]
pub async fn get_endorsements_for_bill(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    id: &str,
) -> Result<Json<EndorsementsResponse>> {
    let result = state
        .bill_service
        .get_endorsements(id, &get_current_identity_node_id(state).await)
        .await?;
    Ok(Json(EndorsementsResponse {
        endorsements: result.into_iter().map(|e| e.into_web()).collect(),
    }))
}

#[utoipa::path(
    tag = "Past Endorsees",
    path = "/bill/past_endorsees/{id}",
    description = "Get all past endorsees of the given bill",
    responses(
        (status = 200, description = "Past Endorsees", body = PastEndorseesResponse)
    )
)]
#[get("/past_endorsees/<id>")]
pub async fn get_past_endorsees_for_bill(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    id: &str,
) -> Result<Json<PastEndorseesResponse>> {
    let result = state
        .bill_service
        .get_past_endorsees(id, &get_current_identity_node_id(state).await)
        .await?;
    Ok(Json(PastEndorseesResponse {
        past_endorsees: result.into_iter().map(|e| e.into_web()).collect(),
    }))
}

#[get("/bitcoin_key/<id>")]
pub async fn bitcoin_key(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    id: &str,
) -> Result<Json<BillCombinedBitcoinKeyWeb>> {
    let (caller_public_data, caller_keys) = get_signer_public_data_and_keys(state).await?;
    let combined_key = state
        .bill_service
        .get_combined_bitcoin_key_for_bill(id, &caller_public_data, &caller_keys)
        .await?;
    Ok(Json(combined_key.into_web()))
}

#[get("/attachment/<bill_id>/<file_name>")]
pub async fn attachment(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    bill_id: &str,
    file_name: &str,
) -> Result<(ContentType, Vec<u8>)> {
    let keys = state.bill_service.get_bill_keys(bill_id).await?;
    let file_bytes = state
        .bill_service
        .open_and_decrypt_attached_file(bill_id, file_name, &keys.private_key)
        .await
        .map_err(|_| service::Error::NotFound)?;

    let content_type = match detect_content_type_for_bytes(&file_bytes) {
        None => None,
        Some(t) => ContentType::parse_flexible(&t),
    }
    .ok_or(service::Error::Validation(
        ValidationError::InvalidContentType,
    ))?;

    Ok((content_type, file_bytes))
}

#[utoipa::path(
    tag = "Bills Search",
    path = "/bill/search",
    description = "Get all bill details for the given filter",
    responses(
        (status = 200, description = "Search for bills", body = BillsResponse<LightBitcreditBillWeb>)
    )
)]
#[post("/search", format = "json", data = "<bills_filter>")]
pub async fn search(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    bills_filter: Json<BillsSearchFilterPayload>,
) -> Result<Json<BillsResponse<LightBitcreditBillWeb>>> {
    let filter = bills_filter.0.filter;
    let (from, to) = match filter.date_range {
        None => (None, None),
        Some(date_range) => {
            let from = util::date::date_string_to_timestamp(&date_range.from, None)?;
            // Change the date to the end of the day, so we collect bills during the day as well
            let to = util::date::date_string_to_timestamp(&date_range.to, None)
                .map(util::date::end_of_day_as_timestamp)?;
            (Some(from), Some(to))
        }
    };
    let bills = state
        .bill_service
        .search_bills(
            &filter.currency,
            &filter.search_term,
            from,
            to,
            &BillsFilterRole::from_web(filter.role),
            &get_current_identity_node_id(state).await,
        )
        .await?;
    Ok(Json(BillsResponse {
        bills: bills.into_iter().map(|b| b.into_web()).collect(),
    }))
}

#[utoipa::path(
    tag = "Bills Light",
    path = "/bill/list/light",
    description = "Get all bill details in a light version",
    responses(
        (status = 200, description = "List of bills light", body = BillsResponse<LightBitcreditBillWeb>)
    )
)]
#[get("/list/light")]
pub async fn list_light(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
) -> Result<Json<BillsResponse<LightBitcreditBillWeb>>> {
    let bills: Vec<LightBitcreditBillResult> = state
        .bill_service
        .get_bills(&get_current_identity_node_id(state).await)
        .await?
        .into_iter()
        .map(|b| b.into())
        .collect();
    Ok(Json(BillsResponse {
        bills: bills.into_iter().map(|b| b.into_web()).collect(),
    }))
}

#[utoipa::path(
    tag = "Bills",
    path = "/bill/list",
    description = "Get all bill details",
    responses(
        (status = 200, description = "List of bills", body = BillsResponse<BitcreditBillWeb>)
    )
)]
#[get("/list")]
pub async fn list(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
) -> Result<Json<BillsResponse<BitcreditBillWeb>>> {
    let bills = state
        .bill_service
        .get_bills(&get_current_identity_node_id(state).await)
        .await?;
    Ok(Json(BillsResponse {
        bills: bills.into_iter().map(|b| b.into_web()).collect(),
    }))
}

#[get("/numbers_to_words_for_sum/<id>")]
pub async fn numbers_to_words_for_sum(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    id: &str,
) -> Result<Json<BillNumbersToWordsForSum>> {
    let current_timestamp = util::date::now().timestamp() as u64;
    let identity = state.identity_service.get_identity().await?;
    let bill = state
        .bill_service
        .get_detail(
            id,
            &identity,
            &get_current_identity_node_id(state).await,
            current_timestamp,
        )
        .await?;
    let sum = bill.data.sum;
    let parsed_sum = currency::parse_sum(&sum)?;
    let sum_as_words = util::numbers_to_words::encode(&parsed_sum);
    Ok(Json(BillNumbersToWordsForSum {
        sum: parsed_sum,
        sum_as_words,
    }))
}

#[utoipa::path(
    tag = "Bills",
    path = "/bill/{id}",
    description = "Get bill details by id",
    params(
        ("id" = String, Path, description = "Id of the bill to return")
    ),
    responses(
        (status = 200, description = "The Bill with given id", body = BitcreditBillWeb),
        (status = 404, description = "Bill not found")
    )
)]
#[get("/detail/<id>")]
pub async fn bill_detail(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    id: &str,
) -> Result<Json<BitcreditBillWeb>> {
    let current_timestamp = util::date::now().timestamp() as u64;
    let identity = state.identity_service.get_identity().await?;
    let bill_detail = state
        .bill_service
        .get_detail(
            id,
            &identity,
            &get_current_identity_node_id(state).await,
            current_timestamp,
        )
        .await?;
    Ok(Json(bill_detail.into_web()))
}

#[get("/check_payment")]
pub async fn check_payment(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
) -> Result<Json<SuccessResponse>> {
    if let Err(e) = state.bill_service.check_bills_payment().await {
        error!("Error while checking bills payment: {e}");
    }

    if let Err(e) = state.bill_service.check_bills_offer_to_sell_payment().await {
        error!("Error while checking bills offer to sell payment: {e}");
    }

    Ok(Json(SuccessResponse::new()))
}

#[post("/upload_file", data = "<file_upload_form>")]
pub async fn upload_file(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    file_upload_form: Form<UploadFileForm<'_>>,
) -> Result<Json<UploadFileResponse>> {
    let file = &file_upload_form.file;
    let upload_file_handler: &dyn UploadFileHandler =
        &TempFileWrapper(file) as &dyn UploadFileHandler;

    state
        .file_upload_service
        .validate_attached_file(upload_file_handler)
        .await?;

    let file_upload_response = state
        .file_upload_service
        .upload_file(upload_file_handler)
        .await?;

    Ok(Json(file_upload_response.into_web()))
}

#[post("/issue", format = "json", data = "<bill_payload>")]
pub async fn issue_bill(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    bill_payload: Json<BitcreditBillPayload>,
) -> Result<Json<BillId>> {
    let (drawer_public_data, drawer_keys) = get_signer_public_data_and_keys(state).await?;
    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;

    let bill = state
        .bill_service
        .issue_new_bill(BillIssueData {
            t: bill_payload.t,
            country_of_issuing: bill_payload.country_of_issuing.to_owned(),
            city_of_issuing: bill_payload.city_of_issuing.to_owned(),
            issue_date: bill_payload.issue_date.to_owned(),
            maturity_date: bill_payload.maturity_date.to_owned(),
            drawee: bill_payload.drawee.to_owned(),
            payee: bill_payload.payee.to_owned(),
            sum: bill_payload.sum.to_owned(),
            currency: bill_payload.currency.to_owned(),
            country_of_payment: bill_payload.country_of_payment.to_owned(),
            city_of_payment: bill_payload.city_of_payment.to_owned(),
            language: bill_payload.language.to_owned(),
            file_upload_ids: bill_payload.file_upload_ids.to_owned(),
            drawer_public_data: drawer_public_data.clone(),
            drawer_keys: drawer_keys.clone(),
            timestamp,
        })
        .await?;

    Ok(Json(BillId {
        id: bill.id.clone(),
    }))
}

#[put("/offer_to_sell", format = "json", data = "<offer_to_sell_payload>")]
pub async fn offer_to_sell_bill(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    offer_to_sell_payload: Json<OfferToSellBitcreditBillPayload>,
) -> Result<Json<SuccessResponse>> {
    let public_data_buyer = match state
        .contact_service
        .get_identity_by_node_id(&offer_to_sell_payload.buyer)
        .await
    {
        Ok(Some(buyer)) => buyer,
        Ok(None) | Err(_) => {
            return Err(BillServiceError::BuyerNotInContacts.into());
        }
    };

    let sum = currency::parse_sum(&offer_to_sell_payload.sum)?;
    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys(state).await?;

    state
        .bill_service
        .execute_bill_action(
            &offer_to_sell_payload.bill_id,
            BillAction::OfferToSell(
                public_data_buyer.clone(),
                sum,
                offer_to_sell_payload.currency.clone(),
            ),
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(Json(SuccessResponse::new()))
}

#[put("/endorse", format = "json", data = "<endorse_bill_payload>")]
pub async fn endorse_bill(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    endorse_bill_payload: Json<EndorseBitcreditBillPayload>,
) -> Result<Json<SuccessResponse>> {
    let public_data_endorsee = match state
        .contact_service
        .get_identity_by_node_id(&endorse_bill_payload.endorsee)
        .await
    {
        Ok(Some(endorsee)) => endorsee,
        Ok(None) | Err(_) => {
            return Err(BillServiceError::EndorseeNotInContacts.into());
        }
    };

    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys(state).await?;
    state
        .bill_service
        .execute_bill_action(
            &endorse_bill_payload.bill_id,
            BillAction::Endorse(public_data_endorsee.clone()),
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(Json(SuccessResponse::new()))
}

#[put(
    "/request_to_pay",
    format = "json",
    data = "<request_to_pay_bill_payload>"
)]
pub async fn request_to_pay_bill(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    request_to_pay_bill_payload: Json<RequestToPayBitcreditBillPayload>,
) -> Result<Json<SuccessResponse>> {
    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys(state).await?;

    state
        .bill_service
        .execute_bill_action(
            &request_to_pay_bill_payload.bill_id,
            BillAction::RequestToPay(request_to_pay_bill_payload.currency.clone()),
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(Json(SuccessResponse::new()))
}

#[put(
    "/request_to_accept",
    format = "json",
    data = "<request_to_accept_bill_payload>"
)]
pub async fn request_to_accept_bill(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    request_to_accept_bill_payload: Json<RequestToAcceptBitcreditBillPayload>,
) -> Result<Json<SuccessResponse>> {
    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys(state).await?;

    state
        .bill_service
        .execute_bill_action(
            &request_to_accept_bill_payload.bill_id,
            BillAction::RejectAcceptance,
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(Json(SuccessResponse::new()))
}

#[put("/accept", format = "json", data = "<accept_bill_payload>")]
pub async fn accept_bill(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    accept_bill_payload: Json<AcceptBitcreditBillPayload>,
) -> Result<Json<SuccessResponse>> {
    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys(state).await?;

    state
        .bill_service
        .execute_bill_action(
            &accept_bill_payload.bill_id,
            BillAction::Accept,
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(Json(SuccessResponse::new()))
}

#[put(
    "/request_to_mint",
    format = "json",
    data = "<request_to_mint_bill_payload>"
)]
pub async fn request_to_mint_bill(
    _identity: IdentityCheck,
    _state: &State<ServiceContext>,
    request_to_mint_bill_payload: Json<RequestToMintBitcreditBillPayload>,
) -> Result<Json<SuccessResponse>> {
    info!(
        "request to mint bill called with payload {request_to_mint_bill_payload:?} - not implemented"
    );
    Ok(Json(SuccessResponse::new()))
}

#[put("/mint", format = "json", data = "<mint_bill_payload>")]
pub async fn mint_bill(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    mint_bill_payload: Json<MintBitcreditBillPayload>,
) -> Result<Json<SuccessResponse>> {
    info!("mint bill called with payload {mint_bill_payload:?} - not implemented");
    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
    let sum = currency::parse_sum(&mint_bill_payload.sum)?;

    let public_mint_node = match state
        .contact_service
        .get_identity_by_node_id(&mint_bill_payload.mint_node)
        .await
    {
        Ok(Some(drawee)) => drawee,
        Ok(None) | Err(_) => {
            return Err(BillServiceError::MintNotInContacts.into());
        }
    };
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys(state).await?;

    state
        .bill_service
        .execute_bill_action(
            &mint_bill_payload.bill_id,
            BillAction::Mint(public_mint_node, sum, mint_bill_payload.currency.clone()),
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;
    Ok(Json(SuccessResponse::new()))
}

// Rejection
#[put("/reject_to_accept", format = "json", data = "<reject_payload>")]
pub async fn reject_to_accept_bill(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    reject_payload: Json<RejectActionBillPayload>,
) -> Result<Json<SuccessResponse>> {
    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys(state).await?;

    state
        .bill_service
        .execute_bill_action(
            &reject_payload.bill_id,
            BillAction::RejectAcceptance,
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(Json(SuccessResponse::new()))
}

#[put("/reject_to_pay", format = "json", data = "<reject_payload>")]
pub async fn reject_to_pay_bill(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    reject_payload: Json<RejectActionBillPayload>,
) -> Result<Json<SuccessResponse>> {
    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys(state).await?;

    state
        .bill_service
        .execute_bill_action(
            &reject_payload.bill_id,
            BillAction::RejectPayment,
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(Json(SuccessResponse::new()))
}

#[put("/reject_to_buy", format = "json", data = "<reject_payload>")]
pub async fn reject_to_buy_bill(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    reject_payload: Json<RejectActionBillPayload>,
) -> Result<Json<SuccessResponse>> {
    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys(state).await?;

    state
        .bill_service
        .execute_bill_action(
            &reject_payload.bill_id,
            BillAction::RejectBuying,
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(Json(SuccessResponse::new()))
}

#[put("/reject_to_pay_recourse", format = "json", data = "<reject_payload>")]
pub async fn reject_to_pay_recourse_bill(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    reject_payload: Json<RejectActionBillPayload>,
) -> Result<Json<SuccessResponse>> {
    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys(state).await?;

    state
        .bill_service
        .execute_bill_action(
            &reject_payload.bill_id,
            BillAction::RejectPaymentForRecourse,
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(Json(SuccessResponse::new()))
}

// Recourse
#[put(
    "/request_recourse_for_payment",
    format = "json",
    data = "<request_recourse_payload>"
)]
pub async fn request_to_recourse_bill_payment(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    request_recourse_payload: Json<RequestRecourseForPaymentPayload>,
) -> Result<Json<SuccessResponse>> {
    let sum = currency::parse_sum(&request_recourse_payload.sum)?;
    request_recourse(
        state,
        RecourseReason::Pay(sum, request_recourse_payload.currency.clone()),
        &request_recourse_payload.bill_id,
        &request_recourse_payload.recoursee,
    )
    .await
}

#[put(
    "/request_recourse_for_acceptance",
    format = "json",
    data = "<request_recourse_payload>"
)]
pub async fn request_to_recourse_bill_acceptance(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    request_recourse_payload: Json<RequestRecourseForAcceptancePayload>,
) -> Result<Json<SuccessResponse>> {
    request_recourse(
        state,
        RecourseReason::Accept,
        &request_recourse_payload.bill_id,
        &request_recourse_payload.recoursee,
    )
    .await
}

async fn request_recourse(
    state: &State<ServiceContext>,
    recourse_reason: RecourseReason,
    bill_id: &str,
    recoursee_node_id: &str,
) -> Result<Json<SuccessResponse>> {
    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys(state).await?;

    let public_data_recoursee = match state
        .contact_service
        .get_identity_by_node_id(recoursee_node_id)
        .await
    {
        Ok(Some(BillParticipant::Ident(recoursee))) => recoursee,
        Ok(Some(BillParticipant::Anon(_))) => {
            // recoursee has to be identified
            return Err(
                BillServiceError::Validation(ValidationError::ContactIsAnonymous(
                    recoursee_node_id.to_owned(),
                ))
                .into(),
            );
        }
        Ok(None) | Err(_) => {
            return Err(BillServiceError::RecourseeNotInContacts.into());
        }
    };

    state
        .bill_service
        .execute_bill_action(
            bill_id,
            BillAction::RequestRecourse(public_data_recoursee, recourse_reason),
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(Json(SuccessResponse::new()))
}
