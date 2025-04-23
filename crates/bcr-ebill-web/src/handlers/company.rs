use super::Result;
use super::middleware::IdentityCheck;
use crate::data::{
    AddSignatoryPayload, CompaniesResponse, CompanyWeb, CreateCompanyPayload, EditCompanyPayload,
    FromWeb, IntoWeb, ListSignatoriesResponse, RemoveSignatoryPayload, SignatoryResponse,
    SuccessResponse, TempFileWrapper, UploadFileForm, UploadFileResponse,
};
use crate::service_context::ServiceContext;
use bcr_ebill_api::data::{OptionalPostalAddress, PostalAddress};
use bcr_ebill_api::util::{ValidationError, validate_file_upload_id};
use bcr_ebill_api::{
    external,
    service::{self},
    util::file::{UploadFileHandler, detect_content_type_for_bytes},
};
use rocket::{State, form::Form, get, http::ContentType, post, put, serde::json::Json};

#[get("/list")]
pub async fn list(state: &State<ServiceContext>) -> Result<Json<CompaniesResponse<CompanyWeb>>> {
    let companies = state
        .company_service
        .get_list_of_companies()
        .await?
        .into_iter()
        .map(|c| c.into_web())
        .collect();
    Ok(Json(CompaniesResponse { companies }))
}

#[get("/signatories/<id>")]
pub async fn list_signatories(
    state: &State<ServiceContext>,
    id: &str,
) -> Result<Json<ListSignatoriesResponse>> {
    let signatories = state.company_service.list_signatories(id).await?;
    let signatories: Vec<SignatoryResponse> = signatories
        .into_iter()
        .map(|c| c.try_into())
        .collect::<std::result::Result<_, _>>()?;
    Ok(Json(ListSignatoriesResponse { signatories }))
}

#[get("/file/<id>/<file_name>")]
pub async fn get_file(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    id: &str,
    file_name: &str,
) -> Result<(ContentType, Vec<u8>)> {
    state.company_service.get_company_by_id(id).await?; // check if company exists
    let private_key = state
        .identity_service
        .get_full_identity()
        .await?
        .key_pair
        .get_private_key_string();

    let file_bytes = state
        .company_service
        .open_and_decrypt_file(id, file_name, &private_key)
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

#[get("/<id>")]
pub async fn detail(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    id: &str,
) -> Result<Json<CompanyWeb>> {
    let company = state.company_service.get_company_by_id(id).await?;
    Ok(Json(company.into_web()))
}

#[post("/create", format = "json", data = "<create_company_payload>")]
pub async fn create(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    create_company_payload: Json<CreateCompanyPayload>,
) -> Result<Json<CompanyWeb>> {
    let payload = create_company_payload.0;
    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;

    validate_file_upload_id(payload.logo_file_upload_id.as_deref())?;
    validate_file_upload_id(payload.proof_of_registration_file_upload_id.as_deref())?;

    let created_company = state
        .company_service
        .create_company(
            payload.name,
            payload.country_of_registration,
            payload.city_of_registration,
            PostalAddress::from_web(payload.postal_address),
            payload.email,
            payload.registration_number,
            payload.registration_date,
            payload.proof_of_registration_file_upload_id,
            payload.logo_file_upload_id,
            timestamp,
        )
        .await?;

    Ok(Json(created_company.into_web()))
}

#[put("/edit", format = "json", data = "<edit_company_payload>")]
pub async fn edit(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    edit_company_payload: Json<EditCompanyPayload>,
) -> Result<Json<SuccessResponse>> {
    let payload = edit_company_payload.0;

    validate_file_upload_id(payload.logo_file_upload_id.as_deref())?;
    validate_file_upload_id(payload.proof_of_registration_file_upload_id.as_deref())?;

    if payload.name.is_none()
        && payload.email.is_none()
        && payload.postal_address.is_none()
        && payload.logo_file_upload_id.is_none()
    {
        return Ok(Json(SuccessResponse::new()));
    }
    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
    state
        .company_service
        .edit_company(
            &payload.id,
            payload.name,
            payload.email,
            OptionalPostalAddress::from_web(payload.postal_address),
            payload.country_of_registration,
            payload.city_of_registration,
            payload.registration_number,
            payload.registration_date,
            payload.logo_file_upload_id,
            payload.proof_of_registration_file_upload_id,
            timestamp,
        )
        .await?;

    Ok(Json(SuccessResponse::new()))
}

#[put("/add_signatory", format = "json", data = "<add_signatory_payload>")]
pub async fn add_signatory(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    add_signatory_payload: Json<AddSignatoryPayload>,
) -> Result<Json<SuccessResponse>> {
    let payload = add_signatory_payload.0;
    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
    state
        .company_service
        .add_signatory(&payload.id, payload.signatory_node_id.clone(), timestamp)
        .await?;

    Ok(Json(SuccessResponse::new()))
}

#[put(
    "/remove_signatory",
    format = "json",
    data = "<remove_signatory_payload>"
)]
pub async fn remove_signatory(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    remove_signatory_payload: Json<RemoveSignatoryPayload>,
) -> Result<Json<SuccessResponse>> {
    let payload = remove_signatory_payload.0;
    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
    state
        .company_service
        .remove_signatory(&payload.id, payload.signatory_node_id.clone(), timestamp)
        .await?;

    Ok(Json(SuccessResponse::new()))
}
