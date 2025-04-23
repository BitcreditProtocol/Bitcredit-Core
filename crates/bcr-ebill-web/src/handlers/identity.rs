use std::env;

use super::Result;
use super::middleware::IdentityCheck;
use crate::data::{
    ChangeIdentityPayload, FromWeb, IdentityTypeWeb, IdentityWeb, IntoWeb, NewIdentityPayload,
    SeedPhrase, SuccessResponse, SwitchIdentity, TempFileWrapper, UploadFileForm,
    UploadFileResponse,
};
use crate::service_context::ServiceContext;
use bcr_ebill_api::data::identity::IdentityType;
use bcr_ebill_api::data::{OptionalPostalAddress, identity::SwitchIdentityType};
use bcr_ebill_api::external;
use bcr_ebill_api::service::Error;
use bcr_ebill_api::util::date::{format_date_string, now};
use bcr_ebill_api::util::file::{UploadFileHandler, detect_content_type_for_bytes};
use bcr_ebill_api::util::{ValidationError, validate_file_upload_id};
use log::info;
use rocket::form::Form;
use rocket::http::ContentType;
use rocket::response::Responder;
use rocket::serde::json::Json;
use rocket::{Response, Shutdown, State, get, post, put};

#[get("/file/<file_name>")]
pub async fn get_file(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    file_name: &str,
) -> Result<(ContentType, Vec<u8>)> {
    let identity = state.identity_service.get_full_identity().await?;
    let private_key = identity.key_pair.get_private_key_string();
    let id = identity.identity.node_id;

    let file_bytes = state
        .identity_service
        .open_and_decrypt_file(&id, file_name, &private_key)
        .await
        .map_err(|_| Error::NotFound)?;

    let content_type = match detect_content_type_for_bytes(&file_bytes) {
        None => None,
        Some(t) => ContentType::parse_flexible(&t),
    }
    .ok_or(Error::Validation(ValidationError::InvalidContentType))?;

    Ok((content_type, file_bytes))
}

#[post("/upload_file", data = "<file_upload_form>")]
pub async fn upload_file(
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

#[utoipa::path(
    tag = "Identity",
    path = "/api/identity/detail",
    description = "Returns the current identity",
    responses(
        (status = 200, description = "The current identity data", body = IdentityWeb)
    ),
)]
#[get("/detail")]
pub async fn return_identity(state: &State<ServiceContext>) -> Result<Json<IdentityWeb>> {
    let my_identity = if !state.identity_service.identity_exists().await {
        return Err(Error::NotFound.into());
    } else {
        let full_identity = state.identity_service.get_full_identity().await?;
        IdentityWeb::from(full_identity.identity, full_identity.key_pair)
    };
    Ok(Json(my_identity))
}

#[utoipa::path(
    tag = "Identity",
    path = "/api/identity/create",
    description = "Creates a new identity with given data",
    responses(
        (status = 200, description = "The identity has been created")
    ),
    request_body(description = "The data to create an identity with", content((NewIdentityPayload)))
)]
#[post("/create", format = "json", data = "<identity_payload>")]
pub async fn create_identity(
    state: &State<ServiceContext>,
    identity_payload: Json<NewIdentityPayload>,
) -> Result<Json<SuccessResponse>> {
    let identity = identity_payload.into_inner();
    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;

    validate_file_upload_id(identity.profile_picture_file_upload_id.as_deref())?;
    validate_file_upload_id(identity.identity_document_file_upload_id.as_deref())?;

    state
        .identity_service
        .create_identity(
            IdentityType::from_web(IdentityTypeWeb::try_from(identity.t)?),
            identity.name,
            identity.email,
            OptionalPostalAddress::from_web(identity.postal_address),
            identity.date_of_birth,
            identity.country_of_birth,
            identity.city_of_birth,
            identity.identification_number,
            identity.profile_picture_file_upload_id,
            identity.identity_document_file_upload_id,
            timestamp,
        )
        .await?;
    Ok(Json(SuccessResponse::new()))
}

#[utoipa::path(
    tag = "Identity",
    path = "/api/identity/change",
    description = "Updates the identity with given data",
    responses(
        (status = 200, description = "The identity has been updated")
    ),
    request_body(description = "The data to update identity with", content((ChangeIdentityPayload)))
)]
#[put("/change", format = "json", data = "<identity_payload>")]
pub async fn change_identity(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    identity_payload: Json<ChangeIdentityPayload>,
) -> Result<Json<SuccessResponse>> {
    let identity_payload = identity_payload.into_inner();

    validate_file_upload_id(identity_payload.profile_picture_file_upload_id.as_deref())?;
    validate_file_upload_id(identity_payload.identity_document_file_upload_id.as_deref())?;

    if identity_payload.name.is_none()
        && identity_payload.email.is_none()
        && identity_payload.postal_address.is_none()
        && identity_payload.date_of_birth.is_none()
        && identity_payload.country_of_birth.is_none()
        && identity_payload.city_of_birth.is_none()
        && identity_payload.identification_number.is_none()
        && identity_payload.profile_picture_file_upload_id.is_none()
        && identity_payload.identity_document_file_upload_id.is_none()
    {
        return Ok(Json(SuccessResponse::new()));
    }
    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
    state
        .identity_service
        .update_identity(
            identity_payload.name,
            identity_payload.email,
            OptionalPostalAddress::from_web(identity_payload.postal_address),
            identity_payload.date_of_birth,
            identity_payload.country_of_birth,
            identity_payload.city_of_birth,
            identity_payload.identification_number,
            identity_payload.profile_picture_file_upload_id,
            identity_payload.identity_document_file_upload_id,
            timestamp,
        )
        .await?;
    Ok(Json(SuccessResponse::new()))
}

#[utoipa::path(
    tag = "Identity",
    path = "/api/identity/active",
    description = "Returns the currently active identity data",
    responses(
        (status = 200, description = "The identity that is currently active", body = SwitchIdentity)
    )
)]
#[get("/active")]
pub async fn active(state: &State<ServiceContext>) -> Result<Json<SwitchIdentity>> {
    let current_identity_state = state.get_current_identity().await;
    let (node_id, t) = match current_identity_state.company {
        None => (current_identity_state.personal, SwitchIdentityType::Person),
        Some(company_node_id) => (company_node_id, SwitchIdentityType::Company),
    };
    Ok(Json(SwitchIdentity {
        t: Some(t.into_web()),
        node_id,
    }))
}

#[utoipa::path(
    tag = "Identity",
    path = "/api/identity/switch",
    description = "Switches the currently active identity to the given identity",
    responses(
        (status = 200, description = "The active identity has been switched")
    ),
    request_body(description = "The identity identifier to switch to", content((SwitchIdentity)))
)]
#[put("/switch", format = "json", data = "<switch_identity_payload>")]
pub async fn switch(
    state: &State<ServiceContext>,
    switch_identity_payload: Json<SwitchIdentity>,
) -> Result<Json<SuccessResponse>> {
    let node_id = switch_identity_payload.0.node_id;
    let personal_node_id = state.identity_service.get_identity().await?.node_id;

    // if it's the personal node id, set it
    if node_id == personal_node_id {
        state.set_current_personal_identity(node_id).await;
        return Ok(Json(SuccessResponse::new()));
    }

    // if it's one of our companies, set it
    if state
        .company_service
        .get_list_of_companies()
        .await?
        .iter()
        .any(|c| c.id == node_id)
    {
        state.set_current_company_identity(node_id).await;
        return Ok(Json(SuccessResponse::new()));
    }

    // otherwise, return an error
    Err(Error::Validation(ValidationError::UnknownNodeId(node_id.to_owned())).into())
}

#[utoipa::path(
    tag = "Identity",
    path = "/api/identity/seed/backup",
    description = "Returns the seed phrase key backup of current private key",
    responses(
        (status = 200, description = "The seed phrase of the current private key", body = SeedPhrase)
    )
)]
#[get("/seed/backup")]
pub async fn get_seed_phrase(state: &State<ServiceContext>) -> Result<Json<SeedPhrase>> {
    let seed_phrase = state.identity_service.get_seedphrase().await?;
    Ok(Json(SeedPhrase { seed_phrase }))
}

#[utoipa::path(
    tag = "Identity",
    path = "/api/identity/seed/recover",
    description = "Restores a private key from the given seed phrase backup",
    responses(
        (status = 200, description = "Private key has been recovered from seed")
    ),
    request_body(description = "The seed phrase to recover the private key from", content((SeedPhrase)))
)]
#[put("/seed/recover", format = "json", data = "<payload>")]
pub async fn recover_from_seed_phrase(
    state: &State<ServiceContext>,
    payload: Json<SeedPhrase>,
) -> Result<Json<SuccessResponse>> {
    state
        .identity_service
        .recover_from_seedphrase(&payload.into_inner().seed_phrase)
        .await?;
    Ok(Json(SuccessResponse::new()))
}

#[utoipa::path(
    tag = "Identity",
    path = "/api/identity/backup",
    description = "Creates an encrypted backup of all the data for current identity and returns the backup file",
    responses(
        (status = 200, description = "The encrypted backup that has been created")
    ),
)]
#[get("/backup")]
pub async fn backup_identity(state: &State<ServiceContext>) -> Result<BinaryFileResponse> {
    let file_name = format!("bitcredit_backup_{}.ecies", format_date_string(now()));
    let bytes = state.backup_service.backup().await?;
    Ok(BinaryFileResponse {
        data: bytes,
        name: file_name.to_string(),
    })
}

#[utoipa::path(
    post,
    tag = "Identity",
    path = "/api/identity/restore",
    request_body(content_type = "multipart/form-data", content = UploadFileForm, description = "Backup file to upload"),
    responses(
        (status = 200, description = "Indentity has been restored")
    )
)]
#[post("/restore", data = "<data>")]
pub async fn restore_identity(
    state: &State<ServiceContext>,
    shutdown: Shutdown,
    mut data: Form<UploadFileForm<'_>>,
) -> Result<Json<SuccessResponse>> {
    let dir = env::temp_dir();
    let target = dir.join("restore.ecies");
    data.file
        .persist_to(target.as_path())
        .await
        .map_err(Error::Io)?;
    state.backup_service.restore(target.as_path()).await?;
    info!("Identity has been restored. Restarting system ...");
    shutdown.notify();
    state.shutdown();
    state.reboot();
    Ok(Json(SuccessResponse::new()))
}

/// Just a wrapper struct to allow setting a content disposition header
pub struct BinaryFileResponse {
    data: Vec<u8>,
    name: String,
}

/// Needed to respond with a binary file that can set a content disposition header
/// to allow named downloads from a browser
impl Responder<'_, 'static> for BinaryFileResponse {
    fn respond_to(self, _: &rocket::Request<'_>) -> rocket::response::Result<'static> {
        Response::build()
            .header(ContentType::Binary)
            .raw_header(
                "Content-Disposition",
                format!(r#"attachment; filename="{}""#, self.name),
            )
            .sized_body(self.data.len(), std::io::Cursor::new(self.data))
            .ok()
    }
}
