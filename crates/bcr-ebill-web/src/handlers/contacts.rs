use super::super::data::{EditContactPayload, NewContactPayload};
use super::Result;
use super::middleware::IdentityCheck;
use crate::data::{
    ContactTypeWeb, ContactWeb, ContactsResponse, FromWeb, IntoWeb, SuccessResponse,
    TempFileWrapper, UploadFileForm, UploadFileResponse,
};
use crate::service_context::ServiceContext;
use bcr_ebill_api::data::{
    OptionalPostalAddress, PostalAddress,
    contact::{Contact, ContactType},
};
use bcr_ebill_api::service::{self};
use bcr_ebill_api::util::file::{UploadFileHandler, detect_content_type_for_bytes};
use bcr_ebill_api::util::{ValidationError, validate_file_upload_id};
use rocket::form::Form;
use rocket::http::ContentType;
use rocket::serde::json::Json;
use rocket::{State, delete, get, post, put};

#[get("/file/<id>/<file_name>")]
pub async fn get_file(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    id: &str,
    file_name: &str,
) -> Result<(ContentType, Vec<u8>)> {
    state.contact_service.get_contact(id).await?; // check if contact exists

    let private_key = state
        .identity_service
        .get_full_identity()
        .await?
        .key_pair
        .get_private_key_string();

    let file_bytes = state
        .contact_service
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

#[get("/list")]
pub async fn return_contacts(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
) -> Result<Json<ContactsResponse<ContactWeb>>> {
    let contacts: Vec<Contact> = state.contact_service.get_contacts().await?;
    Ok(Json(ContactsResponse {
        contacts: contacts.into_iter().map(|c| c.into_web()).collect(),
    }))
}

#[get("/detail/<node_id>")]
pub async fn return_contact(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    node_id: &str,
) -> Result<Json<ContactWeb>> {
    let contact: ContactWeb = state.contact_service.get_contact(node_id).await?.into_web();
    Ok(Json(contact))
}

#[delete("/remove/<node_id>")]
pub async fn remove_contact(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    node_id: &str,
) -> Result<Json<SuccessResponse>> {
    state.contact_service.delete(node_id).await?;
    Ok(Json(SuccessResponse::new()))
}

#[post("/create", format = "json", data = "<new_contact_payload>")]
pub async fn new_contact(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    new_contact_payload: Json<NewContactPayload>,
) -> Result<Json<ContactWeb>> {
    let payload = new_contact_payload.0;
    let contact = state
        .contact_service
        .add_contact(
            &payload.node_id,
            ContactType::from_web(ContactTypeWeb::try_from(payload.t)?),
            payload.name,
            payload.email,
            payload.postal_address.map(PostalAddress::from_web),
            payload.date_of_birth_or_registration,
            payload.country_of_birth_or_registration,
            payload.city_of_birth_or_registration,
            payload.identification_number,
            payload.avatar_file_upload_id,
            payload.proof_document_file_upload_id,
        )
        .await?;
    Ok(Json(contact.into_web()))
}

#[put("/edit", format = "json", data = "<edit_contact_payload>")]
pub async fn edit_contact(
    _identity: IdentityCheck,
    state: &State<ServiceContext>,
    edit_contact_payload: Json<EditContactPayload>,
) -> Result<Json<SuccessResponse>> {
    let payload = edit_contact_payload.0;
    validate_file_upload_id(payload.avatar_file_upload_id.as_deref())?;
    validate_file_upload_id(payload.proof_document_file_upload_id.as_deref())?;
    state
        .contact_service
        .update_contact(
            &payload.node_id,
            payload.name,
            payload.email,
            OptionalPostalAddress::from_web(payload.postal_address),
            payload.date_of_birth_or_registration,
            payload.country_of_birth_or_registration,
            payload.city_of_birth_or_registration,
            payload.identification_number,
            payload.avatar_file_upload_id,
            payload.proof_document_file_upload_id,
        )
        .await?;
    Ok(Json(SuccessResponse::new()))
}
