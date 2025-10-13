use std::str::FromStr;

use crate::data::contact::{
    ContactTypeWeb, ContactWeb, ContactsResponse, EditContactPayload, NewContactPayload,
    SearchContactsPayload,
};
use crate::data::{
    Base64FileResponse, BinaryFileResponse, OptionalPostalAddressWeb, PostalAddressWeb, UploadFile,
    UploadFileResponse, has_field,
};
use crate::{Result, context::get_ctx};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bcr_ebill_api::data::city::City;
use bcr_ebill_api::data::contact::ContactType;
use bcr_ebill_api::data::country::Country;
use bcr_ebill_api::data::date::Date;
use bcr_ebill_api::data::email::Email;
use bcr_ebill_api::data::identification::Identification;
use bcr_ebill_api::data::name::Name;
use bcr_ebill_api::data::{NodeId, OptionalPostalAddress, PostalAddress};
use bcr_ebill_api::service;
use bcr_ebill_api::util::file::{UploadFileHandler, detect_content_type_for_bytes};
use bcr_ebill_api::util::{ValidationError, validate_file_upload_id};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Contact;

async fn get_file(node_id: &str, file_name: &str) -> Result<(Vec<u8>, String)> {
    let parsed_node_id = NodeId::from_str(node_id).map_err(ValidationError::from)?;
    let contact = get_ctx()
        .contact_service
        .get_contact(&parsed_node_id)
        .await?; // check if contact exists

    let private_key = get_ctx()
        .identity_service
        .get_full_identity()
        .await?
        .key_pair
        .get_private_key();

    let file_bytes = get_ctx()
        .contact_service
        .open_and_decrypt_file(contact, &parsed_node_id, file_name, &private_key)
        .await?;
    let content_type = detect_content_type_for_bytes(&file_bytes).ok_or(
        service::Error::Validation(ValidationError::InvalidContentType),
    )?;
    Ok((file_bytes, content_type))
}

#[wasm_bindgen]
impl Contact {
    #[wasm_bindgen]
    pub fn new() -> Self {
        Contact
    }

    #[wasm_bindgen(unchecked_return_type = "BinaryFileResponse")]
    pub async fn file(&self, node_id: &str, file_name: &str) -> Result<JsValue> {
        let (file_bytes, content_type) = get_file(node_id, file_name).await?;
        let res = serde_wasm_bindgen::to_value(&BinaryFileResponse {
            data: file_bytes,
            name: file_name.to_owned(),
            content_type,
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "Base64FileResponse")]
    pub async fn file_base64(&self, node_id: &str, file_name: &str) -> Result<JsValue> {
        let (file_bytes, content_type) = get_file(node_id, file_name).await?;

        let res = serde_wasm_bindgen::to_value(&Base64FileResponse {
            data: STANDARD.encode(&file_bytes),
            name: file_name.to_owned(),
            content_type,
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "UploadFileResponse")]
    pub async fn upload(
        &self,
        #[wasm_bindgen(unchecked_param_type = "UploadFile")] payload: JsValue,
    ) -> Result<JsValue> {
        let upload_file: UploadFile = serde_wasm_bindgen::from_value(payload)?;
        let upload_file_handler: &dyn UploadFileHandler = &upload_file as &dyn UploadFileHandler;

        get_ctx()
            .file_upload_service
            .validate_attached_file(upload_file_handler)
            .await?;

        let file_upload_response = get_ctx()
            .file_upload_service
            .upload_file(upload_file_handler)
            .await?;

        let res = serde_wasm_bindgen::to_value::<UploadFileResponse>(&file_upload_response.into())?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "ContactsResponse")]
    pub async fn list(&self) -> Result<JsValue> {
        let contacts = get_ctx().contact_service.get_contacts().await?;
        let res = serde_wasm_bindgen::to_value(&ContactsResponse {
            contacts: contacts.into_iter().map(|c| c.into()).collect(),
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "ContactsResponse")]
    pub async fn search(
        &self,
        #[wasm_bindgen(unchecked_param_type = "SearchContactsPayload")] payload: JsValue,
    ) -> Result<JsValue> {
        let query: SearchContactsPayload = serde_wasm_bindgen::from_value(payload)?;
        let contacts = get_ctx()
            .contact_service
            .search(
                query.search_term.as_str(),
                query.include_logical,
                query.include_contact,
            )
            .await?;
        let res = serde_wasm_bindgen::to_value(&ContactsResponse {
            contacts: contacts.into_iter().map(|c| c.into()).collect(),
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "ContactWeb")]
    pub async fn detail(&self, node_id: &str) -> Result<JsValue> {
        let parsed_node_id = NodeId::from_str(node_id).map_err(ValidationError::from)?;
        let contact: ContactWeb = get_ctx()
            .contact_service
            .get_contact(&parsed_node_id)
            .await?
            .into();
        let res = serde_wasm_bindgen::to_value(&contact)?;
        Ok(res)
    }

    #[wasm_bindgen]
    pub async fn remove(&self, node_id: &str) -> Result<()> {
        let parsed_node_id = NodeId::from_str(node_id).map_err(ValidationError::from)?;
        get_ctx().contact_service.delete(&parsed_node_id).await?;
        Ok(())
    }

    #[wasm_bindgen(unchecked_return_type = "ContactWeb")]
    pub async fn deanonymize(
        &self,
        #[wasm_bindgen(unchecked_param_type = "NewContactPayload")] payload: JsValue,
    ) -> Result<JsValue> {
        let contact_payload: NewContactPayload = serde_wasm_bindgen::from_value(payload)?;
        let contact = get_ctx()
            .contact_service
            .deanonymize_contact(
                &contact_payload.node_id,
                ContactType::from(ContactTypeWeb::try_from(contact_payload.t)?),
                Name::new(contact_payload.name)?,
                contact_payload.email.map(Email::new).transpose()?,
                contact_payload
                    .postal_address
                    .map(PostalAddressWeb::try_from)
                    .transpose()?
                    .map(PostalAddress::from),
                contact_payload
                    .date_of_birth_or_registration
                    .map(|d| Date::new(&d))
                    .transpose()?,
                contact_payload
                    .country_of_birth_or_registration
                    .as_deref()
                    .map(Country::parse)
                    .transpose()?,
                contact_payload
                    .city_of_birth_or_registration
                    .map(City::new)
                    .transpose()?,
                contact_payload
                    .identification_number
                    .map(Identification::new)
                    .transpose()?,
                contact_payload.avatar_file_upload_id,
                contact_payload.proof_document_file_upload_id,
            )
            .await?;
        let res = serde_wasm_bindgen::to_value::<ContactWeb>(&contact.into())?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "ContactWeb")]
    pub async fn create(
        &self,
        #[wasm_bindgen(unchecked_param_type = "NewContactPayload")] payload: JsValue,
    ) -> Result<JsValue> {
        let contact_payload: NewContactPayload = serde_wasm_bindgen::from_value(payload)?;
        let contact = get_ctx()
            .contact_service
            .add_contact(
                &contact_payload.node_id,
                ContactType::from(ContactTypeWeb::try_from(contact_payload.t)?),
                Name::new(contact_payload.name)?,
                contact_payload.email.map(Email::new).transpose()?,
                contact_payload
                    .postal_address
                    .map(PostalAddressWeb::try_from)
                    .transpose()?
                    .map(PostalAddress::from),
                contact_payload
                    .date_of_birth_or_registration
                    .map(|d| Date::new(&d))
                    .transpose()?,
                contact_payload
                    .country_of_birth_or_registration
                    .as_deref()
                    .map(Country::parse)
                    .transpose()?,
                contact_payload
                    .city_of_birth_or_registration
                    .map(City::new)
                    .transpose()?,
                contact_payload
                    .identification_number
                    .map(Identification::new)
                    .transpose()?,
                contact_payload.avatar_file_upload_id,
                contact_payload.proof_document_file_upload_id,
            )
            .await?;
        let res = serde_wasm_bindgen::to_value::<ContactWeb>(&contact.into())?;
        Ok(res)
    }

    #[wasm_bindgen]
    pub async fn edit(
        &self,
        #[wasm_bindgen(unchecked_param_type = "EditContactPayload")] payload: JsValue,
    ) -> Result<()> {
        // if it's not there, we ignore it, if it's set to undefined, we remove
        let has_avatar_file_upload_id = has_field(&payload, "avatar_file_upload_id");
        let has_proof_document_file_upload_id =
            has_field(&payload, "proof_document_file_upload_id");

        let contact_payload: EditContactPayload = serde_wasm_bindgen::from_value(payload)?;
        validate_file_upload_id(contact_payload.avatar_file_upload_id.as_deref())?;
        validate_file_upload_id(contact_payload.proof_document_file_upload_id.as_deref())?;
        get_ctx()
            .contact_service
            .update_contact(
                &contact_payload.node_id,
                contact_payload.name.map(Name::new).transpose()?,
                contact_payload.email.map(Email::new).transpose()?,
                OptionalPostalAddress::from(OptionalPostalAddressWeb::try_from(
                    contact_payload.postal_address,
                )?),
                contact_payload
                    .date_of_birth_or_registration
                    .map(|d| Date::new(&d))
                    .transpose()?,
                contact_payload
                    .country_of_birth_or_registration
                    .as_deref()
                    .map(Country::parse)
                    .transpose()?,
                contact_payload
                    .city_of_birth_or_registration
                    .map(City::new)
                    .transpose()?,
                contact_payload
                    .identification_number
                    .map(Identification::new)
                    .transpose()?,
                contact_payload.avatar_file_upload_id,
                !has_avatar_file_upload_id,
                contact_payload.proof_document_file_upload_id,
                !has_proof_document_file_upload_id,
            )
            .await?;
        Ok(())
    }
}

impl Default for Contact {
    fn default() -> Self {
        Contact
    }
}
