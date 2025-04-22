use crate::data::contact::{
    ContactTypeWeb, ContactWeb, ContactsResponse, EditContactPayload, NewContactPayload,
};
use crate::data::{BinaryFileResponse, FromWeb, IntoWeb, UploadFile};
use crate::{Result, context::get_ctx};
use bcr_ebill_api::data::contact::ContactType;
use bcr_ebill_api::data::{OptionalPostalAddress, PostalAddress};
use bcr_ebill_api::service;
use bcr_ebill_api::util::file::{UploadFileHandler, detect_content_type_for_bytes};
use bcr_ebill_api::util::{ValidationError, validate_file_upload_id};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Contact;

#[wasm_bindgen]
impl Contact {
    #[wasm_bindgen]
    pub fn new() -> Self {
        Contact
    }

    #[wasm_bindgen(unchecked_return_type = "BinaryFileResponse")]
    pub async fn file(&self, id: &str, file_name: &str) -> Result<JsValue> {
        get_ctx().contact_service.get_contact(id).await?; // check if contact exists

        let private_key = get_ctx()
            .identity_service
            .get_full_identity()
            .await?
            .key_pair
            .get_private_key_string();

        let file_bytes = get_ctx()
            .contact_service
            .open_and_decrypt_file(id, file_name, &private_key)
            .await?;

        let content_type = detect_content_type_for_bytes(&file_bytes).ok_or(
            service::Error::Validation(ValidationError::InvalidContentType),
        )?;

        let res = serde_wasm_bindgen::to_value(&BinaryFileResponse {
            data: file_bytes,
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

        let res = serde_wasm_bindgen::to_value(&file_upload_response.into_web())?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "ContactsResponse")]
    pub async fn list(&self) -> Result<JsValue> {
        let contacts = get_ctx().contact_service.get_contacts().await?;
        let res = serde_wasm_bindgen::to_value(&ContactsResponse {
            contacts: contacts.into_iter().map(|c| c.into_web()).collect(),
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "ContactWeb")]
    pub async fn detail(&self, node_id: &str) -> Result<JsValue> {
        let contact: ContactWeb = get_ctx()
            .contact_service
            .get_contact(node_id)
            .await?
            .into_web();
        let res = serde_wasm_bindgen::to_value(&contact)?;
        Ok(res)
    }

    #[wasm_bindgen]
    pub async fn remove(&self, node_id: &str) -> Result<()> {
        get_ctx().contact_service.delete(node_id).await?;
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
                ContactType::from_web(ContactTypeWeb::try_from(contact_payload.t)?),
                contact_payload.name,
                contact_payload.email,
                contact_payload.postal_address.map(PostalAddress::from_web),
                contact_payload.date_of_birth_or_registration,
                contact_payload.country_of_birth_or_registration,
                contact_payload.city_of_birth_or_registration,
                contact_payload.identification_number,
                contact_payload.avatar_file_upload_id,
                contact_payload.proof_document_file_upload_id,
            )
            .await?;
        let res = serde_wasm_bindgen::to_value(&contact.into_web())?;
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
                ContactType::from_web(ContactTypeWeb::try_from(contact_payload.t)?),
                contact_payload.name,
                contact_payload.email,
                contact_payload.postal_address.map(PostalAddress::from_web),
                contact_payload.date_of_birth_or_registration,
                contact_payload.country_of_birth_or_registration,
                contact_payload.city_of_birth_or_registration,
                contact_payload.identification_number,
                contact_payload.avatar_file_upload_id,
                contact_payload.proof_document_file_upload_id,
            )
            .await?;
        let res = serde_wasm_bindgen::to_value(&contact.into_web())?;
        Ok(res)
    }

    #[wasm_bindgen]
    pub async fn edit(
        &self,
        #[wasm_bindgen(unchecked_param_type = "EditContactPayload")] payload: JsValue,
    ) -> Result<()> {
        let contact_payload: EditContactPayload = serde_wasm_bindgen::from_value(payload)?;
        validate_file_upload_id(contact_payload.avatar_file_upload_id.as_deref())?;
        validate_file_upload_id(contact_payload.proof_document_file_upload_id.as_deref())?;
        get_ctx()
            .contact_service
            .update_contact(
                &contact_payload.node_id,
                contact_payload.name,
                contact_payload.email,
                OptionalPostalAddress::from_web(contact_payload.postal_address),
                contact_payload.date_of_birth_or_registration,
                contact_payload.country_of_birth_or_registration,
                contact_payload.city_of_birth_or_registration,
                contact_payload.identification_number,
                contact_payload.avatar_file_upload_id,
                contact_payload.proof_document_file_upload_id,
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
