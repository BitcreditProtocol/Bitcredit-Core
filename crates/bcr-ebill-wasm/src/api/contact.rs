use std::str::FromStr;

use crate::TSResult;
use crate::data::contact::{
    ApproveContactSharePayload, ContactTypeWeb, ContactWeb, ContactsResponse, EditContactPayload,
    NewContactPayload, PendingContactShareWeb, PendingContactSharesResponse, SearchContactsPayload,
};
use crate::data::{
    Base64FileResponse, BinaryFileResponse, OptionalPostalAddressWeb, PostalAddressWeb, UploadFile,
    UploadFileResponse, has_field,
};
use crate::{Result, context::get_ctx};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bcr_common::core::NodeId;
use bcr_ebill_api::service;
use bcr_ebill_api::service::file_upload_service::{
    UploadFileHandler, detect_content_type_for_bytes,
};
use bcr_ebill_core::protocol::Country;
use bcr_ebill_core::protocol::Date;
use bcr_ebill_core::protocol::Email;
use bcr_ebill_core::protocol::Identification;
use bcr_ebill_core::protocol::Name;
use bcr_ebill_core::protocol::blockchain::bill::ContactType;
use bcr_ebill_core::protocol::{City, ProtocolValidationError};
use bcr_ebill_core::protocol::{OptionalPostalAddress, PostalAddress};
use uuid::Uuid;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Contact;

async fn get_file(node_id: &str, file_name: &Name) -> Result<(Vec<u8>, String)> {
    let parsed_node_id = NodeId::from_str(node_id).map_err(ProtocolValidationError::from)?;
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
        service::Error::Validation(ProtocolValidationError::InvalidContentType.into()),
    )?;
    Ok((file_bytes, content_type))
}

#[wasm_bindgen]
impl Contact {
    #[wasm_bindgen]
    pub fn new() -> Self {
        Contact
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<BinaryFileResponse>")]
    pub async fn file(&self, node_id: &str, file_name: &str) -> JsValue {
        let res: Result<BinaryFileResponse> = async {
            let name = Name::new(file_name)?;
            let (file_bytes, content_type) = get_file(node_id, &name).await?;
            Ok(BinaryFileResponse {
                data: file_bytes,
                name,
                content_type,
            })
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<Base64FileResponse>")]
    pub async fn file_base64(&self, node_id: &str, file_name: &str) -> JsValue {
        let res: Result<Base64FileResponse> = async {
            let name = Name::new(file_name)?;
            let (file_bytes, content_type) = get_file(node_id, &name).await?;

            Ok(Base64FileResponse {
                data: STANDARD.encode(&file_bytes),
                name,
                content_type,
            })
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<UploadFileResponse>")]
    pub async fn upload(
        &self,
        #[wasm_bindgen(unchecked_param_type = "UploadFile")] payload: JsValue,
    ) -> JsValue {
        let res: Result<UploadFileResponse> = async {
            let upload_file: UploadFile = serde_wasm_bindgen::from_value(payload)?;
            let upload_file_handler: &dyn UploadFileHandler =
                &upload_file as &dyn UploadFileHandler;

            get_ctx()
                .file_upload_service
                .validate_attached_file(upload_file_handler)
                .await?;

            let file_upload_response = get_ctx()
                .file_upload_service
                .upload_file(upload_file_handler)
                .await?;

            Ok(file_upload_response.into())
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<ContactsResponse>")]
    pub async fn list(&self) -> JsValue {
        let res: Result<ContactsResponse> = async {
            let contacts = get_ctx().contact_service.get_contacts().await?;
            Ok(ContactsResponse {
                contacts: contacts.into_iter().map(|c| c.into()).collect(),
            })
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<ContactsResponse>")]
    pub async fn search(
        &self,
        #[wasm_bindgen(unchecked_param_type = "SearchContactsPayload")] payload: JsValue,
    ) -> JsValue {
        let res: Result<ContactsResponse> = async {
            let query: SearchContactsPayload = serde_wasm_bindgen::from_value(payload)?;
            let contacts = get_ctx()
                .contact_service
                .search(
                    query.search_term.as_str(),
                    query.include_logical,
                    query.include_contact,
                )
                .await?;
            Ok(ContactsResponse {
                contacts: contacts.into_iter().map(|c| c.into()).collect(),
            })
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<ContactWeb>")]
    pub async fn detail(&self, node_id: &str) -> JsValue {
        let res: Result<ContactWeb> = async {
            let parsed_node_id =
                NodeId::from_str(node_id).map_err(ProtocolValidationError::from)?;
            let contact: ContactWeb = get_ctx()
                .contact_service
                .get_contact(&parsed_node_id)
                .await?
                .into();
            Ok(contact)
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<void>")]
    pub async fn remove(&self, node_id: &str) -> JsValue {
        let res: Result<()> = async {
            let parsed_node_id =
                NodeId::from_str(node_id).map_err(ProtocolValidationError::from)?;
            get_ctx().contact_service.delete(&parsed_node_id).await?;
            Ok(())
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<ContactWeb>")]
    pub async fn deanonymize(
        &self,
        #[wasm_bindgen(unchecked_param_type = "NewContactPayload")] payload: JsValue,
    ) -> JsValue {
        let res: Result<ContactWeb> = async {
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
                    contact_payload
                        .avatar_file_upload_id
                        .map(|s| {
                            Uuid::from_str(&s)
                                .map_err(|_| ProtocolValidationError::InvalidFileUploadId)
                        })
                        .transpose()?,
                    contact_payload
                        .proof_document_file_upload_id
                        .map(|s| {
                            Uuid::from_str(&s)
                                .map_err(|_| ProtocolValidationError::InvalidFileUploadId)
                        })
                        .transpose()?,
                )
                .await?;
            Ok(contact.into())
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<ContactWeb>")]
    pub async fn create(
        &self,
        #[wasm_bindgen(unchecked_param_type = "NewContactPayload")] payload: JsValue,
    ) -> JsValue {
        let res: Result<ContactWeb> = async {
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
                    contact_payload
                        .avatar_file_upload_id
                        .map(|s| {
                            Uuid::from_str(&s)
                                .map_err(|_| ProtocolValidationError::InvalidFileUploadId)
                        })
                        .transpose()?,
                    contact_payload
                        .proof_document_file_upload_id
                        .map(|s| {
                            Uuid::from_str(&s)
                                .map_err(|_| ProtocolValidationError::InvalidFileUploadId)
                        })
                        .transpose()?,
                )
                .await?;
            Ok(contact.into())
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<void>")]
    pub async fn edit(
        &self,
        #[wasm_bindgen(unchecked_param_type = "EditContactPayload")] payload: JsValue,
    ) -> JsValue {
        let res: Result<()> = async {
            // if it's not there, we ignore it, if it's set to undefined, we remove
            let has_avatar_file_upload_id = has_field(&payload, "avatar_file_upload_id");
            let has_proof_document_file_upload_id =
                has_field(&payload, "proof_document_file_upload_id");

            let contact_payload: EditContactPayload = serde_wasm_bindgen::from_value(payload)?;
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
                    contact_payload
                        .avatar_file_upload_id
                        .map(|s| {
                            Uuid::from_str(&s)
                                .map_err(|_| ProtocolValidationError::InvalidFileUploadId)
                        })
                        .transpose()?,
                    !has_avatar_file_upload_id,
                    contact_payload
                        .proof_document_file_upload_id
                        .map(|s| {
                            Uuid::from_str(&s)
                                .map_err(|_| ProtocolValidationError::InvalidFileUploadId)
                        })
                        .transpose()?,
                    !has_proof_document_file_upload_id,
                )
                .await?;
            Ok(())
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<PendingContactSharesResponse>")]
    pub async fn list_pending_contact_shares(&self, receiver_node_id: &str) -> JsValue {
        let res: Result<PendingContactSharesResponse> = async {
            let parsed_node_id = NodeId::from_str(receiver_node_id)
                .map_err(bcr_ebill_core::protocol::ProtocolValidationError::from)?;
            let pending_shares = get_ctx()
                .contact_service
                .list_pending_contact_shares(&parsed_node_id)
                .await?;
            Ok(PendingContactSharesResponse {
                pending_shares: pending_shares.into_iter().map(|ps| ps.into()).collect(),
            })
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<PendingContactShareWeb | undefined>")]
    pub async fn get_pending_contact_share(&self, id: &str) -> JsValue {
        let res: Result<Option<PendingContactShareWeb>> = async {
            let pending_share = get_ctx()
                .contact_service
                .get_pending_contact_share(id)
                .await?;
            Ok(pending_share.map(|ps| ps.into()))
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<void>")]
    pub async fn approve_contact_share(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ApproveContactSharePayload")] payload: JsValue,
    ) -> JsValue {
        let res: Result<()> = async {
            let approve_payload: ApproveContactSharePayload =
                serde_wasm_bindgen::from_value(payload)?;
            get_ctx()
                .contact_service
                .approve_contact_share(
                    &approve_payload.pending_share_id,
                    approve_payload.share_back,
                )
                .await?;
            Ok(())
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<void>")]
    pub async fn reject_contact_share(&self, pending_share_id: &str) -> JsValue {
        let res: Result<()> = async {
            get_ctx()
                .contact_service
                .reject_contact_share(pending_share_id)
                .await?;
            Ok(())
        }
        .await;
        TSResult::res_to_js(res)
    }
}

impl Default for Contact {
    fn default() -> Self {
        Contact
    }
}
