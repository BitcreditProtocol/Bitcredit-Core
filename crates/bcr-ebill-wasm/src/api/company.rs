use std::str::FromStr;

use super::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bcr_common::core::NodeId;
use bcr_ebill_api::{
    external,
    service::{
        Error,
        file_upload_service::{UploadFileHandler, detect_content_type_for_bytes},
    },
};
use bcr_ebill_core::{
    OptionalPostalAddress, PostalAddress, ValidationError, city::City, country::Country,
    date::Date, email::Email, identification::Identification, name::Name,
};
use uuid::Uuid;
use wasm_bindgen::prelude::*;

use crate::{
    TSResult,
    context::get_ctx,
    data::{
        Base64FileResponse, BinaryFileResponse, OptionalPostalAddressWeb, PostalAddressWeb,
        UploadFile, UploadFileResponse,
        company::{
            AddSignatoryPayload, CompaniesResponse, CompanyWeb, CreateCompanyPayload,
            EditCompanyPayload, ListSignatoriesResponse, RemoveSignatoryPayload,
            ResyncCompanyPayload, SignatoryResponse,
        },
        has_field,
        identity::ShareCompanyContactTo,
    },
    error::WasmError,
};

async fn get_file(id: &str, file_name: &Name) -> Result<(Vec<u8>, String)> {
    let parsed_id = NodeId::from_str(id).map_err(ValidationError::from)?;
    let company = get_ctx()
        .company_service
        .get_company_by_id(&parsed_id)
        .await?; // check if company exists
    let private_key = get_ctx()
        .identity_service
        .get_full_identity()
        .await?
        .key_pair
        .get_private_key();

    let file_bytes = get_ctx()
        .company_service
        .open_and_decrypt_file(company, &parsed_id, file_name, &private_key)
        .await?;

    let content_type = detect_content_type_for_bytes(&file_bytes)
        .ok_or(Error::Validation(ValidationError::InvalidContentType))?;
    Ok((file_bytes, content_type))
}

#[wasm_bindgen]
pub struct Company;

#[wasm_bindgen]
impl Company {
    #[wasm_bindgen]
    pub fn new() -> Self {
        Company
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<BinaryFileResponse>")]
    pub async fn file(&self, id: &str, file_name: &str) -> JsValue {
        let res: Result<BinaryFileResponse> = async {
            let name = Name::new(file_name)?;
            let (file_bytes, content_type) = get_file(id, &name).await?;
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
    pub async fn file_base64(&self, id: &str, file_name: &str) -> JsValue {
        let res: Result<Base64FileResponse> = async {
            let name = Name::new(file_name)?;
            let (file_bytes, content_type) = get_file(id, &name).await?;

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

    #[wasm_bindgen(unchecked_return_type = "TSResult<CompaniesResponse>")]
    pub async fn list(&self) -> JsValue {
        let res: Result<CompaniesResponse> = async {
            let companies = get_ctx()
                .company_service
                .get_list_of_companies()
                .await?
                .into_iter()
                .map(|c| c.into())
                .collect();
            Ok(CompaniesResponse { companies })
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<ListSignatoriesResponse>")]
    pub async fn list_signatories(&self, id: &str) -> JsValue {
        let res: Result<ListSignatoriesResponse> = async {
            let parsed_id = NodeId::from_str(id).map_err(ValidationError::from)?;
            let signatories = get_ctx()
                .company_service
                .list_signatories(&parsed_id)
                .await?;
            let signatories: Vec<SignatoryResponse> = signatories
                .into_iter()
                .map(|c| c.try_into())
                .collect::<std::result::Result<_, _>>()?;
            Ok(ListSignatoriesResponse { signatories })
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<CompanyWeb>")]
    pub async fn detail(&self, id: &str) -> JsValue {
        let res: Result<CompanyWeb> = async {
            let parsed_id = NodeId::from_str(id).map_err(ValidationError::from)?;
            let company = get_ctx()
                .company_service
                .get_company_by_id(&parsed_id)
                .await?;
            Ok(company.into())
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<CompanyWeb>")]
    pub async fn create(
        &self,
        #[wasm_bindgen(unchecked_param_type = "CreateCompanyPayload")] payload: JsValue,
    ) -> JsValue {
        let res: Result<CompanyWeb> = async {
            let company_payload: CreateCompanyPayload = serde_wasm_bindgen::from_value(payload)?;
            let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;

            let created_company = get_ctx()
                .company_service
                .create_company(
                    Name::new(company_payload.name)?,
                    company_payload
                        .country_of_registration
                        .as_deref()
                        .map(Country::parse)
                        .transpose()?,
                    company_payload
                        .city_of_registration
                        .map(City::new)
                        .transpose()?,
                    PostalAddress::from(PostalAddressWeb::try_from(
                        company_payload.postal_address,
                    )?),
                    Email::new(company_payload.email)?,
                    company_payload
                        .registration_number
                        .map(Identification::new)
                        .transpose()?,
                    company_payload
                        .registration_date
                        .map(|d| Date::new(&d))
                        .transpose()?,
                    company_payload
                        .proof_of_registration_file_upload_id
                        .map(|s| {
                            Uuid::from_str(&s).map_err(|_| ValidationError::InvalidFileUploadId)
                        })
                        .transpose()?,
                    company_payload
                        .logo_file_upload_id
                        .map(|s| {
                            Uuid::from_str(&s).map_err(|_| ValidationError::InvalidFileUploadId)
                        })
                        .transpose()?,
                    timestamp,
                )
                .await?;

            Ok(created_company.into())
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<void>")]
    pub async fn edit(
        &self,
        #[wasm_bindgen(unchecked_param_type = "EditCompanyPayload")] payload: JsValue,
    ) -> JsValue {
        let res: Result<()> = async {
            // if it's not there, we ignore it, if it's set to undefined, we remove
            let has_logo_file_upload_id = has_field(&payload, "logo_file_upload_id");
            let has_proof_of_registration_file_upload_id =
                has_field(&payload, "proof_of_registration_file_upload_id");

            let company_payload: EditCompanyPayload = serde_wasm_bindgen::from_value(payload)?;

            if company_payload.name.is_none()
                && company_payload.email.is_none()
                && company_payload.postal_address.is_none()
                && company_payload.logo_file_upload_id.is_none()
            {
                return Ok(());
            }
            let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
            get_ctx()
                .company_service
                .edit_company(
                    &company_payload.id,
                    company_payload.name.map(Name::new).transpose()?,
                    company_payload.email.map(Email::new).transpose()?,
                    OptionalPostalAddress::from(OptionalPostalAddressWeb::try_from(
                        company_payload.postal_address,
                    )?),
                    company_payload
                        .country_of_registration
                        .as_deref()
                        .map(Country::parse)
                        .transpose()?,
                    company_payload
                        .city_of_registration
                        .map(City::new)
                        .transpose()?,
                    company_payload
                        .registration_number
                        .map(Identification::new)
                        .transpose()?,
                    company_payload
                        .registration_date
                        .map(|d| Date::new(&d))
                        .transpose()?,
                    company_payload
                        .logo_file_upload_id
                        .map(|s| {
                            Uuid::from_str(&s).map_err(|_| ValidationError::InvalidFileUploadId)
                        })
                        .transpose()?,
                    !has_logo_file_upload_id,
                    company_payload
                        .proof_of_registration_file_upload_id
                        .map(|s| {
                            Uuid::from_str(&s).map_err(|_| ValidationError::InvalidFileUploadId)
                        })
                        .transpose()?,
                    !has_proof_of_registration_file_upload_id,
                    timestamp,
                )
                .await?;
            Ok(())
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<void>")]
    pub async fn add_signatory(
        &self,
        #[wasm_bindgen(unchecked_param_type = "AddSignatoryPayload")] payload: JsValue,
    ) -> JsValue {
        let res: Result<()> = async {
            let company_payload: AddSignatoryPayload = serde_wasm_bindgen::from_value(payload)?;
            let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
            get_ctx()
                .company_service
                .add_signatory(
                    &company_payload.id,
                    company_payload.signatory_node_id.clone(),
                    timestamp,
                )
                .await?;
            Ok(())
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<void>")]
    pub async fn remove_signatory(
        &self,
        #[wasm_bindgen(unchecked_param_type = "RemoveSignatoryPayload")] payload: JsValue,
    ) -> JsValue {
        let res: Result<()> = async {
            let company_payload: RemoveSignatoryPayload = serde_wasm_bindgen::from_value(payload)?;
            let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
            get_ctx()
                .company_service
                .remove_signatory(
                    &company_payload.id,
                    company_payload.signatory_node_id.clone(),
                    timestamp,
                )
                .await?;
            Ok(())
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<void>")]
    pub async fn share_contact_details(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ShareCompanyContactTo")] payload: JsValue,
    ) -> JsValue {
        let res: Result<()> = async {
            let share_to: ShareCompanyContactTo = serde_wasm_bindgen::from_value(payload)?;
            get_ctx()
                .company_service
                .share_contact_details(&share_to.recipient, share_to.company_id)
                .await?;
            Ok(())
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<string[]>")]
    pub async fn dev_mode_get_full_company_chain(&self, company_id: &str) -> JsValue {
        let res: Result<Vec<String>> = async {
            let parsed_company_id = NodeId::from_str(company_id).map_err(ValidationError::from)?;
            let plaintext_chain = get_ctx()
                .company_service
                .dev_mode_get_full_company_chain(&parsed_company_id)
                .await?;
            let json_string_chain: Result<Vec<String>> = plaintext_chain
                .into_iter()
                .map(|plaintext_block| {
                    plaintext_block
                        .to_json_text()
                        .map_err(|e| WasmError::Service(Error::Blockchain(e)))
                })
                .collect();

            json_string_chain
        }
        .await;
        TSResult::res_to_js(res)
    }

    /// Given a node id, resync the company chain via block transport
    #[wasm_bindgen(unchecked_return_type = "TSResult<void>")]
    pub async fn sync_company_chain(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ResyncCompanyPayload")] payload: JsValue,
    ) -> JsValue {
        let res: Result<()> = async {
            let payload: ResyncCompanyPayload = serde_wasm_bindgen::from_value(payload)?;
            get_ctx()
                .transport_service
                .block_transport()
                .resync_company_chain(&payload.node_id)
                .await?;
            Ok(())
        }
        .await;
        TSResult::res_to_js(res)
    }
}

impl Default for Company {
    fn default() -> Self {
        Company
    }
}
