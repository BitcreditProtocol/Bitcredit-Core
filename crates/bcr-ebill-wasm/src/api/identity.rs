use crate::{
    Result,
    context::get_ctx,
    data::{
        Base64FileResponse, BinaryFileResponse, UploadFile, UploadFileResponse, has_field,
        identity::{
            ChangeIdentityPayload, IdentityTypeWeb, IdentityWeb, NewIdentityPayload, SeedPhrase,
            SwitchIdentity,
        },
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bcr_ebill_api::{
    data::{
        NodeId, OptionalPostalAddress,
        identity::{ActiveIdentityState, IdentityType, SwitchIdentityType},
    },
    external,
    service::{
        Error,
        notification_service::{NostrConfig, restore::RestoreAccountApi},
    },
    util::{
        ValidationError,
        file::{UploadFileHandler, detect_content_type_for_bytes},
        validate_file_upload_id,
    },
};
use bcr_ebill_transport::{NostrClient, RestoreAccountService};
use wasm_bindgen::prelude::*;

async fn get_file(file_name: &str) -> Result<(Vec<u8>, String)> {
    let identity = get_ctx().identity_service.get_full_identity().await?;
    let private_key = identity.key_pair.get_private_key();
    let id = identity.identity.node_id.clone();

    let file_bytes = get_ctx()
        .identity_service
        .open_and_decrypt_file(identity.identity, &id, file_name, &private_key)
        .await?;

    let content_type = detect_content_type_for_bytes(&file_bytes)
        .ok_or(Error::Validation(ValidationError::InvalidContentType))?;
    Ok((file_bytes, content_type))
}

/// A structure describing the currently selected identity between the personal and multiple
/// possible company identities
#[derive(Clone, Debug)]
pub struct SwitchIdentityState {
    pub personal: String,
    pub company: Option<String>,
}

#[wasm_bindgen]
pub struct Identity;

#[wasm_bindgen]
impl Identity {
    #[wasm_bindgen]
    pub fn new() -> Self {
        Identity
    }

    #[wasm_bindgen(unchecked_return_type = "BinaryFileResponse")]
    pub async fn file(&self, file_name: &str) -> Result<JsValue> {
        let (file_bytes, content_type) = get_file(file_name).await?;
        let res = serde_wasm_bindgen::to_value(&BinaryFileResponse {
            data: file_bytes,
            name: file_name.to_owned(),
            content_type,
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "Base64FileResponse")]
    pub async fn file_base64(&self, file_name: &str) -> Result<JsValue> {
        let (file_bytes, content_type) = get_file(file_name).await?;

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

    #[wasm_bindgen(unchecked_return_type = "IdentityWeb")]
    pub async fn detail(&self) -> Result<JsValue> {
        let my_identity = if !get_ctx().identity_service.identity_exists().await {
            return Err(Error::NotFound.into());
        } else {
            let full_identity = get_ctx().identity_service.get_full_identity().await?;
            IdentityWeb::from(full_identity.identity)?
        };
        let res = serde_wasm_bindgen::to_value(&my_identity)?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "IdentityWeb")]
    pub async fn deanonymize(
        &self,
        #[wasm_bindgen(unchecked_param_type = "NewIdentityPayload")] payload: JsValue,
    ) -> Result<JsValue> {
        let identity: NewIdentityPayload = serde_wasm_bindgen::from_value(payload)?;

        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;

        validate_file_upload_id(identity.profile_picture_file_upload_id.as_deref())?;
        validate_file_upload_id(identity.identity_document_file_upload_id.as_deref())?;

        get_ctx()
            .identity_service
            .deanonymize_identity(
                IdentityType::from(IdentityTypeWeb::try_from(identity.t)?),
                identity.name,
                identity.email,
                OptionalPostalAddress::from(identity.postal_address),
                identity.date_of_birth,
                identity.country_of_birth,
                identity.city_of_birth,
                identity.identification_number,
                identity.profile_picture_file_upload_id,
                identity.identity_document_file_upload_id,
                timestamp,
            )
            .await?;

        let full_identity = get_ctx().identity_service.get_full_identity().await?;
        let identity = IdentityWeb::from(full_identity.identity)?;

        let res = serde_wasm_bindgen::to_value(&identity)?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "IdentityWeb")]
    pub async fn create(
        &self,
        #[wasm_bindgen(unchecked_param_type = "NewIdentityPayload")] payload: JsValue,
    ) -> Result<JsValue> {
        let identity: NewIdentityPayload = serde_wasm_bindgen::from_value(payload)?;

        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;

        validate_file_upload_id(identity.profile_picture_file_upload_id.as_deref())?;
        validate_file_upload_id(identity.identity_document_file_upload_id.as_deref())?;

        get_ctx()
            .identity_service
            .create_identity(
                IdentityType::from(IdentityTypeWeb::try_from(identity.t)?),
                identity.name,
                identity.email,
                OptionalPostalAddress::from(identity.postal_address),
                identity.date_of_birth,
                identity.country_of_birth,
                identity.city_of_birth,
                identity.identification_number,
                identity.profile_picture_file_upload_id,
                identity.identity_document_file_upload_id,
                timestamp,
            )
            .await?;

        let full_identity = get_ctx().identity_service.get_full_identity().await?;
        let identity = IdentityWeb::from(full_identity.identity)?;

        let res = serde_wasm_bindgen::to_value(&identity)?;
        Ok(res)
    }

    #[wasm_bindgen]
    pub async fn change(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ChangeIdentityPayload")] payload: JsValue,
    ) -> Result<()> {
        // if it's not there, we ignore it, if it's set to undefined, we remove
        let has_profile_picture_file_upload_id =
            has_field(&payload, "profile_picture_file_upload_id");
        let has_identity_document_file_upload_id =
            has_field(&payload, "identity_document_file_upload_id");

        let identity_payload: ChangeIdentityPayload = serde_wasm_bindgen::from_value(payload)?;

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
            return Ok(());
        }
        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        get_ctx()
            .identity_service
            .update_identity(
                identity_payload.name,
                identity_payload.email,
                OptionalPostalAddress::from(identity_payload.postal_address),
                identity_payload.date_of_birth,
                identity_payload.country_of_birth,
                identity_payload.city_of_birth,
                identity_payload.identification_number,
                identity_payload.profile_picture_file_upload_id,
                !has_profile_picture_file_upload_id,
                identity_payload.identity_document_file_upload_id,
                !has_identity_document_file_upload_id,
                timestamp,
            )
            .await?;
        Ok(())
    }

    #[wasm_bindgen(unchecked_return_type = "SwitchIdentity")]
    pub async fn active(&self) -> Result<JsValue> {
        let current_identity = get_current_identity().await?;
        let (node_id, t) = match current_identity.company {
            None => (current_identity.personal, SwitchIdentityType::Person),
            Some(company_node_id) => (company_node_id, SwitchIdentityType::Company),
        };
        let switch_identity = SwitchIdentity {
            t: Some(t.into()),
            node_id,
        };
        let res = serde_wasm_bindgen::to_value(&switch_identity)?;
        Ok(res)
    }

    #[wasm_bindgen]
    pub async fn switch(
        &self,
        #[wasm_bindgen(unchecked_param_type = "SwitchIdentity")] switch_identity_payload: JsValue,
    ) -> Result<()> {
        let payload: SwitchIdentity = serde_wasm_bindgen::from_value(switch_identity_payload)?;
        let node_id = payload.node_id;
        let personal_node_id = get_ctx().identity_service.get_identity().await?.node_id;

        // if it's the personal node id, set it
        if node_id == personal_node_id {
            get_ctx()
                .identity_service
                .set_current_personal_identity(&node_id)
                .await?;
            return Ok(());
        }

        // if it's one of our companies, set it
        if get_ctx()
            .company_service
            .get_list_of_companies()
            .await?
            .iter()
            .any(|c| c.id == node_id)
        {
            get_ctx()
                .identity_service
                .set_current_company_identity(&node_id)
                .await?;
            return Ok(());
        }

        // otherwise, return an error
        Err(Error::Validation(ValidationError::UnknownNodeId(node_id.to_string())).into())
    }

    #[wasm_bindgen(unchecked_return_type = "SeedPhrase")]
    pub async fn seed_backup(&self) -> Result<JsValue> {
        let seed_phrase = get_ctx().identity_service.get_seedphrase().await?;
        let res = serde_wasm_bindgen::to_value(&SeedPhrase { seed_phrase })?;
        Ok(res)
    }

    #[wasm_bindgen]
    pub async fn seed_recover(
        &self,
        #[wasm_bindgen(unchecked_param_type = "SeedPhrase")] payload: JsValue,
    ) -> Result<()> {
        let seed_phrase_payload: SeedPhrase = serde_wasm_bindgen::from_value(payload)?;
        get_ctx()
            .identity_service
            .recover_from_seedphrase(&seed_phrase_payload.seed_phrase)
            .await?;

        let identity = get_ctx().identity_service.get_full_identity().await?;

        let conf = get_ctx().cfg.nostr_config.clone();

        let nostr_config = NostrConfig::new(
            identity.key_pair,
            conf.relays,
            "Recovery user".to_string(),
            true,
            identity.identity.node_id,
        );

        let client = NostrClient::default(&nostr_config).await?;
        let recovery_service = RestoreAccountService::new(Box::new(client)).await;
        recovery_service.restore_account().await?;
        Ok(())
    }
}

impl Default for Identity {
    fn default() -> Self {
        Identity
    }
}

pub async fn get_current_identity() -> Result<ActiveIdentityState> {
    let active_identity = get_ctx().identity_service.get_current_identity().await?;
    Ok(active_identity)
}

pub async fn get_current_identity_node_id() -> Result<NodeId> {
    let current_identity = get_current_identity().await?;
    match current_identity.company {
        None => Ok(current_identity.personal),
        Some(company_node_id) => Ok(company_node_id),
    }
}
