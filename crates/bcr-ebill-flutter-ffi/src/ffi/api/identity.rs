use crate::ffi::{
    context::get_ctx,
    data::{
        Base64FileResponse, BinaryFileResponse, OptionalPostalAddressFfi, UploadFile,
        UploadFileResponse,
        identity::{
            ChangeIdentityEmailPayload, ChangeIdentityPayload, ConfirmEmailPayload,
            IdentityEmailConfirmationFfi, IdentityFfi, IdentityTypeFfi, NewIdentityPayload,
            SeedPhrase, ShareContactTo, SwitchIdentity, VerifyEmailPayload,
        },
    },
    error::EbillFfiError,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bcr_common::core::NodeId;
use bcr_ebill_api::service::{
    Error,
    file_upload_service::{UploadFileHandler, detect_content_type_for_bytes},
    transport_service::restore::RestoreAccountApi,
};
use bcr_ebill_core::{
    application::{
        ValidationError,
        identity::{ActiveIdentityState, SwitchIdentityType},
    },
    protocol::{
        Address, City, Country, Date, Email, Identification, Name, OptionalPostalAddress,
        ProtocolValidationError, Timestamp, Zip, blockchain::identity::IdentityType,
    },
};
use bcr_ebill_transport::create_restore_account_service;
use flutter_rust_bridge::frb;
use std::str::FromStr;
use uuid::Uuid;

/// A structure describing the currently selected identity between the personal and multiple
/// possible company identities
#[derive(Clone, Debug)]
pub struct SwitchIdentityState {
    pub personal: String,
    pub company: Option<String>,
}

async fn get_file(file_name: &Name) -> Result<(Vec<u8>, String), EbillFfiError> {
    let identity = get_ctx().await.identity_service.get_full_identity().await?;
    let private_key = identity.key_pair.get_private_key();
    let id = identity.identity.node_id.clone();

    let file_bytes = get_ctx()
        .await
        .identity_service
        .open_and_decrypt_file(identity.identity, &id, file_name, &private_key)
        .await?;

    let content_type = detect_content_type_for_bytes(&file_bytes).ok_or(Error::Validation(
        ProtocolValidationError::InvalidContentType.into(),
    ))?;
    Ok((file_bytes, content_type))
}

#[frb]
pub async fn file(file_name: &str) -> Result<BinaryFileResponse, EbillFfiError> {
    let name = Name::new(file_name)?;
    let (file_bytes, content_type) = get_file(&name).await?;
    Ok(BinaryFileResponse {
        data: file_bytes,
        name: name.to_string(),
        content_type,
    })
}

#[frb]
pub async fn file_base64(file_name: &str) -> Result<Base64FileResponse, EbillFfiError> {
    let name = Name::new(file_name)?;
    let (file_bytes, content_type) = get_file(&name).await?;

    Ok(Base64FileResponse {
        data: STANDARD.encode(&file_bytes),
        name: name.to_string(),
        content_type,
    })
}

#[frb]
pub async fn upload(upload_file: UploadFile) -> Result<UploadFileResponse, EbillFfiError> {
    let upload_file_handler: &dyn UploadFileHandler = &upload_file as &dyn UploadFileHandler;

    get_ctx()
        .await
        .file_upload_service
        .validate_attached_file(upload_file_handler)
        .await?;

    let file_upload_response = get_ctx()
        .await
        .file_upload_service
        .upload_file(upload_file_handler)
        .await?;

    Ok(file_upload_response.into())
}

#[frb]
pub async fn detail() -> Result<IdentityFfi, EbillFfiError> {
    let my_identity = if !get_ctx().await.identity_service.identity_exists().await {
        return Err(bcr_ebill_api::service::Error::NotFound.into());
    } else {
        let full_identity = get_ctx().await.identity_service.get_full_identity().await?;
        IdentityFfi::from_identity(full_identity.identity)
    };
    Ok(my_identity)
}

#[frb]
pub async fn deanonymize(identity: NewIdentityPayload) -> Result<IdentityFfi, EbillFfiError> {
    let timestamp = Timestamp::now();

    get_ctx()
        .await
        .identity_service
        .deanonymize_identity(
            IdentityType::from(IdentityTypeFfi::try_from(identity.t)?),
            Name::new(identity.name)?,
            identity.email.map(Email::new).transpose()?,
            OptionalPostalAddress::try_from(OptionalPostalAddressFfi::try_from(
                identity.postal_address,
            )?)?,
            identity.date_of_birth.map(|d| Date::new(&d)).transpose()?,
            identity
                .country_of_birth
                .as_deref()
                .map(Country::parse)
                .transpose()?,
            identity.city_of_birth.map(City::new).transpose()?,
            identity
                .identification_number
                .map(Identification::new)
                .transpose()?,
            identity
                .profile_picture_file_upload_id
                .map(|s| {
                    Uuid::from_str(&s).map_err(|_| ProtocolValidationError::InvalidFileUploadId)
                })
                .transpose()?,
            identity
                .identity_document_file_upload_id
                .map(|s| {
                    Uuid::from_str(&s).map_err(|_| ProtocolValidationError::InvalidFileUploadId)
                })
                .transpose()?,
            timestamp,
        )
        .await?;

    let full_identity = get_ctx().await.identity_service.get_full_identity().await?;
    let identity = IdentityFfi::from_identity(full_identity.identity);
    Ok(identity)
}

#[frb]
pub async fn create(identity: NewIdentityPayload) -> Result<IdentityFfi, EbillFfiError> {
    let timestamp = Timestamp::now();

    get_ctx()
        .await
        .identity_service
        .create_identity(
            IdentityType::from(IdentityTypeFfi::try_from(identity.t)?),
            Name::new(identity.name)?,
            identity.email.map(Email::new).transpose()?,
            OptionalPostalAddress::try_from(OptionalPostalAddressFfi::try_from(
                identity.postal_address,
            )?)?,
            identity.date_of_birth.map(|d| Date::new(&d)).transpose()?,
            identity
                .country_of_birth
                .as_deref()
                .map(Country::parse)
                .transpose()?,
            identity.city_of_birth.map(City::new).transpose()?,
            identity
                .identification_number
                .map(Identification::new)
                .transpose()?,
            identity
                .profile_picture_file_upload_id
                .map(|s| {
                    Uuid::from_str(&s).map_err(|_| ProtocolValidationError::InvalidFileUploadId)
                })
                .transpose()?,
            identity
                .identity_document_file_upload_id
                .map(|s| {
                    Uuid::from_str(&s).map_err(|_| ProtocolValidationError::InvalidFileUploadId)
                })
                .transpose()?,
            timestamp,
        )
        .await?;

    let full_identity = get_ctx().await.identity_service.get_full_identity().await?;
    let identity = IdentityFfi::from_identity(full_identity.identity);

    Ok(identity)
}

#[frb]
pub async fn change(identity_payload: ChangeIdentityPayload) -> Result<(), EbillFfiError> {
    let edit_date_of_birth = identity_payload.date_of_birth.try_map(|d| Date::new(&d))?;

    let edit_country_of_birth = identity_payload
        .country_of_birth
        .try_map(|d| Country::parse(&d))?;

    let edit_city_of_birth = identity_payload.city_of_birth.try_map(|d| City::new(&d))?;

    let edit_identification_number = identity_payload
        .identification_number
        .try_map(|d| Identification::new(&d))?;

    let profile_picture_file = identity_payload
        .profile_picture_file_upload_id
        .try_map(|s| {
            Uuid::from_str(&s).map_err(|_| ProtocolValidationError::InvalidFileUploadId)
        })?;
    let identity_document_file =
        identity_payload
            .identity_document_file_upload_id
            .try_map(|s| {
                Uuid::from_str(&s).map_err(|_| ProtocolValidationError::InvalidFileUploadId)
            })?;

    let edit_zip = identity_payload
        .postal_address_zip
        .try_map(|z| Zip::from_str(&z))?;

    let timestamp = Timestamp::now();
    get_ctx()
        .await
        .identity_service
        .update_identity(
            identity_payload.name.map(Name::new).transpose()?,
            identity_payload
                .postal_address_country
                .map(|c| Country::parse(&c))
                .transpose()?,
            identity_payload
                .postal_address_city
                .map(|c| City::from_str(&c))
                .transpose()?,
            edit_zip,
            identity_payload
                .postal_address_address
                .map(|c| Address::from_str(&c))
                .transpose()?,
            edit_date_of_birth,
            edit_country_of_birth,
            edit_city_of_birth,
            edit_identification_number,
            profile_picture_file,
            identity_document_file,
            timestamp,
        )
        .await?;
    Ok(())
}

#[frb]
pub async fn change_email(
    identity_email_payload: ChangeIdentityEmailPayload,
) -> Result<(), EbillFfiError> {
    let timestamp = Timestamp::now();
    get_ctx()
        .await
        .identity_service
        .update_email(&Email::new(identity_email_payload.email)?, timestamp)
        .await?;
    Ok(())
}

#[frb]
pub async fn active() -> Result<SwitchIdentity, EbillFfiError> {
    let current_identity = get_current_identity().await?;
    let (node_id, t) = match current_identity.company {
        None => (current_identity.personal, SwitchIdentityType::Person),
        Some(company_node_id) => (company_node_id, SwitchIdentityType::Company),
    };
    let switch_identity = SwitchIdentity {
        t: Some(t.into()),
        node_id: node_id.to_string(),
    };
    Ok(switch_identity)
}

#[frb]
pub async fn switch(payload: SwitchIdentity) -> Result<(), EbillFfiError> {
    let node_id = NodeId::from_str(&payload.node_id).map_err(ProtocolValidationError::from)?;
    let personal_node_id = get_ctx()
        .await
        .identity_service
        .get_identity()
        .await?
        .node_id;

    // if it's the personal node id, set it
    if node_id == personal_node_id {
        get_ctx()
            .await
            .identity_service
            .set_current_personal_identity(&node_id)
            .await?;
        return Ok(());
    }

    // if it's one of our companies, set it
    if get_ctx()
        .await
        .company_service
        .get_list_of_companies()
        .await?
        .iter()
        .any(|c| c.id == node_id)
    {
        get_ctx()
            .await
            .identity_service
            .set_current_company_identity(&node_id)
            .await?;
        return Ok(());
    }

    // otherwise, return an error
    Err(Error::Validation(ValidationError::UnknownNodeId(node_id.to_string())).into())
}

#[frb]
pub async fn seed_backup() -> Result<SeedPhrase, EbillFfiError> {
    let seed_phrase = get_ctx().await.identity_service.get_seedphrase().await?;
    Ok(SeedPhrase { seed_phrase })
}

#[frb]
pub async fn seed_recover(seed_phrase_payload: SeedPhrase) -> Result<(), EbillFfiError> {
    let context = get_ctx().await;
    context
        .identity_service
        .recover_from_seedphrase(&seed_phrase_payload.seed_phrase)
        .await?;

    let keys = context.identity_service.get_keys().await?;
    let recovery_service = create_restore_account_service(
        &context.cfg,
        &keys,
        context.chain_key_service.clone(),
        context.contact_service.clone(),
        context.push_service.clone(),
        context.mint_client.clone(),
    )
    .await?;
    recovery_service.restore_account().await?;
    Ok(())
}

#[frb]
pub async fn share_contact_details(share_contact_to: ShareContactTo) -> Result<(), EbillFfiError> {
    let node_id =
        NodeId::from_str(&share_contact_to.recipient).map_err(ProtocolValidationError::from)?;
    get_ctx()
        .await
        .identity_service
        .share_contact_details(&node_id)
        .await?;
    Ok(())
}

#[frb]
pub async fn dev_mode_get_full_identity_chain() -> Result<Vec<String>, EbillFfiError> {
    let plaintext_chain = get_ctx()
        .await
        .identity_service
        .dev_mode_get_full_identity_chain()
        .await?;
    let json_string_chain: Result<Vec<String>, EbillFfiError> = plaintext_chain
        .into_iter()
        .map(|plaintext_block| {
            plaintext_block
                .to_json_text()
                .map_err(|e| EbillFfiError::from(Error::Protocol(e.into())))
        })
        .collect();

    json_string_chain
}

#[frb]
pub async fn sync_identity_chain() -> Result<(), EbillFfiError> {
    get_ctx()
        .await
        .transport_service
        .block_transport()
        .resync_identity_chain()
        .await?;
    Ok(())
}

#[frb]
pub async fn confirm_email(payload: ConfirmEmailPayload) -> Result<(), EbillFfiError> {
    let parsed_email = Email::new(payload.email)?;
    get_ctx()
        .await
        .identity_service
        .confirm_email(&parsed_email)
        .await?;
    Ok(())
}

#[frb]
pub async fn verify_email(payload: VerifyEmailPayload) -> Result<(), EbillFfiError> {
    get_ctx()
        .await
        .identity_service
        .verify_email(&payload.confirmation_code)
        .await?;
    Ok(())
}

#[frb]
pub async fn get_email_confirmations() -> Result<Vec<IdentityEmailConfirmationFfi>, EbillFfiError> {
    let email_confirmations = get_ctx()
        .await
        .identity_service
        .get_email_confirmations()
        .await?;
    Ok(email_confirmations
        .into_iter()
        .map(|ec| ec.into())
        .collect())
}

#[frb(ignore)]
pub async fn get_current_identity() -> Result<ActiveIdentityState, EbillFfiError> {
    let active_identity = get_ctx()
        .await
        .identity_service
        .get_current_identity()
        .await?;
    Ok(active_identity)
}

#[frb(ignore)]
pub async fn get_current_identity_node_id() -> Result<NodeId, EbillFfiError> {
    let current_identity = get_current_identity().await?;
    match current_identity.company {
        None => Ok(current_identity.personal),
        Some(company_node_id) => Ok(company_node_id),
    }
}
