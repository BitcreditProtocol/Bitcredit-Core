use base64::{Engine as _, engine::general_purpose::STANDARD};
use bcr_common::core::NodeId;
use bcr_ebill_api::service::{
    self,
    file_upload_service::{UploadFileHandler, detect_content_type_for_bytes},
};
use bcr_ebill_core::protocol::{
    Address, City, Country, Date, EditOptionalFieldMode, Email, Identification, Name,
    PostalAddress, ProtocolValidationError, Zip, blockchain::bill::ContactType,
};
use flutter_rust_bridge::frb;
use std::str::FromStr;
use uuid::Uuid;

use crate::ffi::{
    context::get_ctx,
    data::{
        Base64FileResponse, BinaryFileResponse, PostalAddressFfi, UploadFile, UploadFileResponse,
        contact::{
            ApproveContactSharePayload, ContactFfi, ContactTypeFfi, ContactsResponse,
            EditContactPayload, NewContactPayload, PendingContactShareFfi,
            PendingContactSharesResponse, SearchContactsPayload,
        },
    },
    error::EbillFfiError,
};

async fn get_file(node_id: &str, file_name: &Name) -> Result<(Vec<u8>, String), EbillFfiError> {
    let parsed_node_id = NodeId::from_str(node_id).map_err(ProtocolValidationError::from)?;
    let contact = get_ctx()
        .await
        .contact_service
        .get_contact(&parsed_node_id)
        .await?; // check if contact exists

    let private_key = get_ctx()
        .await
        .identity_service
        .get_full_identity()
        .await?
        .key_pair
        .get_private_key();

    let file_bytes = get_ctx()
        .await
        .contact_service
        .open_and_decrypt_file(contact, &parsed_node_id, file_name, &private_key)
        .await?;
    let content_type = detect_content_type_for_bytes(&file_bytes).ok_or(
        service::Error::Validation(ProtocolValidationError::InvalidContentType.into()),
    )?;
    Ok((file_bytes, content_type))
}

#[frb]
pub async fn file(node_id: &str, file_name: &str) -> Result<BinaryFileResponse, EbillFfiError> {
    let name = Name::new(file_name)?;
    let (file_bytes, content_type) = get_file(node_id, &name).await?;
    Ok(BinaryFileResponse {
        data: file_bytes,
        name: name.to_string(),
        content_type,
    })
}
#[frb]
pub async fn file_base64(
    node_id: &str,
    file_name: &str,
) -> Result<Base64FileResponse, EbillFfiError> {
    let name = Name::new(file_name)?;
    let (file_bytes, content_type) = get_file(node_id, &name).await?;

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
pub async fn list() -> Result<ContactsResponse, EbillFfiError> {
    let contacts = get_ctx().await.contact_service.get_contacts().await?;
    Ok(ContactsResponse {
        contacts: contacts.into_iter().map(|c| c.into()).collect(),
    })
}

#[frb]
pub async fn search(query: SearchContactsPayload) -> Result<ContactsResponse, EbillFfiError> {
    let contacts = get_ctx()
        .await
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

#[frb]
pub async fn detail(node_id: &str) -> Result<ContactFfi, EbillFfiError> {
    let parsed_node_id = NodeId::from_str(node_id).map_err(ProtocolValidationError::from)?;
    let contact: ContactFfi = get_ctx()
        .await
        .contact_service
        .get_contact(&parsed_node_id)
        .await?
        .into();
    Ok(contact)
}

#[frb]
pub async fn remove(node_id: &str) -> Result<(), EbillFfiError> {
    let parsed_node_id = NodeId::from_str(node_id).map_err(ProtocolValidationError::from)?;
    get_ctx()
        .await
        .contact_service
        .delete(&parsed_node_id)
        .await?;
    Ok(())
}

#[frb]
pub async fn deanonymize(contact_payload: NewContactPayload) -> Result<ContactFfi, EbillFfiError> {
    let contact = get_ctx()
        .await
        .contact_service
        .deanonymize_contact(
            &NodeId::from_str(&contact_payload.node_id).map_err(ProtocolValidationError::from)?,
            ContactType::from(ContactTypeFfi::try_from(contact_payload.t)?),
            Name::new(contact_payload.name)?,
            contact_payload.email.map(Email::new).transpose()?,
            contact_payload
                .postal_address
                .map(PostalAddressFfi::try_from)
                .transpose()?
                .map(PostalAddress::try_from)
                .transpose()?,
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
                    Uuid::from_str(&s).map_err(|_| ProtocolValidationError::InvalidFileUploadId)
                })
                .transpose()?,
            contact_payload
                .proof_document_file_upload_id
                .map(|s| {
                    Uuid::from_str(&s).map_err(|_| ProtocolValidationError::InvalidFileUploadId)
                })
                .transpose()?,
        )
        .await?;
    Ok(contact.into())
}

#[frb]
pub async fn create(contact_payload: NewContactPayload) -> Result<ContactFfi, EbillFfiError> {
    let contact = get_ctx()
        .await
        .contact_service
        .add_contact(
            &NodeId::from_str(&contact_payload.node_id).map_err(ProtocolValidationError::from)?,
            ContactType::from(ContactTypeFfi::try_from(contact_payload.t)?),
            Name::new(contact_payload.name)?,
            contact_payload.email.map(Email::new).transpose()?,
            contact_payload
                .postal_address
                .map(PostalAddressFfi::try_from)
                .transpose()?
                .map(PostalAddress::try_from)
                .transpose()?,
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
                    Uuid::from_str(&s).map_err(|_| ProtocolValidationError::InvalidFileUploadId)
                })
                .transpose()?,
            contact_payload
                .proof_document_file_upload_id
                .map(|s| {
                    Uuid::from_str(&s).map_err(|_| ProtocolValidationError::InvalidFileUploadId)
                })
                .transpose()?,
        )
        .await?;
    Ok(contact.into())
}

#[frb]
pub async fn edit(contact_payload: EditContactPayload) -> Result<(), EbillFfiError> {
    let edit_date_of_birth_or_registration: EditOptionalFieldMode<Date> = contact_payload
        .date_of_birth_or_registration
        .try_map(|v| Date::from_str(&v))?;

    let edit_country_of_birth_or_registration = contact_payload
        .country_of_birth_or_registration
        .try_map(|d| Country::parse(&d))?;

    let edit_city_of_birth_or_registration = contact_payload
        .city_of_birth_or_registration
        .try_map(|d| City::new(&d))?;

    let edit_identification_number = contact_payload
        .identification_number
        .try_map(|d| Identification::new(&d))?;

    let edit_avatar_file = contact_payload.avatar_file_upload_id.try_map(|s| {
        Uuid::from_str(&s).map_err(|_| ProtocolValidationError::InvalidFileUploadId)
    })?;

    let edit_proof_file: EditOptionalFieldMode<Uuid> = contact_payload
        .proof_document_file_upload_id
        .try_map(|v| Uuid::from_str(&v))
        .map_err(|_| ProtocolValidationError::InvalidFileUploadId)?;

    let edit_zip: EditOptionalFieldMode<Zip> = contact_payload
        .postal_address_zip
        .try_map(|z| Zip::from_str(&z))?;

    get_ctx()
        .await
        .contact_service
        .update_contact(
            &NodeId::from_str(&contact_payload.node_id).map_err(ProtocolValidationError::from)?,
            contact_payload.name.map(Name::new).transpose()?,
            contact_payload.email.map(Email::new).transpose()?,
            contact_payload
                .postal_address_country
                .map(|c| Country::parse(&c))
                .transpose()?,
            contact_payload
                .postal_address_city
                .map(|c| City::from_str(&c))
                .transpose()?,
            edit_zip,
            contact_payload
                .postal_address_address
                .map(|c| Address::from_str(&c))
                .transpose()?,
            edit_date_of_birth_or_registration,
            edit_country_of_birth_or_registration,
            edit_city_of_birth_or_registration,
            edit_identification_number,
            edit_avatar_file,
            edit_proof_file,
        )
        .await?;
    Ok(())
}

#[frb]
pub async fn list_pending_contact_shares(
    receiver_node_id: &str,
) -> Result<PendingContactSharesResponse, EbillFfiError> {
    let parsed_node_id = NodeId::from_str(receiver_node_id)
        .map_err(bcr_ebill_core::protocol::ProtocolValidationError::from)?;
    let pending_shares = get_ctx()
        .await
        .contact_service
        .list_pending_contact_shares(&parsed_node_id)
        .await?;
    Ok(PendingContactSharesResponse {
        pending_shares: pending_shares.into_iter().map(|ps| ps.into()).collect(),
    })
}

#[frb]
pub async fn get_pending_contact_share(
    id: &str,
) -> Result<Option<PendingContactShareFfi>, EbillFfiError> {
    let pending_share = get_ctx()
        .await
        .contact_service
        .get_pending_contact_share(id)
        .await?;
    Ok(pending_share.map(|ps| ps.into()))
}

#[frb]
pub async fn approve_contact_share(
    approve_payload: ApproveContactSharePayload,
) -> Result<(), EbillFfiError> {
    get_ctx()
        .await
        .contact_service
        .approve_contact_share(
            &approve_payload.pending_share_id,
            approve_payload.add_to_contacts,
            approve_payload.share_back,
        )
        .await?;
    Ok(())
}

#[frb]
pub async fn reject_contact_share(pending_share_id: &str) -> Result<(), EbillFfiError> {
    get_ctx()
        .await
        .contact_service
        .reject_contact_share(pending_share_id)
        .await?;
    Ok(())
}
