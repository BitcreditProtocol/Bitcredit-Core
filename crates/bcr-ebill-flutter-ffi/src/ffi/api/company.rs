use crate::ffi::{
    context::get_ctx,
    data::{
        Base64FileResponse, BinaryFileResponse, PostalAddressFfi, UploadFile, UploadFileResponse,
        company::{
            AcceptCompanyInvitePayload, ChangeSignatoryEmailPayload, CompaniesResponse,
            CompanyConfirmEmailPayload, CompanyFfi, CompanyKeysFfi, CompanyVerifyEmailPayload,
            CreateCompanyPayload, EditCompanyPayload, InviteSignatoryPayload,
            ListSignatoriesResponse, LocallyHideSignatoryPayload, RemoveSignatoryPayload,
            ResyncCompanyPayload, SignatoryResponse,
        },
        identity::{IdentityEmailConfirmationFfi, ShareCompanyContactTo},
    },
    error::EbillFfiError,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bcr_common::core::NodeId;
use bcr_ebill_api::service::{
    Error,
    file_upload_service::{UploadFileHandler, detect_content_type_for_bytes},
};
use bcr_ebill_core::{
    application::company::CompanySignatory,
    protocol::{
        Address, City, Country, Date, Email, Identification, Name, PostalAddress,
        ProtocolValidationError, Timestamp, Zip,
    },
};
use flutter_rust_bridge::frb;
use std::str::FromStr;
use uuid::Uuid;

async fn get_file(id: &str, file_name: &Name) -> Result<(Vec<u8>, String), EbillFfiError> {
    let parsed_id = NodeId::from_str(id).map_err(ProtocolValidationError::from)?;
    let (company, keys) = get_ctx()
        .await
        .company_service
        .get_company_and_keys_by_id(&parsed_id)
        .await?; // check if company exists
    let private_key = keys.get_private_key();

    let file_bytes = get_ctx()
        .await
        .company_service
        .open_and_decrypt_file(company, &parsed_id, file_name, &private_key)
        .await?;

    let content_type = detect_content_type_for_bytes(&file_bytes).ok_or(Error::Validation(
        ProtocolValidationError::InvalidContentType.into(),
    ))?;
    Ok((file_bytes, content_type))
}

#[frb]
pub async fn file(id: &str, file_name: &str) -> Result<BinaryFileResponse, EbillFfiError> {
    let name = Name::new(file_name)?;
    let (file_bytes, content_type) = get_file(id, &name).await?;
    Ok(BinaryFileResponse {
        data: file_bytes,
        name: name.to_string(),
        content_type,
    })
}

#[frb]
pub async fn file_base64(id: &str, file_name: &str) -> Result<Base64FileResponse, EbillFfiError> {
    let name = Name::new(file_name)?;
    let (file_bytes, content_type) = get_file(id, &name).await?;

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
pub async fn list() -> Result<CompaniesResponse, EbillFfiError> {
    let mut companies = get_ctx()
        .await
        .company_service
        .get_list_of_companies()
        .await?;

    filter_hidden_signatories_for_companies(&mut companies).await?;

    Ok(CompaniesResponse {
        companies: companies.into_iter().map(|c| c.into()).collect(),
    })
}

#[frb]
pub async fn list_invites() -> Result<CompaniesResponse, EbillFfiError> {
    let mut companies = get_ctx()
        .await
        .company_service
        .get_active_company_invites()
        .await?;

    filter_hidden_signatories_for_companies(&mut companies).await?;

    Ok(CompaniesResponse {
        companies: companies.into_iter().map(|c| c.into()).collect(),
    })
}

#[frb]
pub async fn list_signatories(id: &str) -> Result<ListSignatoriesResponse, EbillFfiError> {
    let parsed_id = NodeId::from_str(id).map_err(ProtocolValidationError::from)?;
    let mut signatories_and_contacts = get_ctx()
        .await
        .company_service
        .list_signatories(&parsed_id)
        .await?;

    let mut signatories: Vec<CompanySignatory> = signatories_and_contacts
        .iter()
        .map(|(s, _)| s.clone())
        .collect();

    get_ctx()
        .await
        .company_service
        .filter_out_locally_hidden_signatories(&parsed_id, &mut signatories)
        .await?;

    signatories_and_contacts.retain(|(s, _)| {
        signatories
            .iter()
            .any(|filtered| filtered.node_id == s.node_id)
    });

    let signatories_and_contacts: Vec<SignatoryResponse> = signatories_and_contacts
        .into_iter()
        .map(|c| c.try_into())
        .collect::<std::result::Result<_, _>>()?;

    Ok(ListSignatoriesResponse {
        signatories: signatories_and_contacts,
    })
}

#[frb]
pub async fn detail(id: &str) -> Result<CompanyFfi, EbillFfiError> {
    let parsed_id = NodeId::from_str(id).map_err(ProtocolValidationError::from)?;
    let mut company = get_ctx()
        .await
        .company_service
        .get_company_by_id(&parsed_id)
        .await?;

    get_ctx()
        .await
        .company_service
        .filter_out_locally_hidden_signatories(&parsed_id, &mut company.signatories)
        .await?;

    Ok(company.into())
}

#[frb]
pub async fn create_keys() -> Result<CompanyKeysFfi, EbillFfiError> {
    let company_id = get_ctx()
        .await
        .company_service
        .create_company_keys()
        .await?;
    Ok(CompanyKeysFfi {
        id: company_id.to_string(),
    })
}

#[frb]
pub async fn create(company_payload: CreateCompanyPayload) -> Result<CompanyFfi, EbillFfiError> {
    let timestamp = Timestamp::now();

    let created_company = get_ctx()
        .await
        .company_service
        .create_company(
            NodeId::from_str(&company_payload.id).map_err(ProtocolValidationError::from)?,
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
            PostalAddress::try_from(PostalAddressFfi::try_from(company_payload.postal_address)?)?,
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
                    Uuid::from_str(&s).map_err(|_| ProtocolValidationError::InvalidFileUploadId)
                })
                .transpose()?,
            company_payload
                .logo_file_upload_id
                .map(|s| {
                    Uuid::from_str(&s).map_err(|_| ProtocolValidationError::InvalidFileUploadId)
                })
                .transpose()?,
            Email::new(company_payload.creator_email)?,
            timestamp,
        )
        .await?;

    Ok(created_company.into())
}

#[frb]
pub async fn edit(company_payload: EditCompanyPayload) -> Result<(), EbillFfiError> {
    let edit_country_of_registration = company_payload
        .country_of_registration
        .try_map(|c| Country::parse(&c))?;

    let edit_city_of_registration = company_payload.city_of_registration.try_map(City::new)?;

    let edit_registration_number = company_payload
        .registration_number
        .try_map(Identification::new)?;

    let edit_registration_date = company_payload.registration_date.try_map(Date::new)?;

    let edit_logo_file = company_payload.logo_file_upload_id.try_map(|s| {
        Uuid::from_str(&s).map_err(|_| ProtocolValidationError::InvalidFileUploadId)
    })?;

    let edit_proof_file = company_payload
        .proof_of_registration_file_upload_id
        .try_map(|s| {
            Uuid::from_str(&s).map_err(|_| ProtocolValidationError::InvalidFileUploadId)
        })?;

    let edit_zip = company_payload
        .postal_address_zip
        .try_map(|z| Zip::from_str(&z))?;

    let timestamp = Timestamp::now();
    get_ctx()
        .await
        .company_service
        .edit_company(
            &NodeId::from_str(&company_payload.id).map_err(ProtocolValidationError::from)?,
            company_payload.name.map(Name::new).transpose()?,
            company_payload.email.map(Email::new).transpose()?,
            company_payload
                .postal_address_country
                .map(|c| Country::parse(&c))
                .transpose()?,
            company_payload
                .postal_address_city
                .map(|c| City::from_str(&c))
                .transpose()?,
            edit_zip,
            company_payload
                .postal_address_address
                .map(|c| Address::from_str(&c))
                .transpose()?,
            edit_country_of_registration,
            edit_city_of_registration,
            edit_registration_number,
            edit_registration_date,
            edit_logo_file,
            edit_proof_file,
            timestamp,
        )
        .await?;
    Ok(())
}

#[frb]
pub async fn invite_signatory(
    company_payload: InviteSignatoryPayload,
) -> Result<(), EbillFfiError> {
    let timestamp = Timestamp::now();
    get_ctx()
        .await
        .company_service
        .invite_signatory(
            &NodeId::from_str(&company_payload.id).map_err(ProtocolValidationError::from)?,
            NodeId::from_str(&company_payload.signatory_node_id)
                .map_err(ProtocolValidationError::from)?,
            timestamp,
        )
        .await?;
    Ok(())
}

#[frb]
pub async fn remove_signatory(
    company_payload: RemoveSignatoryPayload,
) -> Result<(), EbillFfiError> {
    let timestamp = Timestamp::now();
    get_ctx()
        .await
        .company_service
        .remove_signatory(
            &NodeId::from_str(&company_payload.id).map_err(ProtocolValidationError::from)?,
            NodeId::from_str(&company_payload.signatory_node_id)
                .map_err(ProtocolValidationError::from)?,
            timestamp,
        )
        .await?;
    Ok(())
}

#[frb]
pub async fn share_contact_details(share_to: ShareCompanyContactTo) -> Result<(), EbillFfiError> {
    get_ctx()
        .await
        .company_service
        .share_contact_details(
            &NodeId::from_str(&share_to.recipient).map_err(ProtocolValidationError::from)?,
            NodeId::from_str(&share_to.company_id).map_err(ProtocolValidationError::from)?,
        )
        .await?;
    Ok(())
}

#[frb]
pub async fn dev_mode_get_full_company_chain(
    company_id: &str,
) -> Result<Vec<String>, EbillFfiError> {
    let parsed_company_id = NodeId::from_str(company_id).map_err(ProtocolValidationError::from)?;
    let plaintext_chain = get_ctx()
        .await
        .company_service
        .dev_mode_get_full_company_chain(&parsed_company_id)
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
pub async fn sync_company_chain(payload: ResyncCompanyPayload) -> Result<(), EbillFfiError> {
    get_ctx()
        .await
        .transport_service
        .block_transport()
        .resync_company_chain(
            &NodeId::from_str(&payload.node_id).map_err(ProtocolValidationError::from)?,
        )
        .await?;
    Ok(())
}

#[frb]
pub async fn change_signatory_email(
    payload: ChangeSignatoryEmailPayload,
) -> Result<(), EbillFfiError> {
    let parsed_email = Email::new(payload.email)?;
    let parsed_company_id = NodeId::from_str(&payload.id).map_err(ProtocolValidationError::from)?;

    get_ctx()
        .await
        .company_service
        .change_signatory_email(&parsed_company_id, &parsed_email)
        .await?;
    Ok(())
}

#[frb]
pub async fn confirm_email(payload: CompanyConfirmEmailPayload) -> Result<(), EbillFfiError> {
    let parsed_email = Email::new(payload.email)?;
    let parsed_company_id = NodeId::from_str(&payload.id).map_err(ProtocolValidationError::from)?;
    get_ctx()
        .await
        .company_service
        .confirm_email(&parsed_company_id, &parsed_email)
        .await?;
    Ok(())
}

#[frb]
pub async fn verify_email(payload: CompanyVerifyEmailPayload) -> Result<(), EbillFfiError> {
    let parsed_company_id = NodeId::from_str(&payload.id).map_err(ProtocolValidationError::from)?;
    get_ctx()
        .await
        .company_service
        .verify_email(&parsed_company_id, &payload.confirmation_code)
        .await?;
    Ok(())
}

#[frb]
pub async fn get_email_confirmations(
    company_id: &str,
) -> Result<Vec<IdentityEmailConfirmationFfi>, EbillFfiError> {
    let parsed_company_id = NodeId::from_str(company_id).map_err(ProtocolValidationError::from)?;
    let email_confirmations = get_ctx()
        .await
        .company_service
        .get_email_confirmations(&parsed_company_id)
        .await?;
    Ok(email_confirmations
        .into_iter()
        .map(|ec| ec.into())
        .collect())
}

#[frb]
pub async fn accept_invite(payload: AcceptCompanyInvitePayload) -> Result<(), EbillFfiError> {
    let parsed_email = Email::new(payload.email)?;
    let parsed_company_id = NodeId::from_str(&payload.id).map_err(ProtocolValidationError::from)?;
    let timestamp = Timestamp::now();
    get_ctx()
        .await
        .company_service
        .accept_company_invite(&parsed_company_id, &parsed_email, timestamp)
        .await?;
    Ok(())
}

#[frb]
pub async fn reject_invite(company_id: &str) -> Result<(), EbillFfiError> {
    let parsed_company_id = NodeId::from_str(company_id).map_err(ProtocolValidationError::from)?;
    let timestamp = Timestamp::now();
    get_ctx()
        .await
        .company_service
        .reject_company_invite(&parsed_company_id, timestamp)
        .await?;
    Ok(())
}

#[frb]
pub async fn locally_hide_signatory(
    payload: LocallyHideSignatoryPayload,
) -> Result<(), EbillFfiError> {
    let parsed_company_id = NodeId::from_str(&payload.id).map_err(ProtocolValidationError::from)?;
    let parsed_node_id =
        NodeId::from_str(&payload.signatory_node_id).map_err(ProtocolValidationError::from)?;
    get_ctx()
        .await
        .company_service
        .locally_hide_signatory(&parsed_company_id, &parsed_node_id)
        .await?;
    Ok(())
}

async fn filter_hidden_signatories_for_companies(
    companies: &mut [bcr_ebill_core::application::company::Company],
) -> Result<(), EbillFfiError> {
    for company in companies.iter_mut() {
        get_ctx()
            .await
            .company_service
            .filter_out_locally_hidden_signatories(&company.id, &mut company.signatories)
            .await?;
    }
    Ok(())
}
