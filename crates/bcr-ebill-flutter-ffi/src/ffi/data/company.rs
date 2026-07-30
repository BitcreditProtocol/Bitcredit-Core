use bcr_ebill_core::{
    application::{
        ValidationError,
        company::{Company, CompanySignatory, CompanySignatoryStatus, CompanyStatus},
        contact::Contact,
    },
    protocol::blockchain::bill::block::ContactType,
};

use crate::ffi::data::{
    CreatePostalAddressFfi, EditOptionalFieldModeFfi, identity::IdentityEmailConfirmationFfi,
};

use super::{FileFfi, PostalAddressFfi, contact::ContactTypeFfi};

#[derive(Debug)]
pub struct CompaniesResponse {
    pub companies: Vec<CompanyFfi>,
}

#[derive(Debug, Clone)]
pub enum CompanyStatusFfi {
    Invited,
    Active,
    None,
}

impl From<CompanyStatus> for CompanyStatusFfi {
    fn from(value: CompanyStatus) -> Self {
        match value {
            CompanyStatus::Invited => CompanyStatusFfi::Invited,
            CompanyStatus::Active => CompanyStatusFfi::Active,
            CompanyStatus::None => CompanyStatusFfi::None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompanyFfi {
    pub id: String,
    pub name: String,
    pub country_of_registration: Option<String>,
    pub city_of_registration: Option<String>,
    pub postal_address: PostalAddressFfi,
    pub email: String,
    pub registration_number: Option<String>,
    pub registration_date: Option<String>,
    pub proof_of_registration_file: Option<FileFfi>,
    pub logo_file: Option<FileFfi>,
    pub signatories: Vec<CompanySignatoryFfi>,
    pub creation_time: u64,
    pub status: CompanyStatusFfi,
}

impl From<Company> for CompanyFfi {
    fn from(val: Company) -> Self {
        CompanyFfi {
            id: val.id.to_string(),
            name: val.name.to_string(),
            country_of_registration: val.country_of_registration.map(|c| c.to_string()),
            city_of_registration: val.city_of_registration.map(|c| c.to_string()),
            postal_address: val.postal_address.into(),
            email: val.email.to_string(),
            registration_number: val.registration_number.map(|c| c.to_string()),
            registration_date: val.registration_date.map(|c| c.to_string()),
            proof_of_registration_file: val.proof_of_registration_file.map(|f| f.into()),
            logo_file: val.logo_file.map(|f| f.into()),
            signatories: val.signatories.into_iter().map(|s| s.into()).collect(),
            creation_time: val.creation_time.inner(),
            status: val.status.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum CompanySignatoryStatusFfi {
    Invited {
        ts: u64,
        inviter: String,
    },
    InviteAccepted {
        ts: u64,
    },
    InviteRejected {
        ts: u64,
    },
    InviteAcceptedIdentityProven {
        ts: u64,
        confirmation: IdentityEmailConfirmationFfi,
    },
    Removed {
        ts: u64,
        remover: String,
    },
}

impl From<CompanySignatoryStatus> for CompanySignatoryStatusFfi {
    fn from(value: CompanySignatoryStatus) -> Self {
        match value {
            CompanySignatoryStatus::Invited { ts, inviter } => CompanySignatoryStatusFfi::Invited {
                ts: ts.inner(),
                inviter: inviter.to_string(),
            },
            CompanySignatoryStatus::InviteAccepted { ts } => {
                CompanySignatoryStatusFfi::InviteAccepted { ts: ts.inner() }
            }
            CompanySignatoryStatus::InviteRejected { ts } => {
                CompanySignatoryStatusFfi::InviteRejected { ts: ts.inner() }
            }
            CompanySignatoryStatus::InviteAcceptedIdentityProven { ts, data, proof } => {
                CompanySignatoryStatusFfi::InviteAcceptedIdentityProven {
                    ts: ts.inner(),
                    confirmation: (proof, data).into(),
                }
            }
            CompanySignatoryStatus::Removed { ts, remover } => CompanySignatoryStatusFfi::Removed {
                ts: ts.inner(),
                remover: remover.to_string(),
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompanySignatoryFfi {
    pub node_id: String,
    pub status: CompanySignatoryStatusFfi,
}

impl From<CompanySignatory> for CompanySignatoryFfi {
    fn from(value: CompanySignatory) -> Self {
        Self {
            node_id: value.node_id.to_string(),
            status: value.status.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompanyKeysFfi {
    pub id: String,
}

#[derive(Debug, Clone)]
pub struct CreateCompanyPayload {
    pub id: String,
    pub name: String,
    pub country_of_registration: Option<String>,
    pub city_of_registration: Option<String>,
    pub postal_address: CreatePostalAddressFfi,
    pub email: String,
    pub registration_number: Option<String>,
    pub registration_date: Option<String>,
    pub proof_of_registration_file_upload_id: Option<String>,
    pub logo_file_upload_id: Option<String>,
    pub creator_email: String,
}

#[derive(Debug, Clone)]
pub struct EditCompanyPayload {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub postal_address_country: Option<String>,
    pub postal_address_city: Option<String>,
    pub postal_address_zip: EditOptionalFieldModeFfi,
    pub postal_address_address: Option<String>,
    pub country_of_registration: EditOptionalFieldModeFfi,
    pub city_of_registration: EditOptionalFieldModeFfi,
    pub registration_number: EditOptionalFieldModeFfi,
    pub registration_date: EditOptionalFieldModeFfi,
    pub logo_file_upload_id: EditOptionalFieldModeFfi,
    pub proof_of_registration_file_upload_id: EditOptionalFieldModeFfi,
}

#[derive(Debug, Clone)]
pub struct InviteSignatoryPayload {
    pub id: String,
    pub signatory_node_id: String,
}

#[derive(Debug, Clone)]
pub struct RemoveSignatoryPayload {
    pub id: String,
    pub signatory_node_id: String,
}

#[derive(Debug, Clone)]
pub struct ListSignatoriesResponse {
    pub signatories: Vec<SignatoryResponse>,
}

#[derive(Debug, Clone)]
pub struct SignatoryResponse {
    pub t: ContactTypeFfi,
    pub node_id: String,
    pub name: String,
    pub postal_address: Option<PostalAddressFfi>,
    pub avatar_file: Option<FileFfi>,
    pub is_logical: bool,
    pub signatory: CompanySignatoryFfi,
}

impl TryFrom<(CompanySignatory, Contact)> for SignatoryResponse {
    type Error = ValidationError;

    fn try_from((signatory, contact): (CompanySignatory, Contact)) -> Result<Self, Self::Error> {
        if contact.t == ContactType::Anon {
            return Err(ValidationError::InvalidContact(contact.node_id.to_string()));
        }
        Ok(Self {
            t: contact.t.into(),
            node_id: contact.node_id.to_string(),
            name: contact.name.to_string(),
            postal_address: contact.postal_address.map(|pa| pa.into()),
            avatar_file: contact.avatar_file.map(|f| f.into()),
            is_logical: contact.is_logical,
            signatory: signatory.into(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ResyncCompanyPayload {
    pub node_id: String,
}

#[derive(Debug, Clone)]
pub struct ChangeSignatoryEmailPayload {
    pub id: String,
    pub email: String,
}

#[derive(Debug, Clone)]
pub struct CompanyConfirmEmailPayload {
    pub id: String,
    pub email: String,
}

#[derive(Debug, Clone)]
pub struct CompanyVerifyEmailPayload {
    pub id: String,
    pub confirmation_code: String,
}

#[derive(Debug, Clone)]
pub struct AcceptCompanyInvitePayload {
    pub id: String,
    pub email: String,
}

#[derive(Debug, Clone)]
pub struct LocallyHideSignatoryPayload {
    pub id: String,
    pub signatory_node_id: String,
}
