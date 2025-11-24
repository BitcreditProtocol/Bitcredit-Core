use bcr_common::core::NodeId;
use bcr_ebill_core::{
    application::{
        ValidationError,
        company::{Company, CompanySignatory},
        contact::Contact,
    },
    protocol::{
        City, Country, Date, Email, Identification, Name, blockchain::bill::block::ContactType,
    },
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

use crate::data::{CreateOptionalPostalAddressWeb, CreatePostalAddressWeb};

use super::{FileWeb, PostalAddressWeb, contact::ContactTypeWeb};

#[derive(Tsify, Debug, Serialize)]
#[tsify(into_wasm_abi)]
pub struct CompaniesResponse {
    pub companies: Vec<CompanyWeb>,
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct CompanyWeb {
    #[tsify(type = "string")]
    pub id: NodeId,
    #[tsify(type = "string")]
    pub name: Name,
    #[tsify(type = "string | undefined")]
    pub country_of_registration: Option<Country>,
    #[tsify(type = "string | undefined")]
    pub city_of_registration: Option<City>,
    pub postal_address: PostalAddressWeb,
    #[tsify(type = "string")]
    pub email: Email,
    #[tsify(type = "string | undefined")]
    pub registration_number: Option<Identification>,
    #[tsify(type = "string | undefined")]
    pub registration_date: Option<Date>,
    pub proof_of_registration_file: Option<FileWeb>,
    pub logo_file: Option<FileWeb>,
    #[tsify(type = "string[]")]
    pub signatories: Vec<CompanySignatoryWeb>,
}

impl From<Company> for CompanyWeb {
    fn from(val: Company) -> Self {
        CompanyWeb {
            id: val.id,
            name: val.name,
            country_of_registration: val.country_of_registration,
            city_of_registration: val.city_of_registration,
            postal_address: val.postal_address.into(),
            email: val.email,
            registration_number: val.registration_number,
            registration_date: val.registration_date,
            proof_of_registration_file: val.proof_of_registration_file.map(|f| f.into()),
            logo_file: val.logo_file.map(|f| f.into()),
            signatories: val.signatories.into_iter().map(|s| s.into()).collect(),
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct CompanySignatoryWeb {
    #[tsify(type = "string")]
    pub node_id: NodeId,
    #[tsify(type = "string")]
    pub email: Email,
}

impl From<CompanySignatory> for CompanySignatoryWeb {
    fn from(value: CompanySignatory) -> Self {
        Self {
            node_id: value.node_id,
            email: value.email,
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct CompanyKeysWeb {
    #[tsify(type = "string")]
    pub id: NodeId,
}

#[derive(Tsify, Debug, Deserialize, Clone)]
#[tsify(from_wasm_abi)]
pub struct CreateCompanyPayload {
    pub id: String,
    pub name: String,
    pub country_of_registration: Option<String>,
    pub city_of_registration: Option<String>,
    pub postal_address: CreatePostalAddressWeb,
    pub email: String,
    pub registration_number: Option<String>,
    pub registration_date: Option<String>,
    pub proof_of_registration_file_upload_id: Option<String>,
    pub logo_file_upload_id: Option<String>,
    pub creator_email: String,
}

#[derive(Tsify, Debug, Deserialize, Clone)]
#[tsify(from_wasm_abi)]
pub struct EditCompanyPayload {
    #[tsify(type = "string")]
    pub id: NodeId,
    pub name: Option<String>,
    pub email: Option<String>,
    pub postal_address: CreateOptionalPostalAddressWeb,
    pub country_of_registration: Option<String>,
    pub city_of_registration: Option<String>,
    pub registration_number: Option<String>,
    pub registration_date: Option<String>,
    pub logo_file_upload_id: Option<String>,
    pub proof_of_registration_file_upload_id: Option<String>,
}

#[derive(Tsify, Debug, Deserialize, Clone)]
#[tsify(from_wasm_abi)]
pub struct AddSignatoryPayload {
    #[tsify(type = "string")]
    pub id: NodeId,
    #[tsify(type = "string")]
    pub signatory_node_id: NodeId,
}

#[derive(Tsify, Debug, Deserialize, Clone)]
#[tsify(from_wasm_abi)]
pub struct RemoveSignatoryPayload {
    #[tsify(type = "string")]
    pub id: NodeId,
    #[tsify(type = "string")]
    pub signatory_node_id: NodeId,
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct ListSignatoriesResponse {
    pub signatories: Vec<SignatoryResponse>,
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct SignatoryResponse {
    pub t: ContactTypeWeb,
    #[tsify(type = "string")]
    pub node_id: NodeId,
    #[tsify(type = "string")]
    pub name: Name,
    pub postal_address: Option<PostalAddressWeb>,
    pub avatar_file: Option<FileWeb>,
    pub is_logical: bool,
}

impl TryFrom<Contact> for SignatoryResponse {
    type Error = ValidationError;

    fn try_from(value: Contact) -> Result<Self, Self::Error> {
        if value.t == ContactType::Anon {
            return Err(ValidationError::InvalidContact(value.node_id.to_string()));
        }
        Ok(Self {
            t: value.t.into(),
            node_id: value.node_id.clone(),
            name: value.name,
            postal_address: value.postal_address.map(|pa| pa.into()),
            avatar_file: value.avatar_file.map(|f| f.into()),
            is_logical: value.is_logical,
        })
    }
}

#[derive(Tsify, Debug, Clone, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct ResyncCompanyPayload {
    #[tsify(type = "string")]
    pub node_id: NodeId,
}

#[derive(Tsify, Debug, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct ChangeSignatoryEmailPayload {
    pub id: String,
    pub email: String,
}

#[derive(Tsify, Debug, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct ConfirmEmailPayload {
    pub id: String,
    pub email: String,
}

#[derive(Tsify, Debug, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct VerifyEmailPayload {
    pub id: String,
    pub confirmation_code: String,
}
