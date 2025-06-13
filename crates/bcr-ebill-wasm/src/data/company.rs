use bcr_ebill_api::{
    data::{
        NodeId,
        company::Company,
        contact::{Contact, ContactType},
    },
    util::ValidationError,
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

use super::{FileWeb, OptionalPostalAddressWeb, PostalAddressWeb, contact::ContactTypeWeb};

#[derive(Tsify, Debug, Serialize)]
#[tsify(into_wasm_abi)]
pub struct CompaniesResponse {
    pub companies: Vec<CompanyWeb>,
}

#[derive(Tsify, Debug, Serialize, Deserialize, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct CompanyWeb {
    #[tsify(type = "string")]
    pub id: NodeId,
    pub name: String,
    pub country_of_registration: Option<String>,
    pub city_of_registration: Option<String>,
    pub postal_address: PostalAddressWeb,
    pub email: String,
    pub registration_number: Option<String>,
    pub registration_date: Option<String>,
    pub proof_of_registration_file: Option<FileWeb>,
    pub logo_file: Option<FileWeb>,
    #[tsify(type = "string[]")]
    pub signatories: Vec<NodeId>,
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
            signatories: val.signatories,
        }
    }
}

#[derive(Tsify, Debug, Deserialize, Clone)]
#[tsify(from_wasm_abi)]
pub struct CreateCompanyPayload {
    pub name: String,
    pub country_of_registration: Option<String>,
    pub city_of_registration: Option<String>,
    pub postal_address: PostalAddressWeb,
    pub email: String,
    pub registration_number: Option<String>,
    pub registration_date: Option<String>,
    pub proof_of_registration_file_upload_id: Option<String>,
    pub logo_file_upload_id: Option<String>,
}

#[derive(Tsify, Debug, Deserialize, Clone)]
#[tsify(from_wasm_abi)]
pub struct EditCompanyPayload {
    #[tsify(type = "string")]
    pub id: NodeId,
    pub name: Option<String>,
    pub email: Option<String>,
    pub postal_address: OptionalPostalAddressWeb,
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
    pub name: String,
    pub postal_address: PostalAddressWeb,
    pub avatar_file: Option<FileWeb>,
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
            postal_address: value
                .postal_address
                .ok_or(ValidationError::InvalidContact(value.node_id.to_string()))
                .map(|pa| pa.into())?,
            avatar_file: value.avatar_file.map(|f| f.into()),
        })
    }
}
