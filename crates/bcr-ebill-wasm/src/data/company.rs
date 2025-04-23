use bcr_ebill_api::{
    data::{
        company::Company,
        contact::{Contact, ContactType},
    },
    util::ValidationError,
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

use super::{
    FileWeb, IntoWeb, OptionalPostalAddressWeb, PostalAddressWeb, contact::ContactTypeWeb,
};

#[derive(Tsify, Debug, Serialize)]
#[tsify(into_wasm_abi)]
pub struct CompaniesResponse {
    pub companies: Vec<CompanyWeb>,
}

#[derive(Tsify, Debug, Serialize, Deserialize, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct CompanyWeb {
    pub id: String,
    pub name: String,
    pub country_of_registration: Option<String>,
    pub city_of_registration: Option<String>,
    pub postal_address: PostalAddressWeb,
    pub email: String,
    pub registration_number: Option<String>,
    pub registration_date: Option<String>,
    pub proof_of_registration_file: Option<FileWeb>,
    pub logo_file: Option<FileWeb>,
    pub signatories: Vec<String>,
}

impl IntoWeb<CompanyWeb> for Company {
    fn into_web(self) -> CompanyWeb {
        CompanyWeb {
            id: self.id,
            name: self.name,
            country_of_registration: self.country_of_registration,
            city_of_registration: self.city_of_registration,
            postal_address: self.postal_address.into_web(),
            email: self.email,
            registration_number: self.registration_number,
            registration_date: self.registration_date,
            proof_of_registration_file: self.proof_of_registration_file.map(|f| f.into_web()),
            logo_file: self.logo_file.map(|f| f.into_web()),
            signatories: self.signatories,
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
    pub id: String,
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
    pub id: String,
    pub signatory_node_id: String,
}

#[derive(Tsify, Debug, Deserialize, Clone)]
#[tsify(from_wasm_abi)]
pub struct RemoveSignatoryPayload {
    pub id: String,
    pub signatory_node_id: String,
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
    pub node_id: String,
    pub name: String,
    pub postal_address: PostalAddressWeb,
    pub avatar_file: Option<FileWeb>,
}

impl TryFrom<Contact> for SignatoryResponse {
    type Error = ValidationError;

    fn try_from(value: Contact) -> Result<Self, Self::Error> {
        if value.t == ContactType::Anon {
            return Err(ValidationError::InvalidContact(value.node_id));
        }
        Ok(Self {
            t: value.t.into_web(),
            node_id: value.node_id.clone(),
            name: value.name,
            postal_address: value
                .postal_address
                .ok_or(ValidationError::InvalidContact(value.node_id))
                .map(|pa| pa.into_web())?,
            avatar_file: value.avatar_file.map(|f| f.into_web()),
        })
    }
}
