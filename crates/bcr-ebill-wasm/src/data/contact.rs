use bcr_ebill_api::{
    data::contact::{Contact, ContactType},
    service::Error,
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

use super::{FileWeb, OptionalPostalAddressWeb, PostalAddressWeb};

#[derive(Tsify, Debug, Serialize)]
#[tsify(into_wasm_abi)]
pub struct ContactsResponse {
    pub contacts: Vec<ContactWeb>,
}

#[derive(Tsify, Debug, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct NewContactPayload {
    pub t: u64,
    pub node_id: String,
    pub name: String,
    pub email: Option<String>,
    pub postal_address: Option<PostalAddressWeb>,
    pub date_of_birth_or_registration: Option<String>,
    pub country_of_birth_or_registration: Option<String>,
    pub city_of_birth_or_registration: Option<String>,
    pub identification_number: Option<String>,
    pub avatar_file_upload_id: Option<String>,
    pub proof_document_file_upload_id: Option<String>,
}

#[derive(Tsify, Debug, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct EditContactPayload {
    pub node_id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub postal_address: OptionalPostalAddressWeb,
    pub date_of_birth_or_registration: Option<String>,
    pub country_of_birth_or_registration: Option<String>,
    pub city_of_birth_or_registration: Option<String>,
    pub identification_number: Option<String>,
    pub avatar_file_upload_id: Option<String>,
    pub proof_document_file_upload_id: Option<String>,
}

#[wasm_bindgen]
#[repr(u8)]
#[derive(
    Debug, Copy, Clone, serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Eq,
)]
pub enum ContactTypeWeb {
    Person = 0,
    Company = 1,
    Anon = 2,
}

impl TryFrom<u64> for ContactTypeWeb {
    type Error = Error;

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        Ok(ContactType::try_from(value)
            .map_err(Self::Error::Validation)?
            .into())
    }
}

impl From<ContactType> for ContactTypeWeb {
    fn from(val: ContactType) -> Self {
        match val {
            ContactType::Person => ContactTypeWeb::Person,
            ContactType::Company => ContactTypeWeb::Company,
            ContactType::Anon => ContactTypeWeb::Anon,
        }
    }
}

impl From<ContactTypeWeb> for ContactType {
    fn from(value: ContactTypeWeb) -> Self {
        match value {
            ContactTypeWeb::Person => ContactType::Person,
            ContactTypeWeb::Company => ContactType::Company,
            ContactTypeWeb::Anon => ContactType::Anon,
        }
    }
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct ContactWeb {
    pub t: ContactTypeWeb,
    pub node_id: String,
    pub name: String,
    pub email: Option<String>,
    pub postal_address: Option<PostalAddressWeb>,
    pub date_of_birth_or_registration: Option<String>,
    pub country_of_birth_or_registration: Option<String>,
    pub city_of_birth_or_registration: Option<String>,
    pub identification_number: Option<String>,
    pub avatar_file: Option<FileWeb>,
    pub proof_document_file: Option<FileWeb>,
    pub nostr_relays: Vec<String>,
}

impl From<Contact> for ContactWeb {
    fn from(val: Contact) -> Self {
        ContactWeb {
            t: val.t.into(),
            node_id: val.node_id,
            name: val.name,
            email: val.email,
            postal_address: val.postal_address.map(|pa| pa.into()),
            date_of_birth_or_registration: val.date_of_birth_or_registration,
            country_of_birth_or_registration: val.country_of_birth_or_registration,
            city_of_birth_or_registration: val.city_of_birth_or_registration,
            identification_number: val.identification_number,
            avatar_file: val.avatar_file.map(|f| f.into()),
            proof_document_file: val.proof_document_file.map(|f| f.into()),
            nostr_relays: val.nostr_relays,
        }
    }
}
