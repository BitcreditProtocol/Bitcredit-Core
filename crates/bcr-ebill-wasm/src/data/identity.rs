use bcr_ebill_api::{
    data::identity::{Identity, IdentityType, SwitchIdentityType},
    service::{Error, Result},
    util::BcrKeys,
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

use super::{FileWeb, FromWeb, IntoWeb, OptionalPostalAddressWeb};

#[derive(Tsify, Debug, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct SwitchIdentity {
    pub t: Option<SwitchIdentityTypeWeb>,
    pub node_id: String,
}

#[wasm_bindgen]
#[repr(u8)]
#[derive(
    Debug, Clone, Copy, serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Eq,
)]
pub enum SwitchIdentityTypeWeb {
    Person = 0,
    Company = 1,
}

impl IntoWeb<SwitchIdentityTypeWeb> for SwitchIdentityType {
    fn into_web(self) -> SwitchIdentityTypeWeb {
        match self {
            SwitchIdentityType::Person => SwitchIdentityTypeWeb::Person,
            SwitchIdentityType::Company => SwitchIdentityTypeWeb::Company,
        }
    }
}

#[wasm_bindgen]
#[repr(u8)]
#[derive(
    Debug, Copy, Clone, serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Eq,
)]
pub enum IdentityTypeWeb {
    Ident = 0,
    Anon = 1,
}

impl TryFrom<u64> for IdentityTypeWeb {
    type Error = Error;

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        Ok(IdentityType::try_from(value)
            .map_err(Self::Error::Validation)?
            .into_web())
    }
}

impl IntoWeb<IdentityTypeWeb> for IdentityType {
    fn into_web(self) -> IdentityTypeWeb {
        match self {
            IdentityType::Ident => IdentityTypeWeb::Ident,
            IdentityType::Anon => IdentityTypeWeb::Anon,
        }
    }
}

impl FromWeb<IdentityTypeWeb> for IdentityType {
    fn from_web(value: IdentityTypeWeb) -> Self {
        match value {
            IdentityTypeWeb::Ident => IdentityType::Ident,
            IdentityTypeWeb::Anon => IdentityType::Anon,
        }
    }
}

#[derive(Tsify, Debug, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct NewIdentityPayload {
    pub t: u64,
    pub name: String,
    pub email: Option<String>,
    pub postal_address: OptionalPostalAddressWeb,
    pub date_of_birth: Option<String>,
    pub country_of_birth: Option<String>,
    pub city_of_birth: Option<String>,
    pub identification_number: Option<String>,
    pub profile_picture_file_upload_id: Option<String>,
    pub identity_document_file_upload_id: Option<String>,
}

#[derive(Tsify, Debug, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct ChangeIdentityPayload {
    pub name: Option<String>,
    pub email: Option<String>,
    pub postal_address: OptionalPostalAddressWeb,
    pub date_of_birth: Option<String>,
    pub country_of_birth: Option<String>,
    pub city_of_birth: Option<String>,
    pub identification_number: Option<String>,
    pub profile_picture_file_upload_id: Option<String>,
    pub identity_document_file_upload_id: Option<String>,
}

#[derive(Tsify, Debug, Serialize)]
#[tsify(into_wasm_abi)]
pub struct IdentityWeb {
    pub t: IdentityTypeWeb,
    pub node_id: String,
    pub name: String,
    pub email: Option<String>,
    pub bitcoin_public_key: String,
    pub npub: String,
    pub postal_address: OptionalPostalAddressWeb,
    pub date_of_birth: Option<String>,
    pub country_of_birth: Option<String>,
    pub city_of_birth: Option<String>,
    pub identification_number: Option<String>,
    pub profile_picture_file: Option<FileWeb>,
    pub identity_document_file: Option<FileWeb>,
    pub nostr_relay: Option<String>,
}

impl IdentityWeb {
    pub fn from(identity: Identity, keys: BcrKeys) -> Result<Self> {
        Ok(Self {
            t: identity.t.into_web(),
            node_id: identity.node_id.clone(),
            name: identity.name,
            email: identity.email,
            bitcoin_public_key: identity.node_id.clone(),
            npub: keys.get_nostr_npub(),
            postal_address: identity.postal_address.into_web(),
            date_of_birth: identity.date_of_birth,
            country_of_birth: identity.country_of_birth,
            city_of_birth: identity.city_of_birth,
            identification_number: identity.identification_number,
            profile_picture_file: identity.profile_picture_file.map(|f| f.into_web()),
            identity_document_file: identity.identity_document_file.map(|f| f.into_web()),
            nostr_relay: identity.nostr_relay,
        })
    }
}

/// Response for a private key seeed backup
#[derive(Tsify, Debug, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct SeedPhrase {
    /// The seed phrase of the current private key
    pub seed_phrase: String,
}
