use bcr_ebill_api::{
    data::{
        NodeId, PublicKey,
        identity::{Identity, IdentityType, SwitchIdentityType},
        nostr_contact::NostrPublicKey,
    },
    service::{Error, Result},
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

use super::{FileWeb, OptionalPostalAddressWeb};

#[derive(Tsify, Debug, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct SwitchIdentity {
    pub t: Option<SwitchIdentityTypeWeb>,
    #[tsify(type = "string")]
    pub node_id: NodeId,
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

impl From<SwitchIdentityType> for SwitchIdentityTypeWeb {
    fn from(val: SwitchIdentityType) -> Self {
        match val {
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
            .into())
    }
}

impl From<IdentityType> for IdentityTypeWeb {
    fn from(val: IdentityType) -> Self {
        match val {
            IdentityType::Ident => IdentityTypeWeb::Ident,
            IdentityType::Anon => IdentityTypeWeb::Anon,
        }
    }
}

impl From<IdentityTypeWeb> for IdentityType {
    fn from(value: IdentityTypeWeb) -> Self {
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
    #[tsify(type = "string")]
    pub node_id: NodeId,
    pub name: String,
    pub email: Option<String>,
    #[tsify(type = "string")]
    pub bitcoin_public_key: PublicKey,
    #[tsify(type = "string")]
    pub npub: NostrPublicKey,
    pub postal_address: OptionalPostalAddressWeb,
    pub date_of_birth: Option<String>,
    pub country_of_birth: Option<String>,
    pub city_of_birth: Option<String>,
    pub identification_number: Option<String>,
    pub profile_picture_file: Option<FileWeb>,
    pub identity_document_file: Option<FileWeb>,
    pub nostr_relays: Vec<String>,
}

impl IdentityWeb {
    pub fn from(identity: Identity) -> Result<Self> {
        Ok(Self {
            t: identity.t.into(),
            node_id: identity.node_id.clone(),
            name: identity.name,
            email: identity.email,
            bitcoin_public_key: identity.node_id.pub_key(),
            npub: identity.node_id.npub(),
            postal_address: identity.postal_address.into(),
            date_of_birth: identity.date_of_birth,
            country_of_birth: identity.country_of_birth,
            city_of_birth: identity.city_of_birth,
            identification_number: identity.identification_number,
            profile_picture_file: identity.profile_picture_file.map(|f| f.into()),
            identity_document_file: identity.identity_document_file.map(|f| f.into()),
            nostr_relays: identity.nostr_relays,
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
