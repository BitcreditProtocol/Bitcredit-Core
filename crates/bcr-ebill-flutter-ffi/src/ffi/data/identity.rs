use crate::ffi::data::EditOptionalFieldModeFfi;

use super::CreateOptionalPostalAddressFfi;
use bcr_ebill_api::service::Error;
use bcr_ebill_core::{
    application::{
        ValidationError,
        identity::{Identity, SwitchIdentityType},
    },
    protocol::{EmailIdentityProofData, SignedIdentityProof, blockchain::identity::IdentityType},
};
use flutter_rust_bridge::frb;

use super::{FileFfi, OptionalPostalAddressFfi};

#[derive(Debug)]
pub struct SwitchIdentity {
    pub t: Option<SwitchIdentityTypeFfi>,
    pub node_id: String,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchIdentityTypeFfi {
    Person = 0,
    Company = 1,
}

impl From<SwitchIdentityType> for SwitchIdentityTypeFfi {
    fn from(val: SwitchIdentityType) -> Self {
        match val {
            SwitchIdentityType::Person => SwitchIdentityTypeFfi::Person,
            SwitchIdentityType::Company => SwitchIdentityTypeFfi::Company,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IdentityTypeFfi {
    Ident = 0,
    Anon = 1,
}

impl TryFrom<u64> for IdentityTypeFfi {
    type Error = Error;

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        Ok(IdentityType::try_from(value)
            .map_err(|e| Self::Error::Validation(ValidationError::Protocol(e)))?
            .into())
    }
}

impl From<IdentityType> for IdentityTypeFfi {
    fn from(val: IdentityType) -> Self {
        match val {
            IdentityType::Ident => IdentityTypeFfi::Ident,
            IdentityType::Anon => IdentityTypeFfi::Anon,
        }
    }
}

impl From<IdentityTypeFfi> for IdentityType {
    fn from(value: IdentityTypeFfi) -> Self {
        match value {
            IdentityTypeFfi::Ident => IdentityType::Ident,
            IdentityTypeFfi::Anon => IdentityType::Anon,
        }
    }
}

#[derive(Debug)]
pub struct NewIdentityPayload {
    pub t: u64,
    pub name: String,
    pub email: Option<String>,
    pub postal_address: CreateOptionalPostalAddressFfi,
    pub date_of_birth: Option<String>,
    pub country_of_birth: Option<String>,
    pub city_of_birth: Option<String>,
    pub identification_number: Option<String>,
    pub profile_picture_file_upload_id: Option<String>,
    pub identity_document_file_upload_id: Option<String>,
}

#[derive(Debug)]
pub struct ChangeIdentityPayload {
    pub name: Option<String>,
    pub postal_address_country: Option<String>,
    pub postal_address_city: Option<String>,
    pub postal_address_zip: EditOptionalFieldModeFfi,
    pub postal_address_address: Option<String>,
    pub date_of_birth: EditOptionalFieldModeFfi,
    pub country_of_birth: EditOptionalFieldModeFfi,
    pub city_of_birth: EditOptionalFieldModeFfi,
    pub identification_number: EditOptionalFieldModeFfi,
    pub profile_picture_file_upload_id: EditOptionalFieldModeFfi,
    pub identity_document_file_upload_id: EditOptionalFieldModeFfi,
}

#[derive(Debug)]
pub struct ConfirmEmailPayload {
    pub email: String,
}

#[derive(Debug)]
pub struct VerifyEmailPayload {
    pub confirmation_code: String,
}

#[derive(Debug)]
pub struct ChangeIdentityEmailPayload {
    pub email: String,
}

#[derive(Debug)]
pub struct IdentityFfi {
    pub t: IdentityTypeFfi,
    pub node_id: String,
    pub name: String,
    pub email: Option<String>,
    pub bitcoin_public_key: String,
    pub npub: String,
    pub postal_address: OptionalPostalAddressFfi,
    pub date_of_birth: Option<String>,
    pub country_of_birth: Option<String>,
    pub city_of_birth: Option<String>,
    pub identification_number: Option<String>,
    pub profile_picture_file: Option<FileFfi>,
    pub identity_document_file: Option<FileFfi>,
    pub nostr_relays: Vec<String>,
}

impl IdentityFfi {
    #[frb(ignore)]
    pub fn from_identity(identity: Identity) -> Self {
        Self {
            t: identity.t.into(),
            node_id: identity.node_id.to_string(),
            name: identity.name.to_string(),
            email: identity.email.map(|i| i.to_string()),
            bitcoin_public_key: identity.node_id.pub_key().to_string(),
            npub: identity.node_id.npub().to_string(),
            postal_address: identity.postal_address.into(),
            date_of_birth: identity.date_of_birth.map(|i| i.to_string()),
            country_of_birth: identity.country_of_birth.map(|i| i.to_string()),
            city_of_birth: identity.city_of_birth.map(|i| i.to_string()),
            identification_number: identity.identification_number.map(|i| i.to_string()),
            profile_picture_file: identity.profile_picture_file.map(|f| f.into()),
            identity_document_file: identity.identity_document_file.map(|f| f.into()),
            nostr_relays: identity
                .nostr_relays
                .into_iter()
                .map(|nr| nr.to_string())
                .collect(),
        }
    }
}

/// Response for a private key seeed backup
#[derive(Debug)]
pub struct SeedPhrase {
    /// The seed phrase of the current private key
    pub seed_phrase: String,
}

#[derive(Debug)]
pub struct ShareContactTo {
    /// The node id of the identity to share the contact details to
    pub recipient: String,
}

#[derive(Debug)]
pub struct ShareCompanyContactTo {
    /// The node id of the identity to share the contact details to
    pub recipient: String,

    /// The node id of the company to share the contact details for
    pub company_id: String,
}

#[derive(Debug, Clone)]
pub struct IdentityEmailConfirmationFfi {
    pub signature: String,
    pub witness: String,
    pub node_id: String,
    pub company_node_id: Option<String>,
    pub email: String,
    pub created_at: u64,
}

impl From<(SignedIdentityProof, EmailIdentityProofData)> for IdentityEmailConfirmationFfi {
    fn from((proof, data): (SignedIdentityProof, EmailIdentityProofData)) -> Self {
        Self {
            signature: proof.signature.to_string(),
            witness: proof.witness.to_string(),
            node_id: data.node_id.to_string(),
            company_node_id: data.company_node_id.map(|c| c.to_string()),
            email: data.email.to_string(),
            created_at: data.created_at.inner(),
        }
    }
}
