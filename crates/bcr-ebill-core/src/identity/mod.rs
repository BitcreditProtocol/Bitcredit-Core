use super::{File, OptionalPostalAddress};
use crate::{NodeId, ValidationError, util::BcrKeys};
use serde::{Deserialize, Serialize};

pub mod validation;

#[repr(u8)]
#[derive(Debug, Clone, serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Eq)]
pub enum SwitchIdentityType {
    Person = 0,
    Company = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Eq)]
pub enum IdentityType {
    Ident = 0,
    Anon = 1,
}

impl TryFrom<u64> for IdentityType {
    type Error = ValidationError;

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(IdentityType::Ident),
            1 => Ok(IdentityType::Anon),
            _ => Err(ValidationError::InvalidIdentityType),
        }
    }
}

#[derive(Clone, Debug)]
pub struct IdentityWithAll {
    pub identity: Identity,
    pub key_pair: BcrKeys,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Identity {
    #[serde(rename = "type")]
    pub t: IdentityType,
    pub node_id: NodeId,
    pub name: String,
    pub email: Option<String>,
    pub postal_address: OptionalPostalAddress,
    pub date_of_birth: Option<String>,
    pub country_of_birth: Option<String>,
    pub city_of_birth: Option<String>,
    pub identification_number: Option<String>,
    pub nostr_relays: Vec<String>,
    pub profile_picture_file: Option<File>,
    pub identity_document_file: Option<File>,
}

impl Identity {
    pub fn get_nostr_name(&self) -> String {
        self.name.clone()
    }
}

#[derive(Clone, Debug)]
pub struct ActiveIdentityState {
    pub personal: NodeId,
    pub company: Option<NodeId>,
}
