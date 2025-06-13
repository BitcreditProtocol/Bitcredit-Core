use crate::{ValidationError, identity::IdentityType};

use super::{File, PostalAddress, company::Company, identity::Identity};
use borsh_derive::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

pub mod validation;

#[repr(u8)]
#[derive(
    Debug,
    Clone,
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    Default,
)]
#[borsh(use_discriminant = true)]
pub enum ContactType {
    #[default]
    Person = 0,
    Company = 1,
    Anon = 2,
}

impl TryFrom<u64> for ContactType {
    type Error = ValidationError;

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(ContactType::Person),
            1 => Ok(ContactType::Company),
            2 => Ok(ContactType::Anon),
            _ => Err(ValidationError::InvalidContactType),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    #[serde(rename = "type")]
    pub t: ContactType,
    pub node_id: String,
    pub name: String,
    pub email: Option<String>, // optional for anon only
    #[serde(flatten)]
    pub postal_address: Option<PostalAddress>, // optional for anon only
    pub date_of_birth_or_registration: Option<String>,
    pub country_of_birth_or_registration: Option<String>,
    pub city_of_birth_or_registration: Option<String>,
    pub identification_number: Option<String>,
    pub avatar_file: Option<File>,
    pub proof_document_file: Option<File>,
    pub nostr_relays: Vec<String>,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum BillParticipant {
    Anon(BillAnonParticipant),
    Ident(BillIdentParticipant),
}

impl Default for BillParticipant {
    fn default() -> Self {
        Self::Ident(BillIdentParticipant::default())
    }
}

impl BillParticipant {
    pub fn node_id(&self) -> String {
        match self {
            BillParticipant::Ident(data) => data.node_id.clone(),
            BillParticipant::Anon(data) => data.node_id.clone(),
        }
    }

    pub fn postal_address(&self) -> Option<PostalAddress> {
        match self {
            BillParticipant::Ident(data) => Some(data.postal_address.clone()),
            BillParticipant::Anon(_) => None,
        }
    }

    pub fn name(&self) -> Option<String> {
        match self {
            BillParticipant::Ident(data) => Some(data.name.to_owned()),
            BillParticipant::Anon(_) => None,
        }
    }

    pub fn email(&self) -> Option<String> {
        match self {
            BillParticipant::Ident(data) => data.email.to_owned(),
            BillParticipant::Anon(data) => data.email.to_owned(),
        }
    }

    pub fn nostr_relays(&self) -> Vec<String> {
        match self {
            BillParticipant::Ident(data) => data.nostr_relays.to_owned(),
            BillParticipant::Anon(data) => data.nostr_relays.to_owned(),
        }
    }

    /// Returns an anon version of the given participant
    pub fn as_anon(&self) -> Self {
        match self {
            BillParticipant::Ident(identified) => {
                let anon: BillAnonParticipant = identified.clone().into();
                BillParticipant::Anon(anon)
            }
            BillParticipant::Anon(anon) => BillParticipant::Anon(anon.clone()),
        }
    }
}

#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default,
)]
pub struct BillAnonParticipant {
    /// The node id of the participant
    pub node_id: String,
    /// email address of the participant
    pub email: Option<String>,
    /// The preferred Nostr relay to deliver Nostr messages to
    pub nostr_relays: Vec<String>,
}

impl From<BillIdentParticipant> for BillAnonParticipant {
    fn from(value: BillIdentParticipant) -> Self {
        Self {
            node_id: value.node_id,
            email: value.email,
            nostr_relays: value.nostr_relays,
        }
    }
}

impl From<BillParticipant> for BillAnonParticipant {
    fn from(value: BillParticipant) -> Self {
        match value {
            BillParticipant::Ident(data) => data.into(),
            BillParticipant::Anon(data) => data,
        }
    }
}

#[derive(
    BorshSerialize, BorshDeserialize, Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default,
)]
pub struct BillIdentParticipant {
    /// The type of identity (0 = person, 1 = company)
    #[serde(rename = "type")]
    pub t: ContactType,
    /// The node id of the identity
    pub node_id: String,
    /// The name of the identity
    pub name: String,
    /// Full postal address of the identity
    #[serde(flatten)]
    pub postal_address: PostalAddress,
    /// email address of the identity
    pub email: Option<String>,
    /// The preferred Nostr relay to deliver Nostr messages to
    pub nostr_relays: Vec<String>,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Serialize, Deserialize, Clone)]
pub enum LightBillParticipant {
    Anon(LightBillAnonParticipant),
    Ident(LightBillIdentParticipant),
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Serialize, Deserialize, Clone, Default)]
pub struct LightBillAnonParticipant {
    pub node_id: String,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Serialize, Deserialize, Clone, Default)]
pub struct LightBillIdentParticipant {
    #[serde(rename = "type")]
    pub t: ContactType,
    pub name: String,
    pub node_id: String,
}

impl From<BillParticipant> for LightBillParticipant {
    fn from(value: BillParticipant) -> Self {
        match value {
            BillParticipant::Ident(data) => LightBillParticipant::Ident(data.into()),
            BillParticipant::Anon(data) => LightBillParticipant::Anon(data.into()),
        }
    }
}

impl From<BillIdentParticipant> for LightBillIdentParticipant {
    fn from(value: BillIdentParticipant) -> Self {
        Self {
            t: value.t,
            name: value.name,
            node_id: value.node_id,
        }
    }
}

impl From<BillAnonParticipant> for LightBillAnonParticipant {
    fn from(value: BillAnonParticipant) -> Self {
        Self {
            node_id: value.node_id,
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Serialize, Deserialize, Clone, Default)]
pub struct LightBillIdentParticipantWithAddress {
    #[serde(rename = "type")]
    pub t: ContactType,
    pub name: String,
    pub node_id: String,
    #[serde(flatten)]
    pub postal_address: PostalAddress,
}

impl From<BillIdentParticipant> for LightBillIdentParticipantWithAddress {
    fn from(value: BillIdentParticipant) -> Self {
        Self {
            t: value.t,
            name: value.name,
            node_id: value.node_id,
            postal_address: value.postal_address,
        }
    }
}

impl TryFrom<Contact> for BillIdentParticipant {
    type Error = ValidationError;
    fn try_from(value: Contact) -> Result<Self, Self::Error> {
        match value.t {
            ContactType::Company | ContactType::Person => Ok(Self {
                t: value.t,
                node_id: value.node_id.clone(),
                name: value.name,
                postal_address: value
                    .postal_address
                    .ok_or(ValidationError::InvalidContact(value.node_id.to_owned()))?,
                email: value.email,
                nostr_relays: value.nostr_relays,
            }),
            ContactType::Anon => Err(ValidationError::ContactIsAnonymous(
                value.node_id.to_owned(),
            )),
        }
    }
}

impl TryFrom<Contact> for BillParticipant {
    type Error = ValidationError;
    fn try_from(value: Contact) -> Result<Self, Self::Error> {
        match value.t {
            ContactType::Company | ContactType::Person => {
                Ok(BillParticipant::Ident(BillIdentParticipant {
                    t: value.t,
                    node_id: value.node_id.clone(),
                    name: value.name,
                    postal_address: value
                        .postal_address
                        .ok_or(ValidationError::InvalidContact(value.node_id.to_owned()))?,
                    email: value.email,
                    nostr_relays: value.nostr_relays,
                }))
            }
            ContactType::Anon => Ok(BillParticipant::Anon(BillAnonParticipant {
                node_id: value.node_id.clone(),
                email: value.email,
                nostr_relays: value.nostr_relays,
            })),
        }
    }
}

impl From<Company> for BillIdentParticipant {
    fn from(value: Company) -> Self {
        Self {
            t: ContactType::Company,
            node_id: value.id.clone(),
            name: value.name,
            postal_address: value.postal_address,
            email: Some(value.email),
            nostr_relays: vec![],
        }
    }
}

impl BillIdentParticipant {
    pub fn new(identity: Identity) -> Result<Self, ValidationError> {
        if identity.t == IdentityType::Anon {
            return Err(ValidationError::IdentityCantBeAnon);
        }
        match identity.postal_address.to_full_postal_address() {
            Some(postal_address) => Ok(Self {
                t: ContactType::Person,
                node_id: identity.node_id,
                name: identity.name,
                postal_address,
                email: identity.email,
                nostr_relays: identity.nostr_relays,
            }),
            None => Err(ValidationError::IdentityIsNotBillIssuer),
        }
    }
}

impl BillAnonParticipant {
    pub fn new(identity: Identity) -> Self {
        Self {
            node_id: identity.node_id,
            email: identity.email,
            nostr_relays: identity.nostr_relays,
        }
    }
}
