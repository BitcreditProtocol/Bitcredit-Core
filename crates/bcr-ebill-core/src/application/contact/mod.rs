use crate::application::ValidationError;
use crate::protocol::blockchain::bill::block::{
    BillAnonParticipantBlockData, BillIdentParticipantBlockData, BillParticipantBlockData,
    ContactType,
};
use crate::protocol::blockchain::bill::participant::{
    BillAnonParticipant, BillIdentParticipant, BillParticipant,
};
use crate::protocol::blockchain::identity::IdentityType;
use crate::protocol::{
    City, Country, Date, Email, File, Identification, Name, PostalAddress, ProtocolValidationError,
};

use super::{company::Company, identity::Identity};
use serde::{Deserialize, Serialize};

use bcr_common::core::NodeId;

pub mod validation;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    #[serde(rename = "type")]
    pub t: ContactType,
    pub node_id: NodeId,
    pub name: Name,
    pub email: Option<Email>, // optional for anon only
    #[serde(flatten)]
    pub postal_address: Option<PostalAddress>, // optional for anon only
    pub date_of_birth_or_registration: Option<Date>,
    pub country_of_birth_or_registration: Option<Country>,
    pub city_of_birth_or_registration: Option<City>,
    pub identification_number: Option<Identification>,
    pub avatar_file: Option<File>,
    pub proof_document_file: Option<File>,
    pub nostr_relays: Vec<url::Url>,
    pub is_logical: bool, // indicates that this contact is just a nostr contact
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum LightBillParticipant {
    Anon(LightBillAnonParticipant),
    Ident(LightBillIdentParticipantWithAddress),
}

impl LightBillParticipant {
    pub fn node_id(&self) -> NodeId {
        match self {
            LightBillParticipant::Ident(data) => data.node_id.clone(),
            LightBillParticipant::Anon(data) => data.node_id.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LightBillAnonParticipant {
    pub node_id: NodeId,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LightBillIdentParticipant {
    #[serde(rename = "type")]
    pub t: ContactType,
    pub name: Name,
    pub node_id: NodeId,
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

impl From<BillIdentParticipantBlockData> for LightBillIdentParticipantWithAddress {
    fn from(value: BillIdentParticipantBlockData) -> Self {
        Self {
            t: value.t,
            name: value.name,
            node_id: value.node_id,
            postal_address: value.postal_address,
        }
    }
}

impl From<BillParticipantBlockData> for LightBillParticipant {
    fn from(value: BillParticipantBlockData) -> Self {
        match value {
            BillParticipantBlockData::Anon(data) => LightBillParticipant::Anon(data.into()),
            BillParticipantBlockData::Ident(data) => LightBillParticipant::Ident(data.into()),
        }
    }
}
impl From<BillAnonParticipantBlockData> for LightBillAnonParticipant {
    fn from(value: BillAnonParticipantBlockData) -> Self {
        Self {
            node_id: value.node_id,
        }
    }
}

impl From<BillIdentParticipantBlockData> for LightBillIdentParticipant {
    fn from(value: BillIdentParticipantBlockData) -> Self {
        Self {
            t: value.t,
            name: value.name,
            node_id: value.node_id,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LightBillIdentParticipantWithAddress {
    #[serde(rename = "type")]
    pub t: ContactType,
    pub name: Name,
    pub node_id: NodeId,
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
                    .ok_or(ValidationError::InvalidContact(value.node_id.to_string()))?,
                email: value.email,
                nostr_relays: value.nostr_relays,
            }),
            ContactType::Anon => Err(ValidationError::ContactIsAnonymous(
                value.node_id.to_string(),
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
                        .ok_or(ValidationError::InvalidContact(value.node_id.to_string()))?,
                    email: value.email,
                    nostr_relays: value.nostr_relays,
                }))
            }
            ContactType::Anon => Ok(BillParticipant::Anon(BillAnonParticipant {
                node_id: value.node_id.clone(),
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
            return Err(ProtocolValidationError::IdentityCantBeAnon.into());
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
            None => Err(ProtocolValidationError::IdentityCantBeAnon.into()),
        }
    }
}

impl BillAnonParticipant {
    pub fn new(identity: Identity) -> Self {
        Self {
            node_id: identity.node_id,
            nostr_relays: identity.nostr_relays,
        }
    }
}
