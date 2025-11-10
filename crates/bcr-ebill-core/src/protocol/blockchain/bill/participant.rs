use crate::protocol::blockchain::bill::block::{
    BillAnonParticipantBlockData, BillIdentParticipantBlockData, BillParticipantBlockData,
    BillSignatoryBlockData, ContactType,
};
use crate::protocol::{Email, Name, PostalAddress, Timestamp};

use serde::{Deserialize, Serialize};

use bcr_common::core::NodeId;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum BillParticipant {
    Anon(BillAnonParticipant),
    Ident(BillIdentParticipant),
}

impl BillParticipant {
    pub fn node_id(&self) -> NodeId {
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

    pub fn name(&self) -> Option<Name> {
        match self {
            BillParticipant::Ident(data) => Some(data.name.to_owned()),
            BillParticipant::Anon(_) => None,
        }
    }

    pub fn email(&self) -> Option<Email> {
        match self {
            BillParticipant::Ident(data) => data.email.to_owned(),
            BillParticipant::Anon(_) => None,
        }
    }

    pub fn nostr_relays(&self) -> Vec<url::Url> {
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BillAnonParticipant {
    /// The node id of the participant
    pub node_id: NodeId,
    /// The preferred Nostr relay to deliver Nostr messages to
    pub nostr_relays: Vec<url::Url>,
}

impl From<BillIdentParticipant> for BillAnonParticipant {
    fn from(value: BillIdentParticipant) -> Self {
        Self {
            node_id: value.node_id,
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

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct BillIdentParticipant {
    /// The type of identity (0 = person, 1 = company)
    #[serde(rename = "type")]
    pub t: ContactType,
    /// The node id of the identity
    pub node_id: NodeId,
    /// The name of the identity
    pub name: Name,
    /// Full postal address of the identity
    #[serde(flatten)]
    pub postal_address: PostalAddress,
    /// email address of the identity
    pub email: Option<Email>,
    /// The preferred Nostr relay to deliver Nostr messages to
    pub nostr_relays: Vec<url::Url>,
}

impl From<BillParticipant> for BillParticipantBlockData {
    fn from(value: BillParticipant) -> Self {
        match value {
            BillParticipant::Ident(data) => Self::Ident(BillIdentParticipantBlockData {
                t: data.t,
                node_id: data.node_id,
                name: data.name,
                postal_address: data.postal_address,
            }),
            BillParticipant::Anon(data) => Self::Anon(BillAnonParticipantBlockData {
                node_id: data.node_id,
            }),
        }
    }
}

impl From<BillIdentParticipant> for BillIdentParticipantBlockData {
    fn from(value: BillIdentParticipant) -> Self {
        Self {
            t: value.t,
            node_id: value.node_id,
            name: value.name,
            postal_address: value.postal_address,
        }
    }
}

impl From<BillIdentParticipantBlockData> for BillIdentParticipant {
    fn from(value: BillIdentParticipantBlockData) -> Self {
        Self {
            t: value.t,
            node_id: value.node_id,
            name: value.name,
            postal_address: value.postal_address,
            email: None,
            nostr_relays: vec![],
        }
    }
}

impl From<BillAnonParticipant> for BillAnonParticipantBlockData {
    fn from(value: BillAnonParticipant) -> Self {
        Self {
            node_id: value.node_id,
        }
    }
}

impl From<BillParticipantBlockData> for BillParticipant {
    fn from(value: BillParticipantBlockData) -> Self {
        match value {
            BillParticipantBlockData::Ident(data) => Self::Ident(BillIdentParticipant {
                t: data.t,
                node_id: data.node_id,
                name: data.name,
                postal_address: data.postal_address,
                email: None,
                nostr_relays: vec![],
            }),
            BillParticipantBlockData::Anon(data) => Self::Anon(BillAnonParticipant {
                node_id: data.node_id,
                nostr_relays: vec![],
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SignedBy {
    pub data: BillParticipant,
    pub signatory: Option<BillSignatory>,
}

/// The name and node_id of a company signatory
#[derive(Debug, Clone)]
pub struct BillSignatory {
    pub node_id: NodeId,
    pub name: Name,
}

impl From<(BillParticipantBlockData, Option<BillSignatoryBlockData>)> for SignedBy {
    fn from(value: (BillParticipantBlockData, Option<BillSignatoryBlockData>)) -> Self {
        Self {
            data: value.0.clone().into(),
            signatory: value.1.map(|s| BillSignatory {
                node_id: s.node_id,
                name: s.name,
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PastEndorsee {
    pub pay_to_the_order_of: BillIdentParticipant,
    pub signed: SignedBy,
    pub signing_timestamp: Timestamp,
    pub signing_address: Option<PostalAddress>,
}
