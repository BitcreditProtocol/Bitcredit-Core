use crate::protocol::blockchain::bill::ContactType;
use crate::protocol::blockchain::bill::block::BillSignatoryBlockData;
use crate::protocol::blockchain::identity::IdentityType;
use crate::protocol::{File, OptionalPostalAddress};
use crate::{
    application::contact::Contact,
    protocol::City,
    protocol::Country,
    protocol::Date,
    protocol::Email,
    protocol::Identification,
    protocol::Name,
    protocol::blockchain::identity::{IdentityBlockPayload, IdentityCreateBlockData},
    protocol::crypto::BcrKeys,
};
use bcr_common::core::NodeId;
use serde::{Deserialize, Serialize};

pub mod validation;

#[repr(u8)]
#[derive(Debug, Clone, serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Eq)]
pub enum SwitchIdentityType {
    Person = 0,
    Company = 1,
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
    pub name: Name,
    pub email: Option<Email>,
    pub postal_address: OptionalPostalAddress,
    pub date_of_birth: Option<Date>,
    pub country_of_birth: Option<Country>,
    pub city_of_birth: Option<City>,
    pub identification_number: Option<Identification>,
    pub nostr_relays: Vec<url::Url>,
    pub profile_picture_file: Option<File>,
    pub identity_document_file: Option<File>,
}

impl From<Identity> for IdentityCreateBlockData {
    fn from(value: Identity) -> Self {
        Self {
            t: value.t,
            node_id: value.node_id,
            name: value.name,
            email: value.email,
            date_of_birth: value.date_of_birth,
            country_of_birth: value.country_of_birth,
            city_of_birth: value.city_of_birth,
            postal_address: value.postal_address,
            identification_number: value.identification_number,
            nostr_relays: value.nostr_relays,
            profile_picture_file: value.profile_picture_file,
            identity_document_file: value.identity_document_file,
        }
    }
}

impl From<Identity> for BillSignatoryBlockData {
    fn from(value: Identity) -> Self {
        Self {
            name: value.name,
            node_id: value.node_id,
        }
    }
}

impl Identity {
    pub fn get_nostr_name(&self) -> String {
        self.name.to_string()
    }

    pub fn from_block_data(data: IdentityCreateBlockData) -> Self {
        Self {
            t: data.t,
            node_id: data.node_id,
            name: data.name,
            email: data.email,
            postal_address: data.postal_address,
            date_of_birth: data.date_of_birth,
            country_of_birth: data.country_of_birth,
            city_of_birth: data.city_of_birth,
            identification_number: data.identification_number,
            nostr_relays: data.nostr_relays,
            profile_picture_file: data.profile_picture_file,
            identity_document_file: data.identity_document_file,
        }
    }

    pub fn apply_block_data(&mut self, data: &IdentityBlockPayload) {
        // only the update block does actually mutate the identity
        if let IdentityBlockPayload::Update(payload) = data {
            // check whether the account was deanonymized with the update
            if let Some(ref t) = payload.t
                && self.t == IdentityType::Anon
            {
                self.t = t.to_owned();
            }
            self.name = payload.name.to_owned().unwrap_or(self.name.to_owned());
            self.email = payload.email.to_owned().or(self.email.to_owned());
            self.postal_address.country = payload
                .postal_address
                .country
                .to_owned()
                .or(self.postal_address.country.to_owned());
            self.postal_address.city = payload
                .postal_address
                .city
                .to_owned()
                .or(self.postal_address.city.to_owned());
            self.postal_address.zip = payload
                .postal_address
                .zip
                .to_owned()
                .or(self.postal_address.zip.to_owned());
            self.postal_address.address = payload
                .postal_address
                .address
                .to_owned()
                .or(self.postal_address.address.to_owned());
            self.date_of_birth = payload
                .date_of_birth
                .to_owned()
                .or(self.date_of_birth.to_owned());
            self.country_of_birth = payload
                .country_of_birth
                .to_owned()
                .or(self.country_of_birth.to_owned());
            self.city_of_birth = payload
                .city_of_birth
                .to_owned()
                .or(self.city_of_birth.to_owned());
            self.identification_number = payload
                .identification_number
                .to_owned()
                .or(self.identification_number.to_owned());
            self.profile_picture_file = payload
                .profile_picture_file
                .to_owned()
                .or(self.profile_picture_file.to_owned());
            self.identity_document_file = payload
                .identity_document_file
                .to_owned()
                .or(self.identity_document_file.to_owned());
        }
    }

    pub fn as_contact(&self, t: Option<ContactType>) -> Contact {
        let contact_type = t.unwrap_or(match self.t {
            IdentityType::Ident => ContactType::Person,
            IdentityType::Anon => ContactType::Anon,
        });
        Contact {
            t: contact_type,
            node_id: self.node_id.clone(),
            name: self.name.clone(),
            email: self.email.clone(),
            postal_address: self.postal_address.to_full_postal_address(),
            date_of_birth_or_registration: self.date_of_birth.clone(),
            country_of_birth_or_registration: self.country_of_birth.clone(),
            city_of_birth_or_registration: self.city_of_birth.clone(),
            identification_number: self.identification_number.clone(),
            avatar_file: self.profile_picture_file.clone(),
            proof_document_file: self.identity_document_file.clone(),
            nostr_relays: self.nostr_relays.clone(),
            is_logical: false,
            mint_url: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ActiveIdentityState {
    pub personal: NodeId,
    pub company: Option<NodeId>,
}
