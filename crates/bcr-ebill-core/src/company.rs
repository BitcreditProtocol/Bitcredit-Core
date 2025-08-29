use crate::{
    NodeId,
    blockchain::company::{CompanyBlockPayload, CompanyCreateBlockData},
};

use super::{File, PostalAddress};
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Company {
    pub id: NodeId,
    pub name: String,
    pub country_of_registration: Option<String>,
    pub city_of_registration: Option<String>,
    pub postal_address: PostalAddress,
    pub email: String,
    pub registration_number: Option<String>,
    pub registration_date: Option<String>,
    pub proof_of_registration_file: Option<File>,
    pub logo_file: Option<File>,
    pub signatories: Vec<NodeId>,
    pub active: bool,
}

impl Company {
    /// Creates a new company from a block data payload
    pub fn from_block_data(data: CompanyCreateBlockData, our_node_id: &NodeId) -> Self {
        let active = data.signatories.contains(our_node_id);
        Self {
            id: data.id,
            name: data.name,
            country_of_registration: data.country_of_registration,
            city_of_registration: data.city_of_registration,
            postal_address: data.postal_address,
            email: data.email,
            registration_number: data.registration_number,
            registration_date: data.registration_date,
            proof_of_registration_file: data.proof_of_registration_file,
            logo_file: data.logo_file,
            signatories: data.signatories,
            active,
        }
    }
    /// Applies data from a block to this company.
    pub fn apply_block_data(&mut self, data: &CompanyBlockPayload, our_node_id: &NodeId) {
        match data {
            CompanyBlockPayload::Update(payload) => {
                self.name = payload.name.to_owned().unwrap_or(self.name.to_owned());
                self.email = payload.email.to_owned().unwrap_or(self.email.to_owned());
                self.postal_address.city = payload
                    .postal_address
                    .city
                    .to_owned()
                    .unwrap_or(self.postal_address.city.to_owned());
                self.postal_address.country = payload
                    .postal_address
                    .country
                    .to_owned()
                    .unwrap_or(self.postal_address.country.to_owned());
                self.postal_address.zip = payload
                    .postal_address
                    .zip
                    .to_owned()
                    .or(self.postal_address.zip.to_owned());
                self.postal_address.address = payload
                    .postal_address
                    .address
                    .to_owned()
                    .unwrap_or(self.postal_address.address.to_owned());
                self.country_of_registration = payload
                    .country_of_registration
                    .to_owned()
                    .or(self.country_of_registration.to_owned());
                self.city_of_registration = payload
                    .city_of_registration
                    .to_owned()
                    .or(self.city_of_registration.to_owned());
                self.registration_number = payload
                    .registration_number
                    .to_owned()
                    .or(self.registration_number.to_owned());
                self.registration_date = payload
                    .registration_date
                    .to_owned()
                    .or(self.registration_date.to_owned());
                self.logo_file = payload.logo_file.to_owned().or(self.logo_file.to_owned());
                self.proof_of_registration_file = payload
                    .proof_of_registration_file
                    .to_owned()
                    .or(self.proof_of_registration_file.to_owned());
            }
            CompanyBlockPayload::AddSignatory(payload) => {
                if !self.signatories.contains(&payload.signatory) {
                    self.signatories.push(payload.signatory.to_owned());
                    if &payload.signatory == our_node_id {
                        self.active = true;
                    }
                }
            }
            CompanyBlockPayload::RemoveSignatory(payload) => {
                self.signatories.retain(|i| i != &payload.signatory);
                if &payload.signatory == our_node_id {
                    self.active = false;
                }
            }
            _ => {}
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CompanyKeys {
    pub private_key: SecretKey,
    pub public_key: PublicKey,
}

impl CompanyKeys {
    /// Returns the private key as a hex encoded string
    pub fn get_private_key_string(&self) -> String {
        self.private_key.display_secret().to_string()
    }
}
