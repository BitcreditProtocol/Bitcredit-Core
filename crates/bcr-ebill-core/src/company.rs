use crate::{NodeId, blockchain::company::CompanyBlockPayload};

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
}

impl Company {
    /// Applies data from a block to the company. Retruns a new company with the data applied.
    pub fn apply_block_data(&mut self, data: &CompanyBlockPayload) {
        let mut result = self.clone();
        match data {
            CompanyBlockPayload::Update(payload) => {
                result.name = payload.name.to_owned().unwrap_or(result.name);
                result.email = payload.email.to_owned().unwrap_or(result.email);
                result.postal_address.city = payload
                    .postal_address
                    .city
                    .to_owned()
                    .unwrap_or(result.postal_address.city);
                result.postal_address.country = payload
                    .postal_address
                    .country
                    .to_owned()
                    .unwrap_or(result.postal_address.country);
                result.postal_address.zip = payload
                    .postal_address
                    .zip
                    .to_owned()
                    .or(result.postal_address.zip);
                result.postal_address.address = payload
                    .postal_address
                    .address
                    .to_owned()
                    .unwrap_or(result.postal_address.address);
                result.country_of_registration = payload
                    .country_of_registration
                    .to_owned()
                    .or(result.country_of_registration);
                result.city_of_registration = payload
                    .city_of_registration
                    .to_owned()
                    .or(result.city_of_registration);
                result.registration_number = payload
                    .registration_number
                    .to_owned()
                    .or(result.registration_number);
                result.registration_date = payload
                    .registration_date
                    .to_owned()
                    .or(result.registration_date);
                result.logo_file = payload.logo_file.to_owned().or(result.logo_file);
                result.proof_of_registration_file = payload
                    .proof_of_registration_file
                    .to_owned()
                    .or(result.proof_of_registration_file);
            }
            CompanyBlockPayload::AddSignatory(payload) => {
                result.signatories.push(payload.signatory.to_owned());
            }
            CompanyBlockPayload::RemoveSignatory(payload) => {
                result.signatories.retain(|i| i != &payload.signatory);
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
