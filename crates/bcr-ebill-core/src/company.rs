use crate::NodeId;

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
