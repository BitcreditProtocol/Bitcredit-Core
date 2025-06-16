use super::{File, PostalAddress};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Company {
    pub id: String,
    pub name: String,
    pub country_of_registration: Option<String>,
    pub city_of_registration: Option<String>,
    pub postal_address: PostalAddress,
    pub email: String,
    pub registration_number: Option<String>,
    pub registration_date: Option<String>,
    pub proof_of_registration_file: Option<File>,
    pub logo_file: Option<File>,
    pub signatories: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CompanyKeys {
    pub private_key: String,
    pub public_key: String,
}
