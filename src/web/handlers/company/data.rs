use crate::web::data::File;
use rocket::serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct CompanyToReturn {
    pub id: String,
    pub legal_name: String,
    pub country_of_registration: String,
    pub city_of_registration: String,
    pub postal_address: String,
    pub legal_email: String,
    pub registration_number: String,
    pub registration_date: String,
    pub proof_of_registration_file: Option<File>,
    pub logo_file: Option<File>,
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct CreateCompanyPayload {
    pub legal_name: String,
    pub country_of_registration: String,
    pub city_of_registration: String,
    pub postal_address: String,
    pub legal_email: String,
    pub registration_number: String,
    pub registration_date: String,
    pub proof_of_registration_file_upload_id: Option<String>,
    pub logo_file_upload_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct EditCompanyPayload {
    pub id: String,
    pub legal_name: Option<String>,
    pub legal_email: Option<String>,
    pub postal_address: Option<String>,
    pub logo_file_upload_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct AddSignatoryPayload {
    pub id: String,
    pub signatory_node_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct RemoveSignatoryPayload {
    pub id: String,
    pub signatory_node_id: String,
}
