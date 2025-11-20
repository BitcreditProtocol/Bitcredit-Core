use crate::protocol::{
    City, Country, Date, Email, File, Identification, Name, PostalAddress,
    blockchain::company::{
        CompanyBlockPayload, CompanyCreateBlockData, CompanySignatoryBlockData, SignatoryType,
    },
};
use bcr_common::core::NodeId;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Company {
    pub id: NodeId,
    pub name: Name,
    pub country_of_registration: Option<Country>,
    pub city_of_registration: Option<City>,
    pub postal_address: PostalAddress,
    pub email: Email,
    pub registration_number: Option<Identification>,
    pub registration_date: Option<Date>,
    pub proof_of_registration_file: Option<File>,
    pub logo_file: Option<File>,
    pub signatories: Vec<CompanySignatory>,
    pub active: bool,
}

impl From<Company> for CompanyCreateBlockData {
    fn from(value: Company) -> Self {
        Self {
            id: value.id,
            name: value.name,
            country_of_registration: value.country_of_registration,
            city_of_registration: value.city_of_registration,
            postal_address: value.postal_address,
            email: value.email,
            registration_number: value.registration_number,
            registration_date: value.registration_date,
            proof_of_registration_file: value.proof_of_registration_file,
            logo_file: value.logo_file,
            signatories: value.signatories.into_iter().map(|s| s.into()).collect(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CompanySignatory {
    pub node_id: NodeId,
    pub email: Email,
}

impl From<CompanySignatory> for CompanySignatoryBlockData {
    fn from(value: CompanySignatory) -> Self {
        Self {
            t: SignatoryType::Solo,
            node_id: value.node_id,
            email: value.email,
        }
    }
}

impl From<CompanySignatoryBlockData> for CompanySignatory {
    fn from(value: CompanySignatoryBlockData) -> Self {
        Self {
            node_id: value.node_id,
            email: value.email,
        }
    }
}

impl Company {
    /// Creates a new company from a block data payload
    pub fn from_block_data(data: CompanyCreateBlockData, our_node_id: &NodeId) -> Self {
        let active = data.signatories.iter().any(|s| &s.node_id == our_node_id);
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
            signatories: data.signatories.into_iter().map(|s| s.into()).collect(),
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
                if !self
                    .signatories
                    .iter()
                    .any(|s| s.node_id == payload.signatory)
                {
                    self.signatories.push(
                        CompanySignatoryBlockData {
                            t: SignatoryType::Solo,
                            node_id: payload.signatory.to_owned(),
                            email: payload.signatory_email.to_owned(),
                        }
                        .into(),
                    );
                    if &payload.signatory == our_node_id {
                        self.active = true;
                    }
                }
            }
            CompanyBlockPayload::RemoveSignatory(payload) => {
                self.signatories.retain(|i| i.node_id != payload.signatory);
                if &payload.signatory == our_node_id {
                    self.active = false;
                }
            }
            _ => {}
        }
    }
}
