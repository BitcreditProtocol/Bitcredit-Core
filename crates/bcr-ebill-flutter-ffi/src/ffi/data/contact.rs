use bcr_ebill_api::service::Error;
use bcr_ebill_core::{
    application::{ValidationError, contact::Contact},
    protocol::blockchain::bill::ContactType,
};
use bcr_ebill_persistence::PendingContactShare;

use crate::ffi::data::{
    CreatePostalAddressFfi, EditOptionalFieldModeFfi, FileFfi, PostalAddressFfi,
};

#[derive(Debug)]
pub struct ContactsResponse {
    pub contacts: Vec<ContactFfi>,
}

#[derive(Debug)]
pub struct NewContactPayload {
    pub t: u64,
    pub node_id: String,
    pub name: String,
    pub email: Option<String>,
    pub postal_address: Option<CreatePostalAddressFfi>,
    pub date_of_birth_or_registration: Option<String>,
    pub country_of_birth_or_registration: Option<String>,
    pub city_of_birth_or_registration: Option<String>,
    pub identification_number: Option<String>,
    pub avatar_file_upload_id: Option<String>,
    pub proof_document_file_upload_id: Option<String>,
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ContactTypeFfi {
    Person = 0,
    Company = 1,
    Anon = 2,
}

impl TryFrom<u64> for ContactTypeFfi {
    type Error = Error;

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        Ok(ContactType::try_from(value)
            .map_err(|e| Self::Error::Validation(ValidationError::Protocol(e)))?
            .into())
    }
}

impl From<ContactType> for ContactTypeFfi {
    fn from(val: ContactType) -> Self {
        match val {
            ContactType::Person => ContactTypeFfi::Person,
            ContactType::Company => ContactTypeFfi::Company,
            ContactType::Anon => ContactTypeFfi::Anon,
        }
    }
}

impl From<ContactTypeFfi> for ContactType {
    fn from(value: ContactTypeFfi) -> Self {
        match value {
            ContactTypeFfi::Person => ContactType::Person,
            ContactTypeFfi::Company => ContactType::Company,
            ContactTypeFfi::Anon => ContactType::Anon,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ContactFfi {
    pub t: ContactTypeFfi,
    pub node_id: String,
    pub name: String,
    pub email: Option<String>,
    pub postal_address: Option<PostalAddressFfi>,
    pub date_of_birth_or_registration: Option<String>,
    pub country_of_birth_or_registration: Option<String>,
    pub city_of_birth_or_registration: Option<String>,
    pub identification_number: Option<String>,
    pub avatar_file: Option<FileFfi>,
    pub proof_document_file: Option<FileFfi>,
    pub nostr_relays: Vec<String>,
    pub is_logical: bool,
}

impl From<Contact> for ContactFfi {
    fn from(val: Contact) -> Self {
        ContactFfi {
            t: val.t.into(),
            node_id: val.node_id.to_string(),
            name: val.name.to_string(),
            email: val.email.map(|v| v.to_string()),
            postal_address: val.postal_address.map(|pa| pa.into()),
            date_of_birth_or_registration: val.date_of_birth_or_registration.map(|v| v.to_string()),
            country_of_birth_or_registration: val
                .country_of_birth_or_registration
                .map(|v| v.to_string()),
            city_of_birth_or_registration: val.city_of_birth_or_registration.map(|v| v.to_string()),
            identification_number: val.identification_number.map(|v| v.to_string()),
            avatar_file: val.avatar_file.map(|f| f.into()),
            proof_document_file: val.proof_document_file.map(|f| f.into()),
            nostr_relays: val
                .nostr_relays
                .into_iter()
                .map(|u| u.to_string())
                .collect(),
            is_logical: val.is_logical,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EditContactPayload {
    pub node_id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub postal_address_country: Option<String>,
    pub postal_address_city: Option<String>,
    pub postal_address_zip: EditOptionalFieldModeFfi,
    pub postal_address_address: Option<String>,
    pub date_of_birth_or_registration: EditOptionalFieldModeFfi,
    pub country_of_birth_or_registration: EditOptionalFieldModeFfi,
    pub city_of_birth_or_registration: EditOptionalFieldModeFfi,
    pub identification_number: EditOptionalFieldModeFfi,
    pub avatar_file_upload_id: EditOptionalFieldModeFfi,
    pub proof_document_file_upload_id: EditOptionalFieldModeFfi,
}

#[derive(Debug, Clone)]
pub struct SearchContactsPayload {
    pub search_term: String,
    pub include_logical: Option<bool>,
    pub include_contact: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct PendingContactShareFfi {
    pub id: String,
    pub node_id: String,
    pub contact: ContactFfi,
    pub sender_node_id: String,
    pub receiver_node_id: String,
    pub received_at: u64,
}

impl From<PendingContactShare> for PendingContactShareFfi {
    fn from(val: PendingContactShare) -> Self {
        PendingContactShareFfi {
            id: val.id,
            node_id: val.node_id.to_string(),
            contact: val.contact.into(),
            sender_node_id: val.sender_node_id.to_string(),
            receiver_node_id: val.receiver_node_id.to_string(),
            received_at: val.received_at.inner(),
        }
    }
}

#[derive(Debug)]
pub struct PendingContactSharesResponse {
    pub pending_shares: Vec<PendingContactShareFfi>,
}

#[derive(Debug)]
pub struct ApproveContactSharePayload {
    pub pending_share_id: String,
    pub add_to_contacts: bool,
    pub share_back: bool,
}
