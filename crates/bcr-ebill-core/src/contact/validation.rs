use crate::{Field, OptionalPostalAddress, PostalAddress, Validate, ValidationError, util};

use super::ContactType;

pub fn validate_create_contact(
    t: ContactType,
    node_id: &str,
    name: &str,
    email: &Option<String>,
    postal_address: &Option<PostalAddress>,
    avatar_file_upload_id: &Option<String>,
    proof_document_file_upload_id: &Option<String>,
) -> Result<(), ValidationError> {
    if util::crypto::validate_pub_key(node_id).is_err() {
        return Err(ValidationError::InvalidSecp256k1Key(node_id.to_owned()));
    }

    if name.trim().is_empty() {
        return Err(ValidationError::FieldEmpty(Field::Name));
    }

    match t {
        ContactType::Anon => {
            // only node id and name need to be set
        }
        ContactType::Person | ContactType::Company => {
            // email and address need to be set
            if let Some(pa) = postal_address {
                pa.validate()?;
            } else {
                return Err(ValidationError::FieldEmpty(Field::Address));
            }
            if email.is_none() {
                return Err(ValidationError::FieldEmpty(Field::Email));
            }
            util::validate_file_upload_id(avatar_file_upload_id.as_deref())?;
            util::validate_file_upload_id(proof_document_file_upload_id.as_deref())?;
        }
    };

    Ok(())
}

pub fn validate_update_contact(
    t: ContactType,
    name: &Option<String>,
    email: &Option<String>,
    postal_address: &OptionalPostalAddress,
    avatar_file_upload_id: &Option<String>,
    proof_document_file_upload_id: &Option<String>,
) -> Result<(), ValidationError> {
    if let Some(set_name) = name {
        if set_name.trim().is_empty() {
            return Err(ValidationError::FieldEmpty(Field::Name));
        }
    }

    if let Some(set_email) = email {
        if set_email.trim().is_empty() {
            return Err(ValidationError::FieldEmpty(Field::Email));
        }
    }

    match t {
        ContactType::Anon => {}
        ContactType::Person | ContactType::Company => {
            postal_address.validate()?;
            util::validate_file_upload_id(avatar_file_upload_id.as_deref())?;
            util::validate_file_upload_id(proof_document_file_upload_id.as_deref())?;
        }
    };
    Ok(())
}
