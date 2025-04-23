use crate::{Field, OptionalPostalAddress, Validate, ValidationError, util};

use super::IdentityType;

pub fn validate_create_identity(
    t: IdentityType,
    node_id: &str,
    name: &str,
    email: &Option<String>,
    postal_address: &OptionalPostalAddress,
    profile_picture_file_upload_id: &Option<String>,
    identity_document_file_upload_id: &Option<String>,
) -> Result<(), ValidationError> {
    if util::crypto::validate_pub_key(node_id).is_err() {
        return Err(ValidationError::InvalidSecp256k1Key(node_id.to_owned()));
    }

    if name.trim().is_empty() {
        return Err(ValidationError::FieldEmpty(Field::Name));
    }

    match t {
        IdentityType::Anon => {
            // only node id and name need to be set
        }
        IdentityType::Ident => {
            // email needs to be set
            if email.is_none() {
                return Err(ValidationError::FieldEmpty(Field::Email));
            }
            postal_address.validate()?;
            util::validate_file_upload_id(profile_picture_file_upload_id.as_deref())?;
            util::validate_file_upload_id(identity_document_file_upload_id.as_deref())?;
        }
    };

    Ok(())
}

pub fn validate_update_identity(
    t: IdentityType,
    name: &Option<String>,
    email: &Option<String>,
    postal_address: &OptionalPostalAddress,
    profile_picture_file_upload_id: &Option<String>,
    identity_document_file_upload_id: &Option<String>,
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
        IdentityType::Anon => {}
        IdentityType::Ident => {
            postal_address.validate()?;
            util::validate_file_upload_id(profile_picture_file_upload_id.as_deref())?;
            util::validate_file_upload_id(identity_document_file_upload_id.as_deref())?;
        }
    };
    Ok(())
}
