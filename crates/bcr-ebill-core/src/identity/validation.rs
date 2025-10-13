use crate::{Field, OptionalPostalAddress, Validate, ValidationError, email::Email, util};

use super::IdentityType;

pub fn validate_create_identity(
    t: IdentityType,
    email: &Option<Email>,
    postal_address: &OptionalPostalAddress,
    profile_picture_file_upload_id: &Option<String>,
    identity_document_file_upload_id: &Option<String>,
) -> Result<(), ValidationError> {
    match t {
        IdentityType::Anon => {
            // only node id and name need to be set
        }
        IdentityType::Ident => {
            // email needs to be set and not blank
            if email.is_none() {
                return Err(ValidationError::FieldEmpty(Field::Email));
            }
            // For Ident, the postal address needs to be fully set
            postal_address.validate_to_be_non_optional()?;
            util::validate_file_upload_id(profile_picture_file_upload_id.as_deref())?;
            util::validate_file_upload_id(identity_document_file_upload_id.as_deref())?;
        }
    };

    Ok(())
}

pub fn validate_update_identity(
    t: IdentityType,
    postal_address: &OptionalPostalAddress,
    profile_picture_file_upload_id: &Option<String>,
    identity_document_file_upload_id: &Option<String>,
) -> Result<(), ValidationError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        OptionalPostalAddress, ValidationError, identity::IdentityType,
        tests::tests::valid_optional_address,
    };
    use rstest::rstest;

    #[test]
    fn test_validate_create_identity() {
        let result = validate_create_identity(
            IdentityType::Anon,
            &None,
            &OptionalPostalAddress::empty(),
            &None,
            &None,
        );
        assert!(result.is_ok());
    }

    #[rstest]
    #[case::ident_no_email(IdentityType::Ident, &None, &valid_optional_address(), &None, &None, ValidationError::FieldEmpty(Field::Email))]
    #[case::ident_blank_profile_pic(IdentityType::Ident, &Some(Email::new("mail@mail.com").unwrap()), &valid_optional_address(), &Some("".into()), &None, ValidationError::InvalidFileUploadId)]
    #[case::ident_blank_identity_doc(IdentityType::Ident, &Some(Email::new("mail@mail.com").unwrap()), &valid_optional_address(), &None, &Some("".into()), ValidationError::InvalidFileUploadId)]
    fn test_validate_create_identity_errors(
        #[case] t: IdentityType,
        #[case] email: &Option<Email>,
        #[case] postal_address: &OptionalPostalAddress,
        #[case] profile_picture_file_upload_id: &Option<String>,
        #[case] identity_document_file_upload_id: &Option<String>,
        #[case] expected: ValidationError,
    ) {
        assert_eq!(
            validate_create_identity(
                t,
                email,
                postal_address,
                profile_picture_file_upload_id,
                identity_document_file_upload_id
            ),
            Err(expected)
        );
    }

    #[test]
    fn test_validate_update_identity() {
        let result = validate_update_identity(
            IdentityType::Anon,
            &OptionalPostalAddress::empty(),
            &None,
            &None,
        );
        assert!(result.is_ok());
    }

    #[rstest]
    #[case::ident_blank_profile_pic(IdentityType::Ident, &OptionalPostalAddress::empty(), &Some("".into()), &None, ValidationError::InvalidFileUploadId)]
    #[case::ident_blank_identity_doc(IdentityType::Ident, &OptionalPostalAddress::empty(), &None, &Some("".into()), ValidationError::InvalidFileUploadId)]
    fn test_validate_update_identity_errors(
        #[case] t: IdentityType,
        #[case] postal_address: &OptionalPostalAddress,
        #[case] profile_picture_file_upload_id: &Option<String>,
        #[case] identity_document_file_upload_id: &Option<String>,
        #[case] expected: ValidationError,
    ) {
        assert_eq!(
            validate_update_identity(
                t,
                postal_address,
                profile_picture_file_upload_id,
                identity_document_file_upload_id
            ),
            Err(expected)
        );
    }
}
