use crate::{Field, OptionalPostalAddress, Validate, ValidationError, util};

use super::IdentityType;

pub fn validate_create_identity(
    t: IdentityType,
    name: &str,
    email: &Option<String>,
    postal_address: &OptionalPostalAddress,
    profile_picture_file_upload_id: &Option<String>,
    identity_document_file_upload_id: &Option<String>,
) -> Result<(), ValidationError> {
    if name.trim().is_empty() {
        return Err(ValidationError::FieldEmpty(Field::Name));
    }

    match t {
        IdentityType::Anon => {
            // only node id and name need to be set
        }
        IdentityType::Ident => {
            // email needs to be set and not blank
            if let Some(set_email) = email {
                if set_email.trim().is_empty() {
                    return Err(ValidationError::FieldEmpty(Field::Email));
                }
            } else {
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
    name: &Option<String>,
    email: &Option<String>,
    postal_address: &OptionalPostalAddress,
    profile_picture_file_upload_id: &Option<String>,
    identity_document_file_upload_id: &Option<String>,
) -> Result<(), ValidationError> {
    if let Some(set_name) = name
        && set_name.trim().is_empty()
    {
        return Err(ValidationError::FieldEmpty(Field::Name));
    }

    if let Some(set_email) = email
        && set_email.trim().is_empty()
    {
        return Err(ValidationError::FieldEmpty(Field::Email));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        OptionalPostalAddress, ValidationError, country::Country, identity::IdentityType,
        tests::tests::valid_optional_address,
    };
    use rstest::rstest;

    #[test]
    fn test_validate_create_identity() {
        let result = validate_create_identity(
            IdentityType::Anon,
            "some name",
            &None,
            &OptionalPostalAddress::empty(),
            &None,
            &None,
        );
        assert!(result.is_ok());
    }

    #[rstest]
    #[case::invalid_name(IdentityType::Anon, "", &None, &valid_optional_address(), &None, &None, ValidationError::FieldEmpty(Field::Name))]
    #[case::ident_no_email(IdentityType::Ident, "some name", &None, &valid_optional_address(), &None, &None, ValidationError::FieldEmpty(Field::Email))]
    #[case::ident_blank_email(IdentityType::Ident, "some name", &Some("".into()), &valid_optional_address(), &None, &None, ValidationError::FieldEmpty(Field::Email))]
    #[case::ident_blank_address(IdentityType::Ident, "some name", &Some("mail@mail.com".into()), &OptionalPostalAddress { country: Some(Country::AT), city: Some("Vienna".to_string()), zip: None, address: Some("".into()) }, &None, &None, ValidationError::FieldEmpty(Field::Address))]
    #[case::ident_empty_address(IdentityType::Ident, "some name", &Some("mail@mail.com".into()), &OptionalPostalAddress { country: Some(Country::AT), city: Some("Vienna".to_string()), zip: None, address: None }, &None, &None, ValidationError::FieldEmpty(Field::Address))]
    #[case::ident_blank_city(IdentityType::Ident, "some name", &Some("mail@mail.com".into()), &OptionalPostalAddress { country: Some(Country::AT), address: Some("addr 1".to_string()), zip: None, city: Some("".into()) }, &None, &None, ValidationError::FieldEmpty(Field::City))]
    #[case::ident_empty_city(IdentityType::Ident, "some name", &Some("mail@mail.com".into()), &OptionalPostalAddress { country: Some(Country::AT), address: Some("addr 1".to_string()), zip: None, city: Some("".into()) }, &None, &None, ValidationError::FieldEmpty(Field::City))]
    #[case::ident_empty_country(IdentityType::Ident, "some name", &Some("mail@mail.com".into()), &OptionalPostalAddress { address: Some("addr 1".to_string()), city: Some("Vienna".to_string()), zip: None, country: None }, &None, &None, ValidationError::FieldEmpty(Field::Country))]
    #[case::ident_blank_zip(IdentityType::Ident, "some name", &Some("mail@mail.com".into()), &OptionalPostalAddress { country: Some(Country::AT), city: Some("Vienna".to_string()), address: Some("addr 1".to_string()), zip: Some("".into()) }, &None, &None, ValidationError::FieldEmpty(Field::Zip))]
    #[case::ident_blank_profile_pic(IdentityType::Ident, "some name", &Some("mail@mail.com".into()), &valid_optional_address(), &Some("".into()), &None, ValidationError::InvalidFileUploadId)]
    #[case::ident_blank_identity_doc(IdentityType::Ident, "some name", &Some("mail@mail.com".into()), &valid_optional_address(), &None, &Some("".into()), ValidationError::InvalidFileUploadId)]
    fn test_validate_create_identity_errors(
        #[case] t: IdentityType,
        #[case] name: &str,
        #[case] email: &Option<String>,
        #[case] postal_address: &OptionalPostalAddress,
        #[case] profile_picture_file_upload_id: &Option<String>,
        #[case] identity_document_file_upload_id: &Option<String>,
        #[case] expected: ValidationError,
    ) {
        assert_eq!(
            validate_create_identity(
                t,
                name,
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
            &None,
            &None,
            &OptionalPostalAddress::empty(),
            &None,
            &None,
        );
        assert!(result.is_ok());
    }

    #[rstest]
    #[case::invalid_name(IdentityType::Anon, &Some("".into()), &None, &OptionalPostalAddress::empty(), &None, &None, ValidationError::FieldEmpty(Field::Name))]
    #[case::ident_invalid_email(IdentityType::Ident, &Some("some name".into()), &Some("".into()), &OptionalPostalAddress::empty(), &None, &None, ValidationError::FieldEmpty(Field::Email))]
    #[case::ident_blank_address(IdentityType::Ident, &Some("some name".into()), &Some("mail@mail.com".into()), &OptionalPostalAddress { country: None, city: None, zip: None, address: Some("".into()) }, &None, &None, ValidationError::FieldEmpty(Field::Address))]
    #[case::ident_blank_city(IdentityType::Ident, &Some("some name".into()), &Some("mail@mail.com".into()), &OptionalPostalAddress { country: None, address: None, zip: None, city: Some("".into()) }, &None, &None, ValidationError::FieldEmpty(Field::City))]
    #[case::ident_blank_zip(IdentityType::Ident, &Some("some name".into()), &Some("mail@mail.com".into()), &OptionalPostalAddress { country: None, city: None, address: None, zip: Some("".into()) }, &None, &None, ValidationError::FieldEmpty(Field::Zip))]
    #[case::ident_blank_profile_pic(IdentityType::Ident, &Some("some name".into()), &Some("mail@mail.com".into()), &OptionalPostalAddress::empty(), &Some("".into()), &None, ValidationError::InvalidFileUploadId)]
    #[case::ident_blank_identity_doc(IdentityType::Ident, &Some("some name".into()), &Some("mail@mail.com".into()), &OptionalPostalAddress::empty(), &None, &Some("".into()), ValidationError::InvalidFileUploadId)]
    fn test_validate_update_identity_errors(
        #[case] t: IdentityType,
        #[case] name: &Option<String>,
        #[case] email: &Option<String>,
        #[case] postal_address: &OptionalPostalAddress,
        #[case] profile_picture_file_upload_id: &Option<String>,
        #[case] identity_document_file_upload_id: &Option<String>,
        #[case] expected: ValidationError,
    ) {
        assert_eq!(
            validate_update_identity(
                t,
                name,
                email,
                postal_address,
                profile_picture_file_upload_id,
                identity_document_file_upload_id
            ),
            Err(expected)
        );
    }
}
