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

#[cfg(test)]
mod tests {
    use crate::tests::tests::{TEST_PUB_KEY_SECP, valid_address};

    use super::*;
    use rstest::rstest;

    #[test]
    fn test_validate_create_contact() {
        let result = validate_create_contact(
            ContactType::Anon,
            TEST_PUB_KEY_SECP,
            "some name",
            &None,
            &None,
            &None,
            &None,
        );
        assert!(result.is_ok());
    }

    #[rstest]
    #[case::invalid_node_id(ContactType::Anon, "invalid_node_id", "some name", &None, &None, &None, &None, ValidationError::InvalidSecp256k1Key("invalid_node_id".to_owned()))]
    #[case::invalid_name(ContactType::Anon, TEST_PUB_KEY_SECP, "", &None, &None, &None, &None, ValidationError::FieldEmpty(Field::Name))]
    #[case::invalid_email(ContactType::Person, TEST_PUB_KEY_SECP, "some name", &None, &Some(valid_address()), &None, &None, ValidationError::FieldEmpty(Field::Email))]
    #[case::invalid_address(ContactType::Person, TEST_PUB_KEY_SECP, "some name", &Some("mail@mail.com".into()), &None, &None, &None, ValidationError::FieldEmpty(Field::Address))]
    #[case::blank_city(ContactType::Person, TEST_PUB_KEY_SECP, "some name", &Some("mail@mail.com".into()), &Some(PostalAddress { city: "".into(), ..valid_address()}), &None, &None, ValidationError::FieldEmpty(Field::City))]
    #[case::blank_country(ContactType::Person, TEST_PUB_KEY_SECP, "some name", &Some("mail@mail.com".into()), &Some(PostalAddress { country: "".into(), ..valid_address()}), &None, &None, ValidationError::FieldEmpty(Field::Country))]
    #[case::blank_zip(ContactType::Person, TEST_PUB_KEY_SECP, "some name", &Some("mail@mail.com".into()), &Some(PostalAddress { zip: Some("".into()), ..valid_address()}), &None, &None, ValidationError::FieldEmpty(Field::Zip))]
    #[case::blank_address(ContactType::Person, TEST_PUB_KEY_SECP, "some name", &Some("mail@mail.com".into()), &Some(PostalAddress { address: "".into(), ..valid_address()}), &None, &None, ValidationError::FieldEmpty(Field::Address))]
    #[case::blank_city(ContactType::Person, TEST_PUB_KEY_SECP, "some name", &Some("mail@mail.com".into()), &None, &None, &None, ValidationError::FieldEmpty(Field::Address))]
    #[case::ident_blank_avatar(ContactType::Person, TEST_PUB_KEY_SECP, "some name", &Some("mail@mail.com".into()), &Some(valid_address()), &Some("".into()), &None, ValidationError::InvalidFileUploadId)]
    #[case::ident_blank_proof_document(ContactType::Person, TEST_PUB_KEY_SECP, "some name", &Some("mail@mail.com".into()), &Some(valid_address()), &None, &Some("".into()), ValidationError::InvalidFileUploadId)]
    fn test_validate_create_contact_errors(
        #[case] t: ContactType,
        #[case] node_id: &str,
        #[case] name: &str,
        #[case] email: &Option<String>,
        #[case] postal_address: &Option<PostalAddress>,
        #[case] profile_picture_file_upload_id: &Option<String>,
        #[case] identity_document_file_upload_id: &Option<String>,
        #[case] expected: ValidationError,
    ) {
        assert_eq!(
            validate_create_contact(
                t,
                node_id,
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
    fn test_validate_update_contact() {
        let result = validate_update_contact(
            ContactType::Anon,
            &None,
            &None,
            &OptionalPostalAddress::empty(),
            &None,
            &None,
        );
        assert!(result.is_ok());
    }

    #[rstest]
    #[case::invalid_name(ContactType::Person, &Some("".into()), &Some("mail@mail.com".into()), &OptionalPostalAddress::empty(), &None, &None, ValidationError::FieldEmpty(Field::Name))]
    #[case::invalid_email(ContactType::Person, &Some("some name".into()), &Some("".into()), &OptionalPostalAddress::empty(), &None, &None, ValidationError::FieldEmpty(Field::Email))]
    #[case::blank_city(ContactType::Person, &Some("some name".into()), &Some("mail@mail.com".into()), &OptionalPostalAddress { address: None, country: None, zip: None, city: Some("".into()) }, &None, &None, ValidationError::FieldEmpty(Field::City))]
    #[case::blank_country(ContactType::Person, &Some("some name".into()), &Some("mail@mail.com".into()), &OptionalPostalAddress { address: None, city: None, zip: None, country: Some("".into()) }, &None, &None, ValidationError::FieldEmpty(Field::Country))]
    #[case::blank_zip(ContactType::Person, &Some("some name".into()), &Some("mail@mail.com".into()), &OptionalPostalAddress { address: None, city: None, country: None, zip: Some("".into()) }, &None, &None, ValidationError::FieldEmpty(Field::Zip))]
    #[case::blank_address(ContactType::Person, &Some("some name".into()), &Some("mail@mail.com".into()), &OptionalPostalAddress { country: None, city: None, zip: None, address: Some("".into()) }, &None, &None, ValidationError::FieldEmpty(Field::Address))]
    #[case::ident_blank_avatar(ContactType::Person, &Some("some name".into()), &Some("mail@mail.com".into()), &OptionalPostalAddress::empty(), &Some("".into()), &None, ValidationError::InvalidFileUploadId)]
    #[case::ident_blank_proof_document(ContactType::Person, &Some("some name".into()), &Some("mail@mail.com".into()), &OptionalPostalAddress::empty(), &None, &Some("".into()), ValidationError::InvalidFileUploadId)]
    fn test_validate_update_contact_errors(
        #[case] t: ContactType,
        #[case] name: &Option<String>,
        #[case] email: &Option<String>,
        #[case] postal_address: &OptionalPostalAddress,
        #[case] profile_picture_file_upload_id: &Option<String>,
        #[case] identity_document_file_upload_id: &Option<String>,
        #[case] expected: ValidationError,
    ) {
        assert_eq!(
            validate_update_contact(
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
