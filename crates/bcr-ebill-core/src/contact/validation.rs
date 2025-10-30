use crate::{
    Field, NodeId, OptionalPostalAddress, PostalAddress, Validate, ValidationError, email::Email,
};

use super::ContactType;

pub fn validate_create_contact(
    t: ContactType,
    node_id: &NodeId,
    email: &Option<Email>,
    postal_address: &Option<PostalAddress>,
    btc_network: bitcoin::Network,
) -> Result<(), ValidationError> {
    if node_id.network() != btc_network {
        return Err(ValidationError::InvalidNodeId);
    }

    match t {
        ContactType::Anon => {
            // only node id and name need to be set
        }
        ContactType::Person | ContactType::Company => {
            // email and address need to be set and not blank
            if let Some(pa) = postal_address {
                pa.validate()?;
            } else {
                return Err(ValidationError::FieldEmpty(Field::Address));
            }

            if email.is_none() {
                return Err(ValidationError::FieldEmpty(Field::Email));
            }
        }
    };

    Ok(())
}

pub fn validate_update_contact(
    t: ContactType,
    postal_address: &OptionalPostalAddress,
) -> Result<(), ValidationError> {
    match t {
        ContactType::Anon => {}
        ContactType::Person | ContactType::Company => {
            postal_address.validate()?;
        }
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::tests::tests::{node_id_regtest, node_id_test, valid_address};

    use super::*;
    use rstest::rstest;

    #[test]
    fn test_validate_create_contact() {
        let result = validate_create_contact(
            ContactType::Anon,
            &node_id_test(),
            &None,
            &None,
            bitcoin::Network::Testnet,
        );
        assert!(result.is_ok());
    }

    #[rstest]
    #[case::invalid_node_id(ContactType::Anon, node_id_regtest(), &None, &None,  ValidationError::InvalidNodeId)]
    #[case::invalid_email(ContactType::Person, node_id_test(), &None, &Some(valid_address()),  ValidationError::FieldEmpty(Field::Email))]
    #[case::invalid_address(ContactType::Person, node_id_test(), &Some(Email::new("mail@mail.com").unwrap()),  &None, ValidationError::FieldEmpty(Field::Address))]
    #[case::blank_city(ContactType::Person, node_id_test(), &Some(Email::new("mail@mail.com").unwrap()),  &None, ValidationError::FieldEmpty(Field::Address))]
    fn test_validate_create_contact_errors(
        #[case] t: ContactType,
        #[case] node_id: NodeId,
        #[case] email: &Option<Email>,
        #[case] postal_address: &Option<PostalAddress>,
        #[case] expected: ValidationError,
    ) {
        assert_eq!(
            validate_create_contact(
                t,
                &node_id,
                email,
                postal_address,
                bitcoin::Network::Testnet,
            ),
            Err(expected)
        );
    }

    #[test]
    fn test_validate_update_contact() {
        let result = validate_update_contact(ContactType::Anon, &OptionalPostalAddress::empty());
        assert!(result.is_ok());
    }
}
