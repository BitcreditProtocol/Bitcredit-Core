use crate::protocol::{Email, Field, PostalAddress, ProtocolValidationError};
use bcr_common::core::NodeId;

use super::ContactType;

pub fn validate_create_contact(
    t: ContactType,
    node_id: &NodeId,
    email: &Option<Email>,
    postal_address: &Option<PostalAddress>,
    btc_network: bitcoin::Network,
) -> Result<(), ProtocolValidationError> {
    if node_id.network() != btc_network {
        return Err(ProtocolValidationError::InvalidNodeId);
    }

    match t {
        ContactType::Anon => {
            // only node id and name need to be set
        }
        ContactType::Person | ContactType::Company => {
            // email and address need to be set and not blank
            if postal_address.is_none() {
                return Err(ProtocolValidationError::FieldEmpty(Field::Address));
            }

            if email.is_none() {
                return Err(ProtocolValidationError::FieldEmpty(Field::Email));
            }
        }
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::protocol::tests::tests::{node_id_regtest, node_id_test, valid_address};

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
    #[case::invalid_node_id(ContactType::Anon, node_id_regtest(), &None, &None,  ProtocolValidationError::InvalidNodeId)]
    #[case::invalid_email(ContactType::Person, node_id_test(), &None, &Some(valid_address()),  ProtocolValidationError::FieldEmpty(Field::Email))]
    #[case::invalid_address(ContactType::Person, node_id_test(), &Some(Email::new("mail@mail.com").unwrap()),  &None, ProtocolValidationError::FieldEmpty(Field::Address))]
    #[case::blank_city(ContactType::Person, node_id_test(), &Some(Email::new("mail@mail.com").unwrap()),  &None, ProtocolValidationError::FieldEmpty(Field::Address))]
    fn test_validate_create_contact_errors(
        #[case] t: ContactType,
        #[case] node_id: NodeId,
        #[case] email: &Option<Email>,
        #[case] postal_address: &Option<PostalAddress>,
        #[case] expected: ProtocolValidationError,
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
}
