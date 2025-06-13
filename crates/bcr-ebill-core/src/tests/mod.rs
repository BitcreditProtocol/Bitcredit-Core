#[cfg(test)]
#[allow(clippy::module_inception)]
pub mod tests {
    use std::str::FromStr;

    use crate::bill::BillId;
    use crate::contact::BillParticipant;
    use crate::identity::IdentityType;
    use crate::{
        Field, OptionalPostalAddress, PostalAddress, ValidationError,
        bill::{BillKeys, BitcreditBill},
        contact::{BillIdentParticipant, ContactType},
        identity::Identity,
    };
    use crate::{NodeId, Validate};
    use borsh::BorshDeserialize;
    use rstest::rstest;
    use serde::{Deserialize, Serialize};

    pub fn valid_address() -> PostalAddress {
        PostalAddress {
            country: "AT".into(),
            city: "Vienna".into(),
            zip: Some("1010".into()),
            address: "Kärntner Straße 1".into(),
        }
    }

    pub fn invalid_address() -> PostalAddress {
        PostalAddress {
            country: "".into(),
            city: "".into(),
            zip: Some("".into()),
            address: "".into(),
        }
    }

    #[rstest]
    #[case::empty_country( PostalAddress { country: "".into(), ..valid_address() }, ValidationError::FieldEmpty(Field::Country))]
    #[case::blank_country( PostalAddress { country: "  ".into(), ..valid_address() }, ValidationError::FieldEmpty(Field::Country))]
    #[case::empty_city( PostalAddress { city: "".into(), ..valid_address() }, ValidationError::FieldEmpty(Field::City))]
    #[case::blank_city( PostalAddress { city: "  ".into(), ..valid_address() }, ValidationError::FieldEmpty(Field::City))]
    #[case::empty_zip( PostalAddress { zip: Some("".into()), ..valid_address() }, ValidationError::FieldEmpty(Field::Zip))]
    #[case::blank_zip(PostalAddress { zip: Some("   ".into()), ..valid_address() }, ValidationError::FieldEmpty(Field::Zip))]
    #[case::empty_address( PostalAddress { address: "".into(), ..valid_address() }, ValidationError::FieldEmpty(Field::Address))]
    #[case::blank_address(PostalAddress { address: "  ".into(), ..valid_address() }, ValidationError::FieldEmpty(Field::Address))]
    fn test_invalid_address_cases(
        #[case] address: PostalAddress,
        #[case] expected_error: ValidationError,
    ) {
        assert_eq!(address.validate(), Err(expected_error));
    }

    #[rstest]
    #[case::baseline(valid_address())]
    #[case::spaced_country(PostalAddress { zip: Some("1020".into()), country: " AT ".into(), ..valid_address() })]
    #[case::no_zip( PostalAddress { zip: None, ..valid_address() },)]
    #[case::spaced_zip(PostalAddress { zip: Some(" Some Street 1 ".into()), ..valid_address() })]
    #[case::spaced_zip_address(PostalAddress { zip: Some(" 10101 ".into()), address: " 56 Rue de Paris ".into(), ..valid_address() })]
    fn test_valid_addresses(#[case] address: PostalAddress) {
        assert_eq!(address.validate(), Ok(()));
    }

    pub fn valid_optional_address() -> OptionalPostalAddress {
        OptionalPostalAddress {
            country: Some("AT".into()),
            city: Some("Vienna".into()),
            zip: Some("1010".into()),
            address: Some("Kärntner Straße 1".into()),
        }
    }

    #[test]
    fn test_valid_optional_address() {
        let address = valid_optional_address();
        assert_eq!(address.validate(), Ok(()));
        assert_eq!(
            OptionalPostalAddress {
                country: None,
                city: None,
                zip: None,
                address: None
            }
            .validate(),
            Ok(())
        );
    }

    #[rstest]
    #[case::empty_country( OptionalPostalAddress { country: Some("".into()), ..valid_optional_address() }, ValidationError::FieldEmpty(Field::Country))]
    #[case::blank_country( OptionalPostalAddress { country: Some("  ".into()), ..valid_optional_address() }, ValidationError::FieldEmpty(Field::Country))]
    #[case::empty_city( OptionalPostalAddress { city: Some("".into()), ..valid_optional_address() }, ValidationError::FieldEmpty(Field::City))]
    #[case::blank_city( OptionalPostalAddress { city: Some("\n\t".into()), ..valid_optional_address() }, ValidationError::FieldEmpty(Field::City))]
    #[case::empty_zip( OptionalPostalAddress { zip: Some("".into()), ..valid_optional_address() }, ValidationError::FieldEmpty(Field::Zip))]
    #[case::blank_zip( OptionalPostalAddress { zip: Some("  ".into()), ..valid_optional_address() }, ValidationError::FieldEmpty(Field::Zip))]
    #[case::empty_address( OptionalPostalAddress { address: Some("".into()), ..valid_optional_address() }, ValidationError::FieldEmpty(Field::Address))]
    #[case::blank_address( OptionalPostalAddress { address: Some("    ".into()), ..valid_optional_address() }, ValidationError::FieldEmpty(Field::Address))]
    fn test_optional_address(
        #[case] address: OptionalPostalAddress,
        #[case] expected_error: ValidationError,
    ) {
        assert_eq!(address.validate(), Err(expected_error));
    }

    pub fn empty_identity() -> Identity {
        Identity {
            t: IdentityType::Ident,
            node_id: node_id_test(),
            name: "some name".to_string(),
            email: Some("some@example.com".to_string()),
            postal_address: valid_optional_address(),
            date_of_birth: None,
            country_of_birth: None,
            city_of_birth: None,
            identification_number: None,
            nostr_relays: vec![],
            profile_picture_file: None,
            identity_document_file: None,
        }
    }

    pub fn valid_bill_participant() -> BillParticipant {
        BillParticipant::Ident(BillIdentParticipant {
            t: ContactType::Person,
            node_id: node_id_test(),
            name: "Johanna Smith".into(),
            postal_address: valid_address(),
            email: None,
            nostr_relays: vec![],
        })
    }

    pub fn valid_other_bill_participant() -> BillParticipant {
        BillParticipant::Ident(BillIdentParticipant {
            t: ContactType::Person,
            node_id: node_id_test_other(),
            name: "John Smith".into(),
            postal_address: valid_address(),
            email: None,
            nostr_relays: vec![],
        })
    }

    pub fn valid_bill_identified_participant() -> BillIdentParticipant {
        BillIdentParticipant {
            t: ContactType::Person,
            node_id: node_id_test(),
            name: "Johanna Smith".into(),
            postal_address: valid_address(),
            email: None,
            nostr_relays: vec![],
        }
    }

    pub fn valid_other_bill_identified_participant() -> BillIdentParticipant {
        BillIdentParticipant {
            t: ContactType::Person,
            node_id: node_id_test_other(),
            name: "John Smith".into(),
            postal_address: valid_address(),
            email: None,
            nostr_relays: vec![],
        }
    }

    pub fn empty_bill_identified_participant() -> BillIdentParticipant {
        BillIdentParticipant {
            t: ContactType::Person,
            node_id: node_id_test(),
            name: "some name".to_string(),
            postal_address: valid_address(),
            email: None,
            nostr_relays: vec![],
        }
    }

    pub fn bill_participant_only_node_id(node_id: NodeId) -> BillParticipant {
        BillParticipant::Ident(BillIdentParticipant {
            t: ContactType::Person,
            node_id,
            name: "some name".to_string(),
            postal_address: valid_address(),
            email: None,
            nostr_relays: vec![],
        })
    }

    pub fn bill_identified_participant_only_node_id(node_id: NodeId) -> BillIdentParticipant {
        BillIdentParticipant {
            t: ContactType::Person,
            node_id,
            name: "some name".to_string(),
            postal_address: valid_address(),
            email: None,
            nostr_relays: vec![],
        }
    }

    pub fn empty_bitcredit_bill() -> BitcreditBill {
        BitcreditBill {
            id: bill_id_test(),
            country_of_issuing: "AT".to_string(),
            city_of_issuing: "Vienna".to_string(),
            drawee: empty_bill_identified_participant(),
            drawer: empty_bill_identified_participant(),
            payee: valid_bill_participant(),
            endorsee: None,
            currency: "sat".to_string(),
            sum: 500,
            maturity_date: "2099-11-12".to_string(),
            issue_date: "2099-08-12".to_string(),
            city_of_payment: "Vienna".to_string(),
            country_of_payment: "AT".to_string(),
            language: "DE".to_string(),
            files: vec![],
        }
    }

    pub fn get_bill_keys() -> BillKeys {
        BillKeys {
            private_key: private_key_test(),
            public_key: node_id_test().pub_key(),
        }
    }

    pub fn node_id_test() -> NodeId {
        NodeId::from_str("bitcrt02295fb5f4eeb2f21e01eaf3a2d9a3be10f39db870d28f02146130317973a40ac0")
            .unwrap()
    }

    pub fn node_id_test_other() -> NodeId {
        NodeId::from_str("bitcrt03f9f94d1fdc2090d46f3524807e3f58618c36988e69577d70d5d4d1e9e9645a4f")
            .unwrap()
    }

    pub fn node_id_regtest() -> NodeId {
        NodeId::from_str("bitcrr02295fb5f4eeb2f21e01eaf3a2d9a3be10f39db870d28f02146130317973a40ac0")
            .unwrap()
    }

    // bitcrt285psGq4Lz4fEQwfM3We5HPznJq8p1YvRaddszFaU5dY
    pub fn bill_id_test() -> BillId {
        BillId::new(
            secp256k1::PublicKey::from_str(
                "026423b7d36d05b8d50a89a1b4ef2a06c88bcd2c5e650f25e122fa682d3b39686c",
            )
            .unwrap(),
            bitcoin::Network::Testnet,
        )
    }

    pub fn private_key_test() -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_str(
            "d1ff7427912d3b81743d3b67ffa1e65df2156d3dab257316cbc8d0f35eeeabe9",
        )
        .unwrap()
    }

    pub const TEST_NODE_ID_SECP: &str =
        "03205b8dec12bc9e879f5b517aa32192a2550e88adcee3e54ec2c7294802568fef";

    pub const TEST_NODE_ID_SECP_AS_NPUB_HEX: &str =
        "205b8dec12bc9e879f5b517aa32192a2550e88adcee3e54ec2c7294802568fef";

    pub const VALID_PAYMENT_ADDRESS_TESTNET: &str = "tb1qteyk7pfvvql2r2zrsu4h4xpvju0nz7ykvguyk0";

    pub const OTHER_VALID_PAYMENT_ADDRESS_TESTNET: &str = "msAPAcTqHqosWu3gaVwATTupxdHSY2wyQn";

    #[derive(
        Debug,
        Clone,
        Eq,
        PartialEq,
        borsh_derive::BorshSerialize,
        borsh_derive::BorshDeserialize,
        Serialize,
        Deserialize,
    )]
    pub struct Test {
        pub node_id: NodeId,
    }

    #[test]
    fn test_node_id() {
        // parsing
        let valid_node_id =
            "bitcrt03205b8dec12bc9e879f5b517aa32192a2550e88adcee3e54ec2c7294802568fef";
        let parsed = NodeId::from_str(valid_node_id).unwrap();
        assert_eq!(
            parsed.pub_key(),
            bitcoin::secp256k1::PublicKey::from_str(TEST_NODE_ID_SECP).unwrap()
        );
        assert_eq!(
            parsed.npub(),
            nostr::PublicKey::from_str(TEST_NODE_ID_SECP_AS_NPUB_HEX).unwrap()
        );
        assert!(parsed.equals_npub(&parsed.npub()));
        assert!(matches!(parsed.network(), bitcoin::Network::Testnet));
        assert_eq!(parsed.to_string(), valid_node_id);

        let valid_node_id_mainnet =
            "bitcrm03205b8dec12bc9e879f5b517aa32192a2550e88adcee3e54ec2c7294802568fef";
        assert!(matches!(
            NodeId::from_str(valid_node_id_mainnet).unwrap().network(),
            bitcoin::Network::Bitcoin
        ));
        let valid_node_id_regtest =
            "bitcrr03205b8dec12bc9e879f5b517aa32192a2550e88adcee3e54ec2c7294802568fef";
        assert!(matches!(
            NodeId::from_str(valid_node_id_regtest).unwrap().network(),
            bitcoin::Network::Regtest
        ));
        let valid_node_id_testnet4 =
            "bitcrT03205b8dec12bc9e879f5b517aa32192a2550e88adcee3e54ec2c7294802568fef";
        assert!(matches!(
            NodeId::from_str(valid_node_id_testnet4).unwrap().network(),
            bitcoin::Network::Testnet4
        ));
        // parsing errors
        assert!(matches!(
            NodeId::from_str("invalid_nonsense").unwrap_err(),
            ValidationError::InvalidNodeId
        ));
        assert!(matches!(
            NodeId::from_str("bitcrinvalid_nonsense").unwrap_err(),
            ValidationError::InvalidNodeId
        ));
        assert!(matches!(
            NodeId::from_str("bitcrtinvalid_nonsense").unwrap_err(),
            ValidationError::InvalidNodeId
        ));
        assert!(matches!(
            NodeId::from_str(
                "bitcrt205b8dec12bc9e879f5b517aa32192a2550e88adcee3e54ec2c7294802568fef"
            )
            .unwrap_err(),
            ValidationError::InvalidNodeId
        ));
        assert!(matches!(
            NodeId::from_str(
                "bitcrk03205b8dec12bc9e879f5b517aa32192a2550e88adcee3e54ec2c7294802568fef"
            )
            .unwrap_err(),
            ValidationError::InvalidNodeId
        ));
        assert!(matches!(
            NodeId::from_str("bitcrt").unwrap_err(),
            ValidationError::InvalidNodeId
        ));
        assert!(matches!(
            NodeId::from_str("").unwrap_err(),
            ValidationError::InvalidNodeId
        ));

        // serialization / deserialization
        let test = Test {
            node_id: parsed.clone(),
        };

        let json = serde_json::to_string(&test).unwrap();
        assert_eq!(
            "{\"node_id\":\"bitcrt03205b8dec12bc9e879f5b517aa32192a2550e88adcee3e54ec2c7294802568fef\"}",
            json
        );
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(test, deserialized);
        assert_eq!(parsed, deserialized.node_id);

        let borsh = borsh::to_vec(&parsed).unwrap();
        let borsh_de = NodeId::try_from_slice(&borsh).unwrap();
        assert_eq!(parsed, borsh_de);

        let borsh_test = borsh::to_vec(&test).unwrap();
        let borsh_de_test = Test::try_from_slice(&borsh_test).unwrap();
        assert_eq!(test, borsh_de_test);
        assert_eq!(parsed, borsh_de_test.node_id);
    }

    #[derive(
        Debug,
        Clone,
        Eq,
        PartialEq,
        borsh_derive::BorshSerialize,
        borsh_derive::BorshDeserialize,
        Serialize,
        Deserialize,
    )]
    pub struct TestBill {
        pub bill_id: BillId,
    }

    #[test]
    fn test_bill_id() {
        // parsing
        let valid_bill_id = "bitcrtBBT5a1eNZ8zEUkU2rppXBDrZJjARoxPkZtBgFo2RLz3y";
        let parsed = BillId::from_str(valid_bill_id).unwrap();
        assert_eq!(parsed.id(), "BBT5a1eNZ8zEUkU2rppXBDrZJjARoxPkZtBgFo2RLz3y");
        assert!(matches!(parsed.network(), bitcoin::Network::Testnet));
        assert_eq!(parsed.to_string(), valid_bill_id);

        let valid_bill_id_mainnet = "bitcrmCduj6HZ95qMWDaoDny26FMtyVycdGJRpn5wh6XCRFu14";
        assert!(matches!(
            BillId::from_str(valid_bill_id_mainnet).unwrap().network(),
            bitcoin::Network::Bitcoin
        ));
        let valid_bill_id_regtest = "bitcrrCduj6HZ95qMWDaoDny26FMtyVycdGJRpn5wh6XCRFu14";
        assert!(matches!(
            BillId::from_str(valid_bill_id_regtest).unwrap().network(),
            bitcoin::Network::Regtest
        ));
        let valid_bill_id_testnet4 = "bitcrTCduj6HZ95qMWDaoDny26FMtyVycdGJRpn5wh6XCRFu14";
        assert!(matches!(
            BillId::from_str(valid_bill_id_testnet4).unwrap().network(),
            bitcoin::Network::Testnet4
        ));
        // parsing errors
        assert!(matches!(
            BillId::from_str("invalid_nonsense").unwrap_err(),
            ValidationError::InvalidBillId
        ));
        assert!(matches!(
            BillId::from_str("bitcrinvalid_nonsense").unwrap_err(),
            ValidationError::InvalidBillId
        ));
        assert!(matches!(
            BillId::from_str("bitcrtinvalid_nonsense").unwrap_err(),
            ValidationError::InvalidBillId
        ));
        assert!(matches!(
            BillId::from_str("bitcrtBBT5a1eNZ8zEUkU2rppXBDrZJjARoxPkZtBgFo2RLz").unwrap_err(),
            ValidationError::InvalidBillId
        ));
        assert!(matches!(
            BillId::from_str("bitcrtBBT5a1eNZ8zEUkU2rppXBDrZJjARoxPkZtBgFo2RLz3yy").unwrap_err(),
            ValidationError::InvalidBillId
        ));
        assert!(matches!(
            BillId::from_str(
                "bitcrk03205b8dec12bc9e879f5b517aa32192a2550e88adcee3e54ec2c7294802568fef"
            )
            .unwrap_err(),
            ValidationError::InvalidBillId
        ));
        assert!(matches!(
            BillId::from_str("bitcrt").unwrap_err(),
            ValidationError::InvalidBillId
        ));
        assert!(matches!(
            BillId::from_str("").unwrap_err(),
            ValidationError::InvalidBillId
        ));

        // serialization / deserialization
        let test = TestBill {
            bill_id: parsed.clone(),
        };

        let json = serde_json::to_string(&test).unwrap();
        assert_eq!(
            "{\"bill_id\":\"bitcrtBBT5a1eNZ8zEUkU2rppXBDrZJjARoxPkZtBgFo2RLz3y\"}",
            json
        );
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(test, deserialized);
        assert_eq!(parsed, deserialized.bill_id);

        let borsh = borsh::to_vec(&parsed).unwrap();
        let borsh_de = BillId::try_from_slice(&borsh).unwrap();
        assert_eq!(parsed, borsh_de);

        let borsh_test = borsh::to_vec(&test).unwrap();
        let borsh_de_test = TestBill::try_from_slice(&borsh_test).unwrap();
        assert_eq!(test, borsh_de_test);
        assert_eq!(parsed, borsh_de_test.bill_id);
    }
}
