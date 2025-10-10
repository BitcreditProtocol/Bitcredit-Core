#[cfg(test)]
#[allow(clippy::module_inception)]
pub mod tests {
    use std::str::FromStr;

    use crate::address::Address;
    use crate::bill::BillId;
    use crate::city::City;
    use crate::constants::CURRENCY_SAT;
    use crate::contact::BillParticipant;
    use crate::country::Country;
    use crate::date::Date;
    use crate::email::Email;
    use crate::identity::IdentityType;
    use crate::name::Name;
    use crate::util::date::now;
    use crate::zip::Zip;
    use crate::{NodeId, Validate};
    use crate::{
        OptionalPostalAddress, PostalAddress,
        bill::{BillKeys, BitcreditBill},
        contact::{BillIdentParticipant, ContactType},
        identity::Identity,
    };
    use borsh::BorshDeserialize;
    use rstest::rstest;
    use serde::{Deserialize, Serialize};

    pub fn valid_address() -> PostalAddress {
        PostalAddress {
            country: Country::AT,
            city: City::new("Vienna").unwrap(),
            zip: Some(Zip::new("1010").unwrap()),
            address: Address::new("Kärntner Straße 1").unwrap(),
        }
    }

    #[rstest]
    #[case::baseline(valid_address())]
    #[case::no_zip( PostalAddress { zip: None, ..valid_address() },)]
    #[case::spaced_zip(PostalAddress { zip: Some(Zip::new(" Some Street 1 ").unwrap()), ..valid_address() })]
    #[case::spaced_zip_address(PostalAddress { zip: Some(Zip::new(" 10101 ").unwrap()), address: Address::new(" 56 Rue de Paris ").unwrap(), ..valid_address() })]
    fn test_valid_addresses(#[case] address: PostalAddress) {
        assert_eq!(address.validate(), Ok(()));
    }

    pub fn valid_optional_address() -> OptionalPostalAddress {
        OptionalPostalAddress {
            country: Some(Country::AT),
            city: Some(City::new("Vienna").unwrap()),
            zip: Some(Zip::new("1010").unwrap()),
            address: Some(Address::new("Kärntner Straße 1").unwrap()),
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

    pub fn empty_identity() -> Identity {
        Identity {
            t: IdentityType::Ident,
            node_id: node_id_test(),
            name: Name::new("some name").unwrap(),
            email: Some(Email::new("some@example.com").unwrap()),
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
            name: Name::new("Johanna Smith").unwrap(),
            postal_address: valid_address(),
            email: None,
            nostr_relays: vec![],
        })
    }

    pub fn valid_other_bill_participant() -> BillParticipant {
        BillParticipant::Ident(BillIdentParticipant {
            t: ContactType::Person,
            node_id: node_id_test_other(),
            name: Name::new("John Smith").unwrap(),
            postal_address: valid_address(),
            email: None,
            nostr_relays: vec![],
        })
    }

    pub fn valid_bill_identified_participant() -> BillIdentParticipant {
        BillIdentParticipant {
            t: ContactType::Person,
            node_id: node_id_test(),
            name: Name::new("Johanna Smith").unwrap(),
            postal_address: valid_address(),
            email: None,
            nostr_relays: vec![],
        }
    }

    pub fn valid_other_bill_identified_participant() -> BillIdentParticipant {
        BillIdentParticipant {
            t: ContactType::Person,
            node_id: node_id_test_other(),
            name: Name::new("John Smith").unwrap(),
            postal_address: valid_address(),
            email: None,
            nostr_relays: vec![],
        }
    }

    pub fn empty_bill_identified_participant() -> BillIdentParticipant {
        BillIdentParticipant {
            t: ContactType::Person,
            node_id: node_id_test(),
            name: Name::new("some name").unwrap(),
            postal_address: valid_address(),
            email: None,
            nostr_relays: vec![],
        }
    }

    pub fn bill_participant_only_node_id(node_id: NodeId) -> BillParticipant {
        BillParticipant::Ident(BillIdentParticipant {
            t: ContactType::Person,
            node_id,
            name: Name::new("some name").unwrap(),
            postal_address: valid_address(),
            email: None,
            nostr_relays: vec![],
        })
    }

    pub fn bill_identified_participant_only_node_id(node_id: NodeId) -> BillIdentParticipant {
        BillIdentParticipant {
            t: ContactType::Person,
            node_id,
            name: Name::new("some name").unwrap(),
            postal_address: valid_address(),
            email: None,
            nostr_relays: vec![],
        }
    }

    pub fn empty_bitcredit_bill() -> BitcreditBill {
        BitcreditBill {
            id: bill_id_test(),
            country_of_issuing: Country::AT,
            city_of_issuing: City::new("Vienna").unwrap(),
            drawee: empty_bill_identified_participant(),
            drawer: empty_bill_identified_participant(),
            payee: valid_bill_participant(),
            endorsee: None,
            currency: CURRENCY_SAT.to_string(),
            sum: 500,
            maturity_date: Date::new("2099-11-12").unwrap(),
            issue_date: Date::new("2099-08-12").unwrap(),
            city_of_payment: City::new("Vienna").unwrap(),
            country_of_payment: Country::AT,
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
            bcr_common::core::Error::InvalidNodeId
        ));
        assert!(matches!(
            NodeId::from_str("bitcrinvalid_nonsense").unwrap_err(),
            bcr_common::core::Error::InvalidNodeId
        ));
        assert!(matches!(
            NodeId::from_str("bitcrtinvalid_nonsense").unwrap_err(),
            bcr_common::core::Error::InvalidNodeId
        ));
        assert!(matches!(
            NodeId::from_str(
                "bitcrt205b8dec12bc9e879f5b517aa32192a2550e88adcee3e54ec2c7294802568fef"
            )
            .unwrap_err(),
            bcr_common::core::Error::InvalidNodeId
        ));
        assert!(matches!(
            NodeId::from_str(
                "bitcrk03205b8dec12bc9e879f5b517aa32192a2550e88adcee3e54ec2c7294802568fef"
            )
            .unwrap_err(),
            bcr_common::core::Error::InvalidNodeId
        ));
        assert!(matches!(
            NodeId::from_str("bitcrt").unwrap_err(),
            bcr_common::core::Error::InvalidNodeId
        ));
        assert!(matches!(
            NodeId::from_str("").unwrap_err(),
            bcr_common::core::Error::InvalidNodeId
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
            bcr_common::core::Error::InvalidBillId
        ));
        assert!(matches!(
            BillId::from_str("bitcrinvalid_nonsense").unwrap_err(),
            bcr_common::core::Error::InvalidBillId
        ));
        assert!(matches!(
            BillId::from_str("bitcrtinvalid_nonsense").unwrap_err(),
            bcr_common::core::Error::InvalidBillId
        ));
        assert!(matches!(
            BillId::from_str("bitcrtBBT5a1eNZ8zEUkU2rppXBDrZJjARoxPkZtBgFo2RLz").unwrap_err(),
            bcr_common::core::Error::InvalidBillId
        ));
        assert!(matches!(
            BillId::from_str("bitcrtBBT5a1eNZ8zEUkU2rppXBDrZJjARoxPkZtBgFo2RLz3yy").unwrap_err(),
            bcr_common::core::Error::InvalidBillId
        ));
        assert!(matches!(
            BillId::from_str(
                "bitcrk03205b8dec12bc9e879f5b517aa32192a2550e88adcee3e54ec2c7294802568fef"
            )
            .unwrap_err(),
            bcr_common::core::Error::InvalidBillId
        ));
        assert!(matches!(
            BillId::from_str("bitcrt").unwrap_err(),
            bcr_common::core::Error::InvalidBillId
        ));
        assert!(matches!(
            BillId::from_str("").unwrap_err(),
            bcr_common::core::Error::InvalidBillId
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

    pub fn safe_deadline_ts(min_deadline: u64) -> u64 {
        now().timestamp() as u64 + 2 * min_deadline
    }
}
