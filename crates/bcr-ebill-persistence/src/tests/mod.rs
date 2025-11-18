#[cfg(test)]
#[allow(clippy::module_inception)]
pub mod tests {
    use std::str::FromStr;

    use bcr_common::core::{BillId, NodeId};
    use bcr_ebill_core::{
        application::{
            bill::{
                BillAcceptanceStatus, BillCallerActions, BillData, BillMintStatus,
                BillParticipants, BillPaymentStatus, BillRecourseStatus, BillSellStatus,
                BillStatus, BitcreditBillResult,
            },
            identity::Identity,
        },
        protocol::{
            Address, City, Country, Date, Email, Name, OptionalPostalAddress, PostalAddress,
            PublicKey, SecretKey, SignedEmailIdentityData, SignedIdentityProof, Sum, Timestamp,
            blockchain::{
                bill::{
                    BillHistory, BitcreditBill, ContactType,
                    participant::{BillIdentParticipant, BillParticipant},
                },
                identity::IdentityType,
            },
            crypto::BcrKeys,
        },
    };

    pub fn empty_address() -> PostalAddress {
        PostalAddress {
            country: Country::AT,
            city: City::new("Vienna").unwrap(),
            zip: None,
            address: Address::new("Praterstrasse 1").unwrap(),
        }
    }

    pub fn empty_optional_address() -> OptionalPostalAddress {
        OptionalPostalAddress {
            country: None,
            city: None,
            zip: None,
            address: None,
        }
    }

    pub fn empty_identity() -> Identity {
        Identity {
            t: IdentityType::Ident,
            node_id: node_id_test(),
            name: Name::new("Minka").unwrap(),
            email: Some(Email::new("test@example.com").unwrap()),
            postal_address: empty_optional_address(),
            date_of_birth: None,
            country_of_birth: None,
            city_of_birth: None,
            identification_number: None,
            nostr_relays: vec![],
            profile_picture_file: None,
            identity_document_file: None,
        }
    }

    pub fn empty_bill_identified_participant() -> BillIdentParticipant {
        BillIdentParticipant {
            t: ContactType::Person,
            node_id: node_id_test(),
            name: Name::new("Minka").unwrap(),
            postal_address: empty_address(),
            email: None,
            nostr_relays: vec![],
        }
    }

    pub fn bill_identified_participant_only_node_id(node_id: NodeId) -> BillIdentParticipant {
        BillIdentParticipant {
            t: ContactType::Person,
            node_id,
            name: Name::new("Minka").unwrap(),
            postal_address: empty_address(),
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
            payee: BillParticipant::Ident(bill_identified_participant_only_node_id(NodeId::new(
                BcrKeys::new().pub_key(),
                bitcoin::Network::Testnet,
            ))),
            endorsee: None,
            sum: Sum::new_sat(1500).expect("sat works"),
            maturity_date: Date::new("2025-03-15").unwrap(),
            issue_date: Date::new("2025-01-15").unwrap(),
            city_of_payment: City::new("Vienna").unwrap(),
            country_of_payment: Country::AT,
            files: vec![],
        }
    }

    pub fn cached_bill(id: BillId) -> BitcreditBillResult {
        BitcreditBillResult {
            id,
            participants: BillParticipants {
                drawee: bill_identified_participant_only_node_id(node_id_test()),
                drawer: bill_identified_participant_only_node_id(node_id_test_other()),
                payee: BillParticipant::Ident(bill_identified_participant_only_node_id(
                    node_id_test_other2(),
                )),
                endorsee: None,
                endorsements: vec![],
                endorsements_count: 5,
                all_participant_node_ids: vec![],
            },
            data: BillData {
                time_of_drawing: Timestamp::new(1731593928).unwrap(),
                issue_date: Date::new("2024-05-01").unwrap(),
                time_of_maturity: Timestamp::new(1731593928).unwrap(),
                maturity_date: Date::new("2024-07-01").unwrap(),
                country_of_issuing: Country::AT,
                city_of_issuing: City::new("Vienna").unwrap(),
                country_of_payment: Country::AT,
                city_of_payment: City::new("Vienna").unwrap(),
                sum: Sum::new_sat(15000).expect("sat works"),
                files: vec![],
                active_notification: None,
            },
            status: BillStatus {
                acceptance: BillAcceptanceStatus {
                    time_of_request_to_accept: None,
                    requested_to_accept: false,
                    accepted: false,
                    request_to_accept_timed_out: false,
                    rejected_to_accept: false,
                    acceptance_deadline_timestamp: None,
                },
                payment: BillPaymentStatus {
                    time_of_request_to_pay: None,
                    requested_to_pay: false,
                    paid: false,
                    request_to_pay_timed_out: false,
                    rejected_to_pay: false,
                    payment_deadline_timestamp: None,
                },
                sell: BillSellStatus {
                    time_of_last_offer_to_sell: None,
                    sold: false,
                    offered_to_sell: false,
                    offer_to_sell_timed_out: false,
                    rejected_offer_to_sell: false,
                    buying_deadline_timestamp: None,
                },
                recourse: BillRecourseStatus {
                    time_of_last_request_to_recourse: None,
                    recoursed: false,
                    requested_to_recourse: false,
                    request_to_recourse_timed_out: false,
                    rejected_request_to_recourse: false,
                    recourse_deadline_timestamp: None,
                },
                mint: BillMintStatus {
                    has_mint_requests: false,
                },
                redeemed_funds_available: false,
                has_requested_funds: false,
                last_block_time: Timestamp::new(1731593928).unwrap(),
            },
            current_waiting_state: None,
            history: BillHistory { blocks: vec![] },
            actions: BillCallerActions {
                bill_actions: vec![],
            },
        }
    }

    pub fn get_bill_keys() -> BcrKeys {
        BcrKeys::from_private_key(&private_key_test())
    }

    pub fn private_key_test() -> SecretKey {
        SecretKey::from_str("d1ff7427912d3b81743d3b67ffa1e65df2156d3dab257316cbc8d0f35eeeabe9")
            .unwrap()
    }

    pub fn node_id_test() -> NodeId {
        NodeId::from_str("bitcrt02295fb5f4eeb2f21e01eaf3a2d9a3be10f39db870d28f02146130317973a40ac0")
            .unwrap()
    }

    pub fn node_id_test_other() -> NodeId {
        NodeId::from_str("bitcrt03f9f94d1fdc2090d46f3524807e3f58618c36988e69577d70d5d4d1e9e9645a4f")
            .unwrap()
    }

    pub fn node_id_test_other2() -> NodeId {
        NodeId::from_str("bitcrt039180c169e5f6d7c579cf1cefa37bffd47a2b389c8125601f4068c87bea795943")
            .unwrap()
    }

    pub fn signed_identity_proof_test() -> (SignedIdentityProof, SignedEmailIdentityData) {
        let data = SignedEmailIdentityData {
            node_id: node_id_test(),
            company_node_id: None,
            email: Email::new("test@example.com").unwrap(),
            created_at: Timestamp::new(1731593929).unwrap(),
        };
        let proof = data.sign(&node_id_test(), &private_key_test()).unwrap();
        (proof, data)
    }

    // bitcrt285psGq4Lz4fEQwfM3We5HPznJq8p1YvRaddszFaU5dY
    pub fn bill_id_test() -> BillId {
        BillId::new(
            PublicKey::from_str(
                "026423b7d36d05b8d50a89a1b4ef2a06c88bcd2c5e650f25e122fa682d3b39686c",
            )
            .unwrap(),
            bitcoin::Network::Testnet,
        )
    }

    // bitcrt76LWp9iFregj9Lv1awLSfQAmjtDDinBR4GSCbNrEtqEe
    pub fn bill_id_test_other() -> BillId {
        BillId::new(
            PublicKey::from_str(
                "027a233c85a8f98e276e949ab94bba8bbc07b21946e50e388da767bcc6c95603ce",
            )
            .unwrap(),
            bitcoin::Network::Testnet,
        )
    }
}
