#[cfg(test)]
#[allow(clippy::module_inception)]
pub mod tests {
    use bcr_ebill_core::{
        OptionalPostalAddress, PostalAddress,
        bill::{
            BillAcceptanceStatus, BillData, BillKeys, BillMintStatus, BillParticipants,
            BillPaymentStatus, BillRecourseStatus, BillSellStatus, BillStatus, BitcreditBill,
            BitcreditBillResult,
        },
        contact::{BillIdentParticipant, BillParticipant, ContactType},
        identity::{Identity, IdentityType},
        util::BcrKeys,
    };

    pub fn empty_address() -> PostalAddress {
        PostalAddress {
            country: "".to_string(),
            city: "".to_string(),
            zip: None,
            address: "".to_string(),
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
            node_id: "".to_string(),
            name: "".to_string(),
            email: Some("".to_string()),
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
            node_id: "".to_string(),
            name: "".to_string(),
            postal_address: empty_address(),
            email: None,
            nostr_relays: vec![],
        }
    }

    pub fn bill_identified_participant_only_node_id(node_id: String) -> BillIdentParticipant {
        BillIdentParticipant {
            t: ContactType::Person,
            node_id,
            name: "".to_string(),
            postal_address: empty_address(),
            email: None,
            nostr_relays: vec![],
        }
    }

    pub fn empty_bitcredit_bill() -> BitcreditBill {
        BitcreditBill {
            id: "".to_string(),
            country_of_issuing: "".to_string(),
            city_of_issuing: "".to_string(),
            drawee: empty_bill_identified_participant(),
            drawer: empty_bill_identified_participant(),
            payee: BillParticipant::Ident(bill_identified_participant_only_node_id(
                BcrKeys::new().get_public_key(),
            )),
            endorsee: None,
            currency: "".to_string(),
            sum: 0,
            maturity_date: "".to_string(),
            issue_date: "".to_string(),
            city_of_payment: "".to_string(),
            country_of_payment: "".to_string(),
            language: "".to_string(),
            files: vec![],
        }
    }

    pub fn cached_bill(id: String) -> BitcreditBillResult {
        BitcreditBillResult {
            id,
            participants: BillParticipants {
                drawee: bill_identified_participant_only_node_id("drawee".to_string()),
                drawer: bill_identified_participant_only_node_id("drawer".to_string()),
                payee: BillParticipant::Ident(bill_identified_participant_only_node_id(
                    "payee".to_string(),
                )),
                endorsee: None,
                endorsements_count: 5,
                all_participant_node_ids: vec![],
            },
            data: BillData {
                language: "AT".to_string(),
                time_of_drawing: 1731593928,
                issue_date: "2024-05-01".to_string(),
                time_of_maturity: 1731593928,
                maturity_date: "2024-07-01".to_string(),
                country_of_issuing: "AT".to_string(),
                city_of_issuing: "Vienna".to_string(),
                country_of_payment: "AT".to_string(),
                city_of_payment: "Vienna".to_string(),
                currency: "sat".to_string(),
                sum: "15000".to_string(),
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
                },
                payment: BillPaymentStatus {
                    time_of_request_to_pay: None,
                    requested_to_pay: false,
                    paid: false,
                    request_to_pay_timed_out: false,
                    rejected_to_pay: false,
                },
                sell: BillSellStatus {
                    time_of_last_offer_to_sell: None,
                    sold: false,
                    offered_to_sell: false,
                    offer_to_sell_timed_out: false,
                    rejected_offer_to_sell: false,
                },
                recourse: BillRecourseStatus {
                    time_of_last_request_to_recourse: None,
                    recoursed: false,
                    requested_to_recourse: false,
                    request_to_recourse_timed_out: false,
                    rejected_request_to_recourse: false,
                },
                mint: BillMintStatus {
                    has_mint_requests: false,
                },
                redeemed_funds_available: false,
                has_requested_funds: false,
            },
            current_waiting_state: None,
        }
    }

    pub fn get_bill_keys() -> BillKeys {
        BillKeys {
            private_key: TEST_PRIVATE_KEY_SECP.to_owned(),
            public_key: TEST_PUB_KEY_SECP.to_owned(),
        }
    }

    pub const TEST_PUB_KEY_SECP: &str =
        "02295fb5f4eeb2f21e01eaf3a2d9a3be10f39db870d28f02146130317973a40ac0";

    pub const TEST_PRIVATE_KEY_SECP: &str =
        "d1ff7427912d3b81743d3b67ffa1e65df2156d3dab257316cbc8d0f35eeeabe9";

    pub const TEST_NODE_ID_SECP: &str =
        "03205b8dec12bc9e879f5b517aa32192a2550e88adcee3e54ec2c7294802568fef";
}
