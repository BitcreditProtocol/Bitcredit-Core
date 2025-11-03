use super::*;
use crate::{
    external::{self, court::MockCourtClientApi, file_storage::MockFileStorageClientApi},
    service::{
        company_service::tests::get_valid_company_block,
        contact_service::tests::get_baseline_contact,
        notification_service::MockNotificationServiceApi,
    },
    tests::tests::{
        MockBillChainStoreApiMock, MockBillStoreApiMock, MockCompanyChainStoreApiMock,
        MockCompanyStoreApiMock, MockContactStoreApiMock, MockFileUploadStoreApiMock,
        MockIdentityChainStoreApiMock, MockIdentityStoreApiMock, MockMintStore,
        MockNostrContactStore, bill_id_test, bill_identified_participant_only_node_id,
        bill_participant_only_node_id, empty_address, empty_bill_identified_participant,
        empty_bitcredit_bill, empty_identity, init_test_cfg, node_id_test, node_id_test_other,
        node_id_test_other2, private_key_test, valid_payment_address_testnet,
    },
};
use bcr_ebill_core::{
    BitcoinAddress,
    address::Address,
    bill::{
        BillAcceptanceStatus, BillCallerActions, BillData, BillMintStatus, BillParticipants,
        BillPaymentStatus, BillRecourseStatus, BillSellStatus, BillStatus, PaidData, PaymentState,
    },
    blockchain::{
        Blockchain,
        bill::{
            BillBlock,
            block::{
                BillAcceptBlockData, BillIssueBlockData, BillOfferToSellBlockData,
                BillParticipantBlockData, BillRecourseBlockData, BillRecourseReasonBlockData,
                BillRejectBlockData, BillRejectToBuyBlockData, BillRequestRecourseBlockData,
                BillRequestToAcceptBlockData, BillRequestToPayBlockData, BillSellBlockData,
            },
        },
        identity::IdentityBlockchain,
    },
    city::City,
    constants::{
        ACCEPT_DEADLINE_SECONDS, DAY_IN_SECS, PAYMENT_DEADLINE_SECONDS, RECOURSE_DEADLINE_SECONDS,
    },
    contact::{BillIdentParticipant, BillParticipant},
    country::Country,
    date::Date,
    name::Name,
    sum::Sum,
    timestamp::Timestamp,
};
use external::{bitcoin::MockBitcoinClientApi, mint::MockMintClientApi};
use service::BillService;
use std::str::FromStr;
use std::{collections::HashMap, sync::Arc};

pub struct MockBillContext {
    pub contact_store: MockContactStoreApiMock,
    pub bill_store: MockBillStoreApiMock,
    pub bill_blockchain_store: MockBillChainStoreApiMock,
    pub identity_store: MockIdentityStoreApiMock,
    pub identity_chain_store: MockIdentityChainStoreApiMock,
    pub company_chain_store: MockCompanyChainStoreApiMock,
    pub company_store: MockCompanyStoreApiMock,
    pub file_upload_store: MockFileUploadStoreApiMock,
    pub file_upload_client: MockFileStorageClientApi,
    pub notification_service: MockNotificationServiceApi,
    pub mint_store: MockMintStore,
    pub mint_client: MockMintClientApi,
    pub court_client: MockCourtClientApi,
    pub nostr_contact_store: MockNostrContactStore,
}

pub fn get_baseline_identity() -> IdentityWithAll {
    let keys = BcrKeys::from_private_key(&private_key_test()).unwrap();
    let mut identity = empty_identity();
    identity.name = Name::new("drawer").unwrap();
    identity.node_id = NodeId::new(keys.pub_key(), bitcoin::Network::Testnet);
    identity.postal_address.country = Some(Country::AT);
    identity.postal_address.city = Some(City::new("Vienna").unwrap());
    identity.postal_address.address = Some(Address::new("Hayekweg 5").unwrap());
    identity.nostr_relays = vec![url::Url::parse("ws://localhost:8080").unwrap()];
    IdentityWithAll {
        identity,
        key_pair: keys,
    }
}

pub fn get_baseline_cached_bill(id: BillId) -> BitcreditBillResult {
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
            all_participant_node_ids: vec![
                node_id_test(),
                node_id_test_other(),
                node_id_test_other2(),
            ],
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

pub fn get_baseline_bill(bill_id: &BillId) -> BitcreditBill {
    let mut bill = empty_bitcredit_bill();
    let keys = BcrKeys::new();

    bill.maturity_date = Date::new("2099-10-15").unwrap();
    let mut payee = empty_bill_identified_participant();
    payee.name = Name::new("payee").unwrap();
    payee.node_id = NodeId::new(keys.pub_key(), bitcoin::Network::Testnet);
    bill.payee = BillParticipant::Ident(payee);
    bill.drawee = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
    bill.id = bill_id.to_owned();
    bill
}

pub fn get_genesis_chain(bill: Option<BitcreditBill>) -> BillBlockchain {
    let bill = bill.unwrap_or(get_baseline_bill(&bill_id_test()));
    BillBlockchain::new(
        &BillIssueBlockData::from(bill, None, Timestamp::new(1731593920).unwrap()),
        get_baseline_identity().key_pair,
        None,
        BcrKeys::from_private_key(&private_key_test()).unwrap(),
        Timestamp::new(1731593920).unwrap(),
    )
    .unwrap()
}

pub fn get_service(mut ctx: MockBillContext) -> BillService {
    init_test_cfg();
    let mut bitcoin_client = MockBitcoinClientApi::new();
    bitcoin_client
        .expect_check_payment_for_address()
        .returning(|_, _| {
            Ok(PaymentState::PaidConfirmed(PaidData {
                block_time: Timestamp::new(1731593928).unwrap(),
                block_hash: "000000000061ad7b0d52af77e5a9dbcdc421bf00e93992259f16b2cf2693c4b1"
                    .into(),
                confirmations: 7,
                tx_id: "80e4dc03b2ea934c97e265fa1855eba5c02788cb269e3f43a8e9a7bb0e114e2c".into(),
            }))
        });
    bitcoin_client
        .expect_get_combined_private_descriptor()
        .returning(|_, _| {
            Ok(String::from(
                "wpkh(cNjLH9K88VEhLeinPJkgPCZJZ9vNdi2L2UiTBuEfy4gSbTsMvvJg)",
            ))
        });
    bitcoin_client
        .expect_get_address_to_pay()
        .returning(|_, _| {
            Ok(BitcoinAddress::from_str("tb1qssh7nk78mm35h75dg4th77zqz4qk3eay68krf9").unwrap())
        });
    bitcoin_client
        .expect_get_mempool_link_for_address()
        .returning(|_| {
            String::from(
                "https://esplora.minibill.tech/testnet/address/1Jfn2nZcJ4T7bhE8FdMRz8T3P3YV4LsWn2",
            )
        });
    bitcoin_client.expect_generate_link_to_pay().returning(|_,_,_| String::from("bitcoin:1Jfn2nZcJ4T7bhE8FdMRz8T3P3YV4LsWn2?amount=0.01&message=Payment in relation to bill some bill"));
    ctx.nostr_contact_store
        .expect_by_node_id()
        .returning(|_| Ok(None));
    ctx.contact_store.expect_get().returning(|node_id| {
        let mut contact = get_baseline_contact();
        contact.node_id = node_id.to_owned();
        Ok(Some(contact))
    });
    ctx.contact_store
        .expect_get_map()
        .returning(|| Ok(HashMap::new()));
    ctx.identity_chain_store
        .expect_get_latest_block()
        .returning(|| {
            let identity = empty_identity();
            Ok(IdentityBlockchain::new(
                &identity.into(),
                &BcrKeys::new(),
                Timestamp::new(1731593928).unwrap(),
            )
            .unwrap()
            .get_latest_block()
            .clone())
        });
    ctx.company_chain_store
        .expect_get_latest_block()
        .returning(|_| Ok(get_valid_company_block()));
    ctx.identity_chain_store
        .expect_add_block()
        .returning(|_| Ok(()));
    ctx.company_chain_store
        .expect_add_block()
        .returning(|_, _| Ok(()));
    ctx.bill_blockchain_store
        .expect_add_block()
        .returning(|_, _| Ok(()));
    ctx.bill_store.expect_get_keys().returning(|_| {
        Ok(BillKeys {
            private_key: private_key_test(),
            public_key: node_id_test().pub_key(),
        })
    });
    let payment_state_paid = PaymentState::PaidConfirmed(PaidData {
        block_time: Timestamp::new(1731593928).unwrap(),
        block_hash: "000000000061ad7b0d52af77e5a9dbcdc421bf00e93992259f16b2cf2693c4b1".into(),
        confirmations: 7,
        tx_id: "80e4dc03b2ea934c97e265fa1855eba5c02788cb269e3f43a8e9a7bb0e114e2c".into(),
    });
    let payment_state_clone = payment_state_paid.clone();
    let payment_state_clone2 = payment_state_paid.clone();
    ctx.bill_store
        .expect_get_payment_state()
        .returning(move |_| Ok(Some(payment_state_clone.clone())));
    ctx.bill_store
        .expect_get_offer_to_sell_payment_state()
        .returning(move |_, _| Ok(Some(payment_state_clone2.clone())));
    ctx.bill_store
        .expect_get_recourse_payment_state()
        .returning(move |_, _| Ok(Some(payment_state_paid.clone())));
    ctx.bill_store
        .expect_get_bill_from_cache()
        .returning(|_, _| Ok(None));
    ctx.bill_store
        .expect_get_bills_from_cache()
        .returning(|_, _| Ok(vec![]));
    ctx.bill_store
        .expect_invalidate_bill_in_cache()
        .returning(|_| Ok(()));
    ctx.notification_service
        .expect_get_active_bill_notifications()
        .returning(|_| HashMap::new());
    ctx.bill_store
        .expect_save_bill_to_cache()
        .returning(|_, _, _| Ok(()));
    ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
    ctx.identity_store
        .expect_get()
        .returning(|| Ok(get_baseline_identity().identity));
    ctx.identity_store
        .expect_get_full()
        .returning(|| Ok(get_baseline_identity()));
    ctx.mint_store
        .expect_exists_for_bill()
        .returning(|_, _| Ok(false));
    BillService::new(
        Arc::new(ctx.bill_store),
        Arc::new(ctx.bill_blockchain_store),
        Arc::new(ctx.identity_store),
        Arc::new(ctx.file_upload_store),
        Arc::new(ctx.file_upload_client),
        Arc::new(bitcoin_client),
        Arc::new(ctx.notification_service),
        Arc::new(ctx.identity_chain_store),
        Arc::new(ctx.company_chain_store),
        Arc::new(ctx.contact_store),
        Arc::new(ctx.company_store),
        Arc::new(ctx.mint_store),
        Arc::new(ctx.mint_client),
        Arc::new(ctx.court_client),
        Arc::new(ctx.nostr_contact_store),
    )
}

pub fn get_ctx() -> MockBillContext {
    MockBillContext {
        bill_store: MockBillStoreApiMock::new(),
        bill_blockchain_store: MockBillChainStoreApiMock::new(),
        identity_store: MockIdentityStoreApiMock::new(),
        file_upload_store: MockFileUploadStoreApiMock::new(),
        file_upload_client: MockFileStorageClientApi::new(),
        identity_chain_store: MockIdentityChainStoreApiMock::new(),
        company_chain_store: MockCompanyChainStoreApiMock::new(),
        contact_store: MockContactStoreApiMock::new(),
        company_store: MockCompanyStoreApiMock::new(),
        notification_service: MockNotificationServiceApi::new(),
        mint_store: MockMintStore::new(),
        mint_client: MockMintClientApi::new(),
        court_client: MockCourtClientApi::new(),
        nostr_contact_store: MockNostrContactStore::new(),
    }
}

pub fn request_to_recourse_block(
    id: &BillId,
    first_block: &BillBlock,
    recoursee: &BillIdentParticipant,
    ts: Option<Timestamp>,
) -> BillBlock {
    let timestamp = ts.unwrap_or(first_block.timestamp + 1);
    BillBlock::create_block_for_request_recourse(
        id.to_owned(),
        first_block,
        &BillRequestRecourseBlockData {
            recourser: BillParticipant::Ident(bill_identified_participant_only_node_id(
                node_id_test(),
            ))
            .into(),
            recoursee: recoursee.to_owned().into(),
            sum: Sum::new_sat(15000).expect("sat works"),
            recourse_reason: BillRecourseReasonBlockData::Pay,
            signatory: None,
            signing_timestamp: timestamp,
            signing_address: Some(empty_address()),
            recourse_deadline_timestamp: timestamp + 2 * RECOURSE_DEADLINE_SECONDS,
        },
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        None,
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        timestamp,
    )
    .expect("block could not be created")
}

pub fn recourse_block(
    id: &BillId,
    first_block: &BillBlock,
    recoursee: &BillIdentParticipant,
) -> BillBlock {
    BillBlock::create_block_for_recourse(
        id.to_owned(),
        first_block,
        &BillRecourseBlockData {
            recourser: BillParticipant::Ident(bill_identified_participant_only_node_id(
                node_id_test(),
            ))
            .into(),
            recoursee: recoursee.to_owned().into(),
            sum: Sum::new_sat(15000).expect("sat works"),
            recourse_reason: BillRecourseReasonBlockData::Pay,
            signatory: None,
            signing_timestamp: first_block.timestamp + 1,
            signing_address: Some(empty_address()),
        },
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        None,
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        first_block.timestamp + 1,
    )
    .expect("block could not be created")
}

pub fn reject_recourse_block(id: &BillId, first_block: &BillBlock) -> BillBlock {
    BillBlock::create_block_for_reject_to_pay_recourse(
        id.to_owned(),
        first_block,
        &BillRejectBlockData {
            rejecter: bill_identified_participant_only_node_id(node_id_test()).into(),
            signatory: None,
            signing_timestamp: first_block.timestamp,
            signing_address: empty_address(),
        },
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        None,
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        first_block.timestamp,
    )
    .expect("block could not be created")
}

pub fn request_to_accept_block(
    id: &BillId,
    first_block: &BillBlock,
    ts: Option<Timestamp>,
) -> BillBlock {
    let timestamp = ts.unwrap_or(first_block.timestamp + 1);
    BillBlock::create_block_for_request_to_accept(
        id.to_owned(),
        first_block,
        &BillRequestToAcceptBlockData {
            requester: BillParticipantBlockData::Ident(
                bill_identified_participant_only_node_id(node_id_test()).into(),
            ),
            signatory: None,
            signing_timestamp: timestamp,
            signing_address: Some(empty_address()),
            acceptance_deadline_timestamp: timestamp + 2 * ACCEPT_DEADLINE_SECONDS,
        },
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        None,
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        timestamp,
    )
    .expect("block could not be created")
}

pub fn reject_accept_block(id: &BillId, first_block: &BillBlock) -> BillBlock {
    BillBlock::create_block_for_reject_to_accept(
        id.to_owned(),
        first_block,
        &BillRejectBlockData {
            rejecter: bill_identified_participant_only_node_id(node_id_test()).into(),
            signatory: None,
            signing_timestamp: first_block.timestamp,
            signing_address: empty_address(),
        },
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        None,
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        first_block.timestamp,
    )
    .expect("block could not be created")
}

pub fn offer_to_sell_block(
    id: &BillId,
    first_block: &BillBlock,
    buyer: &BillIdentParticipant,
    ts: Option<Timestamp>,
) -> BillBlock {
    let timestamp = ts.unwrap_or(first_block.timestamp + 1);
    BillBlock::create_block_for_offer_to_sell(
        id.to_owned(),
        first_block,
        &BillOfferToSellBlockData {
            seller: BillParticipantBlockData::Ident(
                bill_identified_participant_only_node_id(node_id_test()).into(),
            ),
            buyer: BillParticipantBlockData::Ident(buyer.to_owned().into()),
            sum: Sum::new_sat(15000).expect("sat works"),
            payment_address: valid_payment_address_testnet(),
            signatory: None,
            signing_timestamp: timestamp,
            signing_address: Some(empty_address()),
            buying_deadline_timestamp: timestamp + 2 * DAY_IN_SECS,
        },
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        None,
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        timestamp,
    )
    .expect("block could not be created")
}

pub fn reject_buy_block(id: &BillId, first_block: &BillBlock) -> BillBlock {
    BillBlock::create_block_for_reject_to_buy(
        id.to_owned(),
        first_block,
        &BillRejectToBuyBlockData {
            rejecter: bill_participant_only_node_id(node_id_test()).into(),
            signatory: None,
            signing_timestamp: first_block.timestamp,
            signing_address: Some(empty_address()),
        },
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        None,
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        first_block.timestamp,
    )
    .expect("block could not be created")
}

pub fn sell_block(id: &BillId, first_block: &BillBlock, buyer: &BillIdentParticipant) -> BillBlock {
    BillBlock::create_block_for_sell(
        id.to_owned(),
        first_block,
        &BillSellBlockData {
            seller: BillParticipantBlockData::Ident(
                bill_identified_participant_only_node_id(node_id_test()).into(),
            ),
            buyer: BillParticipantBlockData::Ident(buyer.to_owned().into()),
            payment_address: valid_payment_address_testnet(),
            sum: Sum::new_sat(15000).expect("sat works"),
            signatory: None,
            signing_timestamp: first_block.timestamp + 1,
            signing_address: Some(empty_address()),
        },
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        None,
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        first_block.timestamp + 1,
    )
    .expect("block could not be created")
}

pub fn accept_block(id: &BillId, first_block: &BillBlock) -> BillBlock {
    BillBlock::create_block_for_accept(
        id.to_owned(),
        first_block,
        &BillAcceptBlockData {
            accepter: bill_identified_participant_only_node_id(node_id_test()).into(),
            signatory: None,
            signing_timestamp: first_block.timestamp + 1,
            signing_address: empty_address(),
        },
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        None,
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        first_block.timestamp + 1,
    )
    .expect("block could not be created")
}

pub fn request_to_pay_block(
    id: &BillId,
    first_block: &BillBlock,
    ts: Option<Timestamp>,
) -> BillBlock {
    let timestamp = ts.unwrap_or(first_block.timestamp + 1);
    BillBlock::create_block_for_request_to_pay(
        id.to_owned(),
        first_block,
        &BillRequestToPayBlockData {
            requester: BillParticipantBlockData::Ident(
                bill_identified_participant_only_node_id(node_id_test()).into(),
            ),
            currency: Currency::sat(),
            signatory: None,
            signing_timestamp: timestamp,
            signing_address: Some(empty_address()),
            payment_deadline_timestamp: timestamp + 2 * PAYMENT_DEADLINE_SECONDS,
        },
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        None,
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        timestamp,
    )
    .expect("block could not be created")
}

pub fn reject_to_pay_block(id: &BillId, first_block: &BillBlock) -> BillBlock {
    BillBlock::create_block_for_reject_to_pay(
        id.to_owned(),
        first_block,
        &BillRejectBlockData {
            rejecter: bill_identified_participant_only_node_id(node_id_test()).into(),
            signatory: None,
            signing_timestamp: first_block.timestamp + 1,
            signing_address: empty_address(),
        },
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        None,
        &BcrKeys::from_private_key(&private_key_test()).unwrap(),
        first_block.timestamp + 1,
    )
    .expect("block could not be created")
}

pub fn bill_keys() -> BillKeys {
    BillKeys {
        private_key: private_key_test(),
        public_key: node_id_test().pub_key(),
    }
}

pub fn safe_deadline_ts(min_deadline: u64) -> Timestamp {
    Timestamp::now() + 2 * min_deadline
}
