use crate::blockchain::bill::BillBlockchain;
use crate::data::{
    File,
    bill::{
        BillCombinedBitcoinKey, BillKeys, BillsBalanceOverview, BillsFilterRole, BitcreditBill,
        BitcreditBillResult, Endorsement, LightBitcreditBillResult, PastEndorsee,
    },
    contact::BillParticipant,
    identity::{Identity, IdentityWithAll},
    mint::MintRequestState,
};
use crate::util::BcrKeys;
use async_trait::async_trait;
use bcr_ebill_core::ServiceTraitBounds;
use bcr_ebill_core::bill::{BillAction, BillIssueData, PastPaymentResult};

pub use error::Error;
#[cfg(test)]
use mockall::automock;

/// Generic result type
pub type Result<T> = std::result::Result<T, error::Error>;

mod blocks;
mod data_fetching;
pub mod error;
mod issue;
mod payment;
mod propagation;
pub mod service;
#[cfg(test)]
pub mod test_utils;

#[cfg(test)]
impl ServiceTraitBounds for MockBillServiceApi {}

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait BillServiceApi: ServiceTraitBounds {
    /// Get bill balances
    async fn get_bill_balances(
        &self,
        currency: &str,
        current_identity_node_id: &str,
    ) -> Result<BillsBalanceOverview>;

    /// Search for bills
    async fn search_bills(
        &self,
        currency: &str,
        search_term: &Option<String>,
        date_range_from: Option<u64>,
        date_range_to: Option<u64>,
        role: &BillsFilterRole,
        current_identity_node_id: &str,
    ) -> Result<Vec<LightBitcreditBillResult>>;

    /// Gets all bills
    async fn get_bills(&self, current_identity_node_id: &str) -> Result<Vec<BitcreditBillResult>>;

    /// Gets the combined bitcoin private key for a given bill
    async fn get_combined_bitcoin_key_for_bill(
        &self,
        bill_id: &str,
        caller_public_data: &BillParticipant,
        caller_keys: &BcrKeys,
    ) -> Result<BillCombinedBitcoinKey>;

    /// Gets the detail for the given bill id
    async fn get_detail(
        &self,
        bill_id: &str,
        local_identity: &Identity,
        current_identity_node_id: &str,
        current_timestamp: u64,
    ) -> Result<BitcreditBillResult>;

    /// Gets the keys for a given bill
    async fn get_bill_keys(&self, bill_id: &str) -> Result<BillKeys>;

    /// opens and decrypts the attached file from the given bill
    async fn open_and_decrypt_attached_file(
        &self,
        bill_id: &str,
        file_name: &str,
        bill_private_key: &str,
    ) -> Result<Vec<u8>>;

    /// encrypts and saves the given uploaded file, returning the file name, as well as the hash of
    /// the unencrypted file
    async fn encrypt_and_save_uploaded_file(
        &self,
        file_name: &str,
        file_bytes: &[u8],
        bill_id: &str,
        bill_public_key: &str,
    ) -> Result<File>;

    /// issues a new bill
    async fn issue_new_bill(&self, data: BillIssueData) -> Result<BitcreditBill>;

    /// executes the given bill action
    async fn execute_bill_action(
        &self,
        bill_id: &str,
        bill_action: BillAction,
        signer_public_data: &BillParticipant,
        signer_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<BillBlockchain>;

    /// request to mint a bill
    async fn request_to_mint(
        &self,
        bill_id: &str,
        mint_node_id: &str,
        signer_public_data: &BillParticipant,
        signer_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<()>;

    /// Check payment status of bills that are requested to pay and not expired and not paid yet, updating their
    /// paid status if they were paid
    async fn check_bills_payment(&self) -> Result<()>;

    /// Check payment status of the bill with the given id that is requested to pay and not expired
    /// and not paid yet updating their paid status if they were paid
    async fn check_payment_for_bill(&self, bill_id: &str, identity: &Identity) -> Result<()>;

    /// Check payment status of bills that are waiting for a payment on an OfferToSell block, which
    /// haven't been expired, adding a Sell block if they were paid
    async fn check_bills_offer_to_sell_payment(&self) -> Result<()>;

    /// Check payment status of the bill with the given id that is waiting for a payment on an OfferToSell block, which
    /// haven't been expired, adding a Sell block if they were paid
    async fn check_offer_to_sell_payment_for_bill(
        &self,
        bill_id: &str,
        identity: &IdentityWithAll,
    ) -> Result<()>;

    /// Check payment status of bills that are waiting for a payment on an RequestRecourse block, which
    /// haven't been expired, adding a Recourse block if they were paid
    async fn check_bills_in_recourse_payment(&self) -> Result<()>;

    /// Check payment status of the bill with the given id that is waiting for a payment on an
    /// RequestRecourse block, which haven't been expired, adding a Recourse block if they were paid
    async fn check_recourse_payment_for_bill(
        &self,
        bill_id: &str,
        identity: &IdentityWithAll,
    ) -> Result<()>;

    /// Check if actions expected on bills in certain states have expired and execute the necessary
    /// steps after timeout.
    async fn check_bills_timeouts(&self, now: u64) -> Result<()>;

    /// Returns previous endorseers of the bill to select from for Recourse
    async fn get_past_endorsees(
        &self,
        bill_id: &str,
        current_identity_node_id: &str,
    ) -> Result<Vec<PastEndorsee>>;

    /// Returns previous payment requests of the given bill, where the user with the given node id
    /// was the financial beneficiary, with the metadata and outcomes
    async fn get_past_payments(
        &self,
        bill_id: &str,
        caller_public_data: &BillParticipant,
        caller_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Vec<PastPaymentResult>>;

    /// Returns all endorsements of the bill
    async fn get_endorsements(
        &self,
        bill_id: &str,
        current_identity_node_id: &str,
    ) -> Result<Vec<Endorsement>>;

    /// Returns the mint state for a given bill
    async fn get_mint_state(
        &self,
        bill_id: &str,
        current_identity_node_id: &str,
    ) -> Result<Vec<MintRequestState>>;

    /// Clear the bill cache
    async fn clear_bill_cache(&self) -> Result<()>;
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        persistence,
        service::company_service::tests::get_baseline_company_data,
        tests::tests::{
            TEST_BILL_ID, TEST_PRIVATE_KEY_SECP, TEST_PUB_KEY_SECP, VALID_PAYMENT_ADDRESS_TESTNET,
            bill_identified_participant_only_node_id, empty_address,
            empty_bill_identified_participant, init_test_cfg,
        },
        util,
    };
    use bcr_ebill_core::{
        ValidationError,
        bill::{
            BillAcceptanceStatus, BillCurrentWaitingState, BillPaymentStatus, BillRecourseStatus,
            BillSellStatus, BillWaitingForPaymentState, PastPaymentStatus, RecourseReason,
        },
        blockchain::{
            Blockchain,
            bill::{
                BillBlock, BillOpCode,
                block::{
                    BillEndorseBlockData, BillMintBlockData, BillOfferToSellBlockData,
                    BillParticipantBlockData, BillRecourseReasonBlockData, BillRejectBlockData,
                    BillRequestRecourseBlockData, BillRequestToAcceptBlockData,
                    BillRequestToPayBlockData, BillSellBlockData, BillSignatoryBlockData, NodeId,
                },
            },
        },
        constants::{ACCEPT_DEADLINE_SECONDS, PAYMENT_DEADLINE_SECONDS, RECOURSE_DEADLINE_SECONDS},
        contact::{BillAnonParticipant, BillIdentParticipant, BillParticipant},
        notification::ActionType,
    };
    use core::str;
    use mockall::predicate::{always, eq, function};
    use std::collections::{HashMap, HashSet};
    use test_utils::{
        accept_block, get_baseline_bill, get_baseline_cached_bill, get_baseline_identity, get_ctx,
        get_genesis_chain, get_service, offer_to_sell_block, recourse_block, reject_accept_block,
        reject_buy_block, reject_recourse_block, reject_to_pay_block, request_to_accept_block,
        request_to_pay_block, request_to_recourse_block, sell_block,
    };
    use util::crypto::BcrKeys;

    #[tokio::test]
    async fn get_bill_balances_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let company_node_id = BcrKeys::new().get_public_key();

        let mut bill1 = get_baseline_bill(TEST_BILL_ID);
        bill1.sum = 1000;
        bill1.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let mut bill2 = get_baseline_bill("4321");
        bill2.sum = 2000;
        bill2.drawee = bill_identified_participant_only_node_id(company_node_id.clone());
        bill2.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            identity.identity.node_id.clone(),
        ));
        let mut bill3 = get_baseline_bill("9999");
        bill3.sum = 20000;
        bill3.drawer = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        bill3.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            company_node_id.clone(),
        ));
        bill3.drawee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());

        ctx.bill_store.expect_get_ids().returning(|| {
            Ok(vec![
                String::from(TEST_BILL_ID),
                String::from("4321"),
                String::from("9999"),
            ])
        });
        ctx.bill_blockchain_store
            .expect_get_chain()
            .withf(|id| id == TEST_BILL_ID)
            .returning(move |_| Ok(get_genesis_chain(Some(bill1.clone()))));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .withf(|id| id == "4321")
            .returning(move |_| Ok(get_genesis_chain(Some(bill2.clone()))));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .withf(|id| id == "9999")
            .returning(move |_| Ok(get_genesis_chain(Some(bill3.clone()))));
        ctx.bill_store.expect_exists().returning(|_| Ok(true));

        ctx.notification_service
            .expect_get_active_bill_notification()
            .returning(|_| None);

        let service = get_service(ctx);

        // for identity
        let res = service
            .get_bill_balances("sat", &identity.identity.node_id)
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().payer.sum, "1000".to_string());
        assert_eq!(res.as_ref().unwrap().payee.sum, "2000".to_string());
        assert_eq!(res.as_ref().unwrap().contingent.sum, "20000".to_string());

        // for company
        let res_comp = service.get_bill_balances("sat", &company_node_id).await;
        assert!(res_comp.is_ok());
        assert_eq!(res_comp.as_ref().unwrap().payer.sum, "2000".to_string());
        assert_eq!(res_comp.as_ref().unwrap().payee.sum, "20000".to_string());
        assert_eq!(res_comp.as_ref().unwrap().contingent.sum, "0".to_string());
    }

    #[tokio::test]
    async fn get_search_bill() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let company_node_id = BcrKeys::new().get_public_key();

        let mut bill1 = get_baseline_bill(TEST_BILL_ID);
        bill1.issue_date = "2020-05-01".to_string();
        bill1.sum = 1000;
        bill1.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let mut bill2 = get_baseline_bill("4321");
        bill2.issue_date = "2030-05-01".to_string();
        bill2.sum = 2000;
        bill2.drawee = bill_identified_participant_only_node_id(company_node_id.clone());
        let mut payee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        payee.name = "hayek".to_string();
        bill2.payee = BillParticipant::Ident(payee);
        let mut bill3 = get_baseline_bill("9999");
        bill3.issue_date = "2030-05-01".to_string();
        bill3.sum = 20000;
        bill3.drawer = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        bill3.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            company_node_id.clone(),
        ));
        bill3.drawee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());

        ctx.bill_store.expect_get_ids().returning(|| {
            Ok(vec![
                String::from(TEST_BILL_ID),
                String::from("4321"),
                String::from("9999"),
            ])
        });
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .withf(|id| id == TEST_BILL_ID)
            .returning(move |_| Ok(get_genesis_chain(Some(bill1.clone()))));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .withf(|id| id == "4321")
            .returning(move |_| Ok(get_genesis_chain(Some(bill2.clone()))));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .withf(|id| id == "9999")
            .returning(move |_| Ok(get_genesis_chain(Some(bill3.clone()))));
        ctx.notification_service
            .expect_get_active_bill_notification()
            .returning(|_| None);

        let service = get_service(ctx);
        let res_all_comp = service
            .search_bills(
                "sat",
                &None,
                None,
                None,
                &BillsFilterRole::All,
                &company_node_id,
            )
            .await;
        assert!(res_all_comp.is_ok());
        assert_eq!(res_all_comp.as_ref().unwrap().len(), 2);
        let res_all = service
            .search_bills(
                "sat",
                &None,
                None,
                None,
                &BillsFilterRole::All,
                &identity.identity.node_id,
            )
            .await;
        assert!(res_all.is_ok());
        assert_eq!(res_all.as_ref().unwrap().len(), 3);

        let res_term = service
            .search_bills(
                "sat",
                &Some(String::from("hayek")),
                None,
                None,
                &BillsFilterRole::All,
                &identity.identity.node_id,
            )
            .await;
        assert!(res_term.is_ok());
        assert_eq!(res_term.as_ref().unwrap().len(), 1);

        let from_ts = util::date::date_string_to_timestamp("2030-05-01", None).unwrap();
        let to_ts = util::date::date_string_to_timestamp("2030-05-30", None).unwrap();
        let res_fromto = service
            .search_bills(
                "sat",
                &None,
                Some(from_ts as u64),
                Some(to_ts as u64),
                &BillsFilterRole::All,
                &identity.identity.node_id,
            )
            .await;
        assert!(res_fromto.is_ok());
        assert_eq!(res_fromto.as_ref().unwrap().len(), 2);

        let res_role = service
            .search_bills(
                "sat",
                &None,
                None,
                None,
                &BillsFilterRole::Payer,
                &identity.identity.node_id,
            )
            .await;
        assert!(res_role.is_ok());
        assert_eq!(res_role.as_ref().unwrap().len(), 1);

        let res_comb = service
            .search_bills(
                "sat",
                &Some(String::from("hayek")),
                Some(from_ts as u64),
                Some(to_ts as u64),
                &BillsFilterRole::Payee,
                &identity.identity.node_id,
            )
            .await;
        assert!(res_comb.is_ok());
        assert_eq!(res_comb.as_ref().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn issue_bill_baseline() {
        let mut ctx = get_ctx();
        let expected_file_name = "invoice_00000000-0000-0000-0000-000000000000.pdf";
        let file_bytes = String::from("hello world").as_bytes().to_vec();

        ctx.file_upload_store
            .expect_read_temp_upload_file()
            .returning(move |_| Ok((expected_file_name.to_string(), file_bytes.clone())));
        ctx.file_upload_store
            .expect_remove_temp_upload_folder()
            .returning(|_| Ok(()));
        ctx.file_upload_store
            .expect_save_attached_file()
            .returning(move |_, _, _| Ok(()));
        ctx.bill_store.expect_save_keys().returning(|_, _| Ok(()));
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        // should send a bill is signed event
        ctx.notification_service
            .expect_send_bill_is_signed_event()
            .returning(|_| Ok(()));

        let service = get_service(ctx);

        let drawer = get_baseline_identity();
        let mut drawee = empty_bill_identified_participant();
        drawee.node_id = BcrKeys::new().get_public_key();
        let mut payee = empty_bill_identified_participant();
        payee.node_id = BcrKeys::new().get_public_key();

        let bill = service
            .issue_new_bill(BillIssueData {
                t: 2,
                country_of_issuing: String::from("UK"),
                city_of_issuing: String::from("London"),
                issue_date: String::from("2030-01-01"),
                maturity_date: String::from("2030-04-01"),
                drawee: drawee.node_id,
                payee: payee.node_id,
                sum: String::from("100"),
                currency: String::from("sat"),
                country_of_payment: String::from("AT"),
                city_of_payment: String::from("Vienna"),
                language: String::from("en-UK"),
                file_upload_ids: vec![TEST_BILL_ID.to_string()],
                drawer_public_data: BillParticipant::Ident(
                    BillIdentParticipant::new(drawer.identity).unwrap(),
                ),
                drawer_keys: drawer.key_pair,
                timestamp: 1731593928,
                blank_issue: false,
            })
            .await
            .unwrap();

        assert_eq!(bill.files.first().unwrap().name, expected_file_name);
        assert!(matches!(bill.payee, BillParticipant::Ident(_))); // payee is ident
    }

    #[tokio::test]
    async fn issue_bill_baseline_anon() {
        let mut ctx = get_ctx();
        let expected_file_name = "invoice_00000000-0000-0000-0000-000000000000.pdf";
        let file_bytes = String::from("hello world").as_bytes().to_vec();
        let mut payee = BillAnonParticipant::from(empty_bill_identified_participant());
        payee.node_id = BcrKeys::new().get_public_key();

        ctx.file_upload_store
            .expect_read_temp_upload_file()
            .returning(move |_| Ok((expected_file_name.to_string(), file_bytes.clone())));
        ctx.file_upload_store
            .expect_remove_temp_upload_folder()
            .returning(|_| Ok(()));
        ctx.file_upload_store
            .expect_save_attached_file()
            .returning(move |_, _, _| Ok(()));
        ctx.bill_store.expect_save_keys().returning(|_, _| Ok(()));
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        // should send a bill is signed event
        ctx.notification_service
            .expect_send_bill_is_signed_event()
            .returning(|_| Ok(()));

        let service = get_service(ctx);

        let drawer = get_baseline_identity();
        let mut drawee = empty_bill_identified_participant();
        drawee.node_id = BcrKeys::new().get_public_key();

        let bill = service
            .issue_new_bill(BillIssueData {
                t: 2,
                country_of_issuing: String::from("UK"),
                city_of_issuing: String::from("London"),
                issue_date: String::from("2030-01-01"),
                maturity_date: String::from("2030-04-01"),
                drawee: drawee.node_id,
                payee: payee.node_id,
                sum: String::from("100"),
                currency: String::from("sat"),
                country_of_payment: String::from("AT"),
                city_of_payment: String::from("Vienna"),
                language: String::from("en-UK"),
                file_upload_ids: vec![TEST_BILL_ID.to_string()],
                drawer_public_data: BillParticipant::Ident(
                    BillIdentParticipant::new(drawer.identity).unwrap(),
                ),
                drawer_keys: drawer.key_pair,
                timestamp: 1731593928,
                blank_issue: true,
            })
            .await
            .unwrap();

        assert_eq!(bill.files.first().unwrap().name, expected_file_name);
        assert!(matches!(bill.payee, BillParticipant::Anon(_))); // payee is anon
    }

    #[tokio::test]
    async fn issue_bill_fails_for_anon_drawer() {
        let ctx = get_ctx();
        let service = get_service(ctx);

        let drawer = get_baseline_identity();
        let mut drawee = empty_bill_identified_participant();
        drawee.node_id = BcrKeys::new().get_public_key();
        let mut payee = empty_bill_identified_participant();
        payee.node_id = BcrKeys::new().get_public_key();

        let result = service
            .issue_new_bill(BillIssueData {
                t: 2,
                country_of_issuing: String::from("UK"),
                city_of_issuing: String::from("London"),
                issue_date: String::from("2030-01-01"),
                maturity_date: String::from("2030-04-01"),
                drawee: drawee.node_id,
                payee: payee.node_id,
                sum: String::from("100"),
                currency: String::from("sat"),
                country_of_payment: String::from("AT"),
                city_of_payment: String::from("Vienna"),
                language: String::from("en-UK"),
                file_upload_ids: vec![TEST_BILL_ID.to_string()],
                drawer_public_data: BillParticipant::Anon(BillAnonParticipant::new(
                    drawer.identity,
                )),
                drawer_keys: drawer.key_pair,
                timestamp: 1731593928,
                blank_issue: false,
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.as_ref().unwrap_err(),
            Error::Validation(ValidationError::DrawerIsNotBillIssuer)
        ));
    }

    #[tokio::test]
    async fn issue_bill_fails_for_self_drafted_blank() {
        let ctx = get_ctx();
        let service = get_service(ctx);

        let drawer = get_baseline_identity();
        let mut drawee = empty_bill_identified_participant();
        drawee.node_id = BcrKeys::new().get_public_key();
        let mut payee = empty_bill_identified_participant();
        payee.node_id = BcrKeys::new().get_public_key();

        let result = service
            .issue_new_bill(BillIssueData {
                t: 1,
                country_of_issuing: String::from("UK"),
                city_of_issuing: String::from("London"),
                issue_date: String::from("2030-01-01"),
                maturity_date: String::from("2030-04-01"),
                drawee: drawee.node_id,
                payee: payee.node_id,
                sum: String::from("100"),
                currency: String::from("sat"),
                country_of_payment: String::from("AT"),
                city_of_payment: String::from("Vienna"),
                language: String::from("en-UK"),
                file_upload_ids: vec![TEST_BILL_ID.to_string()],
                drawer_public_data: BillParticipant::Ident(
                    BillIdentParticipant::new(drawer.identity).unwrap(),
                ),
                drawer_keys: drawer.key_pair,
                timestamp: 1731593928,
                blank_issue: true,
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.as_ref().unwrap_err(),
            Error::Validation(ValidationError::SelfDraftedBillCantBeBlank)
        ));
    }

    #[tokio::test]
    async fn issue_bill_as_company() {
        let mut ctx = get_ctx();
        let expected_file_name = "invoice_00000000-0000-0000-0000-000000000000.pdf";
        let file_bytes = String::from("hello world").as_bytes().to_vec();

        ctx.file_upload_store
            .expect_read_temp_upload_file()
            .returning(move |_| Ok((expected_file_name.to_string(), file_bytes.clone())));
        ctx.file_upload_store
            .expect_remove_temp_upload_folder()
            .returning(|_| Ok(()));
        ctx.file_upload_store
            .expect_save_attached_file()
            .returning(move |_, _, _| Ok(()));
        ctx.bill_store.expect_save_keys().returning(|_, _| Ok(()));
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        // should send a bill is signed event
        ctx.notification_service
            .expect_send_bill_is_signed_event()
            .returning(|_| Ok(()));

        let service = get_service(ctx);

        let drawer = get_baseline_company_data();
        let mut drawee = empty_bill_identified_participant();
        drawee.node_id = BcrKeys::new().get_public_key();
        let mut payee = empty_bill_identified_participant();
        payee.node_id = BcrKeys::new().get_public_key();

        let bill = service
            .issue_new_bill(BillIssueData {
                t: 2,
                country_of_issuing: String::from("UK"),
                city_of_issuing: String::from("London"),
                issue_date: String::from("2030-01-01"),
                maturity_date: String::from("2030-04-01"),
                drawee: drawee.node_id,
                payee: payee.node_id,
                sum: String::from("100"),
                currency: String::from("sat"),
                country_of_payment: String::from("AT"),
                city_of_payment: String::from("Vienna"),
                language: String::from("en-UK"),
                file_upload_ids: vec![TEST_BILL_ID.to_string()],
                drawer_public_data: BillParticipant::Ident(BillIdentParticipant::from(drawer.1.0)),
                drawer_keys: BcrKeys::from_private_key(&drawer.1.1.private_key).unwrap(),
                timestamp: 1731593928,
                blank_issue: false,
            })
            .await
            .unwrap();

        assert_eq!(bill.files.first().unwrap().name, expected_file_name);
        assert_eq!(bill.drawer.node_id, drawer.0);
    }

    #[tokio::test]
    async fn save_encrypt_open_decrypt_compare_hashes() {
        let mut ctx = get_ctx();
        let bill_id = "test_bill_id";
        let file_name = "invoice_00000000-0000-0000-0000-000000000000.pdf";
        let file_bytes = String::from("hello world").as_bytes().to_vec();
        let expected_encrypted =
            util::crypto::encrypt_ecies(&file_bytes, TEST_PUB_KEY_SECP).unwrap();

        ctx.file_upload_store
            .expect_save_attached_file()
            .with(always(), eq(bill_id), eq(file_name))
            .times(1)
            .returning(|_, _, _| Ok(()));

        ctx.file_upload_store
            .expect_open_attached_file()
            .with(eq(bill_id), eq(file_name))
            .times(1)
            .returning(move |_, _| Ok(expected_encrypted.clone()));
        let service = get_service(ctx);

        let bill_file = service
            .encrypt_and_save_uploaded_file(file_name, &file_bytes, bill_id, TEST_PUB_KEY_SECP)
            .await
            .unwrap();
        assert_eq!(
            bill_file.hash,
            String::from("DULfJyE3WQqNxy3ymuhAChyNR3yufT88pmqvAazKFMG4")
        );
        assert_eq!(bill_file.name, String::from(file_name));

        let decrypted = service
            .open_and_decrypt_attached_file(bill_id, file_name, TEST_PRIVATE_KEY_SECP)
            .await
            .unwrap();
        assert_eq!(str::from_utf8(&decrypted).unwrap(), "hello world");
    }

    #[tokio::test]
    async fn save_encrypt_propagates_write_file_error() {
        let mut ctx = get_ctx();
        ctx.file_upload_store
            .expect_save_attached_file()
            .returning(|_, _, _| Err(persistence::Error::Io(std::io::Error::other("test error"))));
        let service = get_service(ctx);

        assert!(
            service
                .encrypt_and_save_uploaded_file("file_name", &[], "test", TEST_PUB_KEY_SECP)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn open_decrypt_propagates_read_file_error() {
        let mut ctx = get_ctx();
        ctx.file_upload_store
            .expect_open_attached_file()
            .returning(|_, _| Err(persistence::Error::Io(std::io::Error::other("test error"))));
        let service = get_service(ctx);

        assert!(
            service
                .open_and_decrypt_attached_file("test", "test", TEST_PRIVATE_KEY_SECP)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn get_bill_keys_calls_storage() {
        let mut ctx = get_ctx();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        let service = get_service(ctx);

        assert!(service.get_bill_keys("test").await.is_ok());
        assert_eq!(
            service.get_bill_keys("test").await.unwrap().private_key,
            TEST_PRIVATE_KEY_SECP.to_owned()
        );
        assert_eq!(
            service.get_bill_keys("test").await.unwrap().public_key,
            TEST_PUB_KEY_SECP.to_owned()
        );
    }

    #[tokio::test]
    async fn get_bill_keys_propagates_errors() {
        let mut ctx = get_ctx();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store
            .expect_get_keys()
            .returning(|_| Err(persistence::Error::Io(std::io::Error::other("test error"))));
        let service = get_service(ctx);
        assert!(service.get_bill_keys("test").await.is_err());
    }

    #[tokio::test]
    async fn get_bills_baseline() {
        let mut ctx = get_ctx();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(
            BillIdentParticipant::new(get_baseline_identity().identity).unwrap(),
        );

        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let chain = get_genesis_chain(Some(bill.clone()));
                Ok(chain)
            });
        ctx.bill_store
            .expect_get_ids()
            .returning(|| Ok(vec![TEST_BILL_ID.to_string()]));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(true));
        ctx.bill_store.expect_exists().returning(|_| Ok(true));

        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let service = get_service(ctx);

        let res = service
            .get_bills(&get_baseline_identity().identity.node_id)
            .await;
        assert!(res.is_ok());
        let returned_bills = res.unwrap();
        assert!(returned_bills.len() == 1);
        assert_eq!(returned_bills[0].id, TEST_BILL_ID.to_string());
    }

    #[tokio::test]
    async fn get_bills_baseline_from_cache() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut chain_bill = get_baseline_bill("4321");
        chain_bill.payee =
            BillParticipant::Ident(BillIdentParticipant::new(identity.identity.clone()).unwrap());
        let mut bill = get_baseline_cached_bill(TEST_BILL_ID.to_string());
        // make sure the local identity is part of the bill
        bill.participants.payee =
            BillParticipant::Ident(BillIdentParticipant::new(identity.identity.clone()).unwrap());
        bill.participants
            .all_participant_node_ids
            .push(identity.identity.node_id.clone());

        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let chain = get_genesis_chain(Some(chain_bill.clone()));
                Ok(chain)
            })
            .times(1);
        ctx.bill_store
            .expect_get_bills_from_cache()
            .returning(move |_| Ok(vec![bill.clone()]));
        ctx.bill_store
            .expect_get_ids()
            .returning(|| Ok(vec![TEST_BILL_ID.to_string(), "4321".to_string()]));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(true));
        ctx.bill_store.expect_exists().returning(|_| Ok(true));

        ctx.notification_service
            .expect_get_active_bill_notifications()
            .returning(|_| HashMap::new());

        let service = get_service(ctx);

        let res = service
            .get_bills(&get_baseline_identity().identity.node_id)
            .await;
        assert!(res.is_ok());
        let returned_bills = res.unwrap();
        assert!(returned_bills.len() == 2);
    }

    #[tokio::test]
    async fn get_bills_baseline_from_cache_with_payment_expiration() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut chain_bill = get_baseline_bill("4321");
        chain_bill.payee =
            BillParticipant::Ident(BillIdentParticipant::new(identity.identity.clone()).unwrap());
        let mut bill = get_baseline_cached_bill(TEST_BILL_ID.to_string());
        // make sure the local identity is part of the bill
        bill.participants.payee =
            BillParticipant::Ident(BillIdentParticipant::new(identity.identity.clone()).unwrap());
        bill.participants
            .all_participant_node_ids
            .push(identity.identity.node_id.clone());
        bill.status.payment = BillPaymentStatus {
            time_of_request_to_pay: Some(1531593928), // more than 2 days before request
            requested_to_pay: true,
            paid: false,
            request_to_pay_timed_out: false,
            rejected_to_pay: false,
        };

        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let chain = get_genesis_chain(Some(chain_bill.clone()));
                Ok(chain)
            })
            .times(2);
        ctx.bill_store
            .expect_get_bills_from_cache()
            .returning(move |_| Ok(vec![bill.clone()]));
        ctx.bill_store
            .expect_get_ids()
            .returning(|| Ok(vec![TEST_BILL_ID.to_string(), "4321".to_string()]));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(true));
        ctx.bill_store.expect_exists().returning(|_| Ok(true));

        ctx.notification_service
            .expect_get_active_bill_notifications()
            .returning(|_| HashMap::new());

        let service = get_service(ctx);

        let res = service
            .get_bills(&get_baseline_identity().identity.node_id)
            .await;
        assert!(res.is_ok());
        let returned_bills = res.unwrap();
        assert!(returned_bills.len() == 2);
    }

    #[tokio::test]
    async fn get_bills_baseline_company() {
        let mut ctx = get_ctx();
        let company_node_id = BcrKeys::new().get_public_key();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(
            BillIdentParticipant::new(get_baseline_identity().identity).unwrap(),
        );
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(|_| Ok(get_genesis_chain(None)));
        ctx.bill_store
            .expect_get_ids()
            .returning(|| Ok(vec![TEST_BILL_ID.to_string()]));
        ctx.bill_store.expect_exists().returning(|_| Ok(true));

        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let service = get_service(ctx);

        let res = service
            .get_bills(&get_baseline_identity().identity.node_id)
            .await;
        assert!(res.is_ok());
        let returned_bills = res.unwrap();
        assert!(returned_bills.len() == 1);
        assert_eq!(returned_bills[0].id, TEST_BILL_ID.to_string());

        let res = service.get_bills(&company_node_id).await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn get_bills_req_to_pay() {
        let mut ctx = get_ctx();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(
            BillIdentParticipant::new(get_baseline_identity().identity).unwrap(),
        );
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let now = util::date::now().timestamp() as u64;
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_pay_block = BillBlock::create_block_for_request_to_pay(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillRequestToPayBlockData {
                        requester: BillParticipantBlockData::Ident(
                            BillIdentParticipant::new(get_baseline_identity().identity)
                                .unwrap()
                                .into(),
                        ),
                        currency: "sat".to_string(),
                        signatory: None,
                        signing_timestamp: now,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now,
                )
                .unwrap();
                assert!(chain.try_add_block(req_to_pay_block));
                Ok(chain)
            });
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store
            .expect_get_ids()
            .returning(|| Ok(vec![TEST_BILL_ID.to_string()]));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(true));
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_bills(&get_baseline_identity().identity.node_id)
            .await;
        assert!(res.is_ok());
        let returned_bills = res.unwrap();
        assert!(returned_bills.len() == 1);
        assert_eq!(returned_bills[0].id, TEST_BILL_ID.to_string());
        assert!(returned_bills[0].status.payment.requested_to_pay);
        assert!(returned_bills[0].status.payment.paid);
    }

    #[tokio::test]
    async fn get_bills_empty_for_no_bills() {
        let mut ctx = get_ctx();
        ctx.bill_store.expect_get_ids().returning(|| Ok(vec![]));
        let res = get_service(ctx)
            .get_bills(&get_baseline_identity().identity.node_id)
            .await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_detail_bill_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(!res.as_ref().unwrap().status.payment.requested_to_pay);
        assert!(!res.as_ref().unwrap().status.payment.paid);
        assert!(!res.as_ref().unwrap().status.redeemed_funds_available);
    }

    #[tokio::test]
    async fn get_detail_bill_baseline_from_cache() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_cached_bill(TEST_BILL_ID.to_string());
        // make sure the local identity is part of the bill
        bill.participants.drawee = BillIdentParticipant::new(identity.identity.clone()).unwrap();
        let drawee_node_id = bill.participants.drawee.node_id.clone();
        bill.participants
            .all_participant_node_ids
            .push(drawee_node_id.clone());
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store
            .expect_get_bill_from_cache()
            .returning(move |_| Ok(Some(bill.clone())));
        ctx.bill_blockchain_store.expect_get_chain().never();
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(!res.as_ref().unwrap().status.payment.requested_to_pay);
        assert!(!res.as_ref().unwrap().status.payment.paid);
        assert!(!res.as_ref().unwrap().status.redeemed_funds_available);
    }

    #[tokio::test]
    async fn get_detail_bill_baseline_from_cache_with_payment_expiration() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut chain_bill = get_baseline_bill(TEST_BILL_ID);
        chain_bill.drawee =
            bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let mut bill = get_baseline_cached_bill(TEST_BILL_ID.to_string());
        // make sure the local identity is part of the bill
        bill.participants.drawee = BillIdentParticipant::new(identity.identity.clone()).unwrap();
        let drawee_node_id = bill.participants.drawee.node_id.clone();
        bill.participants
            .all_participant_node_ids
            .push(drawee_node_id.clone());
        bill.status.payment = BillPaymentStatus {
            time_of_request_to_pay: Some(1531593928), // more than 2 days before request
            requested_to_pay: true,
            paid: false,
            request_to_pay_timed_out: false,
            rejected_to_pay: false,
        };
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store
            .expect_get_bill_from_cache()
            .returning(move |_| Ok(Some(bill.clone())));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(chain_bill.clone()))))
            .times(1);
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(!res.as_ref().unwrap().status.payment.paid);
        assert!(!res.as_ref().unwrap().status.redeemed_funds_available);
    }

    #[tokio::test]
    async fn get_detail_bill_baseline_error_from_cache() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store
            .expect_get_bill_from_cache()
            .returning(move |_| Err(persistence::Error::Io(std::io::Error::other("test error"))));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(!res.as_ref().unwrap().status.payment.requested_to_pay);
        assert!(!res.as_ref().unwrap().status.payment.paid);
        assert!(!res.as_ref().unwrap().status.redeemed_funds_available);
    }

    #[tokio::test]
    async fn get_detail_bill_fails_for_non_participant() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &BcrKeys::new().get_public_key(),
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn get_detail_waiting_for_offer_to_sell() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                assert!(chain.try_add_block(offer_to_sell_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &bill_identified_participant_only_node_id(bill.drawee.node_id.clone()),
                    None,
                )));
                Ok(chain)
            });
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(res.as_ref().unwrap().status.sell.offered_to_sell);
        assert!(!res.as_ref().unwrap().status.sell.offer_to_sell_timed_out);
        assert!(!res.as_ref().unwrap().status.sell.rejected_offer_to_sell);
        assert!(res.as_ref().unwrap().current_waiting_state.is_some());
        assert!(!res.as_ref().unwrap().status.redeemed_funds_available);
        assert!(res.as_ref().unwrap().status.has_requested_funds);
    }

    #[tokio::test]
    async fn get_detail_waiting_for_offer_to_sell_and_sell() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                assert!(chain.try_add_block(offer_to_sell_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &bill.drawee,
                    None,
                )));
                assert!(chain.try_add_block(sell_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &bill.drawee,
                )));
                Ok(chain)
            });
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(res.as_ref().unwrap().status.sell.offered_to_sell);
        assert!(!res.as_ref().unwrap().status.sell.offer_to_sell_timed_out);
        assert!(!res.as_ref().unwrap().status.sell.rejected_offer_to_sell);
        assert!(res.as_ref().unwrap().current_waiting_state.is_none());
        assert_eq!(
            res.as_ref()
                .unwrap()
                .participants
                .endorsee
                .as_ref()
                .unwrap()
                .node_id(),
            identity.identity.node_id
        );
        assert!(res.as_ref().unwrap().status.redeemed_funds_available); // caller is endorsee
        assert!(res.as_ref().unwrap().status.has_requested_funds);
    }

    #[tokio::test]
    async fn get_detail_waiting_for_offer_to_sell_and_expire() {
        let mut ctx = get_ctx();
        let now = util::date::now().timestamp() as u64;
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                assert!(chain.try_add_block(offer_to_sell_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &bill.drawee,
                    // expired
                    Some(now - PAYMENT_DEADLINE_SECONDS * 2),
                )));
                Ok(chain)
            });
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                now,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(res.as_ref().unwrap().status.sell.offered_to_sell);
        assert!(res.as_ref().unwrap().status.sell.offer_to_sell_timed_out);
        assert!(!res.as_ref().unwrap().status.sell.rejected_offer_to_sell);
        assert!(res.as_ref().unwrap().current_waiting_state.is_none());
        assert!(res.as_ref().unwrap().status.has_requested_funds);
    }

    #[tokio::test]
    async fn get_detail_waiting_for_offer_to_sell_and_reject() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        let now = util::date::now().timestamp() as u64;
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                assert!(chain.try_add_block(offer_to_sell_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &bill.drawee,
                    // expired
                    Some(now - PAYMENT_DEADLINE_SECONDS * 2),
                )));
                assert!(
                    chain.try_add_block(reject_buy_block(TEST_BILL_ID, chain.get_latest_block(),))
                );
                Ok(chain)
            });
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                now,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(res.as_ref().unwrap().status.sell.offered_to_sell);
        assert!(!res.as_ref().unwrap().status.sell.offer_to_sell_timed_out);
        assert!(res.as_ref().unwrap().status.sell.rejected_offer_to_sell);
        assert!(res.as_ref().unwrap().current_waiting_state.is_none());
        assert!(res.as_ref().unwrap().status.has_requested_funds);
    }

    #[tokio::test]
    async fn get_detail_bill_req_to_recourse() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_pay_block = request_to_recourse_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &bill_identified_participant_only_node_id(bill.drawee.node_id.clone()),
                    None,
                );
                assert!(chain.try_add_block(req_to_pay_block));
                Ok(chain)
            });
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(res.as_ref().unwrap().status.recourse.requested_to_recourse);
        assert!(
            !res.as_ref()
                .unwrap()
                .status
                .recourse
                .request_to_recourse_timed_out
        );
        assert!(
            !res.as_ref()
                .unwrap()
                .status
                .recourse
                .rejected_request_to_recourse
        );
        assert!(res.as_ref().unwrap().current_waiting_state.is_some());
        assert!(!res.as_ref().unwrap().status.redeemed_funds_available);
        assert!(res.as_ref().unwrap().status.has_requested_funds);
    }

    #[tokio::test]
    async fn get_detail_bill_req_to_recourse_recoursed() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_pay_block = request_to_recourse_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &bill_identified_participant_only_node_id(bill.drawee.node_id.clone()),
                    None,
                );
                assert!(chain.try_add_block(req_to_pay_block));
                assert!(chain.try_add_block(recourse_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &bill_identified_participant_only_node_id(bill.drawee.node_id.clone())
                )));
                Ok(chain)
            });
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id.clone()
        );
        assert!(res.as_ref().unwrap().status.recourse.requested_to_recourse);
        assert!(
            !res.as_ref()
                .unwrap()
                .status
                .recourse
                .request_to_recourse_timed_out
        );
        assert!(
            !res.as_ref()
                .unwrap()
                .status
                .recourse
                .rejected_request_to_recourse
        );
        assert!(res.as_ref().unwrap().current_waiting_state.is_none());
        assert!(res.as_ref().unwrap().status.redeemed_funds_available); // caller is endorsee
        assert!(res.as_ref().unwrap().status.has_requested_funds);
    }

    #[tokio::test]
    async fn get_detail_bill_req_to_recourse_rejected() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_pay_block = request_to_recourse_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &bill_identified_participant_only_node_id(bill.drawee.node_id.clone()),
                    None,
                );
                assert!(chain.try_add_block(req_to_pay_block));
                assert!(chain.try_add_block(reject_recourse_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                )));
                Ok(chain)
            });
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(res.as_ref().unwrap().status.recourse.requested_to_recourse);
        assert!(
            !res.as_ref()
                .unwrap()
                .status
                .recourse
                .request_to_recourse_timed_out
        );
        assert!(
            res.as_ref()
                .unwrap()
                .status
                .recourse
                .rejected_request_to_recourse
        );
        assert!(res.as_ref().unwrap().current_waiting_state.is_none());
        assert!(res.as_ref().unwrap().status.has_requested_funds);
    }

    #[tokio::test]
    async fn get_detail_bill_req_to_recourse_expired() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        let now = util::date::now().timestamp() as u64;
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_pay_block = request_to_recourse_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &bill_identified_participant_only_node_id(bill.drawee.node_id.clone()),
                    Some(now - RECOURSE_DEADLINE_SECONDS * 2),
                );
                assert!(chain.try_add_block(req_to_pay_block));
                Ok(chain)
            });
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                now,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(res.as_ref().unwrap().status.recourse.requested_to_recourse);
        assert!(
            res.as_ref()
                .unwrap()
                .status
                .recourse
                .request_to_recourse_timed_out
        );
        assert!(
            !res.as_ref()
                .unwrap()
                .status
                .recourse
                .rejected_request_to_recourse
        );
        assert!(res.as_ref().unwrap().current_waiting_state.is_none());
        assert!(res.as_ref().unwrap().status.has_requested_funds);
    }

    #[tokio::test]
    async fn get_detail_bill_req_to_pay() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_pay_block =
                    request_to_pay_block(TEST_BILL_ID, chain.get_latest_block(), None);
                assert!(chain.try_add_block(req_to_pay_block));
                Ok(chain)
            });
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(!res.as_ref().unwrap().status.payment.paid);
        assert!(res.as_ref().unwrap().status.payment.requested_to_pay);
        assert!(
            !res.as_ref()
                .unwrap()
                .status
                .payment
                .request_to_pay_timed_out
        );
        assert!(!res.as_ref().unwrap().status.payment.rejected_to_pay);
        assert!(res.as_ref().unwrap().current_waiting_state.is_some());
        assert!(!res.as_ref().unwrap().status.redeemed_funds_available);
        assert!(res.as_ref().unwrap().status.has_requested_funds);
    }

    #[tokio::test]
    async fn get_detail_bill_req_to_pay_paid() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(true));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_pay_block =
                    request_to_pay_block(TEST_BILL_ID, chain.get_latest_block(), None);
                assert!(chain.try_add_block(req_to_pay_block));
                Ok(chain)
            });
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(res.as_ref().unwrap().status.payment.paid);
        assert!(res.as_ref().unwrap().status.payment.requested_to_pay);
        assert!(
            !res.as_ref()
                .unwrap()
                .status
                .payment
                .request_to_pay_timed_out
        );
        assert!(!res.as_ref().unwrap().status.payment.rejected_to_pay);
        assert!(res.as_ref().unwrap().current_waiting_state.is_none());
        assert!(!res.as_ref().unwrap().status.redeemed_funds_available); // caller not payee
        assert!(res.as_ref().unwrap().status.has_requested_funds);
    }

    #[tokio::test]
    async fn get_detail_bill_req_to_pay_rejected() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_pay_block =
                    request_to_pay_block(TEST_BILL_ID, chain.get_latest_block(), None);
                assert!(chain.try_add_block(req_to_pay_block));
                assert!(
                    chain
                        .try_add_block(reject_to_pay_block(TEST_BILL_ID, chain.get_latest_block()))
                );
                Ok(chain)
            });
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(!res.as_ref().unwrap().status.payment.paid);
        assert!(res.as_ref().unwrap().status.payment.requested_to_pay);
        assert!(
            !res.as_ref()
                .unwrap()
                .status
                .payment
                .request_to_pay_timed_out
        );
        assert!(res.as_ref().unwrap().status.payment.rejected_to_pay);
        assert!(res.as_ref().unwrap().current_waiting_state.is_none());
        assert!(res.as_ref().unwrap().status.has_requested_funds);
    }

    #[tokio::test]
    async fn get_detail_bill_req_to_pay_rejected_but_paid() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(true));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_pay_block =
                    request_to_pay_block(TEST_BILL_ID, chain.get_latest_block(), None);
                assert!(chain.try_add_block(req_to_pay_block));
                assert!(
                    chain
                        .try_add_block(reject_to_pay_block(TEST_BILL_ID, chain.get_latest_block()))
                );
                Ok(chain)
            });
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(res.as_ref().unwrap().status.payment.paid);
        assert!(res.as_ref().unwrap().status.payment.requested_to_pay);
        assert!(
            !res.as_ref()
                .unwrap()
                .status
                .payment
                .request_to_pay_timed_out
        );
        assert!(res.as_ref().unwrap().status.payment.rejected_to_pay);
        assert!(res.as_ref().unwrap().current_waiting_state.is_none());
        assert!(res.as_ref().unwrap().status.has_requested_funds);
    }

    #[tokio::test]
    async fn get_detail_bill_req_to_pay_expired() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let now = util::date::now().timestamp() as u64;
        bill.maturity_date =
            util::date::format_date_string(util::date::seconds(now - PAYMENT_DEADLINE_SECONDS * 2));
        let drawee_node_id = bill.drawee.node_id.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_pay_block = request_to_pay_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    Some(now - PAYMENT_DEADLINE_SECONDS * 2),
                );
                assert!(chain.try_add_block(req_to_pay_block));
                Ok(chain)
            });
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                now,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(!res.as_ref().unwrap().status.payment.paid);
        assert!(res.as_ref().unwrap().status.payment.requested_to_pay);
        assert!(
            res.as_ref()
                .unwrap()
                .status
                .payment
                .request_to_pay_timed_out
        );
        assert!(!res.as_ref().unwrap().status.payment.rejected_to_pay);
        assert!(res.as_ref().unwrap().current_waiting_state.is_none());
        assert!(res.as_ref().unwrap().status.has_requested_funds);
    }

    #[tokio::test]
    async fn get_detail_bill_req_to_pay_expired_but_paid() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        let now = util::date::now().timestamp() as u64;
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(true));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_pay_block = request_to_pay_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    Some(now - PAYMENT_DEADLINE_SECONDS * 2),
                );
                assert!(chain.try_add_block(req_to_pay_block));
                Ok(chain)
            });
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                now,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(res.as_ref().unwrap().status.payment.paid);
        assert!(res.as_ref().unwrap().status.payment.requested_to_pay);
        assert!(
            !res.as_ref()
                .unwrap()
                .status
                .payment
                .request_to_pay_timed_out
        );
        assert!(!res.as_ref().unwrap().status.payment.rejected_to_pay);
        assert!(res.as_ref().unwrap().current_waiting_state.is_none());
        assert!(res.as_ref().unwrap().status.has_requested_funds);
    }

    #[tokio::test]
    async fn get_detail_bill_req_to_accept() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_pay_block =
                    request_to_accept_block(TEST_BILL_ID, chain.get_latest_block(), None);
                assert!(chain.try_add_block(req_to_pay_block));
                Ok(chain)
            });
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(!res.as_ref().unwrap().status.acceptance.accepted);
        assert!(res.as_ref().unwrap().status.acceptance.requested_to_accept);
        assert!(
            !res.as_ref()
                .unwrap()
                .status
                .acceptance
                .request_to_accept_timed_out
        );
        assert!(!res.as_ref().unwrap().status.acceptance.rejected_to_accept);
        assert!(res.as_ref().unwrap().current_waiting_state.is_none());
    }

    #[tokio::test]
    async fn get_detail_bill_req_to_accept_accepted() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_pay_block =
                    request_to_accept_block(TEST_BILL_ID, chain.get_latest_block(), None);
                assert!(chain.try_add_block(req_to_pay_block));
                assert!(chain.try_add_block(accept_block(TEST_BILL_ID, chain.get_latest_block())));
                Ok(chain)
            });
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(res.as_ref().unwrap().status.acceptance.accepted);
        assert!(res.as_ref().unwrap().status.acceptance.requested_to_accept);
        assert!(
            !res.as_ref()
                .unwrap()
                .status
                .acceptance
                .request_to_accept_timed_out
        );
        assert!(!res.as_ref().unwrap().status.acceptance.rejected_to_accept);
        assert!(res.as_ref().unwrap().current_waiting_state.is_none());
    }

    #[tokio::test]
    async fn get_detail_bill_req_to_accept_rejected() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        let now = util::date::now().timestamp() as u64;
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_pay_block =
                    request_to_accept_block(TEST_BILL_ID, chain.get_latest_block(), None);
                assert!(chain.try_add_block(req_to_pay_block));
                assert!(
                    chain
                        .try_add_block(reject_accept_block(TEST_BILL_ID, chain.get_latest_block()))
                );
                Ok(chain)
            });
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                now,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(!res.as_ref().unwrap().status.acceptance.accepted);
        assert!(res.as_ref().unwrap().status.acceptance.requested_to_accept);
        assert!(
            !res.as_ref()
                .unwrap()
                .status
                .acceptance
                .request_to_accept_timed_out
        );
        assert!(res.as_ref().unwrap().status.acceptance.rejected_to_accept);
        assert!(res.as_ref().unwrap().current_waiting_state.is_none());
    }

    #[tokio::test]
    async fn get_detail_bill_req_to_accept_expired() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        let now = util::date::now().timestamp() as u64;
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_pay_block = request_to_accept_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    Some(now - ACCEPT_DEADLINE_SECONDS * 2),
                );
                assert!(chain.try_add_block(req_to_pay_block));
                Ok(chain)
            });
        ctx.notification_service
            .expect_get_active_bill_notification()
            .with(eq(TEST_BILL_ID))
            .returning(|_| None);

        let res = get_service(ctx)
            .get_detail(
                TEST_BILL_ID,
                &identity.identity,
                &identity.identity.node_id,
                now,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_BILL_ID.to_string());
        assert_eq!(
            res.as_ref().unwrap().participants.drawee.node_id,
            drawee_node_id
        );
        assert!(!res.as_ref().unwrap().status.acceptance.accepted);
        assert!(res.as_ref().unwrap().status.acceptance.requested_to_accept);
        assert!(
            res.as_ref()
                .unwrap()
                .status
                .acceptance
                .request_to_accept_timed_out
        );
        assert!(!res.as_ref().unwrap().status.acceptance.rejected_to_accept);
        assert!(res.as_ref().unwrap().current_waiting_state.is_none());
    }

    #[tokio::test]
    async fn accept_bill_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));

        // Should send bill accepted event
        ctx.notification_service
            .expect_send_bill_is_accepted_event()
            .returning(|_| Ok(()));

        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Accept,
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().blocks().len() == 2);
        assert!(res.unwrap().blocks()[1].op_code == BillOpCode::Accept);
    }

    #[tokio::test]
    async fn accept_bill_fails_for_anon() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));

        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Accept,
                &BillParticipant::Anon(BillAnonParticipant::new(identity.identity.clone())),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_err());
        assert!(matches!(
            res.as_ref().unwrap_err(),
            Error::Validation(ValidationError::SignerCantBeAnon)
        ));
    }

    #[tokio::test]
    async fn accept_bill_as_company() {
        let mut ctx = get_ctx();
        let company = get_baseline_company_data();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(company.0.clone());

        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));

        // Should send bill accepted event
        ctx.notification_service
            .expect_send_bill_is_accepted_event()
            .returning(|_| Ok(()));

        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Accept,
                &BillParticipant::Ident(BillIdentParticipant::from(company.1.0)),
                &BcrKeys::from_private_key(&company.1.1.private_key).unwrap(),
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().blocks().len() == 2);
        assert!(res.as_ref().unwrap().blocks()[1].op_code == BillOpCode::Accept);
        // company is accepter
        assert!(
            res.as_ref().unwrap().blocks()[1]
                .get_nodes_from_block(&BillKeys {
                    private_key: TEST_PRIVATE_KEY_SECP.to_owned(),
                    public_key: TEST_PUB_KEY_SECP.to_owned(),
                })
                .unwrap()[0]
                == company.0
        );
    }

    #[tokio::test]
    async fn accept_bill_fails_if_drawee_not_caller() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Accept,
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn accept_bill_fails_if_already_accepted() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let keys = identity.key_pair.clone();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let mut chain = get_genesis_chain(Some(bill.clone()));
        chain.blocks_mut().push(
            BillBlock::new(
                TEST_BILL_ID.to_string(),
                123456,
                "prevhash".to_string(),
                "hash".to_string(),
                BillOpCode::Accept,
                &keys,
                None,
                &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                1731593928,
            )
            .unwrap(),
        );
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(chain.clone()));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Accept,
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn request_pay_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.maturity_date = "2022-11-12".to_string(); // maturity date has to be in the past
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            identity.identity.node_id.clone(),
        ));
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        // Request to pay event should be sent
        ctx.notification_service
            .expect_send_request_to_pay_event()
            .returning(|_| Ok(()));

        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::RequestToPay("sat".to_string()),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().blocks().len() == 2);
        assert!(res.unwrap().blocks()[1].op_code == BillOpCode::RequestToPay);
    }

    #[tokio::test]
    async fn request_pay_anon_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.maturity_date = "2022-11-12".to_string(); // maturity date has to be in the past
        bill.payee = BillParticipant::Anon(BillAnonParticipant::from(
            bill_identified_participant_only_node_id(identity.identity.node_id.clone()),
        ));
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        // Request to pay event should be sent
        ctx.notification_service
            .expect_send_request_to_pay_event()
            .returning(|_| Ok(()));

        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::RequestToPay("sat".to_string()),
                &BillParticipant::Anon(BillAnonParticipant::new(identity.identity.clone())),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().blocks().len() == 2);
        assert!(res.unwrap().blocks()[1].op_code == BillOpCode::RequestToPay);
    }

    #[tokio::test]
    async fn request_pay_fails_if_payee_not_caller() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            BcrKeys::new().get_public_key(),
        ));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::RequestToPay("sat".to_string()),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn request_acceptance_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            identity.identity.node_id.clone(),
        ));
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        // Request to accept event should be sent
        ctx.notification_service
            .expect_send_request_to_accept_event()
            .returning(|_| Ok(()));

        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::RequestAcceptance,
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().blocks().len() == 2);
        assert!(res.unwrap().blocks()[1].op_code == BillOpCode::RequestToAccept);
    }

    #[tokio::test]
    async fn request_acceptance_anon_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Anon(BillAnonParticipant::from(
            bill_identified_participant_only_node_id(identity.identity.node_id.clone()),
        ));
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        // Request to accept event should be sent
        ctx.notification_service
            .expect_send_request_to_accept_event()
            .returning(|_| Ok(()));

        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::RequestAcceptance,
                &BillParticipant::Anon(BillAnonParticipant::new(identity.identity.clone())),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().blocks().len() == 2);
        assert!(res.unwrap().blocks()[1].op_code == BillOpCode::RequestToAccept);
    }

    #[tokio::test]
    async fn request_acceptance_fails_if_payee_not_caller() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            BcrKeys::new().get_public_key(),
        ));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::RequestAcceptance,
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn mint_bitcredit_bill_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            identity.identity.node_id.clone(),
        ));
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                chain.try_add_block(accept_block(&bill.id, chain.get_latest_block()));
                Ok(chain)
            });
        // Asset request to mint event is sent
        ctx.notification_service
            .expect_send_request_to_mint_event()
            .returning(|_, _| Ok(()));

        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Mint(
                    BillParticipant::Ident(bill_identified_participant_only_node_id(
                        BcrKeys::new().get_public_key(),
                    )),
                    5000,
                    "sat".to_string(),
                ),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().blocks().len() == 3);
        assert!(res.unwrap().blocks()[2].op_code == BillOpCode::Mint);
    }

    #[tokio::test]
    async fn mint_bitcredit_bill_anon_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            identity.identity.node_id.clone(),
        ));
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                chain.try_add_block(accept_block(&bill.id, chain.get_latest_block()));
                Ok(chain)
            });
        // Asset request to mint event is sent
        ctx.notification_service
            .expect_send_request_to_mint_event()
            .returning(|_, _| Ok(()));

        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Mint(
                    BillParticipant::Anon(BillAnonParticipant::from(
                        bill_identified_participant_only_node_id(BcrKeys::new().get_public_key()),
                    )),
                    5000,
                    "sat".to_string(),
                ),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().blocks().len() == 3);
        assert!(res.unwrap().blocks()[2].op_code == BillOpCode::Mint);
    }

    #[tokio::test]
    async fn mint_bitcredit_bill_fails_if_not_accepted() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            identity.identity.node_id.clone(),
        ));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        // Asset request to mint event is sent
        ctx.notification_service
            .expect_send_request_to_mint_event()
            .returning(|_, _| Ok(()));

        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Mint(
                    BillParticipant::Ident(bill_identified_participant_only_node_id(
                        BcrKeys::new().get_public_key(),
                    )),
                    5000,
                    "sat".to_string(),
                ),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn mint_bitcredit_bill_fails_if_payee_not_caller() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            BcrKeys::new().get_public_key(),
        ));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Mint(
                    BillParticipant::Ident(empty_bill_identified_participant()),
                    5000,
                    "sat".to_string(),
                ),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn offer_to_sell_bitcredit_bill_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            identity.identity.node_id.clone(),
        ));
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        // Request to sell event should be sent
        ctx.notification_service
            .expect_send_offer_to_sell_event()
            .returning(|_, _| Ok(()));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::OfferToSell(
                    BillParticipant::Ident(bill_identified_participant_only_node_id(
                        BcrKeys::new().get_public_key(),
                    )),
                    15000,
                    "sat".to_string(),
                ),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().blocks().len() == 2);
        assert!(res.unwrap().blocks()[1].op_code == BillOpCode::OfferToSell);
    }

    #[tokio::test]
    async fn offer_to_sell_bitcredit_bill_anon_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            identity.identity.node_id.clone(),
        ));
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        // Request to sell event should be sent
        ctx.notification_service
            .expect_send_offer_to_sell_event()
            .returning(|_, _| Ok(()));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::OfferToSell(
                    BillParticipant::Anon(BillAnonParticipant::from(
                        bill_identified_participant_only_node_id(BcrKeys::new().get_public_key()),
                    )),
                    15000,
                    "sat".to_string(),
                ),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().blocks().len() == 2);
        assert!(res.unwrap().blocks()[1].op_code == BillOpCode::OfferToSell);
    }

    #[tokio::test]
    async fn offer_to_sell_bitcredit_bill_fails_if_payee_not_caller() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            BcrKeys::new().get_public_key(),
        ));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::OfferToSell(
                    BillParticipant::Ident(bill_identified_participant_only_node_id(
                        BcrKeys::new().get_public_key(),
                    )),
                    15000,
                    "sat".to_string(),
                ),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn sell_bitcredit_bill_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            identity.identity.node_id.clone(),
        ));
        let buyer = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        let buyer_clone = buyer.clone();
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let offer_to_sell = BillBlock::create_block_for_offer_to_sell(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillOfferToSellBlockData {
                        seller: bill.payee.clone().into(),
                        buyer: BillParticipantBlockData::Ident(buyer_clone.clone().into()),
                        currency: "sat".to_owned(),
                        sum: 15000,
                        payment_address: "tb1qteyk7pfvvql2r2zrsu4h4xpvju0nz7ykvguyk0".to_owned(),
                        signatory: None,
                        signing_timestamp: 1731593927,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::new(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    1731593927,
                )
                .unwrap();
                chain.try_add_block(offer_to_sell);
                Ok(chain)
            });
        // Request to sell event should be sent
        ctx.notification_service
            .expect_send_bill_is_sold_event()
            .returning(|_, _| Ok(()));

        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Sell(
                    BillParticipant::Ident(buyer),
                    15000,
                    "sat".to_string(),
                    VALID_PAYMENT_ADDRESS_TESTNET.to_string(),
                ),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().blocks().len() == 3);
        assert!(res.as_ref().unwrap().blocks()[1].op_code == BillOpCode::OfferToSell);
        assert!(res.as_ref().unwrap().blocks()[2].op_code == BillOpCode::Sell);
    }

    #[tokio::test]
    async fn sell_bitcredit_bill_anon_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            identity.identity.node_id.clone(),
        ));
        let buyer = BillAnonParticipant::from(bill_identified_participant_only_node_id(
            BcrKeys::new().get_public_key(),
        ));
        let buyer_clone = buyer.clone();
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let offer_to_sell = BillBlock::create_block_for_offer_to_sell(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillOfferToSellBlockData {
                        seller: bill.payee.clone().into(),
                        buyer: BillParticipantBlockData::Anon(buyer_clone.clone().into()),
                        currency: "sat".to_owned(),
                        sum: 15000,
                        payment_address: "tb1qteyk7pfvvql2r2zrsu4h4xpvju0nz7ykvguyk0".to_owned(),
                        signatory: None,
                        signing_timestamp: 1731593927,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::new(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    1731593927,
                )
                .unwrap();
                chain.try_add_block(offer_to_sell);
                Ok(chain)
            });
        // Request to sell event should be sent
        ctx.notification_service
            .expect_send_bill_is_sold_event()
            .returning(|_, _| Ok(()));

        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Sell(
                    BillParticipant::Anon(buyer),
                    15000,
                    "sat".to_string(),
                    VALID_PAYMENT_ADDRESS_TESTNET.to_string(),
                ),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().blocks().len() == 3);
        assert!(res.as_ref().unwrap().blocks()[1].op_code == BillOpCode::OfferToSell);
        assert!(res.as_ref().unwrap().blocks()[2].op_code == BillOpCode::Sell);
    }

    #[tokio::test]
    async fn sell_bitcredit_bill_fails_if_sell_data_is_invalid() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            identity.identity.node_id.clone(),
        ));
        let buyer = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let offer_to_sell = BillBlock::create_block_for_offer_to_sell(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillOfferToSellBlockData {
                        seller: bill.payee.clone().into(),
                        buyer: bill.payee.clone().into(), // buyer is seller, which is invalid
                        currency: "sat".to_owned(),
                        sum: 10000, // different sum
                        payment_address: "tb1qteyk7pfvvql2r2zrsu4h4xpvju0nz7ykvguyk0".to_owned(),
                        signatory: None,
                        signing_timestamp: 1731593927,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::new(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    1731593927,
                )
                .unwrap();
                chain.try_add_block(offer_to_sell);
                Ok(chain)
            });
        // Sold event should be sent
        ctx.notification_service
            .expect_send_bill_is_sold_event()
            .returning(|_, _| Ok(()));

        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Sell(
                    BillParticipant::Ident(buyer),
                    15000,
                    "sat".to_string(),
                    VALID_PAYMENT_ADDRESS_TESTNET.to_string(),
                ),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn sell_bitcredit_bill_fails_if_not_offer_to_sell_waiting_for_payment() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            identity.identity.node_id.clone(),
        ));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        // Request to sell event should be sent
        ctx.notification_service
            .expect_send_bill_is_sold_event()
            .returning(|_, _| Ok(()));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Sell(
                    BillParticipant::Ident(bill_identified_participant_only_node_id(
                        BcrKeys::new().get_public_key(),
                    )),
                    15000,
                    "sat".to_string(),
                    VALID_PAYMENT_ADDRESS_TESTNET.to_string(),
                ),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn sell_bitcredit_bill_fails_if_payee_not_caller() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            BcrKeys::new().get_public_key(),
        ));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Sell(
                    BillParticipant::Ident(bill_identified_participant_only_node_id(
                        BcrKeys::new().get_public_key(),
                    )),
                    15000,
                    "sat".to_string(),
                    VALID_PAYMENT_ADDRESS_TESTNET.to_string(),
                ),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn endorse_bitcredit_bill_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            identity.identity.node_id.clone(),
        ));
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        // Bill is endorsed event should be sent
        ctx.notification_service
            .expect_send_bill_is_endorsed_event()
            .returning(|_| Ok(()));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Endorse(BillParticipant::Ident(
                    bill_identified_participant_only_node_id(BcrKeys::new().get_public_key()),
                )),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().blocks().len() == 2);
        assert!(res.unwrap().blocks()[1].op_code == BillOpCode::Endorse);
    }

    #[tokio::test]
    async fn endorse_bitcredit_bill_anon_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            identity.identity.node_id.clone(),
        ));
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        // Bill is endorsed event should be sent
        ctx.notification_service
            .expect_send_bill_is_endorsed_event()
            .returning(|_| Ok(()));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Endorse(BillParticipant::Anon(BillAnonParticipant::from(
                    bill_identified_participant_only_node_id(BcrKeys::new().get_public_key()),
                ))),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().blocks().len() == 2);
        assert!(res.unwrap().blocks()[1].op_code == BillOpCode::Endorse);
    }

    #[tokio::test]
    async fn endorse_bitcredit_bill_fails_if_waiting_for_offer_to_sell() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            identity.identity.node_id.clone(),
        ));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                assert!(chain.try_add_block(offer_to_sell_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &bill_identified_participant_only_node_id(BcrKeys::new().get_public_key()),
                    None,
                )));
                Ok(chain)
            });

        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Endorse(BillParticipant::Ident(
                    bill_identified_participant_only_node_id(BcrKeys::new().get_public_key()),
                )),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_err());
        match res {
            Ok(_) => panic!("expected an error"),
            Err(e) => match e {
                Error::Validation(ValidationError::BillIsOfferedToSellAndWaitingForPayment) => (),
                _ => panic!("expected a different error"),
            },
        };
    }

    #[tokio::test]
    async fn endorse_bitcredit_bill_fails_if_payee_not_caller() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            BcrKeys::new().get_public_key(),
        ));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Endorse(BillParticipant::Ident(empty_bill_identified_participant())),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn get_combined_bitcoin_key_for_bill_baseline() {
        init_test_cfg();
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            identity.key_pair.get_public_key(),
        ));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        let service = get_service(ctx);

        let res = service
            .get_combined_bitcoin_key_for_bill(
                TEST_BILL_ID,
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
            )
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn get_combined_bitcoin_key_for_bill_err() {
        let mut ctx = get_ctx();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(bill_identified_participant_only_node_id(
            BcrKeys::new().get_public_key(),
        ));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        let service = get_service(ctx);

        let non_participant_keys = BcrKeys::new();
        let res = service
            .get_combined_bitcoin_key_for_bill(
                TEST_BILL_ID,
                &BillParticipant::Ident(bill_identified_participant_only_node_id(
                    non_participant_keys.get_public_key(),
                )),
                &non_participant_keys,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn check_bills_payment_baseline() {
        let mut ctx = get_ctx();
        let bill = get_baseline_bill(TEST_BILL_ID);
        ctx.bill_store
            .expect_get_bill_ids_waiting_for_payment()
            .returning(|| Ok(vec![TEST_BILL_ID.to_string()]));
        ctx.bill_store.expect_set_to_paid().returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        let service = get_service(ctx);

        let res = service.check_bills_payment().await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn check_payment_for_bill_baseline() {
        let mut ctx = get_ctx();
        let bill = get_baseline_bill(TEST_BILL_ID);
        ctx.bill_store
            .expect_get_bill_ids_waiting_for_payment()
            .returning(|| Ok(vec![TEST_BILL_ID.to_string()]));
        ctx.bill_store.expect_set_to_paid().returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        let service = get_service(ctx);

        let res = service
            .check_payment_for_bill(TEST_BILL_ID, &get_baseline_identity().identity)
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn check_bill_offer_to_sell_payment_baseline() {
        let mut ctx = get_ctx();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(
            BillIdentParticipant::new(get_baseline_identity().identity).unwrap(),
        );

        ctx.bill_store
            .expect_get_bill_ids_waiting_for_sell_payment()
            .returning(|| Ok(vec![TEST_BILL_ID.to_string()]));
        let buyer_node_id = BcrKeys::new().get_public_key();
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                assert!(chain.try_add_block(offer_to_sell_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &bill_identified_participant_only_node_id(buyer_node_id.clone()),
                    None,
                )));
                Ok(chain)
            });
        ctx.notification_service
            .expect_send_bill_is_sold_event()
            .returning(|_, _| Ok(()));

        let service = get_service(ctx);

        let res = service
            .check_offer_to_sell_payment_for_bill(TEST_BILL_ID, &get_baseline_identity())
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn check_bills_offer_to_sell_payment_company_is_seller() {
        let mut ctx = get_ctx();
        let mut identity = get_baseline_identity();
        identity.key_pair = BcrKeys::new();
        identity.identity.node_id = identity.key_pair.get_public_key();

        let company = get_baseline_company_data();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(BillIdentParticipant::from(company.1.0.clone()));

        ctx.bill_store
            .expect_get_bill_ids_waiting_for_sell_payment()
            .returning(|| Ok(vec![TEST_BILL_ID.to_string()]));
        let company_clone = company.clone();
        ctx.company_store.expect_get_all().returning(move || {
            let mut map = HashMap::new();
            map.insert(
                company_clone.0.clone(),
                (company_clone.1.0.clone(), company_clone.1.1.clone()),
            );
            Ok(map)
        });
        let buyer_node_id = BcrKeys::new().get_public_key();
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                assert!(chain.try_add_block(offer_to_sell_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &bill_identified_participant_only_node_id(buyer_node_id.clone()),
                    None,
                )));
                Ok(chain)
            });
        ctx.notification_service
            .expect_send_bill_is_sold_event()
            .returning(|_, _| Ok(()));
        let service = get_service(ctx);

        let res = service.check_bills_offer_to_sell_payment().await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn check_bills_timeouts_does_nothing_if_not_timed_out() {
        let mut ctx = get_ctx();
        let op_codes = HashSet::from([
            BillOpCode::RequestToAccept,
            BillOpCode::RequestToPay,
            BillOpCode::OfferToSell,
            BillOpCode::RequestRecourse,
        ]);

        // fetches bill ids
        ctx.bill_store
            .expect_get_bill_ids_with_op_codes_since()
            .with(eq(op_codes.clone()), eq(0))
            .returning(|_, _| Ok(vec![TEST_BILL_ID.to_string(), "4321".to_string()]));
        // fetches bill chain accept
        ctx.bill_blockchain_store
            .expect_get_chain()
            .with(eq(TEST_BILL_ID.to_string()))
            .returning(|id| {
                let mut chain = get_genesis_chain(Some(get_baseline_bill(id)));
                chain.try_add_block(request_to_accept_block(id, chain.get_latest_block(), None));
                Ok(chain)
            });
        // fetches bill chain pay
        ctx.bill_blockchain_store
            .expect_get_chain()
            .with(eq("4321".to_string()))
            .returning(|id| {
                let mut chain = get_genesis_chain(Some(get_baseline_bill(id)));
                chain.try_add_block(request_to_pay_block(id, chain.get_latest_block(), None));
                Ok(chain)
            });
        let service = get_service(ctx);

        // now is the same as block created time so no timeout should have happened
        let res = service.check_bills_timeouts(1000).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn check_bills_timeouts_does_nothing_if_notifications_are_already_sent() {
        let mut ctx = get_ctx();
        let op_codes = HashSet::from([
            BillOpCode::RequestToAccept,
            BillOpCode::RequestToPay,
            BillOpCode::OfferToSell,
            BillOpCode::RequestRecourse,
        ]);

        // fetches bill ids
        ctx.bill_store
            .expect_get_bill_ids_with_op_codes_since()
            .with(eq(op_codes.clone()), eq(0))
            .returning(|_, _| Ok(vec![TEST_BILL_ID.to_string(), "4321".to_string()]));

        // fetches bill chain accept
        ctx.bill_blockchain_store
            .expect_get_chain()
            .with(eq(TEST_BILL_ID.to_string()))
            .returning(|id| {
                let mut chain = get_genesis_chain(Some(get_baseline_bill(id)));
                chain.try_add_block(request_to_accept_block(id, chain.get_latest_block(), None));
                Ok(chain)
            });

        // fetches bill chain pay
        ctx.bill_blockchain_store
            .expect_get_chain()
            .with(eq("4321".to_string()))
            .returning(|id| {
                let mut chain = get_genesis_chain(Some(get_baseline_bill(id)));
                chain.try_add_block(request_to_pay_block(id, chain.get_latest_block(), None));
                Ok(chain)
            });
        // notification already sent
        ctx.notification_service
            .expect_check_bill_notification_sent()
            .with(eq(TEST_BILL_ID), eq(2), eq(ActionType::AcceptBill))
            .returning(|_, _, _| Ok(true));

        // notification already sent
        ctx.notification_service
            .expect_check_bill_notification_sent()
            .with(eq("4321"), eq(2), eq(ActionType::PayBill))
            .returning(|_, _, _| Ok(true));

        let service = get_service(ctx);

        let res = service
            .check_bills_timeouts(PAYMENT_DEADLINE_SECONDS + 1100)
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn check_bills_timeouts() {
        let mut ctx = get_ctx();
        let op_codes = HashSet::from([
            BillOpCode::RequestToAccept,
            BillOpCode::RequestToPay,
            BillOpCode::OfferToSell,
            BillOpCode::RequestRecourse,
        ]);

        // fetches bill ids
        ctx.bill_store
            .expect_get_bill_ids_with_op_codes_since()
            .with(eq(op_codes.clone()), eq(0))
            .returning(|_, _| Ok(vec![TEST_BILL_ID.to_string(), "4321".to_string()]));

        // fetches bill chain accept
        ctx.bill_blockchain_store
            .expect_get_chain()
            .with(eq(TEST_BILL_ID.to_string()))
            .returning(|id| {
                let mut chain = get_genesis_chain(Some(get_baseline_bill(id)));
                chain.try_add_block(request_to_accept_block(id, chain.get_latest_block(), None));
                Ok(chain)
            });

        // fetches bill chain pay
        ctx.bill_blockchain_store
            .expect_get_chain()
            .with(eq("4321".to_string()))
            .returning(|id| {
                let mut chain = get_genesis_chain(Some(get_baseline_bill(id)));
                chain.try_add_block(request_to_pay_block(id, chain.get_latest_block(), None));
                Ok(chain)
            });

        // notification not sent
        ctx.notification_service
            .expect_check_bill_notification_sent()
            .with(eq(TEST_BILL_ID), eq(2), eq(ActionType::AcceptBill))
            .returning(|_, _, _| Ok(false));

        // notification not sent
        ctx.notification_service
            .expect_check_bill_notification_sent()
            .with(eq("4321"), eq(2), eq(ActionType::PayBill))
            .returning(|_, _, _| Ok(false));

        // we should have at least two participants
        let recipient_check = function(|r: &Vec<BillParticipant>| r.len() >= 2);

        // send accept timeout notification
        ctx.notification_service
            .expect_send_request_to_action_timed_out_event()
            .with(
                always(),
                eq(TEST_BILL_ID),
                always(),
                eq(ActionType::AcceptBill),
                recipient_check.clone(),
            )
            .returning(|_, _, _, _, _| Ok(()));

        // send pay timeout notification
        ctx.notification_service
            .expect_send_request_to_action_timed_out_event()
            .with(
                always(),
                eq("4321"),
                always(),
                eq(ActionType::PayBill),
                recipient_check,
            )
            .returning(|_, _, _, _, _| Ok(()));

        // marks accept bill timeout as sent
        ctx.notification_service
            .expect_mark_bill_notification_sent()
            .with(eq(TEST_BILL_ID), eq(2), eq(ActionType::AcceptBill))
            .returning(|_, _, _| Ok(()));

        // marks pay bill timeout as sent
        ctx.notification_service
            .expect_mark_bill_notification_sent()
            .with(eq("4321"), eq(2), eq(ActionType::PayBill))
            .returning(|_, _, _| Ok(()));

        let service = get_service(ctx);

        let res = service
            .check_bills_timeouts(PAYMENT_DEADLINE_SECONDS + 1100)
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn get_endorsements_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawer = BillIdentParticipant::new(identity.identity.clone()).unwrap();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));

        let service = get_service(ctx);

        let res = service
            .get_endorsements(TEST_BILL_ID, &identity.identity.node_id)
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn get_endorsements_multi_with_anon() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        let drawer = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        let mint_endorsee =
            bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        // endorsee is anon
        let endorse_endorsee = BillAnonParticipant::from(bill_identified_participant_only_node_id(
            BcrKeys::new().get_public_key(),
        ));
        let sell_endorsee =
            bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        bill.drawer = drawer.clone();
        bill.drawee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        bill.payee = BillParticipant::Ident(
            BillIdentParticipant::new(get_baseline_identity().identity).unwrap(),
        );
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        let mint_endorsee_clone = mint_endorsee.clone();
        let sell_endorsee_clone = sell_endorsee.clone();

        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let now = util::date::now().timestamp() as u64;
                let mut chain = get_genesis_chain(Some(bill.clone()));

                // add endorse block from payee to endorsee
                let endorse_block = BillBlock::create_block_for_endorse(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillEndorseBlockData {
                        endorsee: BillParticipantBlockData::Anon(endorse_endorsee.clone().into()),
                        // endorsed by payee
                        endorser: BillParticipantBlockData::Ident(
                            BillIdentParticipant::new(get_baseline_identity().identity)
                                .unwrap()
                                .into(),
                        ),
                        signatory: None,
                        signing_timestamp: now + 1,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now + 1,
                )
                .unwrap();
                assert!(chain.try_add_block(endorse_block));

                // add sell block from endorsee to sell endorsee
                let sell_block = BillBlock::create_block_for_sell(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillSellBlockData {
                        buyer: BillParticipantBlockData::Ident(sell_endorsee.clone().into()),
                        // endorsed by endorsee
                        seller: BillParticipantBlockData::Anon(endorse_endorsee.clone().into()),
                        currency: "sat".to_string(),
                        sum: 15000,
                        payment_address: VALID_PAYMENT_ADDRESS_TESTNET.to_string(),
                        signatory: None,
                        signing_timestamp: now + 2,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now + 2,
                )
                .unwrap();
                assert!(chain.try_add_block(sell_block));

                // add mint block from sell endorsee to mint endorsee
                let mint_block = BillBlock::create_block_for_mint(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillMintBlockData {
                        endorsee: BillParticipantBlockData::Ident(mint_endorsee.clone().into()),
                        // endorsed by sell endorsee
                        endorser: BillParticipantBlockData::Ident(sell_endorsee.clone().into()),
                        currency: "sat".to_string(),
                        sum: 15000,
                        signatory: None,
                        signing_timestamp: now + 3,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now + 3,
                )
                .unwrap();
                assert!(chain.try_add_block(mint_block));

                Ok(chain)
            });

        let service = get_service(ctx);

        let res = service
            .get_endorsements(TEST_BILL_ID, &identity.identity.node_id)
            .await;
        assert!(res.is_ok());
        // with duplicates
        assert_eq!(res.as_ref().unwrap().len(), 2);
        // mint was last, so it's first
        assert_eq!(
            res.as_ref().unwrap()[0].pay_to_the_order_of.node_id,
            mint_endorsee_clone.node_id
        );
        assert_eq!(
            res.as_ref().unwrap()[1].pay_to_the_order_of.node_id,
            sell_endorsee_clone.node_id
        );
        // endorsee is not in the list, since they're anon
    }

    #[tokio::test]
    async fn get_endorsements_multi() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        let drawer = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        let mint_endorsee =
            bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        let endorse_endorsee =
            bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        let sell_endorsee =
            bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        bill.drawer = drawer.clone();
        bill.drawee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        bill.payee = BillParticipant::Ident(
            BillIdentParticipant::new(get_baseline_identity().identity).unwrap(),
        );
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        let endorse_endorsee_clone = endorse_endorsee.clone();
        let mint_endorsee_clone = mint_endorsee.clone();
        let sell_endorsee_clone = sell_endorsee.clone();

        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let now = util::date::now().timestamp() as u64;
                let mut chain = get_genesis_chain(Some(bill.clone()));

                // add endorse block from payee to endorsee
                let endorse_block = BillBlock::create_block_for_endorse(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillEndorseBlockData {
                        endorsee: BillParticipantBlockData::Ident(endorse_endorsee.clone().into()),
                        // endorsed by payee
                        endorser: BillParticipantBlockData::Ident(
                            BillIdentParticipant::new(get_baseline_identity().identity)
                                .unwrap()
                                .into(),
                        ),
                        signatory: None,
                        signing_timestamp: now + 1,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now + 1,
                )
                .unwrap();
                assert!(chain.try_add_block(endorse_block));

                // add sell block from endorsee to sell endorsee
                let sell_block = BillBlock::create_block_for_sell(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillSellBlockData {
                        buyer: BillParticipantBlockData::Ident(sell_endorsee.clone().into()),
                        // endorsed by endorsee
                        seller: BillParticipantBlockData::Ident(endorse_endorsee.clone().into()),
                        currency: "sat".to_string(),
                        sum: 15000,
                        payment_address: VALID_PAYMENT_ADDRESS_TESTNET.to_string(),
                        signatory: None,
                        signing_timestamp: now + 2,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now + 2,
                )
                .unwrap();
                assert!(chain.try_add_block(sell_block));

                // add mint block from sell endorsee to mint endorsee
                let mint_block = BillBlock::create_block_for_mint(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillMintBlockData {
                        endorsee: BillParticipantBlockData::Ident(mint_endorsee.clone().into()),
                        // endorsed by sell endorsee
                        endorser: BillParticipantBlockData::Ident(sell_endorsee.clone().into()),
                        currency: "sat".to_string(),
                        sum: 15000,
                        signatory: None,
                        signing_timestamp: now + 3,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now + 3,
                )
                .unwrap();
                assert!(chain.try_add_block(mint_block));

                Ok(chain)
            });

        let service = get_service(ctx);

        let res = service
            .get_endorsements(TEST_BILL_ID, &identity.identity.node_id)
            .await;
        assert!(res.is_ok());
        // with duplicates
        assert_eq!(res.as_ref().unwrap().len(), 3);
        // mint was last, so it's first
        assert_eq!(
            res.as_ref().unwrap()[0].pay_to_the_order_of.node_id,
            mint_endorsee_clone.node_id
        );
        assert_eq!(
            res.as_ref().unwrap()[1].pay_to_the_order_of.node_id,
            sell_endorsee_clone.node_id
        );
        assert_eq!(
            res.as_ref().unwrap()[2].pay_to_the_order_of.node_id,
            endorse_endorsee_clone.node_id
        );
    }

    #[tokio::test]
    async fn get_past_endorsees_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawer = BillIdentParticipant::new(identity.identity.clone()).unwrap();

        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        let service = get_service(ctx);

        let res = service
            .get_past_endorsees(TEST_BILL_ID, &identity.identity.node_id)
            .await;
        assert!(res.is_ok());
        // if we're the drawee and drawer, there's no holder before us
        assert_eq!(res.as_ref().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn get_past_endorsees_fails_if_not_my_bill() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawer = BillIdentParticipant::new(identity.identity.clone()).unwrap();

        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        let service = get_service(ctx);

        let res = service
            .get_past_endorsees(TEST_BILL_ID, "some_other_node_id")
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn get_past_endorsees_3_party() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        let drawer = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        bill.drawer = drawer.clone();
        bill.drawee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        bill.payee = BillParticipant::Ident(
            BillIdentParticipant::new(get_baseline_identity().identity).unwrap(),
        );

        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| Ok(get_genesis_chain(Some(bill.clone()))));
        let service = get_service(ctx);

        let res = service
            .get_past_endorsees(TEST_BILL_ID, &identity.identity.node_id)
            .await;
        assert!(res.is_ok());
        // if it's a 3 party bill and we're the payee, the drawer is a previous holder
        assert_eq!(res.as_ref().unwrap().len(), 1);
        assert_eq!(
            res.as_ref().unwrap()[0].pay_to_the_order_of.node_id,
            drawer.node_id
        );
    }

    #[tokio::test]
    async fn get_past_endorsees_multi_with_anon() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        let drawer = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        let mint_endorsee =
            bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        // endorsee is anon
        let endorse_endorsee = BillAnonParticipant::from(bill_identified_participant_only_node_id(
            BcrKeys::new().get_public_key(),
        ));
        let sell_endorsee =
            bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());

        bill.drawer = drawer.clone();
        bill.drawee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        bill.payee = BillParticipant::Ident(
            BillIdentParticipant::new(get_baseline_identity().identity).unwrap(),
        );

        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        let mint_endorsee_clone = mint_endorsee.clone();
        let sell_endorsee_clone = sell_endorsee.clone();

        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let now = util::date::now().timestamp() as u64;
                let mut chain = get_genesis_chain(Some(bill.clone()));

                // add endorse block from payee to endorsee
                let endorse_block = BillBlock::create_block_for_endorse(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillEndorseBlockData {
                        endorsee: BillParticipantBlockData::Anon(endorse_endorsee.clone().into()),
                        // endorsed by payee
                        endorser: BillParticipantBlockData::Ident(
                            BillIdentParticipant::new(get_baseline_identity().identity)
                                .unwrap()
                                .into(),
                        ),
                        signatory: None,
                        signing_timestamp: now + 1,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now + 1,
                )
                .unwrap();
                assert!(chain.try_add_block(endorse_block));

                // add sell block from endorsee to sell endorsee
                let sell_block = BillBlock::create_block_for_sell(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillSellBlockData {
                        buyer: BillParticipantBlockData::Ident(sell_endorsee.clone().into()),
                        // endorsed by endorsee
                        seller: BillParticipantBlockData::Anon(endorse_endorsee.clone().into()),
                        currency: "sat".to_string(),
                        sum: 15000,
                        payment_address: VALID_PAYMENT_ADDRESS_TESTNET.to_string(),
                        signatory: None,
                        signing_timestamp: now + 2,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now + 2,
                )
                .unwrap();
                assert!(chain.try_add_block(sell_block));

                // add mint block from sell endorsee to mint endorsee
                let mint_block = BillBlock::create_block_for_mint(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillMintBlockData {
                        endorsee: BillParticipantBlockData::Ident(mint_endorsee.clone().into()),
                        // endorsed by sell endorsee
                        endorser: BillParticipantBlockData::Ident(sell_endorsee.clone().into()),
                        currency: "sat".to_string(),
                        sum: 15000,
                        signatory: None,
                        signing_timestamp: now + 3,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now + 3,
                )
                .unwrap();
                assert!(chain.try_add_block(mint_block));

                // add endorse block back to endorsee
                let endorse_block_back = BillBlock::create_block_for_endorse(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillEndorseBlockData {
                        endorsee: BillParticipantBlockData::Anon(endorse_endorsee.clone().into()),
                        // endorsed by payee
                        endorser: BillParticipantBlockData::Ident(mint_endorsee.clone().into()),
                        signatory: None,
                        signing_timestamp: now + 4,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now + 4,
                )
                .unwrap();
                assert!(chain.try_add_block(endorse_block_back));

                // add endorse block back to payee (caller)
                let endorse_block_last = BillBlock::create_block_for_endorse(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillEndorseBlockData {
                        endorsee: BillParticipantBlockData::Ident(
                            BillIdentParticipant::new(get_baseline_identity().identity)
                                .unwrap()
                                .into(),
                        ),
                        // endorsed by payee
                        endorser: BillParticipantBlockData::Anon(endorse_endorsee.clone().into()),
                        signatory: None,
                        signing_timestamp: now + 5,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now + 5,
                )
                .unwrap();
                assert!(chain.try_add_block(endorse_block_last));

                Ok(chain)
            });
        let service = get_service(ctx);

        let res = service
            .get_past_endorsees(TEST_BILL_ID, &identity.identity.node_id)
            .await;
        assert!(res.is_ok());
        // if there are mint, sell and endorse blocks, they are considered
        // but without duplicates
        // anon endorsements are not added
        assert_eq!(res.as_ref().unwrap().len(), 3);
        // endorse endorsee is anon, so is not there
        // mint endorsee is the one after that
        assert_eq!(
            res.as_ref().unwrap()[0].pay_to_the_order_of.node_id,
            mint_endorsee_clone.node_id
        );
        // sell endorsee is the next one
        assert_eq!(
            res.as_ref().unwrap()[1].pay_to_the_order_of.node_id,
            sell_endorsee_clone.node_id
        );
        // drawer is the last one, because endorse endorsee is already there
        // and drawer != drawee
        assert_eq!(
            res.as_ref().unwrap()[2].pay_to_the_order_of.node_id,
            drawer.node_id
        );
    }

    #[tokio::test]
    async fn get_past_endorsees_multi() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        let drawer = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        let mint_endorsee =
            bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        let endorse_endorsee =
            bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        let sell_endorsee =
            bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());

        bill.drawer = drawer.clone();
        bill.drawee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        bill.payee = BillParticipant::Ident(
            BillIdentParticipant::new(get_baseline_identity().identity).unwrap(),
        );

        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        let endorse_endorsee_clone = endorse_endorsee.clone();
        let mint_endorsee_clone = mint_endorsee.clone();
        let sell_endorsee_clone = sell_endorsee.clone();

        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let now = util::date::now().timestamp() as u64;
                let mut chain = get_genesis_chain(Some(bill.clone()));

                // add endorse block from payee to endorsee
                let endorse_block = BillBlock::create_block_for_endorse(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillEndorseBlockData {
                        endorsee: BillParticipantBlockData::Ident(endorse_endorsee.clone().into()),
                        // endorsed by payee
                        endorser: BillParticipantBlockData::Ident(
                            BillIdentParticipant::new(get_baseline_identity().identity)
                                .unwrap()
                                .into(),
                        ),
                        signatory: None,
                        signing_timestamp: now + 1,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now + 1,
                )
                .unwrap();
                assert!(chain.try_add_block(endorse_block));

                // add sell block from endorsee to sell endorsee
                let sell_block = BillBlock::create_block_for_sell(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillSellBlockData {
                        buyer: BillParticipantBlockData::Ident(sell_endorsee.clone().into()),
                        // endorsed by endorsee
                        seller: BillParticipantBlockData::Ident(endorse_endorsee.clone().into()),
                        currency: "sat".to_string(),
                        sum: 15000,
                        payment_address: VALID_PAYMENT_ADDRESS_TESTNET.to_string(),
                        signatory: None,
                        signing_timestamp: now + 2,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now + 2,
                )
                .unwrap();
                assert!(chain.try_add_block(sell_block));

                // add mint block from sell endorsee to mint endorsee
                let mint_block = BillBlock::create_block_for_mint(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillMintBlockData {
                        endorsee: BillParticipantBlockData::Ident(mint_endorsee.clone().into()),
                        // endorsed by sell endorsee
                        endorser: BillParticipantBlockData::Ident(sell_endorsee.clone().into()),
                        currency: "sat".to_string(),
                        sum: 15000,
                        signatory: None,
                        signing_timestamp: now + 3,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now + 3,
                )
                .unwrap();
                assert!(chain.try_add_block(mint_block));

                // add endorse block back to endorsee
                let endorse_block_back = BillBlock::create_block_for_endorse(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillEndorseBlockData {
                        endorsee: BillParticipantBlockData::Ident(endorse_endorsee.clone().into()),
                        // endorsed by payee
                        endorser: BillParticipantBlockData::Ident(mint_endorsee.clone().into()),
                        signatory: None,
                        signing_timestamp: now + 4,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now + 4,
                )
                .unwrap();
                assert!(chain.try_add_block(endorse_block_back));

                // add endorse block back to payee (caller)
                let endorse_block_last = BillBlock::create_block_for_endorse(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillEndorseBlockData {
                        endorsee: BillParticipantBlockData::Ident(
                            BillIdentParticipant::new(get_baseline_identity().identity)
                                .unwrap()
                                .into(),
                        ),
                        // endorsed by payee
                        endorser: BillParticipantBlockData::Ident(endorse_endorsee.clone().into()),
                        signatory: None,
                        signing_timestamp: now + 5,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now + 5,
                )
                .unwrap();
                assert!(chain.try_add_block(endorse_block_last));

                Ok(chain)
            });
        let service = get_service(ctx);

        let res = service
            .get_past_endorsees(TEST_BILL_ID, &identity.identity.node_id)
            .await;
        assert!(res.is_ok());
        // if there are mint, sell and endorse blocks, they are considered
        // but without duplicates
        assert_eq!(res.as_ref().unwrap().len(), 4);
        // endorse endorsee is the one directly before
        assert_eq!(
            res.as_ref().unwrap()[0].pay_to_the_order_of.node_id,
            endorse_endorsee_clone.node_id
        );
        // mint endorsee is the one after that
        assert_eq!(
            res.as_ref().unwrap()[1].pay_to_the_order_of.node_id,
            mint_endorsee_clone.node_id
        );
        // sell endorsee is the next one
        assert_eq!(
            res.as_ref().unwrap()[2].pay_to_the_order_of.node_id,
            sell_endorsee_clone.node_id
        );
        // drawer is the last one, because endorse endorsee is already there
        // and drawer != drawee
        assert_eq!(
            res.as_ref().unwrap()[3].pay_to_the_order_of.node_id,
            drawer.node_id
        );
    }

    #[tokio::test]
    async fn past_payments_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let bill = get_baseline_bill(TEST_BILL_ID);

        let identity_clone = identity.identity.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        // paid
        ctx.bill_store.expect_is_paid().returning(|_| Ok(true));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));

                // req to pay
                assert!(chain.try_add_block(request_to_pay_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    None,
                )));
                // paid
                assert!(chain.try_add_block(offer_to_sell_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &BillIdentParticipant::new(identity_clone.clone()).unwrap(),
                    None,
                )));
                assert!(chain.try_add_block(sell_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &BillIdentParticipant::new(identity_clone.clone()).unwrap(),
                )));
                // rejected
                assert!(chain.try_add_block(offer_to_sell_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &BillIdentParticipant::new(identity_clone.clone()).unwrap(),
                    None,
                )));
                assert!(
                    chain.try_add_block(reject_buy_block(TEST_BILL_ID, chain.get_latest_block(),))
                );
                // expired
                assert!(chain.try_add_block(offer_to_sell_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &BillIdentParticipant::new(identity_clone.clone()).unwrap(),
                    None,
                )));
                // active
                assert!(chain.try_add_block(offer_to_sell_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &BillIdentParticipant::new(identity_clone.clone()).unwrap(),
                    Some(1931593928),
                )));

                Ok(chain)
            });

        let service = get_service(ctx);

        let res_past_payments = service
            .get_past_payments(
                TEST_BILL_ID,
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1931593928,
            )
            .await;

        assert!(res_past_payments.is_ok());
        assert_eq!(res_past_payments.as_ref().unwrap().len(), 4);
        match res_past_payments.as_ref().unwrap()[0] {
            PastPaymentResult::Payment(ref data) => {
                assert!(matches!(data.status, PastPaymentStatus::Paid(_)));
            }
            _ => panic!("wrong result"),
        };
        match res_past_payments.as_ref().unwrap()[1] {
            PastPaymentResult::Sell(ref data) => {
                assert!(matches!(data.status, PastPaymentStatus::Paid(_)));
            }
            _ => panic!("wrong result"),
        };
        match res_past_payments.as_ref().unwrap()[2] {
            PastPaymentResult::Sell(ref data) => {
                assert!(matches!(data.status, PastPaymentStatus::Rejected(_)));
            }
            _ => panic!("wrong result"),
        };
        match res_past_payments.as_ref().unwrap()[3] {
            PastPaymentResult::Sell(ref data) => {
                assert!(matches!(data.status, PastPaymentStatus::Expired(_)));
            }
            _ => panic!("wrong result"),
        };
    }

    #[tokio::test]
    async fn past_payments_recourse() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let bill = get_baseline_bill(TEST_BILL_ID);

        let identity_clone = identity.identity.clone();
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        // not paid
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));

                // req to pay
                assert!(chain.try_add_block(request_to_pay_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    None,
                )));
                // reject payment
                assert!(
                    chain
                        .try_add_block(
                            reject_to_pay_block(TEST_BILL_ID, chain.get_latest_block(),)
                        )
                );
                // req to recourse
                assert!(chain.try_add_block(request_to_recourse_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &BillIdentParticipant::new(identity_clone.clone()).unwrap(),
                    None,
                )));
                // recourse - paid
                assert!(chain.try_add_block(recourse_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &BillIdentParticipant::new(identity_clone.clone()).unwrap(),
                )));
                // req to recourse
                assert!(chain.try_add_block(request_to_recourse_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &BillIdentParticipant::new(identity_clone.clone()).unwrap(),
                    None,
                )));
                // reject
                assert!(chain.try_add_block(reject_recourse_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                )));
                // expired
                assert!(chain.try_add_block(request_to_recourse_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &BillIdentParticipant::new(identity_clone.clone()).unwrap(),
                    None,
                )));
                // active
                assert!(chain.try_add_block(request_to_recourse_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &BillIdentParticipant::new(identity_clone.clone()).unwrap(),
                    Some(1931593928),
                )));

                Ok(chain)
            });

        let service = get_service(ctx);

        let res_past_payments = service
            .get_past_payments(
                TEST_BILL_ID,
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1931593928,
            )
            .await;

        assert!(res_past_payments.is_ok());
        assert_eq!(res_past_payments.as_ref().unwrap().len(), 4);
        match res_past_payments.as_ref().unwrap()[0] {
            PastPaymentResult::Payment(ref data) => {
                assert!(matches!(data.status, PastPaymentStatus::Rejected(_)));
            }
            _ => panic!("wrong result"),
        };
        match res_past_payments.as_ref().unwrap()[1] {
            PastPaymentResult::Recourse(ref data) => {
                assert!(matches!(data.status, PastPaymentStatus::Paid(_)));
            }
            _ => panic!("wrong result"),
        };
        match res_past_payments.as_ref().unwrap()[2] {
            PastPaymentResult::Recourse(ref data) => {
                assert!(matches!(data.status, PastPaymentStatus::Rejected(_)));
            }
            _ => panic!("wrong result"),
        };
        match res_past_payments.as_ref().unwrap()[3] {
            PastPaymentResult::Recourse(ref data) => {
                assert!(matches!(data.status, PastPaymentStatus::Expired(_)));
            }
            _ => panic!("wrong result"),
        };
    }

    #[tokio::test]
    async fn reject_acceptance_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let bill = get_baseline_bill(TEST_BILL_ID);
        let payee = bill.payee.clone();
        let now = util::date::now().timestamp() as u64;

        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));

                // add req to accept block
                let req_to_accept = BillBlock::create_block_for_request_to_accept(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillRequestToAcceptBlockData {
                        requester: payee.clone().into(),
                        signatory: None,
                        signing_timestamp: now + 1,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now + 1,
                )
                .unwrap();
                assert!(chain.try_add_block(req_to_accept));

                Ok(chain)
            });
        ctx.notification_service
            .expect_send_request_to_action_rejected_event()
            .with(always(), eq(ActionType::AcceptBill))
            .returning(|_, _| Ok(()));

        let service = get_service(ctx);
        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::RejectAcceptance,
                &BillParticipant::Ident(BillIdentParticipant::new(identity.identity).unwrap()),
                &identity.key_pair,
                now + 2,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(
            res.as_ref().unwrap().blocks()[2].op_code,
            BillOpCode::RejectToAccept
        );
    }

    #[tokio::test]
    async fn reject_acceptance_fails_for_anon() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let bill = get_baseline_bill(TEST_BILL_ID);
        let payee = bill.payee.clone();
        let now = util::date::now().timestamp() as u64;

        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));

                // add req to accept block
                let req_to_accept = BillBlock::create_block_for_request_to_accept(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillRequestToAcceptBlockData {
                        requester: payee.clone().into(),
                        signatory: None,
                        signing_timestamp: now + 1,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now + 1,
                )
                .unwrap();
                assert!(chain.try_add_block(req_to_accept));

                Ok(chain)
            });
        ctx.notification_service
            .expect_send_request_to_action_rejected_event()
            .with(always(), eq(ActionType::AcceptBill))
            .returning(|_, _| Ok(()));

        let service = get_service(ctx);
        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::RejectAcceptance,
                &BillParticipant::Anon(BillAnonParticipant::new(identity.identity)),
                &identity.key_pair,
                now + 2,
            )
            .await;
        assert!(res.is_err());
        assert!(matches!(
            res.as_ref().unwrap_err(),
            Error::Validation(ValidationError::SignerCantBeAnon)
        ));
    }

    #[tokio::test]
    async fn reject_buying_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let bill = get_baseline_bill(TEST_BILL_ID);

        let identity_clone = identity.identity.clone();
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));

                assert!(chain.try_add_block(offer_to_sell_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &BillIdentParticipant::new(identity_clone.clone()).unwrap(),
                    None,
                )));

                Ok(chain)
            });

        ctx.notification_service
            .expect_send_request_to_action_rejected_event()
            .with(always(), eq(ActionType::BuyBill))
            .returning(|_, _| Ok(()));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::RejectBuying,
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(
            res.as_ref().unwrap().blocks()[2].op_code,
            BillOpCode::RejectToBuy
        );
    }

    #[tokio::test]
    async fn reject_buying_anon_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let bill = get_baseline_bill(TEST_BILL_ID);

        let identity_clone = identity.identity.clone();
        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_store.expect_exists().returning(|_| Ok(true));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));

                assert!(chain.try_add_block(offer_to_sell_block(
                    TEST_BILL_ID,
                    chain.get_latest_block(),
                    &BillIdentParticipant::new(identity_clone.clone()).unwrap(),
                    None,
                )));

                Ok(chain)
            });

        ctx.notification_service
            .expect_send_request_to_action_rejected_event()
            .with(always(), eq(ActionType::BuyBill))
            .returning(|_, _| Ok(()));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::RejectBuying,
                &BillParticipant::Anon(BillAnonParticipant::new(identity.identity.clone())),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(
            res.as_ref().unwrap().blocks()[2].op_code,
            BillOpCode::RejectToBuy
        );
    }

    #[tokio::test]
    async fn reject_payment() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let bill = get_baseline_bill(TEST_BILL_ID);
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        let payee = bill.payee.clone();
        let now = util::date::now().timestamp() as u64;

        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));

                // add req to pay
                let req_to_pay = BillBlock::create_block_for_request_to_pay(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillRequestToPayBlockData {
                        requester: payee.clone().into(),
                        currency: "sat".to_string(),
                        signatory: None,
                        signing_timestamp: now,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now,
                )
                .unwrap();
                assert!(chain.try_add_block(req_to_pay));

                Ok(chain)
            });
        ctx.notification_service
            .expect_send_request_to_action_rejected_event()
            .with(always(), eq(ActionType::PayBill))
            .returning(|_, _| Ok(()));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::RejectPayment,
                &BillParticipant::Ident(BillIdentParticipant::new(identity.identity).unwrap()),
                &identity.key_pair,
                now + 1,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(
            res.as_ref().unwrap().blocks()[2].op_code,
            BillOpCode::RejectToPay
        );
    }

    #[tokio::test]
    async fn reject_payment_fails_for_anon() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let bill = get_baseline_bill(TEST_BILL_ID);
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        let payee = bill.payee.clone();
        let now = util::date::now().timestamp() as u64;

        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));

                // add req to pay
                let req_to_pay = BillBlock::create_block_for_request_to_pay(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillRequestToPayBlockData {
                        requester: payee.clone().into(),
                        currency: "sat".to_string(),
                        signatory: None,
                        signing_timestamp: now,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now,
                )
                .unwrap();
                assert!(chain.try_add_block(req_to_pay));

                Ok(chain)
            });
        ctx.notification_service
            .expect_send_request_to_action_rejected_event()
            .with(always(), eq(ActionType::PayBill))
            .returning(|_, _| Ok(()));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::RejectPayment,
                &BillParticipant::Anon(BillAnonParticipant::new(identity.identity)),
                &identity.key_pair,
                now + 1,
            )
            .await;
        assert!(res.is_err());
        assert!(matches!(
            res.as_ref().unwrap_err(),
            Error::Validation(ValidationError::SignerCantBeAnon)
        ));
    }

    #[tokio::test]
    async fn reject_recourse() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let bill = get_baseline_bill(TEST_BILL_ID);
        let payee = bill.payee.clone();
        let now = util::date::now().timestamp() as u64;

        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));

                // add req to pay
                let req_to_pay = BillBlock::create_block_for_request_recourse(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillRequestRecourseBlockData {
                        recourser: bill_identified_participant_only_node_id(payee.node_id()).into(),
                        recoursee: BillIdentParticipant::new(get_baseline_identity().identity)
                            .unwrap()
                            .into(),
                        currency: "sat".to_string(),
                        sum: 15000,
                        recourse_reason: BillRecourseReasonBlockData::Pay,
                        signatory: None,
                        signing_timestamp: now,
                        signing_address: empty_address(),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now,
                )
                .unwrap();
                assert!(chain.try_add_block(req_to_pay));

                Ok(chain)
            });
        ctx.notification_service
            .expect_send_request_to_action_rejected_event()
            .with(always(), eq(ActionType::RecourseBill))
            .returning(|_, _| Ok(()));

        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::RejectPaymentForRecourse,
                &BillParticipant::Ident(BillIdentParticipant::new(identity.identity).unwrap()),
                &identity.key_pair,
                now + 1,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(
            res.as_ref().unwrap().blocks()[2].op_code,
            BillOpCode::RejectToPayRecourse
        );
    }

    #[tokio::test]
    async fn reject_recourse_fails_for_anon() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let bill = get_baseline_bill(TEST_BILL_ID);
        let payee = bill.payee.clone();
        let now = util::date::now().timestamp() as u64;

        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));

                // add req to pay
                let req_to_pay = BillBlock::create_block_for_request_recourse(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillRequestRecourseBlockData {
                        recourser: bill_identified_participant_only_node_id(payee.node_id()).into(),
                        recoursee: BillIdentParticipant::new(get_baseline_identity().identity)
                            .unwrap()
                            .into(),
                        currency: "sat".to_string(),
                        sum: 15000,
                        recourse_reason: BillRecourseReasonBlockData::Pay,
                        signatory: None,
                        signing_timestamp: now,
                        signing_address: empty_address(),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now,
                )
                .unwrap();
                assert!(chain.try_add_block(req_to_pay));

                Ok(chain)
            });
        ctx.notification_service
            .expect_send_request_to_action_rejected_event()
            .with(always(), eq(ActionType::RecourseBill))
            .returning(|_, _| Ok(()));

        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::RejectPaymentForRecourse,
                &BillParticipant::Anon(BillAnonParticipant::new(identity.identity)),
                &identity.key_pair,
                now + 1,
            )
            .await;
        assert!(res.is_err());
        assert!(matches!(
            res.as_ref().unwrap_err(),
            Error::Validation(ValidationError::SignerCantBeAnon)
        ));
    }

    #[tokio::test]
    async fn check_bills_in_recourse_payment_baseline() {
        let mut ctx = get_ctx();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(
            BillIdentParticipant::new(get_baseline_identity().identity).unwrap(),
        );

        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_store
            .expect_get_bill_ids_waiting_for_recourse_payment()
            .returning(|| Ok(vec![TEST_BILL_ID.to_string()]));
        let recoursee = BcrKeys::new().get_public_key();
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let now = util::date::now().timestamp() as u64;
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_recourse = BillBlock::create_block_for_request_recourse(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillRequestRecourseBlockData {
                        recourser: BillIdentParticipant::new(get_baseline_identity().identity)
                            .unwrap()
                            .into(),
                        recoursee: bill_identified_participant_only_node_id(recoursee.clone())
                            .into(),
                        currency: "sat".to_string(),
                        sum: 15000,
                        recourse_reason: BillRecourseReasonBlockData::Pay,
                        signatory: None,
                        signing_timestamp: now,
                        signing_address: empty_address(),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now,
                )
                .unwrap();
                assert!(chain.try_add_block(req_to_recourse));
                Ok(chain)
            });
        ctx.notification_service
            .expect_send_bill_recourse_paid_event()
            .returning(|_, _| Ok(()));

        let service = get_service(ctx);

        let res = service.check_bills_in_recourse_payment().await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn check_bills_in_recourse_payment_company_is_recourser() {
        let mut ctx = get_ctx();
        let mut identity = get_baseline_identity();
        identity.key_pair = BcrKeys::new();
        identity.identity.node_id = identity.key_pair.get_public_key();

        let company = get_baseline_company_data();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.payee = BillParticipant::Ident(BillIdentParticipant::from(company.1.0.clone()));

        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_store
            .expect_get_bill_ids_waiting_for_recourse_payment()
            .returning(|| Ok(vec![TEST_BILL_ID.to_string()]));
        let company_clone = company.clone();
        ctx.company_store.expect_get_all().returning(move || {
            let mut map = HashMap::new();
            map.insert(
                company_clone.0.clone(),
                (company_clone.1.0.clone(), company_clone.1.1.clone()),
            );
            Ok(map)
        });
        let company_clone = company.1.0.clone();
        let recoursee = BcrKeys::new().get_public_key();
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let now = util::date::now().timestamp() as u64;
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_recourse = BillBlock::create_block_for_request_recourse(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillRequestRecourseBlockData {
                        recourser: BillIdentParticipant::from(company_clone.clone()).into(),
                        recoursee: bill_identified_participant_only_node_id(recoursee.clone())
                            .into(),
                        currency: "sat".to_string(),
                        sum: 15000,
                        recourse_reason: BillRecourseReasonBlockData::Pay,
                        signatory: Some(BillSignatoryBlockData {
                            node_id: get_baseline_identity().identity.node_id.clone(),
                            name: get_baseline_identity().identity.name.clone(),
                        }),
                        signing_timestamp: now,
                        signing_address: empty_address(),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    Some(&BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()),
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    now,
                )
                .unwrap();
                assert!(chain.try_add_block(req_to_recourse));
                Ok(chain)
            });
        ctx.notification_service
            .expect_send_bill_recourse_paid_event()
            .returning(|_, _| Ok(()));
        let service = get_service(ctx);

        let res = service.check_bills_in_recourse_payment().await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn request_recourse_accept_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        let payee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        bill.payee = BillParticipant::Ident(payee.clone());
        let recoursee = payee.clone();
        let endorsee_caller = BillIdentParticipant::new(identity.identity.clone()).unwrap();

        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let endorse_block = BillBlock::create_block_for_endorse(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillEndorseBlockData {
                        endorser: bill.payee.clone().into(),
                        endorsee: BillParticipantBlockData::Ident(endorsee_caller.clone().into()),
                        signatory: None,
                        signing_timestamp: 1731593927,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::new(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    1731593927,
                )
                .unwrap();
                chain.try_add_block(endorse_block);
                let req_to_accept = BillBlock::create_block_for_request_to_accept(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillRequestToAcceptBlockData {
                        requester: bill.payee.clone().into(),
                        signatory: None,
                        signing_timestamp: 1731593927,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::new(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    1731593927,
                )
                .unwrap();
                chain.try_add_block(req_to_accept);
                let reject_accept = BillBlock::create_block_for_reject_to_accept(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillRejectBlockData {
                        rejecter: bill.drawee.clone().into(),
                        signatory: None,
                        signing_timestamp: 1731593927,
                        signing_address: empty_address(),
                    },
                    &BcrKeys::new(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    1731593927,
                )
                .unwrap();
                chain.try_add_block(reject_accept);
                Ok(chain)
            });
        // Request to recourse event should be sent
        ctx.notification_service
            .expect_send_recourse_action_event()
            .returning(|_, _, _| Ok(()));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::RequestRecourse(recoursee, RecourseReason::Accept),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().blocks().len() == 5);
        assert!(res.unwrap().blocks()[4].op_code == BillOpCode::RequestRecourse);
    }

    #[tokio::test]
    async fn request_recourse_fails_for_anon() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        let payee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        bill.payee = BillParticipant::Ident(payee.clone());
        let recoursee = payee.clone();
        let endorsee_caller = BillIdentParticipant::new(identity.identity.clone()).unwrap();

        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let endorse_block = BillBlock::create_block_for_endorse(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillEndorseBlockData {
                        endorser: bill.payee.clone().into(),
                        endorsee: BillParticipantBlockData::Ident(endorsee_caller.clone().into()),
                        signatory: None,
                        signing_timestamp: 1731593927,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::new(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    1731593927,
                )
                .unwrap();
                chain.try_add_block(endorse_block);
                let req_to_pay = BillBlock::create_block_for_request_to_pay(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillRequestToPayBlockData {
                        requester: bill.payee.clone().into(),
                        currency: "sat".to_string(),
                        signatory: None,
                        signing_timestamp: 1731593927,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::new(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    1731593927,
                )
                .unwrap();
                chain.try_add_block(req_to_pay);
                let reject_pay = BillBlock::create_block_for_reject_to_pay(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillRejectBlockData {
                        rejecter: bill.drawee.clone().into(),
                        signatory: None,
                        signing_timestamp: 1731593927,
                        signing_address: empty_address(),
                    },
                    &BcrKeys::new(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    1731593927,
                )
                .unwrap();
                chain.try_add_block(reject_pay);
                Ok(chain)
            });
        // Request to recourse event should be sent
        ctx.notification_service
            .expect_send_recourse_action_event()
            .returning(|_, _, _| Ok(()));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::RequestRecourse(
                    recoursee,
                    RecourseReason::Pay(15000, "sat".to_string()),
                ),
                &BillParticipant::Anon(BillAnonParticipant::new(identity.identity.clone())),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_err());
        assert!(matches!(
            res.as_ref().unwrap_err(),
            Error::Validation(ValidationError::SignerCantBeAnon)
        ));
    }

    #[tokio::test]
    async fn request_recourse_payment_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        let payee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        bill.payee = BillParticipant::Ident(payee.clone());
        let recoursee = payee.clone();
        let endorsee_caller = BillIdentParticipant::new(identity.identity.clone()).unwrap();

        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let endorse_block = BillBlock::create_block_for_endorse(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillEndorseBlockData {
                        endorser: bill.payee.clone().into(),
                        endorsee: BillParticipantBlockData::Ident(endorsee_caller.clone().into()),
                        signatory: None,
                        signing_timestamp: 1731593927,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::new(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    1731593927,
                )
                .unwrap();
                chain.try_add_block(endorse_block);
                let req_to_pay = BillBlock::create_block_for_request_to_pay(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillRequestToPayBlockData {
                        requester: bill.payee.clone().into(),
                        currency: "sat".to_string(),
                        signatory: None,
                        signing_timestamp: 1731593927,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::new(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    1731593927,
                )
                .unwrap();
                chain.try_add_block(req_to_pay);
                let reject_pay = BillBlock::create_block_for_reject_to_pay(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillRejectBlockData {
                        rejecter: bill.drawee.clone().into(),
                        signatory: None,
                        signing_timestamp: 1731593927,
                        signing_address: empty_address(),
                    },
                    &BcrKeys::new(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    1731593927,
                )
                .unwrap();
                chain.try_add_block(reject_pay);
                Ok(chain)
            });
        // Request to recourse event should be sent
        ctx.notification_service
            .expect_send_recourse_action_event()
            .returning(|_, _, _| Ok(()));
        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::RequestRecourse(
                    recoursee,
                    RecourseReason::Pay(15000, "sat".to_string()),
                ),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().blocks().len() == 5);
        assert!(res.unwrap().blocks()[4].op_code == BillOpCode::RequestRecourse);
    }

    #[tokio::test]
    async fn recourse_bitcredit_bill_baseline() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        bill.payee =
            BillParticipant::Ident(BillIdentParticipant::new(identity.identity.clone()).unwrap());
        let recoursee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        let recoursee_clone = recoursee.clone();
        let identity_clone = identity.identity.clone();

        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_recourse = BillBlock::create_block_for_request_recourse(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillRequestRecourseBlockData {
                        recourser: BillIdentParticipant::new(identity_clone.clone())
                            .unwrap()
                            .into(),
                        recoursee: recoursee_clone.clone().into(),
                        sum: 15000,
                        currency: "sat".to_string(),
                        recourse_reason: BillRecourseReasonBlockData::Pay,
                        signatory: None,
                        signing_timestamp: 1731593927,
                        signing_address: empty_address(),
                    },
                    &BcrKeys::new(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    1731593927,
                )
                .unwrap();
                chain.try_add_block(req_to_recourse);
                Ok(chain)
            });
        // Recourse paid event should be sent
        ctx.notification_service
            .expect_send_bill_recourse_paid_event()
            .returning(|_, _| Ok(()));

        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Recourse(
                    recoursee,
                    15000,
                    "sat".to_string(),
                    RecourseReason::Pay(15000, "sat".into()),
                ),
                &BillParticipant::Ident(
                    BillIdentParticipant::new(identity.identity.clone()).unwrap(),
                ),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().blocks().len(), 3);
        assert_eq!(res.unwrap().blocks()[2].op_code, BillOpCode::Recourse);
    }

    #[tokio::test]
    async fn recourse_bitcredit_bill_fails_for_anon() {
        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(TEST_BILL_ID);
        bill.drawee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        bill.payee =
            BillParticipant::Ident(BillIdentParticipant::new(identity.identity.clone()).unwrap());
        let recoursee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        let recoursee_clone = recoursee.clone();
        let identity_clone = identity.identity.clone();

        ctx.bill_store
            .expect_save_bill_to_cache()
            .returning(|_, _| Ok(()));
        ctx.bill_store.expect_is_paid().returning(|_| Ok(false));
        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                let req_to_recourse = BillBlock::create_block_for_request_recourse(
                    TEST_BILL_ID.to_string(),
                    chain.get_latest_block(),
                    &BillRequestRecourseBlockData {
                        recourser: BillIdentParticipant::new(identity_clone.clone())
                            .unwrap()
                            .into(),
                        recoursee: recoursee_clone.clone().into(),
                        sum: 15000,
                        currency: "sat".to_string(),
                        recourse_reason: BillRecourseReasonBlockData::Pay,
                        signatory: None,
                        signing_timestamp: 1731593927,
                        signing_address: empty_address(),
                    },
                    &BcrKeys::new(),
                    None,
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    1731593927,
                )
                .unwrap();
                chain.try_add_block(req_to_recourse);
                Ok(chain)
            });
        // Recourse paid event should be sent
        ctx.notification_service
            .expect_send_bill_recourse_paid_event()
            .returning(|_, _| Ok(()));

        let service = get_service(ctx);

        let res = service
            .execute_bill_action(
                TEST_BILL_ID,
                BillAction::Recourse(
                    recoursee,
                    15000,
                    "sat".to_string(),
                    RecourseReason::Pay(15000, "sat".into()),
                ),
                &BillParticipant::Anon(BillAnonParticipant::new(identity.identity.clone())),
                &identity.key_pair,
                1731593928,
            )
            .await;
        assert!(res.is_err());
        assert!(matches!(
            res.as_ref().unwrap_err(),
            Error::Validation(ValidationError::SignerCantBeAnon)
        ));
    }

    #[test]
    fn check_req_for_expiration_baseline() {
        let ctx = get_ctx();
        let service = get_service(ctx);
        let mut bill_payment = get_baseline_cached_bill(TEST_BILL_ID.to_string());
        bill_payment.status.payment = BillPaymentStatus {
            time_of_request_to_pay: Some(1531593928),
            requested_to_pay: true,
            paid: false,
            request_to_pay_timed_out: false,
            rejected_to_pay: false,
        };

        assert!(
            service
                .check_requests_for_expiration(&bill_payment, 1731593928)
                .unwrap()
        );
        bill_payment.status.payment.request_to_pay_timed_out = true;
        // if it already timed out, we don't need to check anymore
        assert!(
            !service
                .check_requests_for_expiration(&bill_payment, 1731593928)
                .unwrap()
        );
        bill_payment.status.payment.request_to_pay_timed_out = false;
        assert!(
            !service
                .check_requests_for_expiration(&bill_payment, 1431593928)
                .unwrap()
        );
        bill_payment.data.maturity_date = "2018-07-15".into(); // before ts
        assert!(
            !service
                .check_requests_for_expiration(&bill_payment, 1531593929)
                .unwrap()
        );
        bill_payment.current_waiting_state = Some(BillCurrentWaitingState::Payment(
            BillWaitingForPaymentState {
                time_of_request: 1531593928,
                payer: empty_bill_identified_participant(),
                payee: BillParticipant::Ident(empty_bill_identified_participant()),
                currency: "sat".into(),
                sum: "10".into(),
                link_to_pay: String::default(),
                address_to_pay: String::default(),
                mempool_link_for_address_to_pay: String::default(),
            },
        ));
        // req to pay expired, but not yet 2 days after end of day maturity date
        // current waiting state set, so wasnt recalculated yet
        assert!(
            service
                .check_requests_for_expiration(
                    &bill_payment,
                    1531593929 + PAYMENT_DEADLINE_SECONDS + 1
                )
                .unwrap()
        );
        bill_payment.current_waiting_state = None;
        // req to pay expired, but not yet 2 days after end of day maturity date
        // but no current waiting state, so was already checked
        assert!(
            !service
                .check_requests_for_expiration(
                    &bill_payment,
                    1531593929 + PAYMENT_DEADLINE_SECONDS + 1
                )
                .unwrap()
        );
        // after req to pay, and after end of day maturity date, payment expired
        assert!(
            service
                .check_requests_for_expiration(&bill_payment, 1831593928)
                .unwrap()
        );
        // 1 sec after req to pay, not expired at all
        assert!(
            !service
                .check_requests_for_expiration(&bill_payment, 1531593929)
                .unwrap()
        );
        bill_payment.status.payment.rejected_to_pay = true;
        // already rejected, no need to check anymore
        assert!(
            !service
                .check_requests_for_expiration(&bill_payment, 1831593928)
                .unwrap()
        );
        bill_payment.status.payment.rejected_to_pay = false;
        bill_payment.status.payment.paid = true;
        // already paid, no need to check anymore
        assert!(
            !service
                .check_requests_for_expiration(&bill_payment, 1831593928)
                .unwrap()
        );
        bill_payment.status.payment.paid = false;

        let mut bill_acceptance = get_baseline_cached_bill(TEST_BILL_ID.to_string());
        bill_acceptance.status.acceptance = BillAcceptanceStatus {
            time_of_request_to_accept: Some(1531593928),
            requested_to_accept: true,
            accepted: false,
            request_to_accept_timed_out: false,
            rejected_to_accept: false,
        };

        assert!(
            service
                .check_requests_for_expiration(&bill_acceptance, 1731593928)
                .unwrap()
        );
        bill_acceptance
            .status
            .acceptance
            .request_to_accept_timed_out = true;
        // already expired, no need to check anymore
        assert!(
            !service
                .check_requests_for_expiration(&bill_acceptance, 1731593928)
                .unwrap()
        );
        bill_acceptance
            .status
            .acceptance
            .request_to_accept_timed_out = false;
        bill_acceptance.status.acceptance.rejected_to_accept = true;
        // already rejected, no need to check anymore
        assert!(
            !service
                .check_requests_for_expiration(&bill_acceptance, 1731593928)
                .unwrap()
        );
        bill_acceptance.status.acceptance.rejected_to_accept = false;
        bill_acceptance.status.acceptance.accepted = true;
        // already accepted, no need to check anymore
        assert!(
            !service
                .check_requests_for_expiration(&bill_acceptance, 1731593928)
                .unwrap()
        );
        bill_acceptance.status.acceptance.accepted = false;

        let mut bill_sell = get_baseline_cached_bill(TEST_BILL_ID.to_string());
        bill_sell.status.sell = BillSellStatus {
            time_of_last_offer_to_sell: Some(1531593928),
            offered_to_sell: true,
            sold: false,
            offer_to_sell_timed_out: false,
            rejected_offer_to_sell: false,
        };

        assert!(
            service
                .check_requests_for_expiration(&bill_sell, 1731593928)
                .unwrap()
        );

        bill_sell.status.sell.offer_to_sell_timed_out = true;
        // already expired, no need to check anymore
        assert!(
            !service
                .check_requests_for_expiration(&bill_sell, 1731593928)
                .unwrap()
        );
        bill_sell.status.sell.offer_to_sell_timed_out = false;
        bill_sell.status.sell.rejected_offer_to_sell = true;
        // already rejected, no need to check anymore
        assert!(
            !service
                .check_requests_for_expiration(&bill_sell, 1731593928)
                .unwrap()
        );
        bill_sell.status.sell.rejected_offer_to_sell = false;
        bill_sell.status.sell.sold = true;
        // already sold, no need to check anymore
        assert!(
            !service
                .check_requests_for_expiration(&bill_sell, 1731593928)
                .unwrap()
        );
        bill_sell.status.sell.sold = false;

        let mut bill_recourse = get_baseline_cached_bill(TEST_BILL_ID.to_string());
        bill_recourse.status.recourse = BillRecourseStatus {
            time_of_last_request_to_recourse: Some(1531593928),
            requested_to_recourse: true,
            recoursed: false,
            request_to_recourse_timed_out: false,
            rejected_request_to_recourse: false,
        };

        assert!(
            service
                .check_requests_for_expiration(&bill_recourse, 1731593928)
                .unwrap()
        );
        bill_recourse.status.recourse.request_to_recourse_timed_out = true;
        // already expired, no need to check anymore
        assert!(
            !service
                .check_requests_for_expiration(&bill_recourse, 1731593928)
                .unwrap()
        );
        bill_recourse.status.recourse.rejected_request_to_recourse = true;
        // already rejected, no need to check anymore
        assert!(
            !service
                .check_requests_for_expiration(&bill_recourse, 1731593928)
                .unwrap()
        );
        bill_recourse.status.recourse.rejected_request_to_recourse = false;
        bill_recourse.status.recourse.recoursed = true;
        // already recoursed, no need to check anymore
        assert!(
            !service
                .check_requests_for_expiration(&bill_recourse, 1731593928)
                .unwrap()
        );
        bill_recourse.status.recourse.recoursed = false;
    }
}
