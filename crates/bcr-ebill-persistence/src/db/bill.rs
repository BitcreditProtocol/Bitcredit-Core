use std::collections::HashSet;

use super::surreal::{Bindings, SurrealWrapper};
use super::{FileDb, PostalAddressDb, Result};
use crate::constants::{DB_BILL_ID, DB_IDS, DB_OP_CODE, DB_TABLE, DB_TIMESTAMP};
use crate::{Error, bill::BillStoreApi};
use async_trait::async_trait;
use bcr_ebill_core::ServiceTraitBounds;
use bcr_ebill_core::bill::{
    BillAcceptanceStatus, BillCurrentWaitingState, BillData, BillParticipants, BillPaymentStatus,
    BillRecourseStatus, BillSellStatus, BillStatus, BillWaitingForPaymentState,
    BillWaitingForRecourseState, BillWaitingForSellState, BitcreditBillResult,
};
use bcr_ebill_core::constants::{PAYMENT_DEADLINE_SECONDS, RECOURSE_DEADLINE_SECONDS};
use bcr_ebill_core::contact::{
    BillAnonParticipant, BillIdentParticipant, BillParticipant, ContactType,
};
use bcr_ebill_core::{bill::BillKeys, blockchain::bill::BillOpCode, util};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Clone)]
pub struct SurrealBillStore {
    db: SurrealWrapper,
}

impl SurrealBillStore {
    const CHAIN_TABLE: &'static str = "bill_chain";
    const KEYS_TABLE: &'static str = "bill_keys";
    const PAID_TABLE: &'static str = "bill_paid";
    const CACHE_TABLE: &'static str = "bill_cache";

    pub fn new(db: SurrealWrapper) -> Self {
        Self { db }
    }
}

impl ServiceTraitBounds for SurrealBillStore {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl BillStoreApi for SurrealBillStore {
    async fn get_bills_from_cache(&self, ids: &[String]) -> Result<Vec<BitcreditBillResult>> {
        let db_ids: Vec<Thing> = ids
            .iter()
            .map(|id| (SurrealBillStore::CACHE_TABLE.to_owned(), id.to_string()).into())
            .collect();
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::CACHE_TABLE)?;
        bindings.add(DB_IDS, db_ids)?;
        let results: Vec<BitcreditBillResultDb> = self
            .db
            .query(
                "SELECT * FROM type::table($table) WHERE id IN $ids",
                bindings,
            )
            .await?;
        Ok(results.into_iter().map(|bill| bill.into()).collect())
    }

    async fn get_bill_from_cache(&self, id: &str) -> Result<Option<BitcreditBillResult>> {
        let result: Option<BitcreditBillResultDb> =
            self.db.select_one(Self::CACHE_TABLE, id.to_owned()).await?;
        match result {
            None => Ok(None),
            Some(c) => Ok(Some(c.into())),
        }
    }

    async fn save_bill_to_cache(&self, id: &str, bill: &BitcreditBillResult) -> Result<()> {
        let id = id.to_owned();
        let entity: BitcreditBillResultDb = bill.into();
        let _: Option<BitcreditBillResultDb> = self
            .db
            .upsert(Self::CACHE_TABLE, id.to_owned(), entity)
            .await?;
        Ok(())
    }

    async fn invalidate_bill_in_cache(&self, id: &str) -> Result<()> {
        let _: Option<BitcreditBillResultDb> =
            self.db.delete(Self::CACHE_TABLE, id.to_owned()).await?;
        Ok(())
    }

    async fn clear_bill_cache(&self) -> Result<()> {
        let _: Vec<BitcreditBillResultDb> = self.db.delete_all(Self::CACHE_TABLE).await?;
        Ok(())
    }

    async fn exists(&self, id: &str) -> Result<bool> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::CHAIN_TABLE)?;
        bindings.add(DB_BILL_ID, id.to_owned())?;
        match self
            .db
            .query::<Option<BillIdDb>>(
                "SELECT bill_id FROM type::table($table) WHERE bill_id = $bill_id GROUP BY bill_id",
                bindings,
            )
            .await
        {
            Ok(res) => {
                if res.is_empty() {
                    // not found
                    Ok(false)
                } else {
                    // found - check keys
                    Ok(self.get_keys(id).await.map(|_| true).unwrap_or(false))
                }
            }
            Err(e) => {
                log::error!("Error checking bill exists: {e}");
                Ok(false)
            }
        }
    }

    async fn get_ids(&self) -> Result<Vec<String>> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::CHAIN_TABLE)?;
        let ids: Vec<BillIdDb> = self
            .db
            .query(
                "SELECT bill_id FROM type::table($table) GROUP BY bill_id",
                bindings,
            )
            .await?;
        Ok(ids.into_iter().map(|b| b.bill_id).collect())
    }

    async fn save_keys(&self, id: &str, key_pair: &BillKeys) -> Result<()> {
        let entity: BillKeysDb = key_pair.into();
        let _: Option<BillKeysDb> = self
            .db
            .create(Self::KEYS_TABLE, Some(id.to_owned()), entity)
            .await?;
        Ok(())
    }

    async fn get_keys(&self, id: &str) -> Result<BillKeys> {
        let result: Option<BillKeysDb> =
            self.db.select_one(Self::KEYS_TABLE, id.to_owned()).await?;
        match result {
            None => Err(Error::NoSuchEntity("bill".to_string(), id.to_owned())),
            Some(c) => Ok(c.into()),
        }
    }

    async fn is_paid(&self, id: &str) -> Result<bool> {
        let result: Option<BillPaidDb> =
            self.db.select_one(Self::PAID_TABLE, id.to_owned()).await?;
        Ok(result.is_some())
    }

    async fn set_to_paid(&self, id: &str, payment_address: &str) -> Result<()> {
        let entity = BillPaidDb {
            id: (Self::PAID_TABLE, id).into(),
            payment_address: payment_address.to_string(),
        };
        let _: Option<BillPaidDb> = self
            .db
            .upsert(Self::PAID_TABLE, id.to_owned(), entity)
            .await?;
        Ok(())
    }

    async fn get_bill_ids_waiting_for_payment(&self) -> Result<Vec<String>> {
        let bill_ids_paid: Vec<BillPaidDb> = self.db.select_all(Self::PAID_TABLE).await?;
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::CHAIN_TABLE)?;
        bindings.add(DB_OP_CODE, BillOpCode::RequestToPay)?;
        let with_req_to_pay_bill_ids: Vec<BillIdDb> = self
            .db
            .query(
                "SELECT bill_id FROM type::table($table) WHERE op_code = $op_code GROUP BY bill_id",
                bindings,
            )
            .await?;
        let result: Vec<String> = with_req_to_pay_bill_ids
            .into_iter()
            .filter_map(|bid| {
                if !bill_ids_paid
                    .iter()
                    .any(|idp| idp.id.id.to_raw() == bid.bill_id)
                {
                    Some(bid.bill_id)
                } else {
                    None
                }
            })
            .collect();
        Ok(result)
    }

    async fn get_bill_ids_waiting_for_sell_payment(&self) -> Result<Vec<String>> {
        let timestamp_now_minus_payment_deadline =
            util::date::now().timestamp() - PAYMENT_DEADLINE_SECONDS as i64;
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::CHAIN_TABLE)?;
        bindings.add(DB_TIMESTAMP, timestamp_now_minus_payment_deadline)?;
        bindings.add(DB_OP_CODE, BillOpCode::OfferToSell)?;
        let query = r#"SELECT bill_id FROM 
            (SELECT bill_id, math::max(block_id) as block_id, op_code, timestamp FROM type::table($table) GROUP BY bill_id)
            .map(|$v| {
                (SELECT bill_id, block_id, op_code, timestamp FROM bill_chain WHERE bill_id = $v.bill_id AND block_id = $v.block_id)[0]
            })
            .flatten() WHERE timestamp > $timestamp AND op_code = $op_code"#;
        let result: Vec<BillIdDb> = self.db.query(query, bindings).await?;
        Ok(result.into_iter().map(|bid| bid.bill_id).collect())
    }

    async fn get_bill_ids_waiting_for_recourse_payment(&self) -> Result<Vec<String>> {
        let timestamp_now_minus_payment_deadline =
            util::date::now().timestamp() - RECOURSE_DEADLINE_SECONDS as i64;
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::CHAIN_TABLE)?;
        bindings.add(DB_TIMESTAMP, timestamp_now_minus_payment_deadline)?;
        bindings.add(DB_OP_CODE, BillOpCode::RequestRecourse)?;
        let query = r#"SELECT bill_id FROM 
            (SELECT bill_id, math::max(block_id) as block_id, op_code, timestamp FROM type::table($table) GROUP BY bill_id)
            .map(|$v| {
                (SELECT bill_id, block_id, op_code, timestamp FROM bill_chain WHERE bill_id = $v.bill_id AND block_id = $v.block_id)[0]
            })
            .flatten() WHERE timestamp > $timestamp AND op_code = $op_code"#;
        let result: Vec<BillIdDb> = self.db.query(query, bindings).await?;
        Ok(result.into_iter().map(|bid| bid.bill_id).collect())
    }

    async fn get_bill_ids_with_op_codes_since(
        &self,
        op_codes: HashSet<BillOpCode>,
        since: u64,
    ) -> Result<Vec<String>> {
        let codes = op_codes.into_iter().collect::<Vec<BillOpCode>>();
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::CHAIN_TABLE)?;
        bindings.add(DB_OP_CODE, codes)?;
        bindings.add(DB_TIMESTAMP, since as i64)?;
        let result: Vec<BillIdDb> = self
            .db
            .query("SELECT bill_id FROM type::table($table) WHERE op_code IN $op_code AND timestamp >= $timestamp GROUP BY bill_id", bindings)
            .await?;
        Ok(result.into_iter().map(|bid| bid.bill_id).collect())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcreditBillResultDb {
    pub id: Thing,
    pub participants: BillParticipantsDb,
    pub data: BillDataDb,
    pub status: BillStatusDb,
    pub current_waiting_state: Option<BillCurrentWaitingStateDb>,
}

impl From<BitcreditBillResultDb> for BitcreditBillResult {
    fn from(value: BitcreditBillResultDb) -> Self {
        Self {
            id: value.id.id.to_raw(),
            participants: value.participants.into(),
            data: value.data.into(),
            status: value.status.into(),
            current_waiting_state: value.current_waiting_state.map(|cws| cws.into()),
        }
    }
}

impl From<&BitcreditBillResult> for BitcreditBillResultDb {
    fn from(value: &BitcreditBillResult) -> Self {
        Self {
            id: (SurrealBillStore::CACHE_TABLE.to_owned(), value.id.clone()).into(),
            participants: (&value.participants).into(),
            data: (&value.data).into(),
            status: (&value.status).into(),
            current_waiting_state: value.current_waiting_state.as_ref().map(|cws| cws.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BillCurrentWaitingStateDb {
    Sell(BillWaitingForSellStateDb),
    Payment(BillWaitingForPaymentStateDb),
    Recourse(BillWaitingForRecourseStateDb),
}

impl From<BillCurrentWaitingStateDb> for BillCurrentWaitingState {
    fn from(value: BillCurrentWaitingStateDb) -> Self {
        match value {
            BillCurrentWaitingStateDb::Sell(state) => BillCurrentWaitingState::Sell(state.into()),
            BillCurrentWaitingStateDb::Payment(state) => {
                BillCurrentWaitingState::Payment(state.into())
            }
            BillCurrentWaitingStateDb::Recourse(state) => {
                BillCurrentWaitingState::Recourse(state.into())
            }
        }
    }
}

impl From<&BillCurrentWaitingState> for BillCurrentWaitingStateDb {
    fn from(value: &BillCurrentWaitingState) -> Self {
        match value {
            BillCurrentWaitingState::Sell(state) => BillCurrentWaitingStateDb::Sell(state.into()),
            BillCurrentWaitingState::Payment(state) => {
                BillCurrentWaitingStateDb::Payment(state.into())
            }
            BillCurrentWaitingState::Recourse(state) => {
                BillCurrentWaitingStateDb::Recourse(state.into())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillWaitingForSellStateDb {
    pub time_of_request: u64,
    pub buyer: BillParticipantDb,
    pub seller: BillParticipantDb,
    pub currency: String,
    pub sum: String,
    pub link_to_pay: String,
    pub address_to_pay: String,
    pub mempool_link_for_address_to_pay: String,
}

impl From<BillWaitingForSellStateDb> for BillWaitingForSellState {
    fn from(value: BillWaitingForSellStateDb) -> Self {
        Self {
            time_of_request: value.time_of_request,
            buyer: value.buyer.into(),
            seller: value.seller.into(),
            currency: value.currency,
            sum: value.sum,
            link_to_pay: value.link_to_pay,
            address_to_pay: value.address_to_pay,
            mempool_link_for_address_to_pay: value.mempool_link_for_address_to_pay,
        }
    }
}

impl From<&BillWaitingForSellState> for BillWaitingForSellStateDb {
    fn from(value: &BillWaitingForSellState) -> Self {
        Self {
            time_of_request: value.time_of_request,
            buyer: (&value.buyer).into(),
            seller: (&value.seller).into(),
            currency: value.currency.clone(),
            sum: value.sum.clone(),
            link_to_pay: value.link_to_pay.clone(),
            address_to_pay: value.address_to_pay.clone(),
            mempool_link_for_address_to_pay: value.mempool_link_for_address_to_pay.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillWaitingForPaymentStateDb {
    pub time_of_request: u64,
    pub payer: BillIdentParticipantDb,
    pub payee: BillParticipantDb,
    pub currency: String,
    pub sum: String,
    pub link_to_pay: String,
    pub address_to_pay: String,
    pub mempool_link_for_address_to_pay: String,
}

impl From<BillWaitingForPaymentStateDb> for BillWaitingForPaymentState {
    fn from(value: BillWaitingForPaymentStateDb) -> Self {
        Self {
            time_of_request: value.time_of_request,
            payer: value.payer.into(),
            payee: value.payee.into(),
            currency: value.currency,
            sum: value.sum,
            link_to_pay: value.link_to_pay,
            address_to_pay: value.address_to_pay,
            mempool_link_for_address_to_pay: value.mempool_link_for_address_to_pay,
        }
    }
}

impl From<&BillWaitingForPaymentState> for BillWaitingForPaymentStateDb {
    fn from(value: &BillWaitingForPaymentState) -> Self {
        Self {
            time_of_request: value.time_of_request,
            payer: (&value.payer).into(),
            payee: (&value.payee).into(),
            currency: value.currency.clone(),
            sum: value.sum.clone(),
            link_to_pay: value.link_to_pay.clone(),
            address_to_pay: value.address_to_pay.clone(),
            mempool_link_for_address_to_pay: value.mempool_link_for_address_to_pay.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillWaitingForRecourseStateDb {
    pub time_of_request: u64,
    pub recourser: BillIdentParticipantDb,
    pub recoursee: BillIdentParticipantDb,
    pub currency: String,
    pub sum: String,
    pub link_to_pay: String,
    pub address_to_pay: String,
    pub mempool_link_for_address_to_pay: String,
}

impl From<BillWaitingForRecourseStateDb> for BillWaitingForRecourseState {
    fn from(value: BillWaitingForRecourseStateDb) -> Self {
        Self {
            time_of_request: value.time_of_request,
            recourser: value.recourser.into(),
            recoursee: value.recoursee.into(),
            currency: value.currency,
            sum: value.sum,
            link_to_pay: value.link_to_pay,
            address_to_pay: value.address_to_pay,
            mempool_link_for_address_to_pay: value.mempool_link_for_address_to_pay,
        }
    }
}

impl From<&BillWaitingForRecourseState> for BillWaitingForRecourseStateDb {
    fn from(value: &BillWaitingForRecourseState) -> Self {
        Self {
            time_of_request: value.time_of_request,
            recourser: (&value.recourser).into(),
            recoursee: (&value.recoursee).into(),
            currency: value.currency.clone(),
            sum: value.sum.clone(),
            link_to_pay: value.link_to_pay.clone(),
            address_to_pay: value.address_to_pay.clone(),
            mempool_link_for_address_to_pay: value.mempool_link_for_address_to_pay.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillStatusDb {
    pub acceptance: BillAcceptanceStatusDb,
    pub payment: BillPaymentStatusDb,
    pub sell: BillSellStatusDb,
    pub recourse: BillRecourseStatusDb,
    pub redeemed_funds_available: bool,
    pub has_requested_funds: bool,
}

impl From<BillStatusDb> for BillStatus {
    fn from(value: BillStatusDb) -> Self {
        Self {
            acceptance: value.acceptance.into(),
            payment: value.payment.into(),
            sell: value.sell.into(),
            recourse: value.recourse.into(),
            redeemed_funds_available: value.redeemed_funds_available,
            has_requested_funds: value.has_requested_funds,
        }
    }
}

impl From<&BillStatus> for BillStatusDb {
    fn from(value: &BillStatus) -> Self {
        Self {
            acceptance: (&value.acceptance).into(),
            payment: (&value.payment).into(),
            sell: (&value.sell).into(),
            recourse: (&value.recourse).into(),
            redeemed_funds_available: value.redeemed_funds_available,
            has_requested_funds: value.has_requested_funds,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillAcceptanceStatusDb {
    pub time_of_request_to_accept: Option<u64>,
    pub requested_to_accept: bool,
    pub accepted: bool,
    pub request_to_accept_timed_out: bool,
    pub rejected_to_accept: bool,
}

impl From<BillAcceptanceStatusDb> for BillAcceptanceStatus {
    fn from(value: BillAcceptanceStatusDb) -> Self {
        Self {
            time_of_request_to_accept: value.time_of_request_to_accept,
            requested_to_accept: value.requested_to_accept,
            accepted: value.accepted,
            request_to_accept_timed_out: value.request_to_accept_timed_out,
            rejected_to_accept: value.rejected_to_accept,
        }
    }
}

impl From<&BillAcceptanceStatus> for BillAcceptanceStatusDb {
    fn from(value: &BillAcceptanceStatus) -> Self {
        Self {
            time_of_request_to_accept: value.time_of_request_to_accept,
            requested_to_accept: value.requested_to_accept,
            accepted: value.accepted,
            request_to_accept_timed_out: value.request_to_accept_timed_out,
            rejected_to_accept: value.rejected_to_accept,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillPaymentStatusDb {
    pub time_of_request_to_pay: Option<u64>,
    pub requested_to_pay: bool,
    pub paid: bool,
    pub request_to_pay_timed_out: bool,
    pub rejected_to_pay: bool,
}

impl From<BillPaymentStatusDb> for BillPaymentStatus {
    fn from(value: BillPaymentStatusDb) -> Self {
        Self {
            time_of_request_to_pay: value.time_of_request_to_pay,
            requested_to_pay: value.requested_to_pay,
            paid: value.paid,
            request_to_pay_timed_out: value.request_to_pay_timed_out,
            rejected_to_pay: value.rejected_to_pay,
        }
    }
}

impl From<&BillPaymentStatus> for BillPaymentStatusDb {
    fn from(value: &BillPaymentStatus) -> Self {
        Self {
            time_of_request_to_pay: value.time_of_request_to_pay,
            requested_to_pay: value.requested_to_pay,
            paid: value.paid,
            request_to_pay_timed_out: value.request_to_pay_timed_out,
            rejected_to_pay: value.rejected_to_pay,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillSellStatusDb {
    pub time_of_last_offer_to_sell: Option<u64>,
    pub sold: bool,
    pub offered_to_sell: bool,
    pub offer_to_sell_timed_out: bool,
    pub rejected_offer_to_sell: bool,
}

impl From<BillSellStatusDb> for BillSellStatus {
    fn from(value: BillSellStatusDb) -> Self {
        Self {
            time_of_last_offer_to_sell: value.time_of_last_offer_to_sell,
            sold: value.sold,
            offered_to_sell: value.offered_to_sell,
            offer_to_sell_timed_out: value.offer_to_sell_timed_out,
            rejected_offer_to_sell: value.rejected_offer_to_sell,
        }
    }
}

impl From<&BillSellStatus> for BillSellStatusDb {
    fn from(value: &BillSellStatus) -> Self {
        Self {
            time_of_last_offer_to_sell: value.time_of_last_offer_to_sell,
            sold: value.sold,
            offered_to_sell: value.offered_to_sell,
            offer_to_sell_timed_out: value.offer_to_sell_timed_out,
            rejected_offer_to_sell: value.rejected_offer_to_sell,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillRecourseStatusDb {
    pub time_of_last_request_to_recourse: Option<u64>,
    pub recoursed: bool,
    pub requested_to_recourse: bool,
    pub request_to_recourse_timed_out: bool,
    pub rejected_request_to_recourse: bool,
}

impl From<BillRecourseStatusDb> for BillRecourseStatus {
    fn from(value: BillRecourseStatusDb) -> Self {
        Self {
            time_of_last_request_to_recourse: value.time_of_last_request_to_recourse,
            recoursed: value.recoursed,
            requested_to_recourse: value.requested_to_recourse,
            request_to_recourse_timed_out: value.request_to_recourse_timed_out,
            rejected_request_to_recourse: value.rejected_request_to_recourse,
        }
    }
}

impl From<&BillRecourseStatus> for BillRecourseStatusDb {
    fn from(value: &BillRecourseStatus) -> Self {
        Self {
            time_of_last_request_to_recourse: value.time_of_last_request_to_recourse,
            recoursed: value.recoursed,
            requested_to_recourse: value.requested_to_recourse,
            request_to_recourse_timed_out: value.request_to_recourse_timed_out,
            rejected_request_to_recourse: value.rejected_request_to_recourse,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillDataDb {
    pub language: String,
    pub time_of_drawing: u64,
    pub issue_date: String,
    pub time_of_maturity: u64,
    pub maturity_date: String,
    pub country_of_issuing: String,
    pub city_of_issuing: String,
    pub country_of_payment: String,
    pub city_of_payment: String,
    pub currency: String,
    pub sum: String,
    pub files: Vec<FileDb>,
}

impl From<BillDataDb> for BillData {
    fn from(value: BillDataDb) -> Self {
        Self {
            language: value.language,
            time_of_drawing: value.time_of_drawing,
            issue_date: value.issue_date,
            time_of_maturity: value.time_of_maturity,
            maturity_date: value.maturity_date,
            country_of_issuing: value.country_of_issuing,
            city_of_issuing: value.city_of_issuing,
            country_of_payment: value.country_of_payment,
            city_of_payment: value.city_of_payment,
            currency: value.currency,
            sum: value.sum,
            files: value.files.iter().map(|f| f.to_owned().into()).collect(),
            active_notification: None,
        }
    }
}

impl From<&BillData> for BillDataDb {
    fn from(value: &BillData) -> Self {
        Self {
            language: value.language.clone(),
            time_of_drawing: value.time_of_drawing,
            issue_date: value.issue_date.clone(),
            time_of_maturity: value.time_of_maturity,
            maturity_date: value.maturity_date.clone(),
            country_of_issuing: value.country_of_issuing.clone(),
            city_of_issuing: value.city_of_issuing.clone(),
            country_of_payment: value.country_of_payment.clone(),
            city_of_payment: value.city_of_payment.clone(),
            currency: value.currency.clone(),
            sum: value.sum.clone(),
            files: value.files.iter().map(|f| f.clone().into()).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillParticipantsDb {
    pub drawee: BillIdentParticipantDb,
    pub drawer: BillIdentParticipantDb,
    pub payee: BillParticipantDb,
    pub endorsee: Option<BillParticipantDb>,
    pub endorsements_count: u64,
    pub all_participant_node_ids: Vec<String>,
}

impl From<BillParticipantsDb> for BillParticipants {
    fn from(value: BillParticipantsDb) -> Self {
        Self {
            drawee: value.drawee.into(),
            drawer: value.drawer.into(),
            payee: value.payee.into(),
            endorsee: value.endorsee.map(|e| e.into()),
            endorsements_count: value.endorsements_count,
            all_participant_node_ids: value.all_participant_node_ids,
        }
    }
}

impl From<&BillParticipants> for BillParticipantsDb {
    fn from(value: &BillParticipants) -> Self {
        Self {
            drawee: (&value.drawee).into(),
            drawer: (&value.drawer).into(),
            payee: (&value.payee).into(),
            endorsee: value.endorsee.as_ref().map(|e| e.into()),
            endorsements_count: value.endorsements_count,
            all_participant_node_ids: value.all_participant_node_ids.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum BillParticipantDb {
    Anon(BillAnonParticipantDb),
    Ident(BillIdentParticipantDb),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BillIdentParticipantDb {
    pub t: ContactType,
    pub node_id: String,
    pub name: String,
    pub postal_address: PostalAddressDb,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BillAnonParticipantDb {
    pub node_id: String,
}

impl From<BillParticipantDb> for BillParticipant {
    fn from(value: BillParticipantDb) -> Self {
        match value {
            BillParticipantDb::Anon(data) => BillParticipant::Anon(data.into()),
            BillParticipantDb::Ident(data) => BillParticipant::Ident(data.into()),
        }
    }
}

impl From<BillAnonParticipantDb> for BillAnonParticipant {
    fn from(value: BillAnonParticipantDb) -> Self {
        Self {
            node_id: value.node_id,
            email: None,
            nostr_relays: vec![],
        }
    }
}

impl From<BillIdentParticipantDb> for BillIdentParticipant {
    fn from(value: BillIdentParticipantDb) -> Self {
        Self {
            t: value.t,
            node_id: value.node_id,
            name: value.name,
            postal_address: value.postal_address.into(),
            email: None,
            nostr_relays: vec![],
        }
    }
}

impl From<&BillParticipant> for BillParticipantDb {
    fn from(value: &BillParticipant) -> Self {
        match value {
            BillParticipant::Anon(data) => BillParticipantDb::Anon(data.into()),
            BillParticipant::Ident(data) => BillParticipantDb::Ident(data.into()),
        }
    }
}

impl From<&BillAnonParticipant> for BillAnonParticipantDb {
    fn from(value: &BillAnonParticipant) -> Self {
        Self {
            node_id: value.node_id.clone(),
        }
    }
}

impl From<&BillIdentParticipant> for BillIdentParticipantDb {
    fn from(value: &BillIdentParticipant) -> Self {
        Self {
            t: value.t.clone(),
            node_id: value.node_id.clone(),
            name: value.name.clone(),
            postal_address: value.postal_address.clone().into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillPaidDb {
    pub id: Thing,
    pub payment_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillIdDb {
    pub bill_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillKeysDb {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Thing>,
    pub public_key: String,
    pub private_key: String,
}

impl From<BillKeysDb> for BillKeys {
    fn from(value: BillKeysDb) -> Self {
        Self {
            public_key: value.public_key,
            private_key: value.private_key,
        }
    }
}

impl From<&BillKeys> for BillKeysDb {
    fn from(value: &BillKeys) -> Self {
        Self {
            id: None,
            public_key: value.public_key.clone(),
            private_key: value.private_key.clone(),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::collections::HashSet;

    use super::SurrealBillStore;
    use crate::{
        bill::{BillChainStoreApi, BillStoreApi},
        db::{bill_chain::SurrealBillChainStore, get_memory_db, surreal::SurrealWrapper},
        tests::tests::{
            TEST_PRIVATE_KEY_SECP, TEST_PUB_KEY_SECP, bill_identified_participant_only_node_id,
            cached_bill, empty_address, empty_bitcredit_bill, get_bill_keys,
        },
        util::{self, BcrKeys},
    };
    use bcr_ebill_core::{
        bill::BillKeys,
        blockchain::bill::{
            BillBlock, BillOpCode,
            block::{
                BillIssueBlockData, BillOfferToSellBlockData, BillParticipantBlockData,
                BillRecourseBlockData, BillRecourseReasonBlockData, BillRequestRecourseBlockData,
                BillRequestToAcceptBlockData, BillRequestToPayBlockData, BillSellBlockData,
            },
        },
        contact::BillParticipant,
    };
    use chrono::Months;
    use surrealdb::{Surreal, engine::any::Any};

    async fn get_db() -> Surreal<Any> {
        get_memory_db("test", "bill")
            .await
            .expect("could not create memory db")
    }

    async fn get_store(mem_db: Surreal<Any>) -> SurrealBillStore {
        SurrealBillStore::new(SurrealWrapper {
            db: mem_db,
            files: false,
        })
    }

    async fn get_chain_store(mem_db: Surreal<Any>) -> SurrealBillChainStore {
        SurrealBillChainStore::new(SurrealWrapper {
            db: mem_db,
            files: false,
        })
    }

    pub fn get_first_block(id: &str) -> BillBlock {
        let mut bill = empty_bitcredit_bill();
        bill.maturity_date = "2099-05-05".to_string();
        bill.id = id.to_owned();
        bill.drawer = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());
        bill.payee = BillParticipant::Ident(bill.drawer.clone());
        bill.drawee = bill_identified_participant_only_node_id(BcrKeys::new().get_public_key());

        BillBlock::create_block_for_issue(
            id.to_owned(),
            String::from("prevhash"),
            &BillIssueBlockData::from(bill, None, 1731593928),
            &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
            None,
            &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
            1731593928,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_exists() {
        let db = get_db().await;
        let chain_store = get_chain_store(db.clone()).await;
        let store = get_store(db.clone()).await;
        assert!(!store.exists("1234").await.as_ref().unwrap());
        let first_block = get_first_block("1234");
        chain_store.add_block("1234", &first_block).await.unwrap();
        assert!(!store.exists("1234").await.as_ref().unwrap());
        chain_store
            .add_block(
                "1234",
                &BillBlock::create_block_for_request_to_pay(
                    "1234".to_string(),
                    &first_block,
                    &BillRequestToPayBlockData {
                        requester: BillParticipantBlockData::Ident(
                            bill_identified_participant_only_node_id(
                                BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP)
                                    .unwrap()
                                    .get_public_key(),
                            )
                            .into(),
                        ),
                        currency: "sat".to_string(),
                        signatory: None,
                        signing_timestamp: 1731593928,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    None,
                    &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
                    1731593928,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert!(!store.exists("1234").await.as_ref().unwrap());
        store
            .save_keys(
                "1234",
                &BillKeys {
                    private_key: TEST_PRIVATE_KEY_SECP.to_string(),
                    public_key: TEST_PUB_KEY_SECP.to_string(),
                },
            )
            .await
            .unwrap();
        assert!(store.exists("1234").await.as_ref().unwrap())
    }

    #[tokio::test]
    async fn test_get_ids() {
        let db = get_db().await;
        let chain_store = get_chain_store(db.clone()).await;
        let store = get_store(db.clone()).await;
        chain_store
            .add_block("1234", &get_first_block("1234"))
            .await
            .unwrap();
        chain_store
            .add_block("4321", &get_first_block("4321"))
            .await
            .unwrap();
        let res = store.get_ids().await;
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().contains(&"1234".to_string()));
        assert!(res.as_ref().unwrap().contains(&"4321".to_string()));
    }

    #[tokio::test]
    async fn test_save_get_keys() {
        let store = get_store(get_db().await).await;
        let res = store
            .save_keys(
                "1234",
                &BillKeys {
                    private_key: TEST_PRIVATE_KEY_SECP.to_owned(),
                    public_key: TEST_PUB_KEY_SECP.to_owned(),
                },
            )
            .await;
        assert!(res.is_ok());
        let get_res = store.get_keys("1234").await;
        assert!(get_res.is_ok());
        assert_eq!(get_res.as_ref().unwrap().private_key, TEST_PRIVATE_KEY_SECP);
    }

    #[tokio::test]
    async fn test_paid() {
        let store = get_store(get_db().await).await;
        let res = store
            .set_to_paid("1234", "tb1qteyk7pfvvql2r2zrsu4h4xpvju0nz7ykvguyk")
            .await;
        assert!(res.is_ok());
        let get_res = store.is_paid("1234").await;
        assert!(get_res.is_ok());
        assert!(get_res.as_ref().unwrap());

        // save again
        let res_again = store
            .set_to_paid("1234", "tb1qteyk7pfvvql2r2zrsu4h4xpvju0nz7ykvguyk")
            .await;
        assert!(res_again.is_ok());
        let get_res_again = store.is_paid("1234").await;
        assert!(get_res_again.is_ok());
        assert!(get_res_again.as_ref().unwrap());

        // different bill without paid state
        let get_res_not_paid = store.is_paid("4321").await;
        assert!(get_res_not_paid.is_ok());
        assert!(!get_res_not_paid.as_ref().unwrap());
    }

    #[tokio::test]
    async fn test_bills_waiting_for_payment() {
        let db = get_db().await;
        let chain_store = get_chain_store(db.clone()).await;
        let store = get_store(db.clone()).await;

        let first_block = get_first_block("1234");
        chain_store
            .add_block("4321", &get_first_block("4321"))
            .await
            .unwrap(); // not returned, no req to pay block
        chain_store.add_block("1234", &first_block).await.unwrap();
        chain_store
            .add_block(
                "1234",
                &BillBlock::create_block_for_request_to_pay(
                    "1234".to_string(),
                    &first_block,
                    &BillRequestToPayBlockData {
                        requester: BillParticipantBlockData::Ident(
                            bill_identified_participant_only_node_id(
                                BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP)
                                    .unwrap()
                                    .get_public_key(),
                            )
                            .into(),
                        ),
                        currency: "sat".to_string(),
                        signatory: None,
                        signing_timestamp: 1731593928,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    None,
                    &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
                    1731593928,
                )
                .unwrap(),
            )
            .await
            .unwrap();

        let res = store.get_bill_ids_waiting_for_payment().await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);

        // add the bill to paid, expect it not to be returned afterwards
        store
            .set_to_paid("1234", "tb1qteyk7pfvvql2r2zrsu4h4xpvju0nz7ykvguyk")
            .await
            .unwrap();

        let res_after_paid = store.get_bill_ids_waiting_for_payment().await;
        assert!(res_after_paid.is_ok());
        assert_eq!(res_after_paid.as_ref().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_bills_waiting_for_payment_offer_to_sell() {
        let db = get_db().await;
        let chain_store = get_chain_store(db.clone()).await;
        let store = get_store(db.clone()).await;
        let now = util::date::now().timestamp() as u64;

        let first_block = get_first_block("1234");
        chain_store
            .add_block("4321", &get_first_block("4321"))
            .await
            .unwrap(); // not returned, no offer to sell block
        chain_store.add_block("1234", &first_block).await.unwrap();
        let second_block = BillBlock::create_block_for_offer_to_sell(
            "1234".to_string(),
            &first_block,
            &BillOfferToSellBlockData {
                seller: BillParticipantBlockData::Ident(
                    bill_identified_participant_only_node_id(
                        BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP)
                            .unwrap()
                            .get_public_key(),
                    )
                    .into(),
                ),
                buyer: BillParticipantBlockData::Ident(
                    bill_identified_participant_only_node_id(BcrKeys::new().get_public_key())
                        .into(),
                ),
                currency: "sat".to_string(),
                sum: 15000,
                payment_address: "tb1qteyk7pfvvql2r2zrsu4h4xpvju0nz7ykvguyk".to_string(),
                signatory: None,
                signing_timestamp: now,
                signing_address: Some(empty_address()),
            },
            &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
            None,
            &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
            now,
        )
        .unwrap();
        chain_store.add_block("1234", &second_block).await.unwrap();

        let res = store.get_bill_ids_waiting_for_sell_payment().await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);

        chain_store
            .add_block(
                "1234",
                &BillBlock::create_block_for_sell(
                    "1234".to_string(),
                    &second_block,
                    &BillSellBlockData {
                        seller: BillParticipantBlockData::Ident(
                            bill_identified_participant_only_node_id(
                                BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP)
                                    .unwrap()
                                    .get_public_key(),
                            )
                            .into(),
                        ),
                        buyer: BillParticipantBlockData::Ident(
                            bill_identified_participant_only_node_id(
                                BcrKeys::new().get_public_key(),
                            )
                            .into(),
                        ),
                        currency: "sat".to_string(),
                        sum: 15000,
                        payment_address: "tb1qteyk7pfvvql2r2zrsu4h4xpvju0nz7ykvguyk".to_string(),
                        signatory: None,
                        signing_timestamp: now,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    None,
                    &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
                    now,
                )
                .unwrap(),
            )
            .await
            .unwrap();

        // add sold block, shouldn't return anymore
        let res_after_sold = store.get_bill_ids_waiting_for_sell_payment().await;
        assert!(res_after_sold.is_ok());
        assert_eq!(res_after_sold.as_ref().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_bills_waiting_for_payment_offer_to_sell_expired() {
        let db = get_db().await;
        let chain_store = get_chain_store(db.clone()).await;
        let store = get_store(db.clone()).await;
        let now_minus_one_month = util::date::now()
            .checked_sub_months(Months::new(1))
            .unwrap()
            .timestamp() as u64;

        let first_block = get_first_block("1234");
        chain_store
            .add_block("4321", &get_first_block("4321"))
            .await
            .unwrap(); // not returned, no offer to sell block
        chain_store.add_block("1234", &first_block).await.unwrap();
        let second_block = BillBlock::create_block_for_offer_to_sell(
            "1234".to_string(),
            &first_block,
            &BillOfferToSellBlockData {
                seller: BillParticipantBlockData::Ident(
                    bill_identified_participant_only_node_id(
                        BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP)
                            .unwrap()
                            .get_public_key(),
                    )
                    .into(),
                ),
                buyer: BillParticipantBlockData::Ident(
                    bill_identified_participant_only_node_id(BcrKeys::new().get_public_key())
                        .into(),
                ),
                currency: "sat".to_string(),
                sum: 15000,
                payment_address: "tb1qteyk7pfvvql2r2zrsu4h4xpvju0nz7ykvguyk".to_string(),
                signatory: None,
                signing_timestamp: now_minus_one_month,
                signing_address: Some(empty_address()),
            },
            &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
            None,
            &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
            now_minus_one_month,
        )
        .unwrap();
        chain_store.add_block("1234", &second_block).await.unwrap();

        // nothing gets returned, because the offer to sell is expired
        let res = store.get_bill_ids_waiting_for_sell_payment().await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn get_bill_ids_with_op_codes_since() {
        let db = get_db().await;
        let chain_store = get_chain_store(db.clone()).await;
        let store = get_store(db.clone()).await;
        let bill_id = "1234";
        let first_block_request_to_accept = get_first_block(bill_id);
        let first_block_ts = first_block_request_to_accept.timestamp;
        chain_store
            .add_block(bill_id, &first_block_request_to_accept)
            .await
            .expect("block could not be added");

        let second_block_request_to_accept = request_to_accept_block(
            bill_id,
            first_block_ts + 1000,
            &first_block_request_to_accept,
        );

        chain_store
            .add_block(bill_id, &second_block_request_to_accept)
            .await
            .expect("failed to add second block");

        let bill_id_pay = "4321";
        let first_block_request_to_pay = get_first_block(bill_id_pay);
        chain_store
            .add_block(bill_id_pay, &first_block_request_to_pay)
            .await
            .expect("block could not be added");
        let second_block_request_to_pay = request_to_pay_block(
            bill_id_pay,
            first_block_ts + 1500,
            &first_block_request_to_pay,
        );

        chain_store
            .add_block(bill_id_pay, &second_block_request_to_pay)
            .await
            .expect("block could not be inserted");

        let all = HashSet::from([BillOpCode::RequestToPay, BillOpCode::RequestToAccept]);

        // should return all bill ids
        let res = store
            .get_bill_ids_with_op_codes_since(all.clone(), 0)
            .await
            .expect("could not get bill ids");
        assert_eq!(res, vec![bill_id.to_string(), bill_id_pay.to_string()]);

        // should return none as all are to old
        let res = store
            .get_bill_ids_with_op_codes_since(all, first_block_ts + 2000)
            .await
            .expect("could not get bill ids");
        assert_eq!(res, Vec::<String>::new());

        // should return only the bill id with request to accept
        let to_accept_only = HashSet::from([BillOpCode::RequestToAccept]);

        let res = store
            .get_bill_ids_with_op_codes_since(to_accept_only, 0)
            .await
            .expect("could not get bill ids");
        assert_eq!(res, vec![bill_id.to_string()]);

        // should return only the bill id with request to pay
        let to_pay_only = HashSet::from([BillOpCode::RequestToPay]);

        let res = store
            .get_bill_ids_with_op_codes_since(to_pay_only, 0)
            .await
            .expect("could not get bill ids");
        assert_eq!(res, vec![bill_id_pay.to_string()]);
    }

    fn request_to_accept_block(id: &str, ts: u64, first_block: &BillBlock) -> BillBlock {
        BillBlock::create_block_for_request_to_accept(
            id.to_string(),
            first_block,
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(
                    bill_identified_participant_only_node_id(
                        BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP)
                            .unwrap()
                            .get_public_key(),
                    )
                    .into(),
                ),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(empty_address()),
            },
            &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
            None,
            &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
            ts,
        )
        .expect("block could not be created")
    }

    fn request_to_pay_block(id: &str, ts: u64, first_block: &BillBlock) -> BillBlock {
        BillBlock::create_block_for_request_to_pay(
            id.to_string(),
            first_block,
            &BillRequestToPayBlockData {
                requester: BillParticipantBlockData::Ident(
                    bill_identified_participant_only_node_id(
                        BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP)
                            .unwrap()
                            .get_public_key(),
                    )
                    .into(),
                ),
                currency: "SATS".to_string(),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(empty_address()),
            },
            &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
            None,
            &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
            ts,
        )
        .expect("block could not be created")
    }

    #[tokio::test]
    async fn test_bills_waiting_for_payment_recourse() {
        let db = get_db().await;
        let chain_store = get_chain_store(db.clone()).await;
        let store = get_store(db.clone()).await;
        let now = util::date::now().timestamp() as u64;

        let first_block = get_first_block("1234");
        chain_store
            .add_block("4321", &get_first_block("4321"))
            .await
            .unwrap(); // not returned, no req to recourse block
        chain_store.add_block("1234", &first_block).await.unwrap();
        let second_block = BillBlock::create_block_for_request_recourse(
            "1234".to_string(),
            &first_block,
            &BillRequestRecourseBlockData {
                recourser: bill_identified_participant_only_node_id(
                    BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP)
                        .unwrap()
                        .get_public_key(),
                )
                .into(),
                recoursee: bill_identified_participant_only_node_id(
                    BcrKeys::new().get_public_key(),
                )
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
            &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
            now,
        )
        .unwrap();
        chain_store.add_block("1234", &second_block).await.unwrap();

        let res = store.get_bill_ids_waiting_for_recourse_payment().await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);

        chain_store
            .add_block(
                "1234",
                &BillBlock::create_block_for_recourse(
                    "1234".to_string(),
                    &second_block,
                    &BillRecourseBlockData {
                        recourser: bill_identified_participant_only_node_id(
                            BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP)
                                .unwrap()
                                .get_public_key(),
                        )
                        .into(),
                        recoursee: bill_identified_participant_only_node_id(
                            BcrKeys::new().get_public_key(),
                        )
                        .into(),
                        recourse_reason: BillRecourseReasonBlockData::Pay,
                        currency: "sat".to_string(),
                        sum: 15000,
                        signatory: None,
                        signing_timestamp: now,
                        signing_address: empty_address(),
                    },
                    &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
                    None,
                    &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
                    now,
                )
                .unwrap(),
            )
            .await
            .unwrap();

        // add recourse block, shouldn't return anymore
        let res_after_recourse = store.get_bill_ids_waiting_for_recourse_payment().await;
        assert!(res_after_recourse.is_ok());
        assert_eq!(res_after_recourse.as_ref().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_bills_waiting_for_payment_recourse_expired() {
        let db = get_db().await;
        let chain_store = get_chain_store(db.clone()).await;
        let store = get_store(db.clone()).await;
        let now_minus_one_month = util::date::now()
            .checked_sub_months(Months::new(1))
            .unwrap()
            .timestamp() as u64;

        let first_block = get_first_block("1234");
        chain_store
            .add_block("4321", &get_first_block("4321"))
            .await
            .unwrap(); // not returned, no offer to sell block
        chain_store.add_block("1234", &first_block).await.unwrap();
        let second_block = BillBlock::create_block_for_request_recourse(
            "1234".to_string(),
            &first_block,
            &BillRequestRecourseBlockData {
                recourser: bill_identified_participant_only_node_id(
                    BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP)
                        .unwrap()
                        .get_public_key(),
                )
                .into(),
                recoursee: bill_identified_participant_only_node_id(
                    BcrKeys::new().get_public_key(),
                )
                .into(),
                currency: "sat".to_string(),
                recourse_reason: BillRecourseReasonBlockData::Pay,
                sum: 15000,
                signatory: None,
                signing_timestamp: now_minus_one_month,
                signing_address: empty_address(),
            },
            &BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap(),
            None,
            &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
            now_minus_one_month,
        )
        .unwrap();
        chain_store.add_block("1234", &second_block).await.unwrap();

        // nothing gets returned, because the req to recourse is expired
        let res = store.get_bill_ids_waiting_for_recourse_payment().await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn bill_caching() {
        let db = get_db().await;
        let store = get_store(db.clone()).await;
        let bill = cached_bill("1234".to_string());
        let bill2 = cached_bill("4321".to_string());

        // save bills to cache
        store
            .save_bill_to_cache("1234", &bill)
            .await
            .expect("could not save bill to cache");

        store
            .save_bill_to_cache("4321", &bill2)
            .await
            .expect("could not save bill to cache");

        // get bill from cache
        let cached_bill = store
            .get_bill_from_cache("1234")
            .await
            .expect("could not fetch from cache");
        assert_eq!(cached_bill.as_ref().unwrap().id, "1234".to_string());

        // get bills from cache
        let cached_bills = store
            .get_bills_from_cache(&["1234".to_string(), "4321".to_string()])
            .await
            .expect("could not fetch from cache");
        assert_eq!(cached_bills.len(), 2);

        // invalidate bill in cache
        store
            .invalidate_bill_in_cache("1234")
            .await
            .expect("could not invalidate cache");

        // bill is not cached anymore
        let cached_bill_gone = store
            .get_bill_from_cache("1234")
            .await
            .expect("could not fetch from cache");
        assert!(cached_bill_gone.is_none());

        // bill is not cached anymore
        let cached_bills_after_invalidate = store
            .get_bills_from_cache(&["4321".to_string()])
            .await
            .expect("could not fetch from cache");
        assert_eq!(cached_bills_after_invalidate.len(), 1);
    }
}
