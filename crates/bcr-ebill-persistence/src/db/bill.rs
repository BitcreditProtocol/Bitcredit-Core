use std::collections::HashSet;

use super::surreal::{Bindings, SurrealWrapper};
use super::{BillIdDb, FileDb, PostalAddressDb, Result};
use crate::constants::{DB_BILL_ID, DB_IDS, DB_OP_CODE, DB_TABLE, DB_TIMESTAMP};
use crate::{Error, bill::BillStoreApi};
use async_trait::async_trait;
use bcr_ebill_core::bill::{
    BillAcceptanceStatus, BillCurrentWaitingState, BillData, BillHistory, BillHistoryBlock, BillId,
    BillMintStatus, BillParticipants, BillPaymentStatus, BillRecourseStatus, BillSellStatus,
    BillStatus, BillWaitingForPaymentState, BillWaitingForRecourseState, BillWaitingForSellState,
    BillWaitingStatePaymentData, BitcreditBillResult, Endorsement, InMempoolData, LightSignedBy,
    PaidData, PaymentState,
};
use bcr_ebill_core::city::City;
use bcr_ebill_core::contact::{
    BillAnonParticipant, BillIdentParticipant, BillParticipant, ContactType,
    LightBillAnonParticipant, LightBillIdentParticipant, LightBillIdentParticipantWithAddress,
    LightBillParticipant,
};
use bcr_ebill_core::country::Country;
use bcr_ebill_core::date::Date;
use bcr_ebill_core::name::Name;
use bcr_ebill_core::{NodeId, PublicKey, SecretKey, ServiceTraitBounds};
use bcr_ebill_core::{bill::BillKeys, blockchain::bill::BillOpCode};
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
    const OFFER_TO_SELL_PAID_TABLE: &'static str = "offer_to_sell_bill_paid";
    const RECOURSE_PAID_TABLE: &'static str = "recourse_bill_paid";
    const CACHE_TABLE: &'static str = "bill_cache";

    pub fn new(db: SurrealWrapper) -> Self {
        Self { db }
    }
}

impl ServiceTraitBounds for SurrealBillStore {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl BillStoreApi for SurrealBillStore {
    async fn get_bills_from_cache(
        &self,
        ids: &[BillId],
        identity_node_id: &NodeId,
    ) -> Result<Vec<BitcreditBillResult>> {
        let db_ids: Vec<Thing> = ids
            .iter()
            .map(|id| {
                (
                    SurrealBillStore::CACHE_TABLE.to_owned(),
                    format!("{id}{identity_node_id}"),
                )
                    .into()
            })
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

    async fn get_bill_from_cache(
        &self,
        id: &BillId,
        identity_node_id: &NodeId,
    ) -> Result<Option<BitcreditBillResult>> {
        let result: Option<BitcreditBillResultDb> = self
            .db
            .select_one(Self::CACHE_TABLE, format!("{id}{identity_node_id}"))
            .await?;
        match result {
            None => Ok(None),
            Some(c) => Ok(Some(c.into())),
        }
    }

    async fn save_bill_to_cache(
        &self,
        id: &BillId,
        identity_node_id: &NodeId,
        bill: &BitcreditBillResult,
    ) -> Result<()> {
        // invalidate bill for all
        self.invalidate_bill_in_cache(id).await?;
        // then, put in the new one
        let entity: BitcreditBillResultDb = (bill, identity_node_id).into();
        let _: Option<BitcreditBillResultDb> = self
            .db
            .upsert(Self::CACHE_TABLE, format!("{id}{identity_node_id}"), entity)
            .await?;
        Ok(())
    }

    async fn invalidate_bill_in_cache(&self, id: &BillId) -> Result<()> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::CACHE_TABLE)?;
        bindings.add(DB_BILL_ID, id.to_owned())?;
        self.db
            .query_check(
                "DELETE FROM type::table($table) WHERE bill_id = $bill_id",
                bindings,
            )
            .await?;
        Ok(())
    }

    async fn clear_bill_cache(&self) -> Result<()> {
        let _: Vec<BitcreditBillResultDb> = self.db.delete_all(Self::CACHE_TABLE).await?;
        Ok(())
    }

    async fn exists(&self, id: &BillId) -> Result<bool> {
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

    async fn get_ids(&self) -> Result<Vec<BillId>> {
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

    async fn save_keys(&self, id: &BillId, key_pair: &BillKeys) -> Result<()> {
        let entity: BillKeysDb = key_pair.into();
        let _: Option<BillKeysDb> = self
            .db
            .create(Self::KEYS_TABLE, Some(id.to_string()), entity)
            .await?;
        Ok(())
    }

    async fn get_keys(&self, id: &BillId) -> Result<BillKeys> {
        let result: Option<BillKeysDb> =
            self.db.select_one(Self::KEYS_TABLE, id.to_string()).await?;
        match result {
            None => Err(Error::NoSuchEntity("bill".to_string(), id.to_string())),
            Some(c) => Ok(c.into()),
        }
    }

    async fn is_paid(&self, id: &BillId) -> Result<bool> {
        let result: Option<BillPaidDb> =
            self.db.select_one(Self::PAID_TABLE, id.to_string()).await?;
        Ok(if let Some(bill_paid) = result {
            match bill_paid.payment_state {
                // only if it's paid and confirmed
                PaymentStateDb::PaidConfirmed(..) => true,
                _ => false,
            }
        } else {
            false
        })
    }

    async fn set_payment_state(&self, id: &BillId, payment_state: &PaymentState) -> Result<()> {
        let entity = BillPaidDb {
            bill_id: id.to_owned(),
            payment_state: payment_state.into(),
        };
        let _: Option<BillPaidDb> = self
            .db
            .upsert(Self::PAID_TABLE, id.to_string(), entity)
            .await?;
        Ok(())
    }

    async fn get_payment_state(&self, id: &BillId) -> Result<Option<PaymentState>> {
        let result: Option<BillPaidDb> =
            self.db.select_one(Self::PAID_TABLE, id.to_string()).await?;
        Ok(result.map(|r| r.payment_state.into()))
    }

    async fn set_offer_to_sell_payment_state(
        &self,
        id: &BillId,
        block_id: u64,
        payment_state: &PaymentState,
    ) -> Result<()> {
        let entity = OfferToSellBillPaidDb {
            bill_id: id.to_owned(),
            block_id,
            payment_state: payment_state.into(),
        };
        let _: Option<OfferToSellBillPaidDb> = self
            .db
            .upsert(
                Self::OFFER_TO_SELL_PAID_TABLE,
                format!("{id}_{block_id}"),
                entity,
            )
            .await?;
        Ok(())
    }

    async fn get_offer_to_sell_payment_state(
        &self,
        id: &BillId,
        block_id: u64,
    ) -> Result<Option<PaymentState>> {
        let result: Option<OfferToSellBillPaidDb> = self
            .db
            .select_one(Self::OFFER_TO_SELL_PAID_TABLE, format!("{id}_{block_id}"))
            .await?;
        Ok(result.map(|r| r.payment_state.into()))
    }

    async fn set_recourse_payment_state(
        &self,
        id: &BillId,
        block_id: u64,
        payment_state: &PaymentState,
    ) -> Result<()> {
        let entity = RecourseBillPaidDb {
            bill_id: id.to_owned(),
            block_id,
            payment_state: payment_state.into(),
        };
        let _: Option<RecourseBillPaidDb> = self
            .db
            .upsert(
                Self::RECOURSE_PAID_TABLE,
                format!("{id}_{block_id}"),
                entity,
            )
            .await?;
        Ok(())
    }

    async fn get_recourse_payment_state(
        &self,
        id: &BillId,
        block_id: u64,
    ) -> Result<Option<PaymentState>> {
        let result: Option<RecourseBillPaidDb> = self
            .db
            .select_one(Self::RECOURSE_PAID_TABLE, format!("{id}_{block_id}"))
            .await?;
        Ok(result.map(|r| r.payment_state.into()))
    }

    async fn get_bill_ids_waiting_for_payment(&self) -> Result<Vec<BillId>> {
        let mut paid_bindings = Bindings::default();
        paid_bindings.add(DB_TABLE, Self::PAID_TABLE)?;
        let bill_ids_paid: Vec<BillPaidDb> = self
            .db
            .query(
                "SELECT * FROM type::table($table) WHERE payment_state.PaidConfirmed?",
                paid_bindings,
            )
            .await?;
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
        let result: Vec<BillId> = with_req_to_pay_bill_ids
            .into_iter()
            .filter_map(|bid| {
                if !bill_ids_paid.iter().any(|idp| idp.bill_id == bid.bill_id) {
                    Some(bid.bill_id)
                } else {
                    None
                }
            })
            .collect();
        Ok(result)
    }

    async fn get_bill_ids_waiting_for_sell_payment(&self) -> Result<Vec<BillId>> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::CHAIN_TABLE)?;
        bindings.add(DB_OP_CODE, BillOpCode::OfferToSell)?;
        let query = r#"SELECT bill_id FROM 
            (SELECT bill_id, math::max(block_id) as block_id, op_code, timestamp FROM type::table($table) GROUP BY bill_id)
            .map(|$v| {
                (SELECT bill_id, block_id, op_code, timestamp FROM bill_chain WHERE bill_id = $v.bill_id AND block_id = $v.block_id)[0]
            })
            .flatten() WHERE op_code = $op_code"#;
        let result: Vec<BillIdDb> = self.db.query(query, bindings).await?;
        Ok(result.into_iter().map(|bid| bid.bill_id).collect())
    }

    async fn get_bill_ids_waiting_for_recourse_payment(&self) -> Result<Vec<BillId>> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::CHAIN_TABLE)?;
        bindings.add(DB_OP_CODE, BillOpCode::RequestRecourse)?;
        let query = r#"SELECT bill_id FROM 
            (SELECT bill_id, math::max(block_id) as block_id, op_code, timestamp FROM type::table($table) GROUP BY bill_id)
            .map(|$v| {
                (SELECT bill_id, block_id, op_code, timestamp FROM bill_chain WHERE bill_id = $v.bill_id AND block_id = $v.block_id)[0]
            })
            .flatten() WHERE op_code = $op_code"#;
        let result: Vec<BillIdDb> = self.db.query(query, bindings).await?;
        Ok(result.into_iter().map(|bid| bid.bill_id).collect())
    }

    async fn get_bill_ids_with_op_codes_since(
        &self,
        op_codes: HashSet<BillOpCode>,
        since: u64,
    ) -> Result<Vec<BillId>> {
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
    pub bill_id: BillId,
    pub participants: BillParticipantsDb,
    pub data: BillDataDb,
    pub status: BillStatusDb,
    pub current_waiting_state: Option<BillCurrentWaitingStateDb>,
    pub history: BillHistoryDb,
    pub identity_node_id: NodeId,
}

impl From<BitcreditBillResultDb> for BitcreditBillResult {
    fn from(value: BitcreditBillResultDb) -> Self {
        Self {
            id: value.bill_id,
            participants: value.participants.into(),
            data: value.data.into(),
            status: value.status.into(),
            current_waiting_state: value.current_waiting_state.map(|cws| cws.into()),
            history: value.history.into(),
        }
    }
}

impl From<(&BitcreditBillResult, &NodeId)> for BitcreditBillResultDb {
    fn from((value, identity_node_id): (&BitcreditBillResult, &NodeId)) -> Self {
        Self {
            bill_id: value.id.clone(),
            participants: (&value.participants).into(),
            data: (&value.data).into(),
            status: (&value.status).into(),
            current_waiting_state: value.current_waiting_state.as_ref().map(|cws| cws.into()),
            history: value.history.clone().into(),
            identity_node_id: identity_node_id.to_owned(),
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
pub struct BillWaitingStatePaymentDataDb {
    pub time_of_request: u64,
    pub currency: String,
    pub sum: String,
    pub link_to_pay: String,
    pub address_to_pay: String,
    pub mempool_link_for_address_to_pay: String,
    pub tx_id: Option<String>,
    pub in_mempool: bool,
    pub confirmations: u64,
    pub payment_deadline: Option<u64>,
}

impl From<BillWaitingStatePaymentDataDb> for BillWaitingStatePaymentData {
    fn from(value: BillWaitingStatePaymentDataDb) -> Self {
        Self {
            time_of_request: value.time_of_request,
            currency: value.currency,
            sum: value.sum,
            link_to_pay: value.link_to_pay,
            address_to_pay: value.address_to_pay,
            mempool_link_for_address_to_pay: value.mempool_link_for_address_to_pay,
            tx_id: value.tx_id,
            in_mempool: value.in_mempool,
            confirmations: value.confirmations,
            payment_deadline: value.payment_deadline,
        }
    }
}

impl From<&BillWaitingStatePaymentData> for BillWaitingStatePaymentDataDb {
    fn from(value: &BillWaitingStatePaymentData) -> Self {
        Self {
            time_of_request: value.time_of_request,
            currency: value.currency.clone(),
            sum: value.sum.clone(),
            link_to_pay: value.link_to_pay.clone(),
            address_to_pay: value.address_to_pay.clone(),
            mempool_link_for_address_to_pay: value.mempool_link_for_address_to_pay.clone(),
            tx_id: value.tx_id.clone(),
            in_mempool: value.in_mempool,
            confirmations: value.confirmations,
            payment_deadline: value.payment_deadline,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillWaitingForSellStateDb {
    pub buyer: BillParticipantDb,
    pub seller: BillParticipantDb,
    pub payment_data: BillWaitingStatePaymentDataDb,
}

impl From<BillWaitingForSellStateDb> for BillWaitingForSellState {
    fn from(value: BillWaitingForSellStateDb) -> Self {
        Self {
            buyer: value.buyer.into(),
            seller: value.seller.into(),
            payment_data: value.payment_data.into(),
        }
    }
}

impl From<&BillWaitingForSellState> for BillWaitingForSellStateDb {
    fn from(value: &BillWaitingForSellState) -> Self {
        Self {
            buyer: (&value.buyer).into(),
            seller: (&value.seller).into(),
            payment_data: (&value.payment_data).into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillWaitingForPaymentStateDb {
    pub payer: BillIdentParticipantDb,
    pub payee: BillParticipantDb,
    pub payment_data: BillWaitingStatePaymentDataDb,
}

impl From<BillWaitingForPaymentStateDb> for BillWaitingForPaymentState {
    fn from(value: BillWaitingForPaymentStateDb) -> Self {
        Self {
            payer: value.payer.into(),
            payee: value.payee.into(),
            payment_data: value.payment_data.into(),
        }
    }
}

impl From<&BillWaitingForPaymentState> for BillWaitingForPaymentStateDb {
    fn from(value: &BillWaitingForPaymentState) -> Self {
        Self {
            payer: (&value.payer).into(),
            payee: (&value.payee).into(),
            payment_data: (&value.payment_data).into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillWaitingForRecourseStateDb {
    pub recourser: BillParticipantDb,
    pub recoursee: BillIdentParticipantDb,
    pub payment_data: BillWaitingStatePaymentDataDb,
}

impl From<BillWaitingForRecourseStateDb> for BillWaitingForRecourseState {
    fn from(value: BillWaitingForRecourseStateDb) -> Self {
        Self {
            recourser: value.recourser.into(),
            recoursee: value.recoursee.into(),
            payment_data: value.payment_data.into(),
        }
    }
}

impl From<&BillWaitingForRecourseState> for BillWaitingForRecourseStateDb {
    fn from(value: &BillWaitingForRecourseState) -> Self {
        Self {
            recourser: (&value.recourser).into(),
            recoursee: (&value.recoursee).into(),
            payment_data: (&value.payment_data).into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillStatusDb {
    pub acceptance: BillAcceptanceStatusDb,
    pub payment: BillPaymentStatusDb,
    pub sell: BillSellStatusDb,
    pub recourse: BillRecourseStatusDb,
    pub mint: BillMintStatusDb,
    pub redeemed_funds_available: bool,
    pub has_requested_funds: bool,
    pub last_block_time: u64,
}

impl From<BillStatusDb> for BillStatus {
    fn from(value: BillStatusDb) -> Self {
        Self {
            acceptance: value.acceptance.into(),
            payment: value.payment.into(),
            sell: value.sell.into(),
            recourse: value.recourse.into(),
            mint: value.mint.into(),
            redeemed_funds_available: value.redeemed_funds_available,
            has_requested_funds: value.has_requested_funds,
            last_block_time: value.last_block_time,
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
            mint: (&value.mint).into(),
            redeemed_funds_available: value.redeemed_funds_available,
            has_requested_funds: value.has_requested_funds,
            last_block_time: value.last_block_time,
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
    pub acceptance_deadline_timestamp: Option<u64>,
}

impl From<BillAcceptanceStatusDb> for BillAcceptanceStatus {
    fn from(value: BillAcceptanceStatusDb) -> Self {
        Self {
            time_of_request_to_accept: value.time_of_request_to_accept,
            requested_to_accept: value.requested_to_accept,
            accepted: value.accepted,
            request_to_accept_timed_out: value.request_to_accept_timed_out,
            rejected_to_accept: value.rejected_to_accept,
            acceptance_deadline_timestamp: value.acceptance_deadline_timestamp,
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
            acceptance_deadline_timestamp: value.acceptance_deadline_timestamp,
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
    pub payment_deadline_timestamp: Option<u64>,
}

impl From<BillPaymentStatusDb> for BillPaymentStatus {
    fn from(value: BillPaymentStatusDb) -> Self {
        Self {
            time_of_request_to_pay: value.time_of_request_to_pay,
            requested_to_pay: value.requested_to_pay,
            paid: value.paid,
            request_to_pay_timed_out: value.request_to_pay_timed_out,
            rejected_to_pay: value.rejected_to_pay,
            payment_deadline_timestamp: value.payment_deadline_timestamp,
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
            payment_deadline_timestamp: value.payment_deadline_timestamp,
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
    pub buying_deadline_timestamp: Option<u64>,
}

impl From<BillSellStatusDb> for BillSellStatus {
    fn from(value: BillSellStatusDb) -> Self {
        Self {
            time_of_last_offer_to_sell: value.time_of_last_offer_to_sell,
            sold: value.sold,
            offered_to_sell: value.offered_to_sell,
            offer_to_sell_timed_out: value.offer_to_sell_timed_out,
            rejected_offer_to_sell: value.rejected_offer_to_sell,
            buying_deadline_timestamp: value.buying_deadline_timestamp,
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
            buying_deadline_timestamp: value.buying_deadline_timestamp,
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
    pub recourse_deadline_timestamp: Option<u64>,
}

impl From<BillRecourseStatusDb> for BillRecourseStatus {
    fn from(value: BillRecourseStatusDb) -> Self {
        Self {
            time_of_last_request_to_recourse: value.time_of_last_request_to_recourse,
            recoursed: value.recoursed,
            requested_to_recourse: value.requested_to_recourse,
            request_to_recourse_timed_out: value.request_to_recourse_timed_out,
            rejected_request_to_recourse: value.rejected_request_to_recourse,
            recourse_deadline_timestamp: value.recourse_deadline_timestamp,
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
            recourse_deadline_timestamp: value.recourse_deadline_timestamp,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillMintStatusDb {
    pub has_mint_requests: bool,
}

impl From<BillMintStatusDb> for BillMintStatus {
    fn from(value: BillMintStatusDb) -> Self {
        Self {
            has_mint_requests: value.has_mint_requests,
        }
    }
}

impl From<&BillMintStatus> for BillMintStatusDb {
    fn from(value: &BillMintStatus) -> Self {
        Self {
            has_mint_requests: value.has_mint_requests,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillDataDb {
    pub time_of_drawing: u64,
    pub issue_date: Date,
    pub time_of_maturity: u64,
    pub maturity_date: Date,
    pub country_of_issuing: Country,
    pub city_of_issuing: City,
    pub country_of_payment: Country,
    pub city_of_payment: City,
    pub currency: String,
    pub sum: String,
    pub files: Vec<FileDb>,
}

impl From<BillDataDb> for BillData {
    fn from(value: BillDataDb) -> Self {
        Self {
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
    pub endorsements: Vec<EndorsementDb>,
    pub endorsements_count: u64,
    pub all_participant_node_ids: Vec<NodeId>,
}

impl From<BillParticipantsDb> for BillParticipants {
    fn from(value: BillParticipantsDb) -> Self {
        Self {
            drawee: value.drawee.into(),
            drawer: value.drawer.into(),
            payee: value.payee.into(),
            endorsee: value.endorsee.map(|e| e.into()),
            endorsements: value
                .endorsements
                .iter()
                .map(|e| e.clone().into())
                .collect(),
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
            endorsements: value.endorsements.iter().map(|e| e.into()).collect(),
            endorsements_count: value.endorsements_count,
            all_participant_node_ids: value.all_participant_node_ids.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillHistoryDb {
    pub blocks: Vec<BillHistoryBlockDb>,
}

impl From<BillHistoryDb> for BillHistory {
    fn from(value: BillHistoryDb) -> Self {
        Self {
            blocks: value.blocks.into_iter().map(|b| b.into()).collect(),
        }
    }
}

impl From<BillHistory> for BillHistoryDb {
    fn from(value: BillHistory) -> Self {
        Self {
            blocks: value.blocks.into_iter().map(|b| b.into()).collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BillHistoryBlockDb {
    pub block_id: u64,
    pub block_type: BillOpCode,
    pub pay_to_the_order_of: Option<BillParticipantDb>,
    pub signed: LightSignedByDb,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddressDb>,
}

impl From<BillHistoryBlockDb> for BillHistoryBlock {
    fn from(value: BillHistoryBlockDb) -> Self {
        Self {
            block_id: value.block_id,
            block_type: value.block_type,
            pay_to_the_order_of: value.pay_to_the_order_of.map(|pttoo| pttoo.into()),
            signed: value.signed.into(),
            signing_timestamp: value.signing_timestamp,
            signing_address: value.signing_address.map(|sa| sa.into()),
        }
    }
}

impl From<BillHistoryBlock> for BillHistoryBlockDb {
    fn from(value: BillHistoryBlock) -> Self {
        Self {
            block_id: value.block_id,
            block_type: value.block_type,
            pay_to_the_order_of: value.pay_to_the_order_of.as_ref().map(|pttoo| pttoo.into()),
            signed: (&value.signed).into(),
            signing_timestamp: value.signing_timestamp,
            signing_address: value.signing_address.map(|sa| sa.into()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EndorsementDb {
    pub pay_to_the_order_of: BillParticipantDb,
    pub signed: LightSignedByDb,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddressDb>,
}

impl From<EndorsementDb> for Endorsement {
    fn from(value: EndorsementDb) -> Self {
        Self {
            pay_to_the_order_of: value.pay_to_the_order_of.into(),
            signed: value.signed.into(),
            signing_timestamp: value.signing_timestamp,
            signing_address: value.signing_address.as_ref().map(|e| e.clone().into()),
        }
    }
}

impl From<&Endorsement> for EndorsementDb {
    fn from(value: &Endorsement) -> Self {
        Self {
            pay_to_the_order_of: (&value.pay_to_the_order_of).into(),
            signed: (&value.signed).into(),
            signing_timestamp: value.signing_timestamp,
            signing_address: value.signing_address.as_ref().map(|e| e.to_owned().into()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LightSignedByDb {
    pub data: BillParticipantDb,
    pub signatory: Option<LightBillIdentParticipantDb>,
}

impl From<LightSignedByDb> for LightSignedBy {
    fn from(value: LightSignedByDb) -> Self {
        Self {
            data: value.data.into(),
            signatory: value.signatory.map(|s| s.into()),
        }
    }
}

impl From<&LightSignedBy> for LightSignedByDb {
    fn from(value: &LightSignedBy) -> Self {
        Self {
            data: (&value.data).into(),
            signatory: value.signatory.as_ref().map(|s| s.into()),
        }
    }
}

impl From<&LightBillParticipant> for BillParticipantDb {
    fn from(value: &LightBillParticipant) -> Self {
        match value {
            LightBillParticipant::Anon(data) => BillParticipantDb::Anon(data.into()),
            LightBillParticipant::Ident(data) => BillParticipantDb::Ident(data.into()),
        }
    }
}

impl From<&LightBillAnonParticipant> for BillAnonParticipantDb {
    fn from(value: &LightBillAnonParticipant) -> Self {
        Self {
            node_id: value.node_id.to_owned(),
        }
    }
}

impl From<&LightBillIdentParticipantWithAddress> for BillIdentParticipantDb {
    fn from(value: &LightBillIdentParticipantWithAddress) -> Self {
        Self {
            t: value.t.to_owned(),
            node_id: value.node_id.to_owned(),
            name: value.name.to_owned(),
            postal_address: value.postal_address.to_owned().into(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LightBillIdentParticipantDb {
    pub t: ContactType,
    pub name: Name,
    pub node_id: NodeId,
}

impl From<LightBillIdentParticipantDb> for LightBillIdentParticipant {
    fn from(value: LightBillIdentParticipantDb) -> Self {
        Self {
            t: value.t,
            name: value.name,
            node_id: value.node_id,
        }
    }
}

impl From<&LightBillIdentParticipant> for LightBillIdentParticipantDb {
    fn from(value: &LightBillIdentParticipant) -> Self {
        Self {
            t: value.t.to_owned(),
            name: value.name.to_owned(),
            node_id: value.node_id.to_owned(),
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
    pub node_id: NodeId,
    pub name: Name,
    pub postal_address: PostalAddressDb,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BillAnonParticipantDb {
    pub node_id: NodeId,
}

impl From<BillParticipantDb> for LightBillParticipant {
    fn from(value: BillParticipantDb) -> Self {
        match value {
            BillParticipantDb::Anon(data) => LightBillParticipant::Anon(data.into()),
            BillParticipantDb::Ident(data) => LightBillParticipant::Ident(data.into()),
        }
    }
}

impl From<BillAnonParticipantDb> for LightBillAnonParticipant {
    fn from(value: BillAnonParticipantDb) -> Self {
        Self {
            node_id: value.node_id,
        }
    }
}

impl From<BillIdentParticipantDb> for LightBillIdentParticipantWithAddress {
    fn from(value: BillIdentParticipantDb) -> Self {
        Self {
            t: value.t,
            name: value.name,
            node_id: value.node_id,
            postal_address: value.postal_address.into(),
        }
    }
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
    pub bill_id: BillId,
    pub payment_state: PaymentStateDb,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferToSellBillPaidDb {
    pub bill_id: BillId,
    pub block_id: u64,
    pub payment_state: PaymentStateDb,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecourseBillPaidDb {
    pub bill_id: BillId,
    pub block_id: u64,
    pub payment_state: PaymentStateDb,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaymentStateDb {
    PaidConfirmed(PaidDataDb),
    PaidUnconfirmed(PaidDataDb),
    InMempool(InMempoolDataDb),
    NotFound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaidDataDb {
    pub block_time: u64, // unix timestamp
    pub block_hash: String,
    pub confirmations: u64,
    pub tx_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InMempoolDataDb {
    pub tx_id: String,
}

impl From<&PaymentState> for PaymentStateDb {
    fn from(value: &PaymentState) -> Self {
        match value {
            PaymentState::PaidConfirmed(paid_data) => {
                PaymentStateDb::PaidConfirmed(paid_data.into())
            }
            PaymentState::PaidUnconfirmed(paid_data) => {
                PaymentStateDb::PaidUnconfirmed(paid_data.into())
            }
            PaymentState::InMempool(in_mempool_data) => {
                PaymentStateDb::InMempool(in_mempool_data.into())
            }
            PaymentState::NotFound => PaymentStateDb::NotFound,
        }
    }
}

impl From<PaymentStateDb> for PaymentState {
    fn from(value: PaymentStateDb) -> Self {
        match value {
            PaymentStateDb::PaidConfirmed(paid_data) => {
                PaymentState::PaidConfirmed(paid_data.into())
            }
            PaymentStateDb::PaidUnconfirmed(paid_data) => {
                PaymentState::PaidUnconfirmed(paid_data.into())
            }
            PaymentStateDb::InMempool(in_mempool_data) => {
                PaymentState::InMempool(in_mempool_data.into())
            }
            PaymentStateDb::NotFound => PaymentState::NotFound,
        }
    }
}

impl From<&PaidData> for PaidDataDb {
    fn from(value: &PaidData) -> Self {
        Self {
            block_time: value.block_time,
            block_hash: value.block_hash.clone(),
            confirmations: value.confirmations,
            tx_id: value.tx_id.clone(),
        }
    }
}

impl From<PaidDataDb> for PaidData {
    fn from(value: PaidDataDb) -> Self {
        Self {
            block_time: value.block_time,
            block_hash: value.block_hash.clone(),
            confirmations: value.confirmations,
            tx_id: value.tx_id,
        }
    }
}

impl From<&InMempoolData> for InMempoolDataDb {
    fn from(value: &InMempoolData) -> Self {
        Self {
            tx_id: value.tx_id.clone(),
        }
    }
}

impl From<InMempoolDataDb> for InMempoolData {
    fn from(value: InMempoolDataDb) -> Self {
        Self {
            tx_id: value.tx_id.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillKeysDb {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Thing>,
    pub public_key: PublicKey,
    pub private_key: SecretKey,
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
            public_key: value.public_key,
            private_key: value.private_key,
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
            bill_id_test, bill_id_test_other, bill_identified_participant_only_node_id,
            cached_bill, empty_address, empty_bitcredit_bill, get_bill_keys, node_id_test,
            node_id_test_other, private_key_test,
        },
        util::{self, BcrKeys},
    };
    use bcr_ebill_core::{
        NodeId,
        bill::{BillId, BillKeys, PaidData, PaymentState},
        blockchain::bill::{
            BillBlock, BillOpCode,
            block::{
                BillIssueBlockData, BillOfferToSellBlockData, BillParticipantBlockData,
                BillRecourseBlockData, BillRecourseReasonBlockData, BillRequestRecourseBlockData,
                BillRequestToAcceptBlockData, BillRequestToPayBlockData, BillSellBlockData,
            },
        },
        constants::{
            ACCEPT_DEADLINE_SECONDS, CURRENCY_SAT, DAY_IN_SECS, PAYMENT_DEADLINE_SECONDS,
            RECOURSE_DEADLINE_SECONDS,
        },
        contact::BillParticipant,
        date::Date,
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

    pub fn get_first_block(id: &BillId) -> BillBlock {
        let mut bill = empty_bitcredit_bill();
        bill.maturity_date = Date::new("2099-05-05").unwrap();
        bill.id = id.to_owned();
        bill.drawer = bill_identified_participant_only_node_id(NodeId::new(
            BcrKeys::new().pub_key(),
            bitcoin::Network::Testnet,
        ));
        bill.payee = BillParticipant::Ident(bill.drawer.clone());
        bill.drawee = bill_identified_participant_only_node_id(NodeId::new(
            BcrKeys::new().pub_key(),
            bitcoin::Network::Testnet,
        ));

        BillBlock::create_block_for_issue(
            id.to_owned(),
            String::from("prevhash"),
            &BillIssueBlockData::from(bill, None, 1731593928),
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
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
        assert!(!store.exists(&bill_id_test()).await.as_ref().unwrap());
        let first_block = get_first_block(&bill_id_test());
        chain_store
            .add_block(&bill_id_test(), &first_block)
            .await
            .unwrap();
        assert!(!store.exists(&bill_id_test()).await.as_ref().unwrap());
        chain_store
            .add_block(
                &bill_id_test(),
                &BillBlock::create_block_for_request_to_pay(
                    bill_id_test(),
                    &first_block,
                    &BillRequestToPayBlockData {
                        requester: BillParticipantBlockData::Ident(
                            bill_identified_participant_only_node_id(node_id_test()).into(),
                        ),
                        currency: CURRENCY_SAT.to_string(),
                        signatory: None,
                        signing_timestamp: 1731593928,
                        signing_address: Some(empty_address()),
                        payment_deadline_timestamp: 1731593928 + 2 * PAYMENT_DEADLINE_SECONDS,
                    },
                    &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
                    None,
                    &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
                    1731593928,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert!(!store.exists(&bill_id_test()).await.as_ref().unwrap());
        store
            .save_keys(
                &bill_id_test(),
                &BillKeys {
                    private_key: private_key_test(),
                    public_key: node_id_test().pub_key(),
                },
            )
            .await
            .unwrap();
        assert!(store.exists(&bill_id_test()).await.as_ref().unwrap())
    }

    #[tokio::test]
    async fn test_get_ids() {
        let db = get_db().await;
        let chain_store = get_chain_store(db.clone()).await;
        let store = get_store(db.clone()).await;
        chain_store
            .add_block(&bill_id_test(), &get_first_block(&bill_id_test()))
            .await
            .unwrap();
        chain_store
            .add_block(
                &bill_id_test_other(),
                &get_first_block(&bill_id_test_other()),
            )
            .await
            .unwrap();
        let res = store.get_ids().await;
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().contains(&bill_id_test()));
        assert!(res.as_ref().unwrap().contains(&bill_id_test_other()));
    }

    #[tokio::test]
    async fn test_save_get_keys() {
        let store = get_store(get_db().await).await;
        let res = store
            .save_keys(
                &bill_id_test(),
                &BillKeys {
                    private_key: private_key_test(),
                    public_key: node_id_test().pub_key(),
                },
            )
            .await;
        assert!(res.is_ok());
        let get_res = store.get_keys(&bill_id_test()).await;
        assert!(get_res.is_ok());
        assert_eq!(get_res.as_ref().unwrap().private_key, private_key_test());
    }

    #[tokio::test]
    async fn test_paid() {
        let store = get_store(get_db().await).await;
        let res = store
            .set_payment_state(
                &bill_id_test(),
                &PaymentState::PaidConfirmed(PaidData {
                    block_time: 1731593928,
                    block_hash: "000000000061ad7b0d52af77e5a9dbcdc421bf00e93992259f16b2cf2693c4b1"
                        .into(),
                    confirmations: 6,
                    tx_id: "80e4dc03b2ea934c97e265fa1855eba5c02788cb269e3f43a8e9a7bb0e114e2c"
                        .into(),
                }),
            )
            .await;
        assert!(res.is_ok());
        let get_res = store.is_paid(&bill_id_test()).await;
        assert!(get_res.is_ok());
        assert!(get_res.as_ref().unwrap());
        let payment_state = store
            .get_payment_state(&bill_id_test())
            .await
            .expect("succeeds")
            .expect("is there");
        assert!(matches!(payment_state, PaymentState::PaidConfirmed(..)));

        // save again
        let res_again = store
            .set_payment_state(
                &bill_id_test(),
                &PaymentState::PaidConfirmed(PaidData {
                    block_time: 1731593928,
                    block_hash: "000000000061ad7b0d52af77e5a9dbcdc421bf00e93992259f16b2cf2693c4b1"
                        .into(),
                    confirmations: 6,
                    tx_id: "80e4dc03b2ea934c97e265fa1855eba5c02788cb269e3f43a8e9a7bb0e114e2c"
                        .into(),
                }),
            )
            .await;
        assert!(res_again.is_ok());
        let get_res_again = store.is_paid(&bill_id_test()).await;
        assert!(get_res_again.is_ok());
        assert!(get_res_again.as_ref().unwrap());

        // different bill without paid state
        let get_res_not_paid = store.is_paid(&bill_id_test_other()).await;
        assert!(get_res_not_paid.is_ok());
        assert!(!get_res_not_paid.as_ref().unwrap());
    }

    #[tokio::test]
    async fn test_payment_state_offer_to_sell() {
        let store = get_store(get_db().await).await;
        let res = store
            .set_offer_to_sell_payment_state(
                &bill_id_test(),
                1,
                &PaymentState::PaidConfirmed(PaidData {
                    block_time: 1731593928,
                    block_hash: "000000000061ad7b0d52af77e5a9dbcdc421bf00e93992259f16b2cf2693c4b1"
                        .into(),
                    confirmations: 6,
                    tx_id: "80e4dc03b2ea934c97e265fa1855eba5c02788cb269e3f43a8e9a7bb0e114e2c"
                        .into(),
                }),
            )
            .await;
        assert!(res.is_ok());

        let payment_state = store
            .get_offer_to_sell_payment_state(&bill_id_test(), 1)
            .await
            .expect("succeeds")
            .expect("is there");
        assert!(matches!(payment_state, PaymentState::PaidConfirmed(..)));

        let payment_state_different_block = store
            .get_offer_to_sell_payment_state(&bill_id_test(), 2)
            .await
            .expect("succeeds");
        assert!(payment_state_different_block.is_none());
    }

    #[tokio::test]
    async fn test_payment_state_recourse() {
        let store = get_store(get_db().await).await;
        let res = store
            .set_recourse_payment_state(
                &bill_id_test(),
                1,
                &PaymentState::PaidConfirmed(PaidData {
                    block_time: 1731593928,
                    block_hash: "000000000061ad7b0d52af77e5a9dbcdc421bf00e93992259f16b2cf2693c4b1"
                        .into(),
                    confirmations: 6,
                    tx_id: "80e4dc03b2ea934c97e265fa1855eba5c02788cb269e3f43a8e9a7bb0e114e2c"
                        .into(),
                }),
            )
            .await;
        assert!(res.is_ok());

        let payment_state = store
            .get_recourse_payment_state(&bill_id_test(), 1)
            .await
            .expect("succeeds")
            .expect("is there");
        assert!(matches!(payment_state, PaymentState::PaidConfirmed(..)));

        let payment_state_different_block = store
            .get_recourse_payment_state(&bill_id_test(), 2)
            .await
            .expect("succeeds");
        assert!(payment_state_different_block.is_none());
    }

    #[tokio::test]
    async fn test_bills_waiting_for_payment() {
        let db = get_db().await;
        let chain_store = get_chain_store(db.clone()).await;
        let store = get_store(db.clone()).await;

        let first_block = get_first_block(&bill_id_test());
        chain_store
            .add_block(
                &bill_id_test_other(),
                &get_first_block(&bill_id_test_other()),
            )
            .await
            .unwrap(); // not returned, no req to pay block
        chain_store
            .add_block(&bill_id_test(), &first_block)
            .await
            .unwrap();
        chain_store
            .add_block(
                &bill_id_test(),
                &BillBlock::create_block_for_request_to_pay(
                    bill_id_test(),
                    &first_block,
                    &BillRequestToPayBlockData {
                        requester: BillParticipantBlockData::Ident(
                            bill_identified_participant_only_node_id(node_id_test()).into(),
                        ),
                        currency: CURRENCY_SAT.to_string(),
                        signatory: None,
                        signing_timestamp: 1731593928,
                        signing_address: Some(empty_address()),
                        payment_deadline_timestamp: 1731593928 + 2 * PAYMENT_DEADLINE_SECONDS,
                    },
                    &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
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

        // set the bill to paid, expect it not to be returned afterwards
        store
            .set_payment_state(
                &bill_id_test(),
                &PaymentState::PaidConfirmed(PaidData {
                    block_time: 1731593928,
                    block_hash: "000000000061ad7b0d52af77e5a9dbcdc421bf00e93992259f16b2cf2693c4b1"
                        .into(),
                    confirmations: 6,
                    tx_id: "80e4dc03b2ea934c97e265fa1855eba5c02788cb269e3f43a8e9a7bb0e114e2c"
                        .into(),
                }),
            )
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

        let first_block = get_first_block(&bill_id_test());
        chain_store
            .add_block(
                &bill_id_test_other(),
                &get_first_block(&bill_id_test_other()),
            )
            .await
            .unwrap(); // not returned, no offer to sell block
        chain_store
            .add_block(&bill_id_test(), &first_block)
            .await
            .unwrap();
        let second_block = BillBlock::create_block_for_offer_to_sell(
            bill_id_test(),
            &first_block,
            &BillOfferToSellBlockData {
                seller: BillParticipantBlockData::Ident(
                    bill_identified_participant_only_node_id(node_id_test()).into(),
                ),
                buyer: BillParticipantBlockData::Ident(
                    bill_identified_participant_only_node_id(NodeId::new(
                        BcrKeys::new().pub_key(),
                        bitcoin::Network::Testnet,
                    ))
                    .into(),
                ),
                currency: CURRENCY_SAT.to_string(),
                sum: 15000,
                payment_address: "tb1qteyk7pfvvql2r2zrsu4h4xpvju0nz7ykvguyk".to_string(),
                signatory: None,
                signing_timestamp: now,
                signing_address: Some(empty_address()),
                buying_deadline_timestamp: now + 2 * DAY_IN_SECS,
            },
            &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
            None,
            &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
            now,
        )
        .unwrap();
        chain_store
            .add_block(&bill_id_test(), &second_block)
            .await
            .unwrap();

        let res = store.get_bill_ids_waiting_for_sell_payment().await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);

        chain_store
            .add_block(
                &bill_id_test(),
                &BillBlock::create_block_for_sell(
                    bill_id_test(),
                    &second_block,
                    &BillSellBlockData {
                        seller: BillParticipantBlockData::Ident(
                            bill_identified_participant_only_node_id(node_id_test()).into(),
                        ),
                        buyer: BillParticipantBlockData::Ident(
                            bill_identified_participant_only_node_id(NodeId::new(
                                BcrKeys::new().pub_key(),
                                bitcoin::Network::Testnet,
                            ))
                            .into(),
                        ),
                        currency: CURRENCY_SAT.to_string(),
                        sum: 15000,
                        payment_address: "tb1qteyk7pfvvql2r2zrsu4h4xpvju0nz7ykvguyk".to_string(),
                        signatory: None,
                        signing_timestamp: now,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(&private_key_test()).unwrap(),
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

        let first_block = get_first_block(&bill_id_test());
        chain_store
            .add_block(
                &bill_id_test_other(),
                &get_first_block(&bill_id_test_other()),
            )
            .await
            .unwrap(); // not returned, no offer to sell block
        chain_store
            .add_block(&bill_id_test(), &first_block)
            .await
            .unwrap();
        let second_block = BillBlock::create_block_for_offer_to_sell(
            bill_id_test(),
            &first_block,
            &BillOfferToSellBlockData {
                seller: BillParticipantBlockData::Ident(
                    bill_identified_participant_only_node_id(node_id_test()).into(),
                ),
                buyer: BillParticipantBlockData::Ident(
                    bill_identified_participant_only_node_id(NodeId::new(
                        BcrKeys::new().pub_key(),
                        bitcoin::Network::Testnet,
                    ))
                    .into(),
                ),
                currency: CURRENCY_SAT.to_string(),
                sum: 15000,
                payment_address: "tb1qteyk7pfvvql2r2zrsu4h4xpvju0nz7ykvguyk".to_string(),
                signatory: None,
                signing_timestamp: now_minus_one_month,
                signing_address: Some(empty_address()),
                buying_deadline_timestamp: now_minus_one_month + 2 * DAY_IN_SECS,
            },
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            None,
            &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
            now_minus_one_month,
        )
        .unwrap();
        chain_store
            .add_block(&bill_id_test(), &second_block)
            .await
            .unwrap();

        // block is still returned even though it's expired, since we can't check on DB level
        let res = store.get_bill_ids_waiting_for_sell_payment().await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn get_bill_ids_with_op_codes_since() {
        let db = get_db().await;
        let chain_store = get_chain_store(db.clone()).await;
        let store = get_store(db.clone()).await;
        let bill_id = &bill_id_test();
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

        let bill_id_pay = &bill_id_test_other();
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
        assert_eq!(res, vec![bill_id_pay.to_owned(), bill_id.to_owned()]);

        // should return none as all are to old
        let res = store
            .get_bill_ids_with_op_codes_since(all, first_block_ts + 2000)
            .await
            .expect("could not get bill ids");
        assert_eq!(res, Vec::<BillId>::new());

        // should return only the bill id with request to accept
        let to_accept_only = HashSet::from([BillOpCode::RequestToAccept]);

        let res = store
            .get_bill_ids_with_op_codes_since(to_accept_only, 0)
            .await
            .expect("could not get bill ids");
        assert_eq!(res, vec![bill_id.to_owned()]);

        // should return only the bill id with request to pay
        let to_pay_only = HashSet::from([BillOpCode::RequestToPay]);

        let res = store
            .get_bill_ids_with_op_codes_since(to_pay_only, 0)
            .await
            .expect("could not get bill ids");
        assert_eq!(res, vec![bill_id_pay.to_owned()]);
    }

    fn request_to_accept_block(id: &BillId, ts: u64, first_block: &BillBlock) -> BillBlock {
        BillBlock::create_block_for_request_to_accept(
            id.clone(),
            first_block,
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(
                    bill_identified_participant_only_node_id(node_id_test()).into(),
                ),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(empty_address()),
                acceptance_deadline_timestamp: ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            None,
            &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
            ts,
        )
        .expect("block could not be created")
    }

    fn request_to_pay_block(id: &BillId, ts: u64, first_block: &BillBlock) -> BillBlock {
        BillBlock::create_block_for_request_to_pay(
            id.clone(),
            first_block,
            &BillRequestToPayBlockData {
                requester: BillParticipantBlockData::Ident(
                    bill_identified_participant_only_node_id(node_id_test()).into(),
                ),
                currency: "SATS".to_string(),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(empty_address()),
                payment_deadline_timestamp: ts + 2 * PAYMENT_DEADLINE_SECONDS,
            },
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
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

        let first_block = get_first_block(&bill_id_test());
        chain_store
            .add_block(
                &bill_id_test_other(),
                &get_first_block(&bill_id_test_other()),
            )
            .await
            .unwrap(); // not returned, no req to recourse block
        chain_store
            .add_block(&bill_id_test(), &first_block)
            .await
            .unwrap();
        let second_block = BillBlock::create_block_for_request_recourse(
            bill_id_test(),
            &first_block,
            &BillRequestRecourseBlockData {
                recourser: BillParticipantBlockData::Ident(
                    bill_identified_participant_only_node_id(node_id_test()).into(),
                ),
                recoursee: bill_identified_participant_only_node_id(NodeId::new(
                    BcrKeys::new().pub_key(),
                    bitcoin::Network::Testnet,
                ))
                .into(),
                currency: CURRENCY_SAT.to_string(),
                sum: 15000,
                recourse_reason: BillRecourseReasonBlockData::Pay,
                signatory: None,
                signing_timestamp: now,
                signing_address: Some(empty_address()),
                recourse_deadline_timestamp: now + 2 * RECOURSE_DEADLINE_SECONDS,
            },
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            None,
            &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
            now,
        )
        .unwrap();
        chain_store
            .add_block(&bill_id_test(), &second_block)
            .await
            .unwrap();

        let res = store.get_bill_ids_waiting_for_recourse_payment().await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);

        chain_store
            .add_block(
                &bill_id_test(),
                &BillBlock::create_block_for_recourse(
                    bill_id_test(),
                    &second_block,
                    &BillRecourseBlockData {
                        recourser: BillParticipant::Ident(
                            bill_identified_participant_only_node_id(node_id_test()),
                        )
                        .into(),
                        recoursee: bill_identified_participant_only_node_id(NodeId::new(
                            BcrKeys::new().pub_key(),
                            bitcoin::Network::Testnet,
                        ))
                        .into(),
                        recourse_reason: BillRecourseReasonBlockData::Pay,
                        currency: CURRENCY_SAT.to_string(),
                        sum: 15000,
                        signatory: None,
                        signing_timestamp: now,
                        signing_address: Some(empty_address()),
                    },
                    &BcrKeys::from_private_key(&private_key_test()).unwrap(),
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

        let first_block = get_first_block(&bill_id_test());
        chain_store
            .add_block(
                &bill_id_test_other(),
                &get_first_block(&bill_id_test_other()),
            )
            .await
            .unwrap(); // not returned, no offer to sell block
        chain_store
            .add_block(&bill_id_test(), &first_block)
            .await
            .unwrap();
        let second_block = BillBlock::create_block_for_request_recourse(
            bill_id_test(),
            &first_block,
            &BillRequestRecourseBlockData {
                recourser: BillParticipantBlockData::Ident(
                    bill_identified_participant_only_node_id(node_id_test()).into(),
                ),
                recoursee: bill_identified_participant_only_node_id(NodeId::new(
                    BcrKeys::new().pub_key(),
                    bitcoin::Network::Testnet,
                ))
                .into(),
                currency: CURRENCY_SAT.to_string(),
                recourse_reason: BillRecourseReasonBlockData::Pay,
                sum: 15000,
                signatory: None,
                signing_timestamp: now_minus_one_month,
                signing_address: Some(empty_address()),
                recourse_deadline_timestamp: now_minus_one_month + 2 * RECOURSE_DEADLINE_SECONDS,
            },
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            None,
            &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
            now_minus_one_month,
        )
        .unwrap();
        chain_store
            .add_block(&bill_id_test(), &second_block)
            .await
            .unwrap();

        // block is returned even though it's expired, since we can't check it on DB level
        let res = store.get_bill_ids_waiting_for_recourse_payment().await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn bill_caching() {
        let db = get_db().await;
        let store = get_store(db.clone()).await;
        let bill = cached_bill(bill_id_test());
        let bill2 = cached_bill(bill_id_test_other());

        // save bills to cache
        store
            .save_bill_to_cache(&bill_id_test(), &node_id_test(), &bill)
            .await
            .expect("could not save bill to cache");

        store
            .save_bill_to_cache(&bill_id_test_other(), &node_id_test(), &bill2)
            .await
            .expect("could not save bill to cache");

        // different identity
        store
            .save_bill_to_cache(&bill_id_test(), &node_id_test_other(), &bill)
            .await
            .expect("could not save bill to cache");

        // get bill from cache
        let cached_bill = store
            .get_bill_from_cache(&bill_id_test(), &node_id_test_other())
            .await
            .expect("could not fetch from cache");
        assert_eq!(cached_bill.as_ref().unwrap().id, bill_id_test());

        // removed for other identity now
        // get bills from cache
        let cached_bills = store
            .get_bills_from_cache(&[bill_id_test(), bill_id_test_other()], &node_id_test())
            .await
            .expect("could not fetch from cache");
        assert_eq!(cached_bills.len(), 1);

        // get bills from cache for other identity
        let cached_bills = store
            .get_bills_from_cache(
                &[bill_id_test(), bill_id_test_other()],
                &node_id_test_other(),
            )
            .await
            .expect("could not fetch from cache");
        assert_eq!(cached_bills.len(), 1);

        // invalidate bill in cache
        store
            .invalidate_bill_in_cache(&bill_id_test())
            .await
            .expect("could not invalidate cache");

        // bill is not cached anymore
        let cached_bill_gone = store
            .get_bill_from_cache(&bill_id_test(), &node_id_test())
            .await
            .expect("could not fetch from cache");
        assert!(cached_bill_gone.is_none());
        // bill is not cached anymore for all identities
        let cached_bill_gone = store
            .get_bill_from_cache(&bill_id_test(), &node_id_test_other())
            .await
            .expect("could not fetch from cache");
        assert!(cached_bill_gone.is_none());

        // bill is not cached anymore
        let cached_bills_after_invalidate = store
            .get_bills_from_cache(&[bill_id_test_other()], &node_id_test())
            .await
            .expect("could not fetch from cache");
        assert_eq!(cached_bills_after_invalidate.len(), 1);
    }
}
