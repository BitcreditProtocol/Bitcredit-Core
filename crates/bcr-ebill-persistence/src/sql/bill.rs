use crate::sql::{required, timestamp_from_db, timestamp_to_db, u64_from_db, u64_to_db};
use crate::{Error, Result};
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::application::bill::{
    BillAcceptState, BillAcceptanceStatus, BillCallerActions, BillCallerBillAction,
    BillCallerPayment, BillCallerPaymentAction, BillCallerPaymentState, BillCurrentWaitingState,
    BillData, BillMintState, BillMintStatus, BillParticipants, BillPaymentState, BillPaymentStatus,
    BillRecourseStatus, BillSellStatus, BillState, BillStatus, BillWaitingForPaymentState,
    BillWaitingForRecourseState, BillWaitingForSellState, BillWaitingStatePaymentData,
    BitcreditBillResult, Endorsement, InMempoolData, LightSignedBy, PaidData, PaymentState,
};
use bcr_ebill_core::application::contact::{
    LightBillAnonParticipant, LightBillIdentParticipant, LightBillIdentParticipantWithAddress,
    LightBillParticipant, LightBillSignatory,
};
use bcr_ebill_core::protocol::Country;
use bcr_ebill_core::protocol::Date;
use bcr_ebill_core::protocol::Name;
use bcr_ebill_core::protocol::Sum;
use bcr_ebill_core::protocol::Timestamp;
use bcr_ebill_core::protocol::blockchain::bill::participant::{
    BillAnonParticipant, BillIdentParticipant, BillParticipant, BillSignatory, SignedBy,
};
use bcr_ebill_core::protocol::blockchain::bill::{
    BillHistory, BillHistoryBlock, BillHistoryBlockPaymentData, PaymentStatus,
};
use bcr_ebill_core::protocol::blockchain::bill::{BillOpCode, ContactType};
use bcr_ebill_core::protocol::crypto::btc::BtcDescriptor;
use bcr_ebill_core::protocol::{Address, City, PostalAddress, Zip};
use bcr_ebill_core::protocol::{BitcoinAddress, Sha256Hash};
use bcr_ebill_core::protocol::{BlockId, File};
use bitcoin::hashes::sha256::Hash as Sha256HexHash;
use serde::{Deserialize, Serialize};
use sqlx::{
    FromRow,
    types::{Json, Text},
};

// SQL
pub(crate) const SELECT_CACHE_ONE: &str = r#"
    SELECT
        bill_id,
        identity_node_id,
        payload
    FROM bill_cache
    WHERE bill_id = $1
      AND identity_node_id = $2
"#;

pub(crate) const UPSERT_CACHE: &str = r#"
    INSERT INTO bill_cache (
        bill_id,
        identity_node_id,
        payload
    )
    VALUES ($1, $2, $3)
    ON CONFLICT(bill_id) DO UPDATE SET
        identity_node_id =
            excluded.identity_node_id,
        payload =
            excluded.payload
"#;

pub(crate) const INVALIDATE_CACHE: &str = r#"
    DELETE FROM bill_cache
    WHERE bill_id = $1
"#;

pub(crate) const CLEAR_CACHE: &str = r#"
    DELETE FROM bill_cache
"#;

pub(crate) const INSERT_KEYS: &str = r#"
    INSERT INTO bill_keys (
        bill_id,
        private_key
    )
    VALUES ($1, $2)
"#;

pub(crate) const SELECT_KEYS: &str = r#"
    SELECT private_key
    FROM bill_keys
    WHERE bill_id = $1
"#;

pub(crate) const UPSERT_PAYMENT: &str = r#"
    INSERT INTO bill_paid (
        bill_id,
        payment_state,
        block_time,
        block_hash,
        confirmations,
        tx_id
    )
    VALUES ($1, $2, $3, $4, $5, $6)
    ON CONFLICT(bill_id) DO UPDATE SET
        payment_state =
            excluded.payment_state,
        block_time =
            excluded.block_time,
        block_hash =
            excluded.block_hash,
        confirmations =
            excluded.confirmations,
        tx_id =
            excluded.tx_id
"#;

pub(crate) const SELECT_PAYMENT: &str = r#"
    SELECT
        payment_state,
        block_time,
        block_hash,
        confirmations,
        tx_id
    FROM bill_paid
    WHERE bill_id = $1
"#;

pub(crate) const IS_PAID: &str = r#"
    SELECT EXISTS (
        SELECT 1
        FROM bill_paid
        WHERE bill_id = $1
          AND payment_state =
              'paid_confirmed'
    )
"#;

pub(crate) const UPSERT_OFFER_TO_SELL_PAYMENT: &str = r#"
    INSERT INTO offer_to_sell_bill_paid (
        bill_id,
        block_id,
        payment_state,
        block_time,
        block_hash,
        confirmations,
        tx_id
    )
    VALUES (
        $1, $2, $3, $4, $5, $6, $7
    )
    ON CONFLICT(bill_id, block_id)
    DO UPDATE SET
        payment_state =
            excluded.payment_state,
        block_time =
            excluded.block_time,
        block_hash =
            excluded.block_hash,
        confirmations =
            excluded.confirmations,
        tx_id =
            excluded.tx_id
"#;

pub(crate) const SELECT_OFFER_TO_SELL_PAYMENT: &str = r#"
    SELECT
        payment_state,
        block_time,
        block_hash,
        confirmations,
        tx_id
    FROM offer_to_sell_bill_paid
    WHERE bill_id = $1
      AND block_id = $2
"#;

pub(crate) const UPSERT_RECOURSE_PAYMENT: &str = r#"
    INSERT INTO recourse_bill_paid (
        bill_id,
        block_id,
        payment_state,
        block_time,
        block_hash,
        confirmations,
        tx_id
    )
    VALUES (
        $1, $2, $3, $4, $5, $6, $7
    )
    ON CONFLICT(bill_id, block_id)
    DO UPDATE SET
        payment_state =
            excluded.payment_state,
        block_time =
            excluded.block_time,
        block_hash =
            excluded.block_hash,
        confirmations =
            excluded.confirmations,
        tx_id =
            excluded.tx_id
"#;

pub(crate) const SELECT_RECOURSE_PAYMENT: &str = r#"
    SELECT
        payment_state,
        block_time,
        block_hash,
        confirmations,
        tx_id
    FROM recourse_bill_paid
    WHERE bill_id = $1
      AND block_id = $2
"#;

pub(crate) const BILL_EXISTS: &str = r#"
    SELECT EXISTS (
        SELECT 1
        FROM bill_chain AS c
        INNER JOIN bill_keys AS k
            ON k.bill_id = c.bill_id
        WHERE c.bill_id = $1
    )
"#;

pub(crate) const GET_BILL_IDS: &str = r#"
    SELECT DISTINCT bill_id
    FROM bill_chain
"#;

pub(crate) const WAITING_FOR_PAYMENT: &str = r#"
    SELECT DISTINCT c.bill_id
    FROM bill_chain AS c
    WHERE c.op_code = $1
      AND NOT EXISTS (
          SELECT 1
          FROM bill_paid AS p
          WHERE p.bill_id = c.bill_id
            AND p.payment_state =
                'paid_confirmed'
      )
"#;

pub(crate) const BILLS_WITH_LATEST_OP_CODE: &str = r#"
    SELECT b.bill_id
    FROM bill_chain AS b
    WHERE b.op_code = $1
      AND b.block_id = (
          SELECT MAX(b2.block_id)
          FROM bill_chain AS b2
          WHERE b2.bill_id = b.bill_id
      )
"#;

// cache models
#[derive(Debug, FromRow)]
pub(crate) struct BillCacheRow {
    pub bill_id: Text<BillId>,
    pub identity_node_id: Text<NodeId>,
    pub payload: Json<BitcreditBillResultDb>,
}

impl TryFrom<BillCacheRow> for BitcreditBillResult {
    type Error = Error;

    fn try_from(row: BillCacheRow) -> Result<Self> {
        let bill_id = row.bill_id.into_inner();
        let identity_node_id = row.identity_node_id.into_inner();
        let payload = row.payload.0;
        if payload.bill_id != bill_id {
            return Err(Error::InvalidData("bill cache bill_id mismatch".to_owned()));
        }
        if payload.identity_node_id != identity_node_id {
            return Err(Error::InvalidData(
                "bill cache identity_node_id mismatch".to_owned(),
            ));
        }
        Ok(payload.into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcreditBillResultDb {
    pub bill_id: BillId,
    pub participants: BillParticipantsDb,
    pub data: BillDataDb,
    pub status: BillStatusDb,
    pub state: BillStateDb,
    pub current_waiting_state: Option<BillCurrentWaitingStateDb>,
    pub history: BillHistoryDb,
    pub actions: BillCallerActionsDb,
    pub identity_node_id: NodeId,
}

impl From<BitcreditBillResultDb> for BitcreditBillResult {
    fn from(value: BitcreditBillResultDb) -> Self {
        Self {
            id: value.bill_id,
            participants: value.participants.into(),
            data: value.data.into(),
            status: value.status.into(),
            state: value.state.into(),
            current_waiting_state: value.current_waiting_state.map(|cws| cws.into()),
            history: value.history.into(),
            actions: value.actions.into(),
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
            state: (&value.state).into(),
            current_waiting_state: value.current_waiting_state.as_ref().map(|cws| cws.into()),
            history: value.history.clone().into(),
            actions: (&value.actions).into(),
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
    pub time_of_request: Timestamp,
    pub sum: Sum,
    pub address_to_pay: BitcoinAddress,
    pub tx_id: Option<String>,
    pub in_mempool: bool,
    pub confirmations: u64,
    pub payment_deadline: Option<Timestamp>,
}

impl From<BillWaitingStatePaymentDataDb> for BillWaitingStatePaymentData {
    fn from(value: BillWaitingStatePaymentDataDb) -> Self {
        Self {
            time_of_request: value.time_of_request,
            sum: value.sum,
            address_to_pay: value.address_to_pay,
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
            sum: value.sum.clone(),
            address_to_pay: value.address_to_pay.clone(),
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
    pub last_block_time: Timestamp,
    #[serde(default)]
    pub is_mature: bool,
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
            is_mature: value.is_mature,
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
            is_mature: value.is_mature,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillStateDb {
    pub mint: BillMintStateDb,
    pub accept: BillAcceptStateDb,
    pub payment: BillPaymentStateDb,
}

impl From<BillStateDb> for BillState {
    fn from(value: BillStateDb) -> Self {
        Self {
            mint: value.mint.into(),
            accept: value.accept.into(),
            payment: value.payment.into(),
        }
    }
}

impl From<&BillState> for BillStateDb {
    fn from(value: &BillState) -> Self {
        Self {
            mint: (&value.mint).into(),
            accept: (&value.accept).into(),
            payment: (&value.payment).into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BillAcceptStateDb {
    None,
    Requested(Timestamp),
    Accepted(Timestamp),
    Expired(Timestamp),
    Rejected(Timestamp),
}

impl From<BillAcceptStateDb> for BillAcceptState {
    fn from(value: BillAcceptStateDb) -> Self {
        match value {
            BillAcceptStateDb::None => BillAcceptState::None,
            BillAcceptStateDb::Requested(timestamp) => BillAcceptState::Requested(timestamp),
            BillAcceptStateDb::Accepted(timestamp) => BillAcceptState::Accepted(timestamp),
            BillAcceptStateDb::Expired(timestamp) => BillAcceptState::Expired(timestamp),
            BillAcceptStateDb::Rejected(timestamp) => BillAcceptState::Rejected(timestamp),
        }
    }
}

impl From<&BillAcceptState> for BillAcceptStateDb {
    fn from(value: &BillAcceptState) -> Self {
        match value {
            BillAcceptState::None => BillAcceptStateDb::None,
            BillAcceptState::Requested(timestamp) => {
                BillAcceptStateDb::Requested(timestamp.to_owned())
            }
            BillAcceptState::Accepted(timestamp) => {
                BillAcceptStateDb::Accepted(timestamp.to_owned())
            }
            BillAcceptState::Expired(timestamp) => BillAcceptStateDb::Expired(timestamp.to_owned()),
            BillAcceptState::Rejected(timestamp) => {
                BillAcceptStateDb::Rejected(timestamp.to_owned())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BillPaymentStateDb {
    None,
    Requested(Timestamp),
    Paid(Timestamp),
    Expired(Timestamp),
    Rejected(Timestamp),
}

impl From<BillPaymentStateDb> for BillPaymentState {
    fn from(value: BillPaymentStateDb) -> Self {
        match value {
            BillPaymentStateDb::None => BillPaymentState::None,
            BillPaymentStateDb::Requested(timestamp) => BillPaymentState::Requested(timestamp),
            BillPaymentStateDb::Paid(timestamp) => BillPaymentState::Paid(timestamp),
            BillPaymentStateDb::Expired(timestamp) => BillPaymentState::Expired(timestamp),
            BillPaymentStateDb::Rejected(timestamp) => BillPaymentState::Rejected(timestamp),
        }
    }
}

impl From<&BillPaymentState> for BillPaymentStateDb {
    fn from(value: &BillPaymentState) -> Self {
        match value {
            BillPaymentState::None => BillPaymentStateDb::None,
            BillPaymentState::Requested(timestamp) => {
                BillPaymentStateDb::Requested(timestamp.to_owned())
            }
            BillPaymentState::Paid(timestamp) => BillPaymentStateDb::Paid(timestamp.to_owned()),
            BillPaymentState::Expired(timestamp) => {
                BillPaymentStateDb::Expired(timestamp.to_owned())
            }
            BillPaymentState::Rejected(timestamp) => {
                BillPaymentStateDb::Rejected(timestamp.to_owned())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BillMintStateDb {
    None,
    Requested,
}
impl From<BillMintStateDb> for BillMintState {
    fn from(value: BillMintStateDb) -> Self {
        match value {
            BillMintStateDb::None => BillMintState::None,
            BillMintStateDb::Requested => BillMintState::Requested,
        }
    }
}
impl From<&BillMintState> for BillMintStateDb {
    fn from(value: &BillMintState) -> Self {
        match value {
            BillMintState::None => BillMintStateDb::None,
            BillMintState::Requested => BillMintStateDb::Requested,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillAcceptanceStatusDb {
    pub time_of_request_to_accept: Option<Timestamp>,
    pub requested_to_accept: bool,
    pub accepted: bool,
    pub request_to_accept_timed_out: bool,
    pub rejected_to_accept: bool,
    pub acceptance_deadline_timestamp: Option<Timestamp>,
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
    pub time_of_request_to_pay: Option<Timestamp>,
    pub requested_to_pay: bool,
    pub paid: bool,
    pub request_to_pay_timed_out: bool,
    pub rejected_to_pay: bool,
    pub payment_deadline_timestamp: Option<Timestamp>,
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
    pub time_of_last_offer_to_sell: Option<Timestamp>,
    pub sold: bool,
    pub offered_to_sell: bool,
    pub offer_to_sell_timed_out: bool,
    pub rejected_offer_to_sell: bool,
    pub buying_deadline_timestamp: Option<Timestamp>,
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
    pub time_of_last_request_to_recourse: Option<Timestamp>,
    pub recoursed: bool,
    pub requested_to_recourse: bool,
    pub request_to_recourse_timed_out: bool,
    pub rejected_request_to_recourse: bool,
    pub recourse_deadline_timestamp: Option<Timestamp>,
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
    pub time_of_drawing: Timestamp,
    pub issue_date: Date,
    pub time_of_maturity: Timestamp,
    pub maturity_date: Date,
    pub country_of_issuing: Country,
    pub city_of_issuing: City,
    pub country_of_payment: Country,
    pub city_of_payment: City,
    pub sum: Sum,
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
            sum: value.sum.clone(),
            files: value.files.iter().map(|f| f.clone().into()).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDb {
    pub name: Name,
    pub hash: Sha256Hash,
    pub nostr_hash: Sha256HexHash,
}

impl From<FileDb> for File {
    fn from(value: FileDb) -> Self {
        Self {
            name: value.name,
            hash: value.hash,
            nostr_hash: value.nostr_hash,
        }
    }
}

impl From<File> for FileDb {
    fn from(value: File) -> Self {
        Self {
            name: value.name,
            hash: value.hash,
            nostr_hash: value.nostr_hash,
        }
    }
}

impl From<&File> for FileDb {
    fn from(value: &File) -> Self {
        Self {
            name: value.name.clone(),
            hash: value.hash.clone(),
            nostr_hash: value.nostr_hash,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillCallerActionsDb {
    pub bill_actions: Vec<BillCallerBillAction>,
    pub payment_actions: Vec<BillCallerPaymentActionDb>,
}

impl From<BillCallerActionsDb> for BillCallerActions {
    fn from(value: BillCallerActionsDb) -> Self {
        Self {
            bill_actions: value.bill_actions,
            payment_actions: value
                .payment_actions
                .into_iter()
                .map(|b| b.into())
                .collect(),
        }
    }
}

impl From<&BillCallerActions> for BillCallerActionsDb {
    fn from(value: &BillCallerActions) -> Self {
        Self {
            bill_actions: value.bill_actions.to_owned(),
            payment_actions: value.payment_actions.iter().map(|b| b.into()).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BillCallerPaymentActionDb {
    Pay(BillCallerPaymentDb),
    CheckPayment(BillCallerPaymentDb),
}

impl From<BillCallerPaymentActionDb> for BillCallerPaymentAction {
    fn from(value: BillCallerPaymentActionDb) -> Self {
        match value {
            BillCallerPaymentActionDb::Pay(bill_caller_payment_db) => {
                BillCallerPaymentAction::Pay(bill_caller_payment_db.into())
            }
            BillCallerPaymentActionDb::CheckPayment(bill_caller_payment_db) => {
                BillCallerPaymentAction::CheckPayment(bill_caller_payment_db.into())
            }
        }
    }
}

impl From<&BillCallerPaymentAction> for BillCallerPaymentActionDb {
    fn from(value: &BillCallerPaymentAction) -> Self {
        match value {
            BillCallerPaymentAction::Pay(bill_caller_payment_db) => {
                BillCallerPaymentActionDb::Pay(bill_caller_payment_db.into())
            }
            BillCallerPaymentAction::CheckPayment(bill_caller_payment_db) => {
                BillCallerPaymentActionDb::CheckPayment(bill_caller_payment_db.into())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BillCallerPaymentDb {
    Sell {
        buyer: BillParticipantDb,
        seller: BillParticipantDb,
        state: BillCallerPaymentStateDb,
    },
    Payment {
        payer: BillIdentParticipantDb,
        payee: BillParticipantDb,
        state: BillCallerPaymentStateDb,
    },
    Recourse {
        recourser: BillParticipantDb,
        recoursee: BillIdentParticipantDb,
        state: BillCallerPaymentStateDb,
    },
}

impl From<BillCallerPaymentDb> for BillCallerPayment {
    fn from(value: BillCallerPaymentDb) -> Self {
        match value {
            BillCallerPaymentDb::Sell {
                buyer,
                seller,
                state,
            } => BillCallerPayment::Sell {
                buyer: buyer.into(),
                seller: seller.into(),
                state: state.into(),
            },
            BillCallerPaymentDb::Payment {
                payer,
                payee,
                state,
            } => BillCallerPayment::Payment {
                payer: payer.into(),
                payee: payee.into(),
                state: state.into(),
            },
            BillCallerPaymentDb::Recourse {
                recourser,
                recoursee,
                state,
            } => BillCallerPayment::Recourse {
                recourser: recourser.into(),
                recoursee: recoursee.into(),
                state: state.into(),
            },
        }
    }
}

impl From<&BillCallerPayment> for BillCallerPaymentDb {
    fn from(value: &BillCallerPayment) -> Self {
        match value {
            BillCallerPayment::Sell {
                buyer,
                seller,
                state,
            } => BillCallerPaymentDb::Sell {
                buyer: buyer.into(),
                seller: seller.into(),
                state: state.into(),
            },
            BillCallerPayment::Payment {
                payer,
                payee,
                state,
            } => BillCallerPaymentDb::Payment {
                payer: payer.into(),
                payee: payee.into(),
                state: state.into(),
            },
            BillCallerPayment::Recourse {
                recourser,
                recoursee,
                state,
            } => BillCallerPaymentDb::Recourse {
                recourser: recourser.into(),
                recoursee: recoursee.into(),
                state: state.into(),
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BillCallerPaymentStateDb {
    pub time_of_request: Timestamp,
    pub sum: Sum,
    pub address_to_pay: BitcoinAddress,
    pub private_descriptor_to_spend: Option<BtcDescriptor>,
    pub status: PaymentStatusDb,
    pub payment_deadline: Timestamp,
    pub tx_id: Option<String>,
    pub in_mempool: bool,
    pub confirmations: u64,
}

impl From<BillCallerPaymentStateDb> for BillCallerPaymentState {
    fn from(value: BillCallerPaymentStateDb) -> Self {
        Self {
            time_of_request: value.time_of_request,
            sum: value.sum,
            address_to_pay: value.address_to_pay,
            private_descriptor_to_spend: value.private_descriptor_to_spend,
            status: value.status.into(),
            payment_deadline: value.payment_deadline,
            tx_id: value.tx_id,
            in_mempool: value.in_mempool,
            confirmations: value.confirmations,
        }
    }
}

impl From<&BillCallerPaymentState> for BillCallerPaymentStateDb {
    fn from(value: &BillCallerPaymentState) -> Self {
        Self {
            time_of_request: value.time_of_request,
            sum: value.sum.to_owned(),
            address_to_pay: value.address_to_pay.to_owned(),
            private_descriptor_to_spend: value
                .private_descriptor_to_spend
                .as_ref()
                .map(|pd| pd.to_owned()),
            status: (&value.status).into(),
            payment_deadline: value.payment_deadline,
            tx_id: value.tx_id.as_ref().map(|tx| tx.to_owned()),
            in_mempool: value.in_mempool,
            confirmations: value.confirmations,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaymentStatusDb {
    Requested(Timestamp),
    Paid(Timestamp),
    Rejected(Timestamp),
    Expired(Timestamp),
}

impl From<PaymentStatusDb> for PaymentStatus {
    fn from(value: PaymentStatusDb) -> Self {
        match value {
            PaymentStatusDb::Requested(timestamp) => PaymentStatus::Requested(timestamp),
            PaymentStatusDb::Paid(timestamp) => PaymentStatus::Paid(timestamp),
            PaymentStatusDb::Rejected(timestamp) => PaymentStatus::Rejected(timestamp),
            PaymentStatusDb::Expired(timestamp) => PaymentStatus::Expired(timestamp),
        }
    }
}

impl From<&PaymentStatus> for PaymentStatusDb {
    fn from(value: &PaymentStatus) -> Self {
        match value {
            PaymentStatus::Requested(timestamp) => PaymentStatusDb::Requested(timestamp.to_owned()),
            PaymentStatus::Paid(timestamp) => PaymentStatusDb::Paid(timestamp.to_owned()),
            PaymentStatus::Rejected(timestamp) => PaymentStatusDb::Rejected(timestamp.to_owned()),
            PaymentStatus::Expired(timestamp) => PaymentStatusDb::Expired(timestamp.to_owned()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BillHistoryBlockDb {
    pub block_id: BlockId,
    pub block_type: BillOpCode,
    pub pay_to_the_order_of: Option<BillParticipantDb>,
    pub payment_data: Option<BillHistoryBlockPaymentDataDb>,
    pub request_deadline: Option<Timestamp>,
    pub signed: LightSignedByDb,
    pub signing_timestamp: Timestamp,
    pub signing_address: Option<PostalAddressDb>,
}

impl From<BillHistoryBlockDb> for BillHistoryBlock {
    fn from(value: BillHistoryBlockDb) -> Self {
        Self {
            block_id: value.block_id,
            block_type: value.block_type,
            pay_to_the_order_of: value.pay_to_the_order_of.map(|pttoo| pttoo.into()),
            payment_data: value.payment_data.map(|pd| pd.into()),
            request_deadline: value.request_deadline,
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
            payment_data: value.payment_data.map(|pd| pd.into()),
            request_deadline: value.request_deadline,
            signed: (&value.signed).into(),
            signing_timestamp: value.signing_timestamp,
            signing_address: value.signing_address.map(|sa| sa.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostalAddressDb {
    pub country: Country,
    pub city: City,
    pub zip: Option<Zip>,
    pub address: Address,
}

impl From<PostalAddressDb> for PostalAddress {
    fn from(value: PostalAddressDb) -> Self {
        Self {
            country: value.country,
            city: value.city,
            zip: value.zip,
            address: value.address,
        }
    }
}

impl From<PostalAddress> for PostalAddressDb {
    fn from(value: PostalAddress) -> Self {
        Self {
            country: value.country,
            city: value.city,
            zip: value.zip,
            address: value.address,
        }
    }
}

impl From<&PostalAddress> for PostalAddressDb {
    fn from(value: &PostalAddress) -> Self {
        Self {
            country: value.country.clone(),
            city: value.city.clone(),
            zip: value.zip.clone(),
            address: value.address.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BillHistoryBlockPaymentDataDb {
    pub sum: Sum,
    pub payment_address: BitcoinAddress,
}

impl From<BillHistoryBlockPaymentDataDb> for BillHistoryBlockPaymentData {
    fn from(value: BillHistoryBlockPaymentDataDb) -> Self {
        Self {
            sum: value.sum,
            payment_address: value.payment_address,
        }
    }
}

impl From<BillHistoryBlockPaymentData> for BillHistoryBlockPaymentDataDb {
    fn from(value: BillHistoryBlockPaymentData) -> Self {
        Self {
            sum: value.sum,
            payment_address: value.payment_address,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EndorsementDb {
    pub pay_to_the_order_of: BillParticipantDb,
    pub signed: LightSignedByDb,
    pub signing_timestamp: Timestamp,
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
    pub signatory: Option<LightBillSignatoryDb>,
}

impl From<LightSignedByDb> for SignedBy {
    fn from(value: LightSignedByDb) -> Self {
        Self {
            data: value.data.into(),
            signatory: value.signatory.map(|s| BillSignatory {
                node_id: s.node_id,
                name: s.name,
            }),
        }
    }
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

impl From<&SignedBy> for LightSignedByDb {
    fn from(value: &SignedBy) -> Self {
        Self {
            data: (&value.data).into(),
            signatory: value.signatory.as_ref().map(|s| LightBillSignatoryDb {
                name: s.name.to_owned(),
                node_id: s.node_id.to_owned(),
            }),
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
pub struct LightBillSignatoryDb {
    pub name: Option<Name>,
    pub node_id: NodeId,
}

impl From<LightBillSignatoryDb> for LightBillSignatory {
    fn from(value: LightBillSignatoryDb) -> Self {
        Self {
            name: value.name,
            node_id: value.node_id,
        }
    }
}

impl From<&LightBillSignatory> for LightBillSignatoryDb {
    fn from(value: &LightBillSignatory) -> Self {
        Self {
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

// payment state
pub(crate) struct PaymentStateColumns {
    pub payment_state: &'static str,
    pub block_time: Option<i64>,
    pub block_hash: Option<String>,
    pub confirmations: Option<i64>,
    pub tx_id: Option<String>,
}

pub(crate) fn payment_state_to_db(value: &PaymentState) -> Result<PaymentStateColumns> {
    match value {
        PaymentState::PaidConfirmed(data) => Ok(PaymentStateColumns {
            payment_state: "paid_confirmed",
            block_time: Some(timestamp_to_db(data.block_time)?),
            block_hash: Some(data.block_hash.clone()),
            confirmations: Some(u64_to_db(data.confirmations, "confirmations")?),
            tx_id: Some(data.tx_id.clone()),
        }),
        PaymentState::PaidUnconfirmed(data) => Ok(PaymentStateColumns {
            payment_state: "paid_unconfirmed",
            block_time: Some(timestamp_to_db(data.block_time)?),
            block_hash: Some(data.block_hash.clone()),
            confirmations: Some(u64_to_db(data.confirmations, "confirmations")?),
            tx_id: Some(data.tx_id.clone()),
        }),
        PaymentState::InMempool(data) => Ok(PaymentStateColumns {
            payment_state: "in_mempool",
            block_time: None,
            block_hash: None,
            confirmations: None,
            tx_id: Some(data.tx_id.clone()),
        }),
        PaymentState::NotFound => Ok(PaymentStateColumns {
            payment_state: "not_found",
            block_time: None,
            block_hash: None,
            confirmations: None,
            tx_id: None,
        }),
    }
}

#[derive(Debug, FromRow)]
pub(crate) struct PaymentStateRow {
    pub payment_state: String,
    pub block_time: Option<i64>,
    pub block_hash: Option<String>,
    pub confirmations: Option<i64>,
    pub tx_id: Option<String>,
}

impl TryFrom<PaymentStateRow> for PaymentState {
    type Error = Error;

    fn try_from(row: PaymentStateRow) -> Result<Self> {
        match row.payment_state.as_str() {
            "paid_confirmed" => Ok(PaymentState::PaidConfirmed(PaidData {
                block_time: timestamp_from_db(required(row.block_time, "block_time")?)?,
                block_hash: required(row.block_hash, "block_hash")?,
                confirmations: u64_from_db(
                    required(row.confirmations, "confirmations")?,
                    "confirmations",
                )?,
                tx_id: required(row.tx_id, "tx_id")?,
            })),
            "paid_unconfirmed" => Ok(PaymentState::PaidUnconfirmed(PaidData {
                block_time: timestamp_from_db(required(row.block_time, "block_time")?)?,
                block_hash: required(row.block_hash, "block_hash")?,
                confirmations: u64_from_db(
                    required(row.confirmations, "confirmations")?,
                    "confirmations",
                )?,
                tx_id: required(row.tx_id, "tx_id")?,
            })),
            "in_mempool" => Ok(PaymentState::InMempool(InMempoolData {
                tx_id: required(row.tx_id, "tx_id")?,
            })),
            "not_found" => Ok(PaymentState::NotFound),
            other => Err(Error::InvalidData(format!(
                "invalid payment state: \
                         {other}"
            ))),
        }
    }
}
