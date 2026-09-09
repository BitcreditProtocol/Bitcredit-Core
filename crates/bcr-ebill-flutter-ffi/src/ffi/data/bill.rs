use bcr_ebill_core::{
    application::{
        bill::{
            BillAcceptState, BillAcceptanceStatus, BillCallerActions, BillCallerBillAction,
            BillCallerPayment, BillCallerPaymentAction, BillCallerPaymentState,
            BillCombinedBitcoinKey, BillCurrentWaitingState, BillData, BillMintState,
            BillMintStatus, BillParticipants, BillPaymentState, BillPaymentStatus,
            BillRecourseStatus, BillSellStatus, BillState, BillStatus, BillWaitingForPaymentState,
            BillWaitingForRecourseState, BillWaitingForSellState, BillWaitingStatePaymentData,
            BillsFilterRole, BitcreditBillResult, Endorsement, LightBitcreditBillResult,
            LightSignedBy, PastPaymentDataPayment, PastPaymentDataRecourse, PastPaymentDataSell,
            PastPaymentResult, SweepEstimate, SweepOption, SweepResult,
        },
        contact::{
            LightBillAnonParticipant, LightBillIdentParticipant,
            LightBillIdentParticipantWithAddress, LightBillParticipant, LightBillSignatory,
        },
    },
    protocol::blockchain::bill::{
        BillHistory, BillHistoryBlock, BillHistoryBlockPaymentData, BillOpCode, PaymentStatus,
        participant::{
            BillAnonParticipant, BillIdentParticipant, BillParticipant, PastEndorsee, SignedBy,
        },
    },
};

use crate::ffi::data::{
    FileFfi, PostalAddressFfi, contact::ContactTypeFfi, notification::NotificationFfi,
};

#[derive(Debug, Clone)]
pub struct BillIdResponse {
    pub id: String,
}

#[derive(Debug, Clone)]
pub struct BitcreditBillPayload {
    pub t: u64,
    pub country_of_issuing: String,
    pub city_of_issuing: String,
    pub issue_date: String,
    pub maturity_date: String,
    pub payee: String,
    pub drawee: String,
    pub sum: String,
    #[allow(unused)]
    pub currency: String,
    pub country_of_payment: String,
    pub city_of_payment: String,
    pub file_upload_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct EndorseBitcreditBillPayload {
    pub endorsee: String,
    pub bill_id: String,
}

#[derive(Debug, Clone)]
pub struct RequestToMintBitcreditBillPayload {
    pub mint_node: String,
    pub bill_id: String,
}

#[derive(Debug, Clone)]
pub struct OfferToSellBitcreditBillPayload {
    pub buyer: String,
    pub bill_id: String,
    pub sum: String,
    #[allow(unused)]
    pub currency: String,
    pub buying_deadline: String,
}

#[derive(Debug)]
pub struct RequestToPayBitcreditBillPayload {
    pub bill_id: String,
    #[allow(unused)]
    pub currency: String,
    pub payment_deadline: String,
}

#[derive(Debug)]
pub struct RequestToPayAsMintBitcreditBillPayload {
    pub bill_id: String,
    #[allow(unused)]
    pub currency: String,
    pub payment_deadline: String,
    pub payment_address: String,
}

#[derive(Debug)]
pub struct RequestRecourseForPaymentPayload {
    pub bill_id: String,
    pub recoursee: String,
    #[allow(unused)]
    pub currency: String,
    pub sum: String,
    pub recourse_deadline: String,
}

#[derive(Debug)]
pub struct RequestRecourseForAcceptancePayload {
    pub bill_id: String,
    pub recoursee: String,
    pub recourse_deadline: String,
}

#[derive(Debug)]
pub struct AcceptBitcreditBillPayload {
    pub bill_id: String,
}

#[derive(Debug, Clone)]
pub struct RequestToAcceptBitcreditBillPayload {
    pub bill_id: String,
    pub acceptance_deadline: String,
}

#[derive(Debug, Clone)]
pub struct RejectActionBillPayload {
    pub bill_id: String,
}

#[derive(Debug, Clone)]
pub struct BillCombinedBitcoinKeyFfi {
    pub block_id: u64,
    pub signing_timestamp: u64,
    pub payment_op: BillOpCodeFfi,
    pub private_descriptor: String,
}

#[derive(Debug, Clone)]
pub struct BillCheckSweepBTCFundsPayload {
    pub bill_id: String,
    pub source_address: String,
    pub destination_address: String,
}

#[derive(Debug, Clone)]
pub struct BillSweepBTCEstimateFfi {
    pub available_funds: u64,
    pub economy: BillSweepBTCOptionFfi,
    pub fast: BillSweepBTCOptionFfi,
}

impl From<SweepEstimate> for BillSweepBTCEstimateFfi {
    fn from(val: SweepEstimate) -> Self {
        Self {
            available_funds: val.available_funds,
            economy: val.economy.into(),
            fast: val.fast.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BillSweepBTCOptionFfi {
    pub fee_rate_sat_vb: f64,
    pub fee_sat: u64,
    pub amount_to_sweep_sat: u64,
}

impl From<SweepOption> for BillSweepBTCOptionFfi {
    fn from(val: SweepOption) -> Self {
        Self {
            fee_rate_sat_vb: val.fee_rate_sat_vb,
            fee_sat: val.fee_sat,
            amount_to_sweep_sat: val.amount_to_sweep_sat,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BillSweepBTCFundsPayload {
    pub bill_id: String,
    pub source_address: String,
    pub destination_address: String,
    pub fee: u64,
}

#[derive(Debug, Clone)]
pub struct BillSweepBTCFundsResultFfi {
    pub tx_id: String,
    pub link_to_tx: String,
    pub fee_sat: u64,
    pub sweep_amount: u64,
}

impl From<SweepResult> for BillSweepBTCFundsResultFfi {
    fn from(val: SweepResult) -> Self {
        Self {
            tx_id: val.tx_id,
            link_to_tx: val.link_to_tx,
            fee_sat: val.fee_sat,
            sweep_amount: val.sweep_amount,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResyncBillPayload {
    pub bill_id: String,
    pub from_nostr: Option<bool>,
}

impl From<BillCombinedBitcoinKey> for BillCombinedBitcoinKeyFfi {
    fn from(val: BillCombinedBitcoinKey) -> Self {
        BillCombinedBitcoinKeyFfi {
            block_id: val.block_id.inner(),
            signing_timestamp: val.signing_timestamp.inner(),
            payment_op: val.payment_op.into(),
            private_descriptor: val.private_descriptor.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum BillsFilterRoleFfi {
    All,
    Payer,
    Payee,
    Contingent,
}

impl From<BillsFilterRoleFfi> for BillsFilterRole {
    fn from(value: BillsFilterRoleFfi) -> Self {
        match value {
            BillsFilterRoleFfi::All => BillsFilterRole::All,
            BillsFilterRoleFfi::Payer => BillsFilterRole::Payer,
            BillsFilterRoleFfi::Payee => BillsFilterRole::Payee,
            BillsFilterRoleFfi::Contingent => BillsFilterRole::Contingent,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BillsResponse {
    pub bills: Vec<BitcreditBillFfi>,
}

#[derive(Debug, Clone)]
pub struct BitcreditBillFfi {
    pub id: String,
    pub participants: BillParticipantsFfi,
    pub data: BillDataFfi,
    pub status: BillStatusFfi,
    pub state: BillStateFfi,
    /* Marked for deprecation */
    pub current_waiting_state: Option<BillCurrentWaitingStateFfi>,
    pub actions: BillCallerActionsFfi,
}

impl From<BitcreditBillResult> for BitcreditBillFfi {
    fn from(val: BitcreditBillResult) -> Self {
        BitcreditBillFfi {
            id: val.id.to_string(),
            participants: val.participants.into(),
            data: val.data.into(),
            status: val.status.into(),
            state: val.state.into(),
            current_waiting_state: val.current_waiting_state.map(|cws| cws.into()),
            actions: val.actions.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BillStateFfi {
    pub mint: BillMintStateFfi,
    pub accept: BillAcceptStateFfi,
    pub payment: BillPaymentStateFfi,
}

impl From<BillState> for BillStateFfi {
    fn from(value: BillState) -> Self {
        Self {
            mint: value.mint.into(),
            accept: value.accept.into(),
            payment: value.payment.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum BillAcceptStateFfi {
    None,
    Requested(u64),
    Accepted(u64),
    Expired(u64),
    Rejected(u64),
}

impl From<BillAcceptState> for BillAcceptStateFfi {
    fn from(value: BillAcceptState) -> Self {
        match value {
            BillAcceptState::None => BillAcceptStateFfi::None,
            BillAcceptState::Requested(timestamp) => {
                BillAcceptStateFfi::Requested(timestamp.inner())
            }
            BillAcceptState::Accepted(timestamp) => BillAcceptStateFfi::Accepted(timestamp.inner()),
            BillAcceptState::Expired(timestamp) => BillAcceptStateFfi::Expired(timestamp.inner()),
            BillAcceptState::Rejected(timestamp) => BillAcceptStateFfi::Rejected(timestamp.inner()),
        }
    }
}

#[derive(Debug, Clone)]
pub enum BillPaymentStateFfi {
    None,
    Requested(u64),
    Paid(u64),
    Expired(u64),
    Rejected(u64),
}

impl From<BillPaymentState> for BillPaymentStateFfi {
    fn from(value: BillPaymentState) -> Self {
        match value {
            BillPaymentState::None => BillPaymentStateFfi::None,
            BillPaymentState::Requested(timestamp) => {
                BillPaymentStateFfi::Requested(timestamp.inner())
            }
            BillPaymentState::Paid(timestamp) => BillPaymentStateFfi::Paid(timestamp.inner()),
            BillPaymentState::Expired(timestamp) => BillPaymentStateFfi::Expired(timestamp.inner()),
            BillPaymentState::Rejected(timestamp) => {
                BillPaymentStateFfi::Rejected(timestamp.inner())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum BillMintStateFfi {
    None,
    Requested,
}
impl From<BillMintState> for BillMintStateFfi {
    fn from(value: BillMintState) -> Self {
        match value {
            BillMintState::None => BillMintStateFfi::None,
            BillMintState::Requested => BillMintStateFfi::Requested,
        }
    }
}

/* Marked for deprecation */
#[derive(Debug, Clone)]
pub enum BillCurrentWaitingStateFfi {
    Sell(BillWaitingForSellStateFfi),
    Payment(BillWaitingForPaymentStateFfi),
    Recourse(BillWaitingForRecourseStateFfi),
}

impl From<BillCurrentWaitingState> for BillCurrentWaitingStateFfi {
    fn from(val: BillCurrentWaitingState) -> Self {
        match val {
            BillCurrentWaitingState::Sell(state) => BillCurrentWaitingStateFfi::Sell(state.into()),
            BillCurrentWaitingState::Payment(state) => {
                BillCurrentWaitingStateFfi::Payment(state.into())
            }
            BillCurrentWaitingState::Recourse(state) => {
                BillCurrentWaitingStateFfi::Recourse(state.into())
            }
        }
    }
}

/* Marked for deprecation */
#[derive(Debug, Clone)]
pub struct BillWaitingStatePaymentDataFfi {
    pub time_of_request: u64,
    pub currency: String,
    pub sum: String,
    pub address_to_pay: String,
    pub tx_id: Option<String>,
    pub in_mempool: bool,
    pub confirmations: u64,
    pub payment_deadline: Option<u64>,
}

impl From<BillWaitingStatePaymentData> for BillWaitingStatePaymentDataFfi {
    fn from(val: BillWaitingStatePaymentData) -> Self {
        BillWaitingStatePaymentDataFfi {
            time_of_request: val.time_of_request.inner(),
            currency: val.sum.currency().code().to_owned(),
            sum: val.sum.as_sat_string(),
            address_to_pay: val.address_to_pay.assume_checked().to_string(),
            tx_id: val.tx_id,
            in_mempool: val.in_mempool,
            confirmations: val.confirmations,
            payment_deadline: val.payment_deadline.map(|t| t.inner()),
        }
    }
}

/* Marked for deprecation */
#[derive(Debug, Clone)]
pub struct BillWaitingForSellStateFfi {
    pub buyer: BillParticipantFfi,
    pub seller: BillParticipantFfi,
    pub payment_data: BillWaitingStatePaymentDataFfi,
}

impl From<BillWaitingForSellState> for BillWaitingForSellStateFfi {
    fn from(val: BillWaitingForSellState) -> Self {
        BillWaitingForSellStateFfi {
            buyer: val.buyer.into(),
            seller: val.seller.into(),
            payment_data: val.payment_data.into(),
        }
    }
}

/* Marked for deprecation */
#[derive(Debug, Clone)]
pub struct BillWaitingForPaymentStateFfi {
    pub payer: BillIdentParticipantFfi,
    pub payee: BillParticipantFfi,
    pub payment_data: BillWaitingStatePaymentDataFfi,
}

impl From<BillWaitingForPaymentState> for BillWaitingForPaymentStateFfi {
    fn from(val: BillWaitingForPaymentState) -> Self {
        BillWaitingForPaymentStateFfi {
            payer: val.payer.into(),
            payee: val.payee.into(),
            payment_data: val.payment_data.into(),
        }
    }
}

/* Marked for deprecation */
#[derive(Debug, Clone)]
pub struct BillWaitingForRecourseStateFfi {
    pub recourser: BillParticipantFfi,
    pub recoursee: BillIdentParticipantFfi,
    pub payment_data: BillWaitingStatePaymentDataFfi,
}
impl From<BillWaitingForRecourseState> for BillWaitingForRecourseStateFfi {
    fn from(val: BillWaitingForRecourseState) -> Self {
        BillWaitingForRecourseStateFfi {
            recourser: val.recourser.into(),
            recoursee: val.recoursee.into(),
            payment_data: val.payment_data.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BillStatusFfi {
    /* Marked for deprecation */
    pub acceptance: BillAcceptanceStatusFfi,
    /* Marked for deprecation */
    pub payment: BillPaymentStatusFfi,
    /* Marked for deprecation */
    pub sell: BillSellStatusFfi,
    /* Marked for deprecation */
    pub recourse: BillRecourseStatusFfi,
    pub mint: BillMintStatusFfi,
    /* Marked for deprecation */
    pub redeemed_funds_available: bool,
    /* Marked for deprecation */
    pub has_requested_funds: bool,
    /* Marked for deprecation */
    pub last_block_time: u64,
}

impl From<BillStatus> for BillStatusFfi {
    fn from(val: BillStatus) -> Self {
        BillStatusFfi {
            acceptance: val.acceptance.into(),
            payment: val.payment.into(),
            sell: val.sell.into(),
            recourse: val.recourse.into(),
            mint: val.mint.into(),
            redeemed_funds_available: val.redeemed_funds_available,
            has_requested_funds: val.has_requested_funds,
            last_block_time: val.last_block_time.inner(),
        }
    }
}

/* Marked for deprecation */
#[derive(Debug, Clone)]
pub struct BillAcceptanceStatusFfi {
    pub time_of_request_to_accept: Option<u64>,
    pub requested_to_accept: bool,
    pub accepted: bool,
    pub request_to_accept_timed_out: bool,
    pub rejected_to_accept: bool,
    pub acceptance_deadline_timestamp: Option<u64>,
}

impl From<BillAcceptanceStatus> for BillAcceptanceStatusFfi {
    fn from(val: BillAcceptanceStatus) -> Self {
        BillAcceptanceStatusFfi {
            time_of_request_to_accept: val.time_of_request_to_accept.map(|t| t.inner()),
            requested_to_accept: val.requested_to_accept,
            accepted: val.accepted,
            request_to_accept_timed_out: val.request_to_accept_timed_out,
            rejected_to_accept: val.rejected_to_accept,
            acceptance_deadline_timestamp: val.acceptance_deadline_timestamp.map(|t| t.inner()),
        }
    }
}

/* Marked for deprecation */
#[derive(Debug, Clone)]
pub struct BillPaymentStatusFfi {
    pub time_of_request_to_pay: Option<u64>,
    pub requested_to_pay: bool,
    pub paid: bool,
    pub request_to_pay_timed_out: bool,
    pub rejected_to_pay: bool,
    pub payment_deadline_timestamp: Option<u64>,
}
impl From<BillPaymentStatus> for BillPaymentStatusFfi {
    fn from(val: BillPaymentStatus) -> Self {
        BillPaymentStatusFfi {
            time_of_request_to_pay: val.time_of_request_to_pay.map(|t| t.inner()),
            requested_to_pay: val.requested_to_pay,
            paid: val.paid,
            request_to_pay_timed_out: val.request_to_pay_timed_out,
            rejected_to_pay: val.rejected_to_pay,
            payment_deadline_timestamp: val.payment_deadline_timestamp.map(|t| t.inner()),
        }
    }
}

/* Marked for deprecation */
#[derive(Debug, Clone)]
pub struct BillSellStatusFfi {
    pub time_of_last_offer_to_sell: Option<u64>,
    pub sold: bool,
    pub offered_to_sell: bool,
    pub offer_to_sell_timed_out: bool,
    pub rejected_offer_to_sell: bool,
    pub buying_deadline_timestamp: Option<u64>,
}
impl From<BillSellStatus> for BillSellStatusFfi {
    fn from(val: BillSellStatus) -> Self {
        BillSellStatusFfi {
            time_of_last_offer_to_sell: val.time_of_last_offer_to_sell.map(|t| t.inner()),
            sold: val.sold,
            offered_to_sell: val.offered_to_sell,
            offer_to_sell_timed_out: val.offer_to_sell_timed_out,
            rejected_offer_to_sell: val.rejected_offer_to_sell,
            buying_deadline_timestamp: val.buying_deadline_timestamp.map(|t| t.inner()),
        }
    }
}

/* Marked for deprecation */
#[derive(Debug, Clone)]
pub struct BillRecourseStatusFfi {
    pub time_of_last_request_to_recourse: Option<u64>,
    pub recoursed: bool,
    pub requested_to_recourse: bool,
    pub request_to_recourse_timed_out: bool,
    pub rejected_request_to_recourse: bool,
    pub recourse_deadline_timestamp: Option<u64>,
}

impl From<BillRecourseStatus> for BillRecourseStatusFfi {
    fn from(val: BillRecourseStatus) -> Self {
        BillRecourseStatusFfi {
            time_of_last_request_to_recourse: val
                .time_of_last_request_to_recourse
                .map(|t| t.inner()),
            recoursed: val.recoursed,
            requested_to_recourse: val.requested_to_recourse,
            request_to_recourse_timed_out: val.request_to_recourse_timed_out,
            rejected_request_to_recourse: val.rejected_request_to_recourse,
            recourse_deadline_timestamp: val.recourse_deadline_timestamp.map(|t| t.inner()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BillMintStatusFfi {
    pub has_mint_requests: bool,
}

impl From<BillMintStatus> for BillMintStatusFfi {
    fn from(val: BillMintStatus) -> Self {
        BillMintStatusFfi {
            has_mint_requests: val.has_mint_requests,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BillDataFfi {
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
    pub files: Vec<FileFfi>,
    pub active_notification: Option<NotificationFfi>,
}

impl From<BillData> for BillDataFfi {
    fn from(val: BillData) -> Self {
        BillDataFfi {
            time_of_drawing: val.time_of_drawing.inner(),
            issue_date: val.issue_date.to_string(),
            time_of_maturity: val.time_of_maturity.inner(),
            maturity_date: val.maturity_date.to_string(),
            country_of_issuing: val.country_of_issuing.to_string(),
            city_of_issuing: val.city_of_issuing.to_string(),
            country_of_payment: val.country_of_payment.to_string(),
            city_of_payment: val.city_of_payment.to_string(),
            currency: val.sum.currency().code().to_owned(),
            sum: val.sum.as_sat_string(),
            files: val.files.into_iter().map(|f| f.into()).collect(),
            active_notification: val.active_notification.map(|an| an.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BillParticipantsFfi {
    pub drawee: BillIdentParticipantFfi,
    pub drawer: BillIdentParticipantFfi,
    pub payee: BillParticipantFfi,
    pub endorsee: Option<BillParticipantFfi>,
    pub endorsements_count: u64,
    pub all_participant_node_ids: Vec<String>,
}

impl From<BillParticipants> for BillParticipantsFfi {
    fn from(val: BillParticipants) -> Self {
        BillParticipantsFfi {
            drawee: val.drawee.into(),
            drawer: val.drawer.into(),
            payee: val.payee.into(),
            endorsee: val.endorsee.map(|e| e.into()),
            endorsements_count: val.endorsements_count,
            all_participant_node_ids: val
                .all_participant_node_ids
                .into_iter()
                .map(|id| id.to_string())
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BillCallerActionsFfi {
    pub bill_actions: Vec<BillCallerBillActionFfi>,
    pub payment_actions: Vec<BillCallerPaymentActionFfi>,
}

impl From<BillCallerActions> for BillCallerActionsFfi {
    fn from(value: BillCallerActions) -> Self {
        Self {
            bill_actions: value.bill_actions.into_iter().map(|ba| ba.into()).collect(),
            payment_actions: value
                .payment_actions
                .into_iter()
                .map(|ba| ba.into())
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum BillCallerBillActionFfi {
    RequestAcceptance,
    Accept,
    RequestToPay,
    OfferToSell,
    Sell,
    Endorse,
    RequestRecourseForAcceptance,
    RequestRecourseForPayment,
    Recourse,
    Mint,
    RejectAcceptance,
    RejectPayment,
    RejectBuying,
    RejectPaymentForRecourse,
}

impl From<BillCallerBillAction> for BillCallerBillActionFfi {
    fn from(value: BillCallerBillAction) -> Self {
        match value {
            BillCallerBillAction::RequestAcceptance => BillCallerBillActionFfi::RequestAcceptance,
            BillCallerBillAction::Accept => BillCallerBillActionFfi::Accept,
            BillCallerBillAction::RequestToPay => BillCallerBillActionFfi::RequestToPay,
            BillCallerBillAction::OfferToSell => BillCallerBillActionFfi::OfferToSell,
            BillCallerBillAction::Sell => BillCallerBillActionFfi::Sell,
            BillCallerBillAction::Endorse => BillCallerBillActionFfi::Endorse,
            BillCallerBillAction::RequestRecourseForAcceptance => {
                BillCallerBillActionFfi::RequestRecourseForAcceptance
            }
            BillCallerBillAction::RequestRecourseForPayment => {
                BillCallerBillActionFfi::RequestRecourseForPayment
            }
            BillCallerBillAction::Recourse => BillCallerBillActionFfi::Recourse,
            BillCallerBillAction::Mint => BillCallerBillActionFfi::Mint,
            BillCallerBillAction::RejectAcceptance => BillCallerBillActionFfi::RejectAcceptance,
            BillCallerBillAction::RejectPayment => BillCallerBillActionFfi::RejectPayment,
            BillCallerBillAction::RejectBuying => BillCallerBillActionFfi::RejectBuying,
            BillCallerBillAction::RejectPaymentForRecourse => {
                BillCallerBillActionFfi::RejectPaymentForRecourse
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum BillCallerPaymentActionFfi {
    Pay(BillCallerPaymentFfi),
    CheckPayment(BillCallerPaymentFfi),
}

impl From<BillCallerPaymentAction> for BillCallerPaymentActionFfi {
    fn from(value: BillCallerPaymentAction) -> Self {
        match value {
            BillCallerPaymentAction::Pay(bill_caller_payment) => {
                BillCallerPaymentActionFfi::Pay(bill_caller_payment.into())
            }
            BillCallerPaymentAction::CheckPayment(bill_caller_payment) => {
                BillCallerPaymentActionFfi::CheckPayment(bill_caller_payment.into())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum BillCallerPaymentFfi {
    Sell {
        buyer: BillParticipantFfi,
        seller: BillParticipantFfi,
        state: BillCallerPaymentStateFfi,
    },
    Payment {
        payer: BillIdentParticipantFfi,
        payee: BillParticipantFfi,
        state: BillCallerPaymentStateFfi,
    },
    Recourse {
        recourser: BillParticipantFfi,
        recoursee: BillIdentParticipantFfi,
        state: BillCallerPaymentStateFfi,
    },
}

impl From<BillCallerPayment> for BillCallerPaymentFfi {
    fn from(value: BillCallerPayment) -> Self {
        match value {
            BillCallerPayment::Sell {
                buyer,
                seller,
                state,
            } => BillCallerPaymentFfi::Sell {
                buyer: buyer.into(),
                seller: seller.into(),
                state: state.into(),
            },
            BillCallerPayment::Payment {
                payer,
                payee,
                state,
            } => BillCallerPaymentFfi::Payment {
                payer: payer.into(),
                payee: payee.into(),
                state: state.into(),
            },
            BillCallerPayment::Recourse {
                recourser,
                recoursee,
                state,
            } => BillCallerPaymentFfi::Recourse {
                recourser: recourser.into(),
                recoursee: recoursee.into(),
                state: state.into(),
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct BillCallerPaymentStateFfi {
    pub time_of_request: u64,
    pub currency: String,
    pub sum: String,
    pub address_to_pay: String,
    pub status: PaymentStatusFfi,
    pub payment_deadline: u64,
    pub tx_id: Option<String>,
    pub in_mempool: bool,
    pub confirmations: u64,
    // only set if we're receiver
    pub private_descriptor_to_spend: Option<String>,
}

impl From<BillCallerPaymentState> for BillCallerPaymentStateFfi {
    fn from(value: BillCallerPaymentState) -> Self {
        Self {
            time_of_request: value.time_of_request.inner(),
            currency: value.sum.currency().code().to_owned(),
            sum: value.sum.as_sat_string(),
            address_to_pay: value.address_to_pay.assume_checked().to_string(),
            status: value.status.into(),
            payment_deadline: value.payment_deadline.inner(),
            tx_id: value.tx_id,
            in_mempool: value.in_mempool,
            confirmations: value.confirmations,
            private_descriptor_to_spend: value.private_descriptor_to_spend.map(|d| d.to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub enum BillParticipantFfi {
    Anon(BillAnonParticipantFfi),
    Ident(BillIdentParticipantFfi),
}

impl From<BillParticipant> for BillParticipantFfi {
    fn from(val: BillParticipant) -> Self {
        match val {
            BillParticipant::Ident(data) => BillParticipantFfi::Ident(data.into()),
            BillParticipant::Anon(data) => BillParticipantFfi::Anon(data.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BillAnonParticipantFfi {
    pub node_id: String,
    pub nostr_relays: Vec<String>,
}

impl From<BillAnonParticipant> for BillAnonParticipantFfi {
    fn from(val: BillAnonParticipant) -> Self {
        BillAnonParticipantFfi {
            node_id: val.node_id.to_string(),
            nostr_relays: val
                .nostr_relays
                .into_iter()
                .map(|u| u.to_string())
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BillIdentParticipantFfi {
    pub t: ContactTypeFfi,
    pub node_id: String,
    pub name: String,
    pub postal_address: PostalAddressFfi,
    pub email: Option<String>,
    pub nostr_relays: Vec<String>,
}

impl From<BillIdentParticipant> for BillIdentParticipantFfi {
    fn from(val: BillIdentParticipant) -> Self {
        BillIdentParticipantFfi {
            t: val.t.into(),
            name: val.name.to_string(),
            node_id: val.node_id.to_string(),
            postal_address: val.postal_address.into(),
            email: val.email.map(|e| e.to_string()),
            nostr_relays: val
                .nostr_relays
                .into_iter()
                .map(|u| u.to_string())
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum PaymentStatusFfi {
    Requested(u64),
    Paid(u64),
    Rejected(u64),
    Expired(u64),
}

impl From<PaymentStatus> for PaymentStatusFfi {
    fn from(val: PaymentStatus) -> Self {
        match val {
            PaymentStatus::Requested(ts) => PaymentStatusFfi::Requested(ts.inner()),
            PaymentStatus::Paid(ts) => PaymentStatusFfi::Paid(ts.inner()),
            PaymentStatus::Rejected(ts) => PaymentStatusFfi::Rejected(ts.inner()),
            PaymentStatus::Expired(ts) => PaymentStatusFfi::Expired(ts.inner()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LightBitcreditBillFfi {
    pub id: String,
    pub drawee: LightBillIdentParticipantFfi,
    pub drawer: LightBillIdentParticipantFfi,
    pub payee: LightBillParticipantFfi,
    pub endorsee: Option<LightBillParticipantFfi>,
    pub active_notification: Option<NotificationFfi>,
    pub sum: String,
    pub currency: String,
    pub issue_date: String,
    pub time_of_drawing: u64,
    pub time_of_maturity: u64,
    pub last_block_time: u64,
}

impl From<LightBitcreditBillResult> for LightBitcreditBillFfi {
    fn from(val: LightBitcreditBillResult) -> Self {
        LightBitcreditBillFfi {
            id: val.id.to_string(),
            drawee: val.drawee.into(),
            drawer: val.drawer.into(),
            payee: val.payee.into(),
            endorsee: val.endorsee.map(|e| e.into()),
            active_notification: val.active_notification.map(|n| n.into()),
            currency: val.sum.currency().code().to_owned(),
            sum: val.sum.as_sat_string(),
            issue_date: val.issue_date.to_string(),
            time_of_drawing: val.time_of_drawing.inner(),
            time_of_maturity: val.time_of_maturity.inner(),
            last_block_time: val.last_block_time.inner(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum LightBillParticipantFfi {
    Anon(LightBillAnonParticipantFfi),
    Ident(LightBillIdentParticipantWithAddressFfi),
}

impl From<LightBillParticipant> for LightBillParticipantFfi {
    fn from(val: LightBillParticipant) -> Self {
        match val {
            LightBillParticipant::Ident(data) => LightBillParticipantFfi::Ident(data.into()),
            LightBillParticipant::Anon(data) => LightBillParticipantFfi::Anon(data.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LightBillAnonParticipantFfi {
    pub node_id: String,
}

impl From<LightBillAnonParticipant> for LightBillAnonParticipantFfi {
    fn from(val: LightBillAnonParticipant) -> Self {
        LightBillAnonParticipantFfi {
            node_id: val.node_id.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LightBillIdentParticipantFfi {
    pub t: ContactTypeFfi,
    pub name: String,
    pub node_id: String,
}

impl From<LightBillIdentParticipant> for LightBillIdentParticipantFfi {
    fn from(val: LightBillIdentParticipant) -> Self {
        LightBillIdentParticipantFfi {
            t: val.t.into(),
            name: val.name.to_string(),
            node_id: val.node_id.to_string(),
        }
    }
}

impl From<BillIdentParticipant> for LightBillIdentParticipantFfi {
    fn from(val: BillIdentParticipant) -> Self {
        LightBillIdentParticipantFfi {
            t: val.t.into(),
            name: val.name.to_string(),
            node_id: val.node_id.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LightBillSignatoryFfi {
    pub name: Option<String>,
    pub node_id: String,
}

impl From<LightBillSignatory> for LightBillSignatoryFfi {
    fn from(val: LightBillSignatory) -> Self {
        Self {
            name: val.name.map(|n| n.to_string()),
            node_id: val.node_id.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LightBillIdentParticipantWithAddressFfi {
    pub t: ContactTypeFfi,
    pub name: String,
    pub node_id: String,
    pub postal_address: PostalAddressFfi,
}

impl From<LightBillIdentParticipantWithAddress> for LightBillIdentParticipantWithAddressFfi {
    fn from(val: LightBillIdentParticipantWithAddress) -> Self {
        LightBillIdentParticipantWithAddressFfi {
            t: val.t.into(),
            name: val.name.to_string(),
            node_id: val.node_id.to_string(),
            postal_address: val.postal_address.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BillHistoryResponse {
    pub blocks: Vec<BillHistoryBlockFfi>,
}

impl From<BillHistory> for BillHistoryResponse {
    fn from(value: BillHistory) -> Self {
        Self {
            blocks: value.blocks.into_iter().map(|b| b.into()).collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BillHistoryBlockFfi {
    pub block_id: u64,
    pub block_type: BillOpCodeFfi,
    pub pay_to_the_order_of: Option<LightBillParticipantFfi>,
    pub payment_data: Option<BillHistoryBlockPaymentDataFfi>,
    pub request_deadline: Option<u64>,
    pub signed: LightSignedByFfi,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddressFfi>,
}

impl From<BillHistoryBlock> for BillHistoryBlockFfi {
    fn from(value: BillHistoryBlock) -> Self {
        Self {
            block_id: value.block_id.inner(),
            block_type: value.block_type.into(),
            pay_to_the_order_of: value
                .pay_to_the_order_of
                .map(|pttoo| LightBillParticipant::from(pttoo).into()),
            payment_data: value.payment_data.map(|pd| pd.into()),
            request_deadline: value.request_deadline.map(|t| t.inner()),
            signed: value.signed.into(),
            signing_timestamp: value.signing_timestamp.inner(),
            signing_address: value.signing_address.map(|sa| sa.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BillHistoryBlockPaymentDataFfi {
    pub currency: String,
    pub sum: String,
    pub payment_address: String,
}

impl From<BillHistoryBlockPaymentData> for BillHistoryBlockPaymentDataFfi {
    fn from(value: BillHistoryBlockPaymentData) -> Self {
        Self {
            currency: value.sum.currency().code().to_owned(),
            sum: value.sum.as_sat_string(),
            payment_address: value.payment_address.assume_checked().to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LightBillsResponse {
    pub bills: Vec<LightBitcreditBillFfi>,
}

#[derive(Debug, Clone)]
pub struct EndorsementsResponse {
    pub endorsements: Vec<EndorsementFfi>,
}

#[derive(Debug, Clone)]
pub struct EndorsementFfi {
    pub pay_to_the_order_of: LightBillParticipantFfi,
    pub signed: LightSignedByFfi,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddressFfi>,
}

impl From<Endorsement> for EndorsementFfi {
    fn from(val: Endorsement) -> Self {
        EndorsementFfi {
            pay_to_the_order_of: val.pay_to_the_order_of.into(),
            signed: val.signed.into(),
            signing_timestamp: val.signing_timestamp.inner(),
            signing_address: val.signing_address.map(|s| s.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PastEndorseesResponse {
    pub past_endorsees: Vec<PastEndorseeFfi>,
}

#[derive(Debug, Clone)]
pub struct PastEndorseeFfi {
    pub pay_to_the_order_of: LightBillIdentParticipantFfi,
    pub signed: LightSignedByFfi,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddressFfi>,
}

impl From<PastEndorsee> for PastEndorseeFfi {
    fn from(val: PastEndorsee) -> Self {
        PastEndorseeFfi {
            pay_to_the_order_of: val.pay_to_the_order_of.into(),
            signed: val.signed.into(),
            signing_timestamp: val.signing_timestamp.inner(),
            signing_address: val.signing_address.map(|s| s.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LightSignedByFfi {
    pub data: LightBillParticipantFfi,
    pub signatory: Option<LightBillSignatoryFfi>,
}

impl From<LightSignedBy> for LightSignedByFfi {
    fn from(val: LightSignedBy) -> Self {
        LightSignedByFfi {
            data: val.data.into(),
            signatory: val.signatory.map(|s| s.into()),
        }
    }
}

impl From<SignedBy> for LightSignedByFfi {
    fn from(val: SignedBy) -> Self {
        LightSignedByFfi {
            data: LightBillParticipant::from(val.data).into(),
            signatory: val.signatory.map(|s| LightBillSignatoryFfi {
                name: s.name.map(|n| n.to_string()),
                node_id: s.node_id.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PastPaymentsResponse {
    pub past_payments: Vec<PastPaymentResultFfi>,
}

#[derive(Debug, Clone)]
pub enum PastPaymentResultFfi {
    Sell(PastPaymentDataSellFfi),
    Payment(PastPaymentDataPaymentFfi),
    Recourse(PastPaymentDataRecourseFfi),
}

impl From<PastPaymentResult> for PastPaymentResultFfi {
    fn from(val: PastPaymentResult) -> Self {
        match val {
            PastPaymentResult::Sell(state) => PastPaymentResultFfi::Sell(state.into()),
            PastPaymentResult::Payment(state) => PastPaymentResultFfi::Payment(state.into()),
            PastPaymentResult::Recourse(state) => PastPaymentResultFfi::Recourse(state.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PastPaymentDataSellFfi {
    pub time_of_request: u64,
    pub buyer: BillParticipantFfi,
    pub seller: BillParticipantFfi,
    pub currency: String,
    pub sum: String,
    pub address_to_pay: String,
    pub private_descriptor_to_spend: Option<String>,
    pub status: PaymentStatusFfi,
}

impl From<PastPaymentDataSell> for PastPaymentDataSellFfi {
    fn from(val: PastPaymentDataSell) -> Self {
        PastPaymentDataSellFfi {
            time_of_request: val.time_of_request.inner(),
            buyer: val.buyer.into(),
            seller: val.seller.into(),
            currency: val.sum.currency().code().to_owned(),
            sum: val.sum.as_sat_string(),
            address_to_pay: val.address_to_pay.assume_checked().to_string(),
            private_descriptor_to_spend: val.private_descriptor_to_spend.map(|d| d.to_string()),
            status: val.status.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PastPaymentDataPaymentFfi {
    pub time_of_request: u64,
    pub payer: BillIdentParticipantFfi,
    pub payee: BillParticipantFfi,
    pub currency: String,
    pub sum: String,
    pub address_to_pay: String,
    pub private_descriptor_to_spend: Option<String>,
    pub status: PaymentStatusFfi,
}
impl From<PastPaymentDataPayment> for PastPaymentDataPaymentFfi {
    fn from(val: PastPaymentDataPayment) -> Self {
        PastPaymentDataPaymentFfi {
            time_of_request: val.time_of_request.inner(),
            payer: val.payer.into(),
            payee: val.payee.into(),
            currency: val.sum.currency().code().to_owned(),
            sum: val.sum.as_sat_string(),
            address_to_pay: val.address_to_pay.assume_checked().to_string(),
            private_descriptor_to_spend: val.private_descriptor_to_spend.map(|d| d.to_string()),
            status: val.status.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PastPaymentDataRecourseFfi {
    pub time_of_request: u64,
    pub recourser: BillParticipantFfi,
    pub recoursee: BillIdentParticipantFfi,
    pub currency: String,
    pub sum: String,
    pub address_to_pay: String,
    pub private_descriptor_to_spend: Option<String>,
    pub status: PaymentStatusFfi,
}

impl From<PastPaymentDataRecourse> for PastPaymentDataRecourseFfi {
    fn from(val: PastPaymentDataRecourse) -> Self {
        PastPaymentDataRecourseFfi {
            time_of_request: val.time_of_request.inner(),
            recourser: val.recourser.into(),
            recoursee: val.recoursee.into(),
            currency: val.sum.currency().code().to_owned(),
            sum: val.sum.as_sat_string(),
            address_to_pay: val.address_to_pay.assume_checked().to_string(),
            private_descriptor_to_spend: val.private_descriptor_to_spend.map(|d| d.to_string()),
            status: val.status.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShareBillWithCourtPayload {
    pub bill_id: String,
    pub court_node_id: String,
}

#[derive(Debug, Copy, Clone)]
pub enum BillOpCodeFfi {
    Issue,
    Accept,
    Endorse,
    RequestToAccept,
    RequestToPay,
    OfferToSell,
    Sell,
    Mint,
    RejectToAccept,
    RejectToPay,
    RejectToBuy,
    RejectToPayRecourse,
    RequestRecourse,
    Recourse,
}

impl From<BillOpCode> for BillOpCodeFfi {
    fn from(value: BillOpCode) -> Self {
        match value {
            BillOpCode::Issue => BillOpCodeFfi::Issue,
            BillOpCode::Accept => BillOpCodeFfi::Accept,
            BillOpCode::Endorse => BillOpCodeFfi::Endorse,
            BillOpCode::RequestToAccept => BillOpCodeFfi::RequestToAccept,
            BillOpCode::RequestToPay => BillOpCodeFfi::RequestToPay,
            BillOpCode::OfferToSell => BillOpCodeFfi::OfferToSell,
            BillOpCode::Sell => BillOpCodeFfi::Sell,
            BillOpCode::Mint => BillOpCodeFfi::Mint,
            BillOpCode::RejectToAccept => BillOpCodeFfi::RejectToAccept,
            BillOpCode::RejectToPay => BillOpCodeFfi::RejectToPay,
            BillOpCode::RejectToBuy => BillOpCodeFfi::RejectToBuy,
            BillOpCode::RejectToPayRecourse => BillOpCodeFfi::RejectToPayRecourse,
            BillOpCode::RequestRecourse => BillOpCodeFfi::RequestRecourse,
            BillOpCode::Recourse => BillOpCodeFfi::Recourse,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BillsSearchFilterPayload {
    pub filter: BillsSearchFilter,
}

#[derive(Debug, Clone)]
pub struct DateRange {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone)]
pub struct BillsSearchFilter {
    pub search_term: Option<String>,
    pub date_range: Option<DateRange>,
    pub role: BillsFilterRoleFfi,
    pub participants: Vec<String>,
    #[allow(unused)]
    pub currency: String,
}
