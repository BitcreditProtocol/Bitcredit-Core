use bcr_ebill_api::{
    BillOpCode,
    data::{
        NodeId,
        bill::{
            BillAcceptanceStatus, BillCallerActions, BillCallerBillAction, BillCombinedBitcoinKey,
            BillCurrentWaitingState, BillData, BillHistory, BillHistoryBlock, BillId,
            BillMintStatus, BillParticipants, BillPaymentStatus, BillRecourseStatus,
            BillSellStatus, BillStatus, BillWaitingForPaymentState, BillWaitingForRecourseState,
            BillWaitingForSellState, BillWaitingStatePaymentData, BillsFilterRole,
            BitcreditBillResult, Endorsement, LightBitcreditBillResult, LightSignedBy,
            PastEndorsee, PastPaymentDataPayment, PastPaymentDataRecourse, PastPaymentDataSell,
            PastPaymentResult, PastPaymentStatus,
        },
        city::City,
        contact::{
            BillAnonParticipant, BillIdentParticipant, BillParticipant, LightBillAnonParticipant,
            LightBillIdentParticipant, LightBillIdentParticipantWithAddress, LightBillParticipant,
        },
        country::Country,
        date::Date,
        email::Email,
        name::Name,
    },
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

use super::{FileWeb, PostalAddressWeb, contact::ContactTypeWeb, notification::NotificationWeb};

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct BillIdResponse {
    #[tsify(type = "string")]
    pub id: BillId,
}

#[derive(Tsify, Debug, Clone, Deserialize)]
#[tsify(from_wasm_abi)]
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

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct BillNumbersToWordsForSum {
    pub sum: u64,
    pub sum_as_words: String,
}

#[derive(Tsify, Debug, Clone, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct EndorseBitcreditBillPayload {
    pub endorsee: String,
    #[tsify(type = "string")]
    pub bill_id: BillId,
}

#[derive(Tsify, Debug, Deserialize, Clone)]
#[tsify(from_wasm_abi)]
pub struct RequestToMintBitcreditBillPayload {
    pub mint_node: String,
    #[tsify(type = "string")]
    pub bill_id: BillId,
}

#[derive(Tsify, Debug, Clone, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct OfferToSellBitcreditBillPayload {
    #[tsify(type = "string")]
    pub buyer: NodeId,
    #[tsify(type = "string")]
    pub bill_id: BillId,
    pub sum: String,
    #[allow(unused)]
    pub currency: String,
    pub buying_deadline: String,
}

#[derive(Tsify, Debug, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct RequestToPayBitcreditBillPayload {
    #[tsify(type = "string")]
    pub bill_id: BillId,
    #[allow(unused)]
    pub currency: String,
    pub payment_deadline: String,
}

#[derive(Tsify, Debug, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct RequestRecourseForPaymentPayload {
    #[tsify(type = "string")]
    pub bill_id: BillId,
    #[tsify(type = "string")]
    pub recoursee: NodeId,
    #[allow(unused)]
    pub currency: String,
    pub sum: String,
    pub recourse_deadline: String,
}

#[derive(Tsify, Debug, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct RequestRecourseForAcceptancePayload {
    #[tsify(type = "string")]
    pub bill_id: BillId,
    #[tsify(type = "string")]
    pub recoursee: NodeId,
    pub recourse_deadline: String,
}

#[derive(Tsify, Debug, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct AcceptBitcreditBillPayload {
    #[tsify(type = "string")]
    pub bill_id: BillId,
}

#[derive(Tsify, Debug, Clone, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct RequestToAcceptBitcreditBillPayload {
    #[tsify(type = "string")]
    pub bill_id: BillId,
    pub acceptance_deadline: String,
}

#[derive(Tsify, Debug, Clone, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct RejectActionBillPayload {
    #[tsify(type = "string")]
    pub bill_id: BillId,
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct BillCombinedBitcoinKeyWeb {
    pub private_descriptor: String,
}

#[derive(Tsify, Debug, Clone, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct ResyncBillPayload {
    #[tsify(type = "string")]
    pub bill_id: BillId,
}

impl From<BillCombinedBitcoinKey> for BillCombinedBitcoinKeyWeb {
    fn from(val: BillCombinedBitcoinKey) -> Self {
        BillCombinedBitcoinKeyWeb {
            private_descriptor: val.private_descriptor,
        }
    }
}

#[derive(Tsify, Debug, Clone, Copy, Deserialize)]
#[tsify(from_wasm_abi)]
pub enum BillsFilterRoleWeb {
    All,
    Payer,
    Payee,
    Contingent,
}

impl From<BillsFilterRoleWeb> for BillsFilterRole {
    fn from(value: BillsFilterRoleWeb) -> Self {
        match value {
            BillsFilterRoleWeb::All => BillsFilterRole::All,
            BillsFilterRoleWeb::Payer => BillsFilterRole::Payer,
            BillsFilterRoleWeb::Payee => BillsFilterRole::Payee,
            BillsFilterRoleWeb::Contingent => BillsFilterRole::Contingent,
        }
    }
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct PastEndorseeWeb {
    pub pay_to_the_order_of: LightBillIdentParticipantWeb,
    pub signed: LightSignedByWeb,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddressWeb>,
}

impl From<PastEndorsee> for PastEndorseeWeb {
    fn from(val: PastEndorsee) -> Self {
        PastEndorseeWeb {
            pay_to_the_order_of: val.pay_to_the_order_of.into(),
            signed: val.signed.into(),
            signing_timestamp: val.signing_timestamp,
            signing_address: val.signing_address.map(|s| s.into()),
        }
    }
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct LightSignedByWeb {
    pub data: LightBillParticipantWeb,
    pub signatory: Option<LightBillIdentParticipantWeb>,
}

impl From<LightSignedBy> for LightSignedByWeb {
    fn from(val: LightSignedBy) -> Self {
        LightSignedByWeb {
            data: val.data.into(),
            signatory: val.signatory.map(|s| s.into()),
        }
    }
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct EndorsementWeb {
    pub pay_to_the_order_of: LightBillParticipantWeb,
    pub signed: LightSignedByWeb,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddressWeb>,
}

impl From<Endorsement> for EndorsementWeb {
    fn from(val: Endorsement) -> Self {
        EndorsementWeb {
            pay_to_the_order_of: val.pay_to_the_order_of.into(),
            signed: val.signed.into(),
            signing_timestamp: val.signing_timestamp,
            signing_address: val.signing_address.map(|s| s.into()),
        }
    }
}

#[derive(Tsify, Debug, Clone, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct BillsSearchFilterPayload {
    pub filter: BillsSearchFilter,
}

#[derive(Tsify, Debug, Clone, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct DateRange {
    pub from: String,
    pub to: String,
}

#[derive(Tsify, Debug, Clone, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct BillsSearchFilter {
    pub search_term: Option<String>,
    pub date_range: Option<DateRange>,
    pub role: BillsFilterRoleWeb,
    #[allow(unused)]
    pub currency: String,
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct BillsResponse {
    pub bills: Vec<BitcreditBillWeb>,
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct BillHistoryResponse {
    pub blocks: Vec<BillHistoryBlockWeb>,
}

impl From<BillHistory> for BillHistoryResponse {
    fn from(value: BillHistory) -> Self {
        Self {
            blocks: value.blocks.into_iter().map(|b| b.into()).collect(),
        }
    }
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct BillHistoryBlockWeb {
    pub block_id: u64,
    pub block_type: BillOpCodeWeb,
    pub pay_to_the_order_of: Option<LightBillParticipantWeb>,
    pub signed: LightSignedByWeb,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddressWeb>,
}

impl From<BillHistoryBlock> for BillHistoryBlockWeb {
    fn from(value: BillHistoryBlock) -> Self {
        Self {
            block_id: value.block_id,
            block_type: value.block_type.into(),
            pay_to_the_order_of: value.pay_to_the_order_of.map(|pttoo| pttoo.into()),
            signed: value.signed.into(),
            signing_timestamp: value.signing_timestamp,
            signing_address: value.signing_address.map(|sa| sa.into()),
        }
    }
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct LightBillsResponse {
    pub bills: Vec<LightBitcreditBillWeb>,
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct EndorsementsResponse {
    pub endorsements: Vec<EndorsementWeb>,
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct PastEndorseesResponse {
    pub past_endorsees: Vec<PastEndorseeWeb>,
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct PastPaymentsResponse {
    pub past_payments: Vec<PastPaymentResultWeb>,
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub enum PastPaymentResultWeb {
    Sell(PastPaymentDataSellWeb),
    Payment(PastPaymentDataPaymentWeb),
    Recourse(PastPaymentDataRecourseWeb),
}

impl From<PastPaymentResult> for PastPaymentResultWeb {
    fn from(val: PastPaymentResult) -> Self {
        match val {
            PastPaymentResult::Sell(state) => PastPaymentResultWeb::Sell(state.into()),
            PastPaymentResult::Payment(state) => PastPaymentResultWeb::Payment(state.into()),
            PastPaymentResult::Recourse(state) => PastPaymentResultWeb::Recourse(state.into()),
        }
    }
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub enum PastPaymentStatusWeb {
    Paid(u64),
    Rejected(u64),
    Expired(u64),
}

impl From<PastPaymentStatus> for PastPaymentStatusWeb {
    fn from(val: PastPaymentStatus) -> Self {
        match val {
            PastPaymentStatus::Paid(ts) => PastPaymentStatusWeb::Paid(ts),
            PastPaymentStatus::Rejected(ts) => PastPaymentStatusWeb::Rejected(ts),
            PastPaymentStatus::Expired(ts) => PastPaymentStatusWeb::Expired(ts),
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct PastPaymentDataSellWeb {
    pub time_of_request: u64,
    pub buyer: BillParticipantWeb,
    pub seller: BillParticipantWeb,
    pub currency: String,
    pub sum: String,
    pub link_to_pay: String,
    pub address_to_pay: String,
    pub private_descriptor_to_spend: String,
    pub mempool_link_for_address_to_pay: String,
    pub status: PastPaymentStatusWeb,
}

impl From<PastPaymentDataSell> for PastPaymentDataSellWeb {
    fn from(val: PastPaymentDataSell) -> Self {
        PastPaymentDataSellWeb {
            time_of_request: val.time_of_request,
            buyer: val.buyer.into(),
            seller: val.seller.into(),
            currency: val.sum.currency().code().to_owned(),
            sum: val.sum.as_sat_string(),
            link_to_pay: val.link_to_pay,
            address_to_pay: val.address_to_pay,
            private_descriptor_to_spend: val.private_descriptor_to_spend,
            mempool_link_for_address_to_pay: val.mempool_link_for_address_to_pay,
            status: val.status.into(),
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct PastPaymentDataPaymentWeb {
    pub time_of_request: u64,
    pub payer: BillIdentParticipantWeb,
    pub payee: BillParticipantWeb,
    pub currency: String,
    pub sum: String,
    pub link_to_pay: String,
    pub address_to_pay: String,
    pub private_descriptor_to_spend: String,
    pub mempool_link_for_address_to_pay: String,
    pub status: PastPaymentStatusWeb,
}
impl From<PastPaymentDataPayment> for PastPaymentDataPaymentWeb {
    fn from(val: PastPaymentDataPayment) -> Self {
        PastPaymentDataPaymentWeb {
            time_of_request: val.time_of_request,
            payer: val.payer.into(),
            payee: val.payee.into(),
            currency: val.sum.currency().code().to_owned(),
            sum: val.sum.as_sat_string(),
            link_to_pay: val.link_to_pay,
            address_to_pay: val.address_to_pay,
            private_descriptor_to_spend: val.private_descriptor_to_spend,
            mempool_link_for_address_to_pay: val.mempool_link_for_address_to_pay,
            status: val.status.into(),
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct PastPaymentDataRecourseWeb {
    pub time_of_request: u64,
    pub recourser: BillParticipantWeb,
    pub recoursee: BillIdentParticipantWeb,
    pub currency: String,
    pub sum: String,
    pub link_to_pay: String,
    pub address_to_pay: String,
    pub private_descriptor_to_spend: String,
    pub mempool_link_for_address_to_pay: String,
    pub status: PastPaymentStatusWeb,
}

impl From<PastPaymentDataRecourse> for PastPaymentDataRecourseWeb {
    fn from(val: PastPaymentDataRecourse) -> Self {
        PastPaymentDataRecourseWeb {
            time_of_request: val.time_of_request,
            recourser: val.recourser.into(),
            recoursee: val.recoursee.into(),
            currency: val.sum.currency().code().to_owned(),
            sum: val.sum.as_sat_string(),
            link_to_pay: val.link_to_pay,
            address_to_pay: val.address_to_pay,
            private_descriptor_to_spend: val.private_descriptor_to_spend,
            mempool_link_for_address_to_pay: val.mempool_link_for_address_to_pay,
            status: val.status.into(),
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct BitcreditBillWeb {
    #[tsify(type = "string")]
    pub id: BillId,
    pub participants: BillParticipantsWeb,
    pub data: BillDataWeb,
    pub status: BillStatusWeb,
    pub current_waiting_state: Option<BillCurrentWaitingStateWeb>,
    pub actions: BillCallerActionsWeb,
}

impl From<BitcreditBillResult> for BitcreditBillWeb {
    fn from(val: BitcreditBillResult) -> Self {
        BitcreditBillWeb {
            id: val.id,
            participants: val.participants.into(),
            data: val.data.into(),
            status: val.status.into(),
            current_waiting_state: val.current_waiting_state.map(|cws| cws.into()),
            actions: val.actions.into(),
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub enum BillCurrentWaitingStateWeb {
    Sell(BillWaitingForSellStateWeb),
    Payment(BillWaitingForPaymentStateWeb),
    Recourse(BillWaitingForRecourseStateWeb),
}

impl From<BillCurrentWaitingState> for BillCurrentWaitingStateWeb {
    fn from(val: BillCurrentWaitingState) -> Self {
        match val {
            BillCurrentWaitingState::Sell(state) => BillCurrentWaitingStateWeb::Sell(state.into()),
            BillCurrentWaitingState::Payment(state) => {
                BillCurrentWaitingStateWeb::Payment(state.into())
            }
            BillCurrentWaitingState::Recourse(state) => {
                BillCurrentWaitingStateWeb::Recourse(state.into())
            }
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct BillWaitingStatePaymentDataWeb {
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

impl From<BillWaitingStatePaymentData> for BillWaitingStatePaymentDataWeb {
    fn from(val: BillWaitingStatePaymentData) -> Self {
        BillWaitingStatePaymentDataWeb {
            time_of_request: val.time_of_request,
            currency: val.sum.currency().code().to_owned(),
            sum: val.sum.as_sat_string(),
            link_to_pay: val.link_to_pay,
            address_to_pay: val.address_to_pay,
            mempool_link_for_address_to_pay: val.mempool_link_for_address_to_pay,
            tx_id: val.tx_id,
            in_mempool: val.in_mempool,
            confirmations: val.confirmations,
            payment_deadline: val.payment_deadline,
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct BillWaitingForSellStateWeb {
    pub buyer: BillParticipantWeb,
    pub seller: BillParticipantWeb,
    pub payment_data: BillWaitingStatePaymentDataWeb,
}

impl From<BillWaitingForSellState> for BillWaitingForSellStateWeb {
    fn from(val: BillWaitingForSellState) -> Self {
        BillWaitingForSellStateWeb {
            buyer: val.buyer.into(),
            seller: val.seller.into(),
            payment_data: val.payment_data.into(),
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct BillWaitingForPaymentStateWeb {
    pub payer: BillIdentParticipantWeb,
    pub payee: BillParticipantWeb,
    pub payment_data: BillWaitingStatePaymentDataWeb,
}

impl From<BillWaitingForPaymentState> for BillWaitingForPaymentStateWeb {
    fn from(val: BillWaitingForPaymentState) -> Self {
        BillWaitingForPaymentStateWeb {
            payer: val.payer.into(),
            payee: val.payee.into(),
            payment_data: val.payment_data.into(),
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct BillWaitingForRecourseStateWeb {
    pub recourser: BillParticipantWeb,
    pub recoursee: BillIdentParticipantWeb,
    pub payment_data: BillWaitingStatePaymentDataWeb,
}
impl From<BillWaitingForRecourseState> for BillWaitingForRecourseStateWeb {
    fn from(val: BillWaitingForRecourseState) -> Self {
        BillWaitingForRecourseStateWeb {
            recourser: val.recourser.into(),
            recoursee: val.recoursee.into(),
            payment_data: val.payment_data.into(),
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct BillStatusWeb {
    pub acceptance: BillAcceptanceStatusWeb,
    pub payment: BillPaymentStatusWeb,
    pub sell: BillSellStatusWeb,
    pub recourse: BillRecourseStatusWeb,
    pub mint: BillMintStatusWeb,
    pub redeemed_funds_available: bool,
    pub has_requested_funds: bool,
    pub last_block_time: u64,
}

impl From<BillStatus> for BillStatusWeb {
    fn from(val: BillStatus) -> Self {
        BillStatusWeb {
            acceptance: val.acceptance.into(),
            payment: val.payment.into(),
            sell: val.sell.into(),
            recourse: val.recourse.into(),
            mint: val.mint.into(),
            redeemed_funds_available: val.redeemed_funds_available,
            has_requested_funds: val.has_requested_funds,
            last_block_time: val.last_block_time,
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct BillAcceptanceStatusWeb {
    pub time_of_request_to_accept: Option<u64>,
    pub requested_to_accept: bool,
    pub accepted: bool,
    pub request_to_accept_timed_out: bool,
    pub rejected_to_accept: bool,
    pub acceptance_deadline_timestamp: Option<u64>,
}

impl From<BillAcceptanceStatus> for BillAcceptanceStatusWeb {
    fn from(val: BillAcceptanceStatus) -> Self {
        BillAcceptanceStatusWeb {
            time_of_request_to_accept: val.time_of_request_to_accept,
            requested_to_accept: val.requested_to_accept,
            accepted: val.accepted,
            request_to_accept_timed_out: val.request_to_accept_timed_out,
            rejected_to_accept: val.rejected_to_accept,
            acceptance_deadline_timestamp: val.acceptance_deadline_timestamp,
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct BillPaymentStatusWeb {
    pub time_of_request_to_pay: Option<u64>,
    pub requested_to_pay: bool,
    pub paid: bool,
    pub request_to_pay_timed_out: bool,
    pub rejected_to_pay: bool,
    pub payment_deadline_timestamp: Option<u64>,
}
impl From<BillPaymentStatus> for BillPaymentStatusWeb {
    fn from(val: BillPaymentStatus) -> Self {
        BillPaymentStatusWeb {
            time_of_request_to_pay: val.time_of_request_to_pay,
            requested_to_pay: val.requested_to_pay,
            paid: val.paid,
            request_to_pay_timed_out: val.request_to_pay_timed_out,
            rejected_to_pay: val.rejected_to_pay,
            payment_deadline_timestamp: val.payment_deadline_timestamp,
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct BillSellStatusWeb {
    pub time_of_last_offer_to_sell: Option<u64>,
    pub sold: bool,
    pub offered_to_sell: bool,
    pub offer_to_sell_timed_out: bool,
    pub rejected_offer_to_sell: bool,
    pub buying_deadline_timestamp: Option<u64>,
}
impl From<BillSellStatus> for BillSellStatusWeb {
    fn from(val: BillSellStatus) -> Self {
        BillSellStatusWeb {
            time_of_last_offer_to_sell: val.time_of_last_offer_to_sell,
            sold: val.sold,
            offered_to_sell: val.offered_to_sell,
            offer_to_sell_timed_out: val.offer_to_sell_timed_out,
            rejected_offer_to_sell: val.rejected_offer_to_sell,
            buying_deadline_timestamp: val.buying_deadline_timestamp,
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct BillRecourseStatusWeb {
    pub time_of_last_request_to_recourse: Option<u64>,
    pub recoursed: bool,
    pub requested_to_recourse: bool,
    pub request_to_recourse_timed_out: bool,
    pub rejected_request_to_recourse: bool,
    pub recourse_deadline_timestamp: Option<u64>,
}

impl From<BillRecourseStatus> for BillRecourseStatusWeb {
    fn from(val: BillRecourseStatus) -> Self {
        BillRecourseStatusWeb {
            time_of_last_request_to_recourse: val.time_of_last_request_to_recourse,
            recoursed: val.recoursed,
            requested_to_recourse: val.requested_to_recourse,
            request_to_recourse_timed_out: val.request_to_recourse_timed_out,
            rejected_request_to_recourse: val.rejected_request_to_recourse,
            recourse_deadline_timestamp: val.recourse_deadline_timestamp,
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct BillMintStatusWeb {
    pub has_mint_requests: bool,
}

impl From<BillMintStatus> for BillMintStatusWeb {
    fn from(val: BillMintStatus) -> Self {
        BillMintStatusWeb {
            has_mint_requests: val.has_mint_requests,
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct BillDataWeb {
    pub time_of_drawing: u64,
    #[tsify(type = "string")]
    pub issue_date: Date,
    pub time_of_maturity: u64,
    #[tsify(type = "string")]
    pub maturity_date: Date,
    #[tsify(type = "string")]
    pub country_of_issuing: Country,
    #[tsify(type = "string")]
    pub city_of_issuing: City,
    #[tsify(type = "string")]
    pub country_of_payment: Country,
    #[tsify(type = "string")]
    pub city_of_payment: City,
    pub currency: String,
    pub sum: String,
    pub files: Vec<FileWeb>,
    pub active_notification: Option<NotificationWeb>,
}

impl From<BillData> for BillDataWeb {
    fn from(val: BillData) -> Self {
        BillDataWeb {
            time_of_drawing: val.time_of_drawing,
            issue_date: val.issue_date,
            time_of_maturity: val.time_of_maturity,
            maturity_date: val.maturity_date,
            country_of_issuing: val.country_of_issuing,
            city_of_issuing: val.city_of_issuing,
            country_of_payment: val.country_of_payment,
            city_of_payment: val.city_of_payment,
            currency: val.sum.currency().code().to_owned(),
            sum: val.sum.as_sat_string(),
            files: val.files.into_iter().map(|f| f.into()).collect(),
            active_notification: val.active_notification.map(|an| an.into()),
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct BillParticipantsWeb {
    pub drawee: BillIdentParticipantWeb,
    pub drawer: BillIdentParticipantWeb,
    pub payee: BillParticipantWeb,
    pub endorsee: Option<BillParticipantWeb>,
    pub endorsements_count: u64,
    #[tsify(type = "string[]")]
    pub all_participant_node_ids: Vec<NodeId>,
}

impl From<BillParticipants> for BillParticipantsWeb {
    fn from(val: BillParticipants) -> Self {
        BillParticipantsWeb {
            drawee: val.drawee.into(),
            drawer: val.drawer.into(),
            payee: val.payee.into(),
            endorsee: val.endorsee.map(|e| e.into()),
            endorsements_count: val.endorsements_count,
            all_participant_node_ids: val.all_participant_node_ids,
        }
    }
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct BillCallerActionsWeb {
    pub bill_actions: Vec<BillCallerBillActionWeb>,
}

impl From<BillCallerActions> for BillCallerActionsWeb {
    fn from(value: BillCallerActions) -> Self {
        Self {
            bill_actions: value.bill_actions.into_iter().map(|ba| ba.into()).collect(),
        }
    }
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub enum BillCallerBillActionWeb {
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

impl From<BillCallerBillAction> for BillCallerBillActionWeb {
    fn from(value: BillCallerBillAction) -> Self {
        match value {
            BillCallerBillAction::RequestAcceptance => BillCallerBillActionWeb::RequestAcceptance,
            BillCallerBillAction::Accept => BillCallerBillActionWeb::Accept,
            BillCallerBillAction::RequestToPay => BillCallerBillActionWeb::RequestToPay,
            BillCallerBillAction::OfferToSell => BillCallerBillActionWeb::OfferToSell,
            BillCallerBillAction::Sell => BillCallerBillActionWeb::Sell,
            BillCallerBillAction::Endorse => BillCallerBillActionWeb::Endorse,
            BillCallerBillAction::RequestRecourseForAcceptance => {
                BillCallerBillActionWeb::RequestRecourseForAcceptance
            }
            BillCallerBillAction::RequestRecourseForPayment => {
                BillCallerBillActionWeb::RequestRecourseForPayment
            }
            BillCallerBillAction::Recourse => BillCallerBillActionWeb::Recourse,
            BillCallerBillAction::Mint => BillCallerBillActionWeb::Mint,
            BillCallerBillAction::RejectAcceptance => BillCallerBillActionWeb::RejectAcceptance,
            BillCallerBillAction::RejectPayment => BillCallerBillActionWeb::RejectPayment,
            BillCallerBillAction::RejectBuying => BillCallerBillActionWeb::RejectBuying,
            BillCallerBillAction::RejectPaymentForRecourse => {
                BillCallerBillActionWeb::RejectPaymentForRecourse
            }
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct LightBitcreditBillWeb {
    #[tsify(type = "string")]
    pub id: BillId,
    pub drawee: LightBillIdentParticipantWeb,
    pub drawer: LightBillIdentParticipantWeb,
    pub payee: LightBillParticipantWeb,
    pub endorsee: Option<LightBillParticipantWeb>,
    pub active_notification: Option<NotificationWeb>,
    pub sum: String,
    pub currency: String,
    #[tsify(type = "string")]
    pub issue_date: Date,
    pub time_of_drawing: u64,
    pub time_of_maturity: u64,
    pub last_block_time: u64,
}

impl From<LightBitcreditBillResult> for LightBitcreditBillWeb {
    fn from(val: LightBitcreditBillResult) -> Self {
        LightBitcreditBillWeb {
            id: val.id,
            drawee: val.drawee.into(),
            drawer: val.drawer.into(),
            payee: val.payee.into(),
            endorsee: val.endorsee.map(|e| e.into()),
            active_notification: val.active_notification.map(|n| n.into()),
            currency: val.sum.currency().code().to_owned(),
            sum: val.sum.as_sat_string(),
            issue_date: val.issue_date,
            time_of_drawing: val.time_of_drawing,
            time_of_maturity: val.time_of_maturity,
            last_block_time: val.last_block_time,
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub enum BillParticipantWeb {
    Anon(BillAnonParticipantWeb),
    Ident(BillIdentParticipantWeb),
}

impl From<BillParticipant> for BillParticipantWeb {
    fn from(val: BillParticipant) -> Self {
        match val {
            BillParticipant::Ident(data) => BillParticipantWeb::Ident(data.into()),
            BillParticipant::Anon(data) => BillParticipantWeb::Anon(data.into()),
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct BillAnonParticipantWeb {
    #[tsify(type = "string")]
    pub node_id: NodeId,
    #[tsify(type = "string | undefined")]
    pub email: Option<Email>,
    #[tsify(type = "string[]")]
    pub nostr_relays: Vec<url::Url>,
}

impl From<BillAnonParticipant> for BillAnonParticipantWeb {
    fn from(val: BillAnonParticipant) -> Self {
        BillAnonParticipantWeb {
            node_id: val.node_id,
            email: val.email,
            nostr_relays: val.nostr_relays,
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct BillIdentParticipantWeb {
    pub t: ContactTypeWeb,
    #[tsify(type = "string")]
    pub node_id: NodeId,
    #[tsify(type = "string")]
    pub name: Name,
    pub postal_address: PostalAddressWeb,
    #[tsify(type = "string | undefined")]
    pub email: Option<Email>,
    #[tsify(type = "string[]")]
    pub nostr_relays: Vec<url::Url>,
}

impl From<BillIdentParticipant> for BillIdentParticipantWeb {
    fn from(val: BillIdentParticipant) -> Self {
        BillIdentParticipantWeb {
            t: val.t.into(),
            name: val.name,
            node_id: val.node_id,
            postal_address: val.postal_address.into(),
            email: val.email,
            nostr_relays: val.nostr_relays,
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct LightBillIdentParticipantWithAddressWeb {
    pub t: ContactTypeWeb,
    #[tsify(type = "string")]
    pub name: Name,
    #[tsify(type = "string")]
    pub node_id: NodeId,
    pub postal_address: PostalAddressWeb,
}

impl From<LightBillIdentParticipantWithAddress> for LightBillIdentParticipantWithAddressWeb {
    fn from(val: LightBillIdentParticipantWithAddress) -> Self {
        LightBillIdentParticipantWithAddressWeb {
            t: val.t.into(),
            name: val.name,
            node_id: val.node_id,
            postal_address: val.postal_address.into(),
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub enum LightBillParticipantWeb {
    Anon(LightBillAnonParticipantWeb),
    Ident(LightBillIdentParticipantWithAddressWeb),
}

impl From<LightBillParticipant> for LightBillParticipantWeb {
    fn from(val: LightBillParticipant) -> Self {
        match val {
            LightBillParticipant::Ident(data) => LightBillParticipantWeb::Ident(data.into()),
            LightBillParticipant::Anon(data) => LightBillParticipantWeb::Anon(data.into()),
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct LightBillAnonParticipantWeb {
    #[tsify(type = "string")]
    pub node_id: NodeId,
}

impl From<LightBillAnonParticipant> for LightBillAnonParticipantWeb {
    fn from(val: LightBillAnonParticipant) -> Self {
        LightBillAnonParticipantWeb {
            node_id: val.node_id,
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct LightBillIdentParticipantWeb {
    pub t: ContactTypeWeb,
    #[tsify(type = "string")]
    pub name: Name,
    #[tsify(type = "string")]
    pub node_id: NodeId,
}

impl From<LightBillIdentParticipant> for LightBillIdentParticipantWeb {
    fn from(val: LightBillIdentParticipant) -> Self {
        LightBillIdentParticipantWeb {
            t: val.t.into(),
            name: val.name,
            node_id: val.node_id,
        }
    }
}

impl From<BillIdentParticipant> for LightBillIdentParticipantWeb {
    fn from(val: BillIdentParticipant) -> Self {
        LightBillIdentParticipantWeb {
            t: val.t.into(),
            name: val.name,
            node_id: val.node_id,
        }
    }
}

#[derive(Tsify, Debug, Clone, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct ShareBillWithCourtPayload {
    #[tsify(type = "string")]
    pub bill_id: BillId,
    #[tsify(type = "string")]
    pub court_node_id: NodeId,
}

#[derive(Tsify, Debug, Copy, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub enum BillOpCodeWeb {
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

impl From<BillOpCode> for BillOpCodeWeb {
    fn from(value: BillOpCode) -> Self {
        match value {
            BillOpCode::Issue => BillOpCodeWeb::Issue,
            BillOpCode::Accept => BillOpCodeWeb::Accept,
            BillOpCode::Endorse => BillOpCodeWeb::Endorse,
            BillOpCode::RequestToAccept => BillOpCodeWeb::RequestToAccept,
            BillOpCode::RequestToPay => BillOpCodeWeb::RequestToPay,
            BillOpCode::OfferToSell => BillOpCodeWeb::OfferToSell,
            BillOpCode::Sell => BillOpCodeWeb::Sell,
            BillOpCode::Mint => BillOpCodeWeb::Mint,
            BillOpCode::RejectToAccept => BillOpCodeWeb::RejectToAccept,
            BillOpCode::RejectToPay => BillOpCodeWeb::RejectToPay,
            BillOpCode::RejectToBuy => BillOpCodeWeb::RejectToBuy,
            BillOpCode::RejectToPayRecourse => BillOpCodeWeb::RejectToPayRecourse,
            BillOpCode::RequestRecourse => BillOpCodeWeb::RequestRecourse,
            BillOpCode::Recourse => BillOpCodeWeb::Recourse,
        }
    }
}
