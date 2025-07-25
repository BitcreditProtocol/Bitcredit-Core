use bcr_ebill_api::data::{
    NodeId,
    bill::{
        BillAcceptanceStatus, BillCombinedBitcoinKey, BillCurrentWaitingState, BillData, BillId,
        BillMintStatus, BillParticipants, BillPaymentStatus, BillRecourseStatus, BillSellStatus,
        BillStatus, BillWaitingForPaymentState, BillWaitingForRecourseState,
        BillWaitingForSellState, BillsFilterRole, BitcreditBillResult, Endorsement,
        LightBitcreditBillResult, LightSignedBy, PastEndorsee, PastPaymentDataPayment,
        PastPaymentDataRecourse, PastPaymentDataSell, PastPaymentResult, PastPaymentStatus,
    },
    contact::{
        BillAnonParticipant, BillIdentParticipant, BillParticipant, LightBillAnonParticipant,
        LightBillIdentParticipant, LightBillIdentParticipantWithAddress, LightBillParticipant,
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
    pub currency: String,
    pub country_of_payment: String,
    pub city_of_payment: String,
    pub language: String,
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
    pub currency: String,
}

#[derive(Tsify, Debug, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct RequestToPayBitcreditBillPayload {
    #[tsify(type = "string")]
    pub bill_id: BillId,
    pub currency: String,
}

#[derive(Tsify, Debug, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct RequestRecourseForPaymentPayload {
    #[tsify(type = "string")]
    pub bill_id: BillId,
    #[tsify(type = "string")]
    pub recoursee: NodeId,
    pub currency: String,
    pub sum: String,
}

#[derive(Tsify, Debug, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct RequestRecourseForAcceptancePayload {
    #[tsify(type = "string")]
    pub bill_id: BillId,
    #[tsify(type = "string")]
    pub recoursee: NodeId,
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
    pub pay_to_the_order_of: LightBillIdentParticipantWithAddressWeb,
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
    pub currency: String,
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct BillsResponse {
    pub bills: Vec<BitcreditBillWeb>,
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
            currency: val.currency,
            sum: val.sum,
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
            currency: val.currency,
            sum: val.sum,
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
    pub recourser: BillIdentParticipantWeb,
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
            currency: val.currency,
            sum: val.sum,
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
pub struct BitcreditEbillQuote {
    #[tsify(type = "string")]
    pub bill_id: BillId,
    pub quote_id: String,
    pub sum: u64,
    #[tsify(type = "string")]
    pub mint_node_id: NodeId,
    pub mint_url: String,
    pub accepted: bool,
    pub token: String,
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
}

impl From<BitcreditBillResult> for BitcreditBillWeb {
    fn from(val: BitcreditBillResult) -> Self {
        BitcreditBillWeb {
            id: val.id,
            participants: val.participants.into(),
            data: val.data.into(),
            status: val.status.into(),
            current_waiting_state: val.current_waiting_state.map(|cws| cws.into()),
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
pub struct BillWaitingForSellStateWeb {
    pub time_of_request: u64,
    pub buyer: BillParticipantWeb,
    pub seller: BillParticipantWeb,
    pub currency: String,
    pub sum: String,
    pub link_to_pay: String,
    pub address_to_pay: String,
    pub mempool_link_for_address_to_pay: String,
}

impl From<BillWaitingForSellState> for BillWaitingForSellStateWeb {
    fn from(val: BillWaitingForSellState) -> Self {
        BillWaitingForSellStateWeb {
            time_of_request: val.time_of_request,
            buyer: val.buyer.into(),
            seller: val.seller.into(),
            currency: val.currency,
            sum: val.sum,
            link_to_pay: val.link_to_pay,
            address_to_pay: val.address_to_pay,
            mempool_link_for_address_to_pay: val.mempool_link_for_address_to_pay,
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct BillWaitingForPaymentStateWeb {
    pub time_of_request: u64,
    pub payer: BillIdentParticipantWeb,
    pub payee: BillParticipantWeb,
    pub currency: String,
    pub sum: String,
    pub link_to_pay: String,
    pub address_to_pay: String,
    pub mempool_link_for_address_to_pay: String,
}

impl From<BillWaitingForPaymentState> for BillWaitingForPaymentStateWeb {
    fn from(val: BillWaitingForPaymentState) -> Self {
        BillWaitingForPaymentStateWeb {
            time_of_request: val.time_of_request,
            payer: val.payer.into(),
            payee: val.payee.into(),
            currency: val.currency,
            sum: val.sum,
            link_to_pay: val.link_to_pay,
            address_to_pay: val.address_to_pay,
            mempool_link_for_address_to_pay: val.mempool_link_for_address_to_pay,
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct BillWaitingForRecourseStateWeb {
    pub time_of_request: u64,
    pub recourser: BillIdentParticipantWeb,
    pub recoursee: BillIdentParticipantWeb,
    pub currency: String,
    pub sum: String,
    pub link_to_pay: String,
    pub address_to_pay: String,
    pub mempool_link_for_address_to_pay: String,
}
impl From<BillWaitingForRecourseState> for BillWaitingForRecourseStateWeb {
    fn from(val: BillWaitingForRecourseState) -> Self {
        BillWaitingForRecourseStateWeb {
            time_of_request: val.time_of_request,
            recourser: val.recourser.into(),
            recoursee: val.recoursee.into(),
            currency: val.currency,
            sum: val.sum,
            link_to_pay: val.link_to_pay,
            address_to_pay: val.address_to_pay,
            mempool_link_for_address_to_pay: val.mempool_link_for_address_to_pay,
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
}

impl From<BillAcceptanceStatus> for BillAcceptanceStatusWeb {
    fn from(val: BillAcceptanceStatus) -> Self {
        BillAcceptanceStatusWeb {
            time_of_request_to_accept: val.time_of_request_to_accept,
            requested_to_accept: val.requested_to_accept,
            accepted: val.accepted,
            request_to_accept_timed_out: val.request_to_accept_timed_out,
            rejected_to_accept: val.rejected_to_accept,
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
}
impl From<BillPaymentStatus> for BillPaymentStatusWeb {
    fn from(val: BillPaymentStatus) -> Self {
        BillPaymentStatusWeb {
            time_of_request_to_pay: val.time_of_request_to_pay,
            requested_to_pay: val.requested_to_pay,
            paid: val.paid,
            request_to_pay_timed_out: val.request_to_pay_timed_out,
            rejected_to_pay: val.rejected_to_pay,
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
}
impl From<BillSellStatus> for BillSellStatusWeb {
    fn from(val: BillSellStatus) -> Self {
        BillSellStatusWeb {
            time_of_last_offer_to_sell: val.time_of_last_offer_to_sell,
            sold: val.sold,
            offered_to_sell: val.offered_to_sell,
            offer_to_sell_timed_out: val.offer_to_sell_timed_out,
            rejected_offer_to_sell: val.rejected_offer_to_sell,
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
}

impl From<BillRecourseStatus> for BillRecourseStatusWeb {
    fn from(val: BillRecourseStatus) -> Self {
        BillRecourseStatusWeb {
            time_of_last_request_to_recourse: val.time_of_last_request_to_recourse,
            recoursed: val.recoursed,
            requested_to_recourse: val.requested_to_recourse,
            request_to_recourse_timed_out: val.request_to_recourse_timed_out,
            rejected_request_to_recourse: val.rejected_request_to_recourse,
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
    pub files: Vec<FileWeb>,
    pub active_notification: Option<NotificationWeb>,
}

impl From<BillData> for BillDataWeb {
    fn from(val: BillData) -> Self {
        BillDataWeb {
            language: val.language,
            time_of_drawing: val.time_of_drawing,
            issue_date: val.issue_date,
            time_of_maturity: val.time_of_maturity,
            maturity_date: val.maturity_date,
            country_of_issuing: val.country_of_issuing,
            city_of_issuing: val.city_of_issuing,
            country_of_payment: val.country_of_payment,
            city_of_payment: val.city_of_payment,
            currency: val.currency,
            sum: val.sum,
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
    pub issue_date: String,
    pub time_of_drawing: u64,
    pub time_of_maturity: u64,
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
            sum: val.sum,
            currency: val.currency,
            issue_date: val.issue_date,
            time_of_drawing: val.time_of_drawing,
            time_of_maturity: val.time_of_maturity,
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
    pub email: Option<String>,
    pub nostr_relays: Vec<String>,
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
    pub name: String,
    pub postal_address: PostalAddressWeb,
    pub email: Option<String>,
    pub nostr_relays: Vec<String>,
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
    pub name: String,
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
    pub name: String,
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
