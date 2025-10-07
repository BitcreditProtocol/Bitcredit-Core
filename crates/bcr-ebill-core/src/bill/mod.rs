use super::{
    File, PostalAddress,
    contact::{BillIdentParticipant, LightBillIdentParticipant},
    notification::Notification,
};
use crate::{
    NodeId,
    blockchain::bill::BillBlockchain,
    contact::{BillParticipant, LightBillParticipant},
    util::BcrKeys,
};
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

pub mod validation;

pub use bcr_common::core::BillId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BillAction {
    // deadline_ts
    RequestAcceptance(u64),
    Accept,
    // currency, deadline_ts
    RequestToPay(String, u64),
    // buyer, sum, currency, deadline_ts
    OfferToSell(BillParticipant, u64, String, u64),
    // buyer, sum, currency, payment_address
    Sell(BillParticipant, u64, String, String),
    // endorsee
    Endorse(BillParticipant),
    // recoursee, recourse reason, deadline_ts
    RequestRecourse(BillIdentParticipant, RecourseReason, u64),
    // recoursee, sum, currency reason/
    Recourse(BillIdentParticipant, u64, String, RecourseReason),
    // mint, sum, currency
    Mint(BillParticipant, u64, String),
    RejectAcceptance,
    RejectPayment,
    RejectBuying,
    RejectPaymentForRecourse,
}

#[repr(u8)]
#[derive(Debug, Clone, serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Eq)]
pub enum BillType {
    PromissoryNote = 0, // Drawer pays to payee
    SelfDrafted = 1,    // Drawee pays to drawer
    ThreeParties = 2,   // Drawee pays to payee
}

#[derive(Debug, Clone)]
pub struct BillIssueData {
    pub t: u64,
    pub country_of_issuing: String,
    pub city_of_issuing: String,
    pub issue_date: String,
    pub maturity_date: String,
    pub drawee: NodeId,
    pub payee: NodeId,
    pub sum: String,
    pub currency: String,
    pub country_of_payment: String,
    pub city_of_payment: String,
    pub language: String,
    pub file_upload_ids: Vec<String>,
    pub drawer_public_data: BillParticipant,
    pub drawer_keys: BcrKeys,
    pub timestamp: u64,
    pub blank_issue: bool,
}

#[derive(Debug, Clone)]
pub struct BillValidateActionData {
    pub blockchain: BillBlockchain,
    pub drawee_node_id: NodeId,
    pub payee_node_id: NodeId,
    pub endorsee_node_id: Option<NodeId>,
    pub maturity_date: String,
    pub bill_keys: BillKeys,
    pub timestamp: u64,
    pub signer_node_id: NodeId,
    pub bill_action: BillAction,
    pub is_paid: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BitcreditBill {
    pub id: BillId,
    pub country_of_issuing: String,
    pub city_of_issuing: String,
    // The party obliged to pay a Bill
    pub drawee: BillIdentParticipant,
    // The party issuing a Bill
    pub drawer: BillIdentParticipant,
    pub payee: BillParticipant,
    // The person to whom the Payee or an Endorsee endorses a bill
    pub endorsee: Option<BillParticipant>,
    pub currency: String,
    pub sum: u64,
    pub maturity_date: String,
    pub issue_date: String,
    pub country_of_payment: String,
    pub city_of_payment: String,
    pub language: String,
    pub files: Vec<File>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BillKeys {
    pub private_key: SecretKey,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecourseReason {
    Accept,
    Pay(u64, String), // sum and currency
}

#[derive(Debug, Clone)]
pub struct BitcreditBillResult {
    pub id: BillId,
    pub participants: BillParticipants,
    pub data: BillData,
    pub status: BillStatus,
    pub current_waiting_state: Option<BillCurrentWaitingState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BillCurrentWaitingState {
    Sell(BillWaitingForSellState),
    Payment(BillWaitingForPaymentState),
    Recourse(BillWaitingForRecourseState),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillWaitingForSellState {
    pub buyer: BillParticipant,
    pub seller: BillParticipant,
    pub payment_data: BillWaitingStatePaymentData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillWaitingForPaymentState {
    pub payer: BillIdentParticipant,
    pub payee: BillParticipant,
    pub payment_data: BillWaitingStatePaymentData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillWaitingForRecourseState {
    pub recourser: BillParticipant,
    pub recoursee: BillIdentParticipant,
    pub payment_data: BillWaitingStatePaymentData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillWaitingStatePaymentData {
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

#[derive(Debug, Clone)]
pub struct BillStatus {
    pub acceptance: BillAcceptanceStatus,
    pub payment: BillPaymentStatus,
    pub sell: BillSellStatus,
    pub recourse: BillRecourseStatus,
    pub mint: BillMintStatus,
    pub redeemed_funds_available: bool,
    pub has_requested_funds: bool,
    pub last_block_time: u64,
}

#[derive(Debug, Clone)]
pub struct BillAcceptanceStatus {
    pub time_of_request_to_accept: Option<u64>,
    pub requested_to_accept: bool,
    pub accepted: bool,
    pub request_to_accept_timed_out: bool,
    pub rejected_to_accept: bool,
    pub acceptance_deadline_timestamp: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct BillPaymentStatus {
    pub time_of_request_to_pay: Option<u64>,
    pub requested_to_pay: bool,
    pub paid: bool,
    pub request_to_pay_timed_out: bool,
    pub rejected_to_pay: bool,
    pub payment_deadline_timestamp: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct BillSellStatus {
    pub time_of_last_offer_to_sell: Option<u64>,
    pub sold: bool,
    pub offered_to_sell: bool,
    pub offer_to_sell_timed_out: bool,
    pub rejected_offer_to_sell: bool,
    pub buying_deadline_timestamp: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct BillRecourseStatus {
    pub time_of_last_request_to_recourse: Option<u64>,
    pub recoursed: bool,
    pub requested_to_recourse: bool,
    pub request_to_recourse_timed_out: bool,
    pub rejected_request_to_recourse: bool,
    pub recourse_deadline_timestamp: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct BillMintStatus {
    pub has_mint_requests: bool,
}

#[derive(Debug, Clone)]
pub struct BillData {
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
    pub files: Vec<File>,
    pub active_notification: Option<Notification>,
}

#[derive(Debug, Clone)]
pub struct BillParticipants {
    pub drawee: BillIdentParticipant,
    pub drawer: BillIdentParticipant,
    pub payee: BillParticipant,
    pub endorsee: Option<BillParticipant>,
    pub endorsements: Vec<Endorsement>,
    pub endorsements_count: u64,
    pub all_participant_node_ids: Vec<NodeId>,
}

impl BitcreditBillResult {
    /// Returns the role of the given node_id in the bill, or None if the node_id is not a
    /// participant in the bill
    pub fn get_bill_role_for_node_id(&self, node_id: &NodeId) -> Option<BillRole> {
        // Node id is not part of the bill
        if !self
            .participants
            .all_participant_node_ids
            .iter()
            .any(|bp| bp == node_id)
        {
            return None;
        }

        // Node id is the payer
        if self.participants.drawee.node_id == *node_id {
            return Some(BillRole::Payer);
        }

        // Node id is payee, or, if an endorsee is set and node id is endorsee, node id is payee
        if let Some(ref endorsee) = self.participants.endorsee {
            if endorsee.node_id() == *node_id {
                return Some(BillRole::Payee);
            }
        } else if self.participants.payee.node_id() == *node_id {
            return Some(BillRole::Payee);
        }

        // Node id is part of the bill, but neither payer, nor payee - they are part of the risk
        // chain
        Some(BillRole::Contingent)
    }

    // Search in the participants for the search term
    pub fn search_bill_for_search_term(&self, search_term: &str) -> bool {
        let search_term_lc = search_term.to_lowercase();
        if self
            .participants
            .payee
            .name()
            .as_ref()
            .map(|n| n.to_lowercase().contains(&search_term_lc))
            .unwrap_or(false)
        {
            return true;
        }

        if self
            .participants
            .drawer
            .name
            .to_lowercase()
            .contains(&search_term_lc)
        {
            return true;
        }

        if self
            .participants
            .drawee
            .name
            .to_lowercase()
            .contains(&search_term_lc)
        {
            return true;
        }

        if let Some(ref endorsee) = self.participants.endorsee
            && endorsee
                .name()
                .as_ref()
                .map(|n| n.to_lowercase().contains(&search_term_lc))
                .unwrap_or(false)
        {
            return true;
        }

        if let Some(BillCurrentWaitingState::Sell(ref sell_waiting_state)) =
            self.current_waiting_state
        {
            if sell_waiting_state
                .buyer
                .name()
                .as_ref()
                .map(|n| n.to_lowercase().contains(&search_term_lc))
                .unwrap_or(false)
            {
                return true;
            }

            if sell_waiting_state
                .seller
                .name()
                .as_ref()
                .map(|n| n.to_lowercase().contains(&search_term_lc))
                .unwrap_or(false)
            {
                return true;
            }
        }

        false
    }
}

#[derive(Debug, Clone)]
pub struct LightBitcreditBillResult {
    pub id: BillId,
    pub drawee: LightBillIdentParticipant,
    pub drawer: LightBillIdentParticipant,
    pub payee: LightBillParticipant,
    pub endorsee: Option<LightBillParticipant>,
    pub active_notification: Option<Notification>,
    pub sum: String,
    pub currency: String,
    pub issue_date: String,
    pub time_of_drawing: u64,
    pub time_of_maturity: u64,
    pub last_block_time: u64,
}

impl From<BitcreditBillResult> for LightBitcreditBillResult {
    fn from(value: BitcreditBillResult) -> Self {
        Self {
            id: value.id,
            drawee: value.participants.drawee.into(),
            drawer: value.participants.drawer.into(),
            payee: value.participants.payee.into(),
            endorsee: value.participants.endorsee.map(|v| v.into()),
            active_notification: value.data.active_notification,
            sum: value.data.sum,
            currency: value.data.currency,
            issue_date: value.data.issue_date,
            time_of_drawing: value.data.time_of_drawing,
            time_of_maturity: value.data.time_of_maturity,
            last_block_time: value.status.last_block_time,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BillsBalanceOverview {
    pub payee: BillsBalance,
    pub payer: BillsBalance,
    pub contingent: BillsBalance,
}

#[derive(Debug, Clone)]
pub struct BillsBalance {
    pub sum: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BillRole {
    Payee,
    Payer,
    Contingent,
}

#[derive(Debug)]
pub struct BillCombinedBitcoinKey {
    pub private_descriptor: String,
}

#[derive(Debug)]
pub enum BillsFilterRole {
    All,
    Payer,
    Payee,
    Contingent,
}

#[derive(Clone, Debug)]
pub struct PastEndorsee {
    pub pay_to_the_order_of: BillIdentParticipant,
    pub signed: LightSignedBy,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddress>,
}

#[derive(Clone, Debug)]
pub struct Endorsement {
    pub pay_to_the_order_of: LightBillParticipant,
    pub signed: LightSignedBy,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddress>,
}

#[derive(Clone, Debug)]
pub struct LightSignedBy {
    pub data: LightBillParticipant,
    pub signatory: Option<LightBillIdentParticipant>,
}

#[derive(Debug, Clone)]
pub enum PastPaymentResult {
    Sell(PastPaymentDataSell),
    Payment(PastPaymentDataPayment),
    Recourse(PastPaymentDataRecourse),
}

#[derive(Debug, Clone)]
pub enum PastPaymentStatus {
    Paid(u64),     // timestamp
    Rejected(u64), // timestamp
    Expired(u64),  // timestamp
}

#[derive(Debug, Clone)]
pub struct PastPaymentDataSell {
    pub time_of_request: u64,
    pub buyer: BillParticipant,
    pub seller: BillParticipant,
    pub currency: String,
    pub sum: String,
    pub link_to_pay: String,
    pub address_to_pay: String,
    pub private_descriptor_to_spend: String,
    pub mempool_link_for_address_to_pay: String,
    pub status: PastPaymentStatus,
    pub payment_deadline: u64,
}

#[derive(Debug, Clone)]
pub struct PastPaymentDataPayment {
    pub time_of_request: u64,
    pub payer: BillIdentParticipant,
    pub payee: BillParticipant,
    pub currency: String,
    pub sum: String,
    pub link_to_pay: String,
    pub address_to_pay: String,
    pub private_descriptor_to_spend: String,
    pub mempool_link_for_address_to_pay: String,
    pub status: PastPaymentStatus,
    pub payment_deadline: u64,
}

#[derive(Debug, Clone)]
pub struct PastPaymentDataRecourse {
    pub time_of_request: u64,
    pub recourser: BillParticipant,
    pub recoursee: BillIdentParticipant,
    pub currency: String,
    pub sum: String,
    pub link_to_pay: String,
    pub address_to_pay: String,
    pub private_descriptor_to_spend: String,
    pub mempool_link_for_address_to_pay: String,
    pub status: PastPaymentStatus,
    pub payment_deadline: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PaymentState {
    PaidConfirmed(PaidData),
    PaidUnconfirmed(PaidData),
    InMempool(InMempoolData),
    NotFound,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PaidData {
    pub block_time: u64, // unix timestamp
    pub block_hash: String,
    pub confirmations: u64,
    pub tx_id: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InMempoolData {
    pub tx_id: String,
}
