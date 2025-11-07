use super::{
    contact::{LightBillIdentParticipant, LightBillParticipant},
    notification::Notification,
};
use crate::protocol::{
    BitcoinAddress, City, Country, Date, File, PostalAddress, Sum, Timestamp,
    blockchain::bill::{
        BillHistory, BillOpCode, ContactType, PastPaymentStatus,
        participant::{BillIdentParticipant, BillParticipant, SignedBy},
    },
};
use bcr_common::core::{BillId, NodeId};
use serde::{Deserialize, Serialize};
use strum::{EnumCount, EnumIter};

/// Possible Bill Actions a caller can do on a bill
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, EnumCount, EnumIter)]
pub enum BillCallerBillAction {
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

impl BillCallerBillAction {
    pub fn op_code(&self) -> BillOpCode {
        match self {
            BillCallerBillAction::RequestAcceptance => BillOpCode::RequestToAccept,
            BillCallerBillAction::Accept => BillOpCode::Accept,
            BillCallerBillAction::RequestToPay => BillOpCode::RequestToPay,
            BillCallerBillAction::OfferToSell => BillOpCode::OfferToSell,
            BillCallerBillAction::Sell => BillOpCode::Sell,
            BillCallerBillAction::Endorse => BillOpCode::Endorse,
            BillCallerBillAction::RequestRecourseForAcceptance => BillOpCode::RequestRecourse,
            BillCallerBillAction::RequestRecourseForPayment => BillOpCode::RequestRecourse,
            BillCallerBillAction::Recourse => BillOpCode::Recourse,
            BillCallerBillAction::Mint => BillOpCode::Mint,
            BillCallerBillAction::RejectAcceptance => BillOpCode::RejectToAccept,
            BillCallerBillAction::RejectPayment => BillOpCode::RejectToPay,
            BillCallerBillAction::RejectBuying => BillOpCode::RejectToBuy,
            BillCallerBillAction::RejectPaymentForRecourse => BillOpCode::RejectToPayRecourse,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Eq)]
pub enum BillType {
    PromissoryNote = 0, // Drawer pays to payee
    SelfDrafted = 1,    // Drawee pays to drawer
    ThreeParties = 2,   // Drawee pays to payee
}

/// The calculated bill for a given caller (=bill participant)
#[derive(Debug, Clone)]
pub struct BitcreditBillResult {
    pub id: BillId,
    pub participants: BillParticipants,
    pub data: BillData,
    pub status: BillStatus,
    pub current_waiting_state: Option<BillCurrentWaitingState>,
    pub history: BillHistory,
    pub actions: BillCallerActions,
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
    pub time_of_request: Timestamp,
    pub sum: Sum,
    pub link_to_pay: String,
    pub address_to_pay: BitcoinAddress,
    pub mempool_link_for_address_to_pay: String,
    pub tx_id: Option<String>,
    pub in_mempool: bool,
    pub confirmations: u64,
    pub payment_deadline: Option<Timestamp>,
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
    pub last_block_time: Timestamp,
}

#[derive(Debug, Clone)]
pub struct BillAcceptanceStatus {
    pub time_of_request_to_accept: Option<Timestamp>,
    pub requested_to_accept: bool,
    pub accepted: bool,
    pub request_to_accept_timed_out: bool,
    pub rejected_to_accept: bool,
    pub acceptance_deadline_timestamp: Option<Timestamp>,
}

#[derive(Debug, Clone)]
pub struct BillPaymentStatus {
    pub time_of_request_to_pay: Option<Timestamp>,
    pub requested_to_pay: bool,
    pub paid: bool,
    pub request_to_pay_timed_out: bool,
    pub rejected_to_pay: bool,
    pub payment_deadline_timestamp: Option<Timestamp>,
}

#[derive(Debug, Clone)]
pub struct BillSellStatus {
    pub time_of_last_offer_to_sell: Option<Timestamp>,
    pub sold: bool,
    pub offered_to_sell: bool,
    pub offer_to_sell_timed_out: bool,
    pub rejected_offer_to_sell: bool,
    pub buying_deadline_timestamp: Option<Timestamp>,
}

#[derive(Debug, Clone)]
pub struct BillRecourseStatus {
    pub time_of_last_request_to_recourse: Option<Timestamp>,
    pub recoursed: bool,
    pub requested_to_recourse: bool,
    pub request_to_recourse_timed_out: bool,
    pub rejected_request_to_recourse: bool,
    pub recourse_deadline_timestamp: Option<Timestamp>,
}

#[derive(Debug, Clone)]
pub struct BillMintStatus {
    pub has_mint_requests: bool,
}

#[derive(Debug, Clone)]
pub struct BillData {
    pub time_of_drawing: Timestamp,
    pub issue_date: Date,
    pub time_of_maturity: Timestamp,
    pub maturity_date: Date,
    pub country_of_issuing: Country,
    pub city_of_issuing: City,
    pub country_of_payment: Country,
    pub city_of_payment: City,
    pub sum: Sum,
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

/// The actions the caller can make for a bill
#[derive(Clone, Debug)]
pub struct BillCallerActions {
    /// Actions that concern the bill chain directly - e.g. Accept etc.
    pub bill_actions: Vec<BillCallerBillAction>,
}

impl BillHistory {
    /// Gets endorsements from bill history
    pub fn get_endorsements(&self) -> Vec<Endorsement> {
        let mut result: Vec<Endorsement> = vec![];

        // iterate from the back to the front, collecting all endorsement blocks
        for block in self.blocks.iter().rev() {
            if let Some(ref pay_to_the_order_of) = block.pay_to_the_order_of
                && matches!(
                    block.block_type,
                    BillOpCode::Mint
                        | BillOpCode::Sell
                        | BillOpCode::Endorse
                        | BillOpCode::Recourse
                )
            {
                result.push(Endorsement {
                    pay_to_the_order_of: pay_to_the_order_of.to_owned().into(),
                    signed: block.signed.to_owned().into(),
                    signing_timestamp: block.signing_timestamp,
                    signing_address: block.signing_address.to_owned(),
                });
            }
        }

        result
    }
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
            .map(|n| n.as_str().to_lowercase().contains(&search_term_lc))
            .unwrap_or(false)
        {
            return true;
        }

        if self
            .participants
            .drawer
            .name
            .as_str()
            .to_lowercase()
            .contains(&search_term_lc)
        {
            return true;
        }

        if self
            .participants
            .drawee
            .name
            .as_str()
            .to_lowercase()
            .contains(&search_term_lc)
        {
            return true;
        }

        if let Some(ref endorsee) = self.participants.endorsee
            && endorsee
                .name()
                .as_ref()
                .map(|n| n.as_str().to_lowercase().contains(&search_term_lc))
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
                .map(|n| n.as_str().to_lowercase().contains(&search_term_lc))
                .unwrap_or(false)
            {
                return true;
            }

            if sell_waiting_state
                .seller
                .name()
                .as_ref()
                .map(|n| n.as_str().to_lowercase().contains(&search_term_lc))
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
    pub sum: Sum,
    pub issue_date: Date,
    pub time_of_drawing: Timestamp,
    pub time_of_maturity: Timestamp,
    pub last_block_time: Timestamp,
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
    pub sum: Sum,
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
pub struct Endorsement {
    pub pay_to_the_order_of: LightBillParticipant,
    pub signed: LightSignedBy,
    pub signing_timestamp: Timestamp,
    pub signing_address: Option<PostalAddress>,
}

#[derive(Clone, Debug)]
pub struct LightSignedBy {
    pub data: LightBillParticipant,
    pub signatory: Option<LightBillIdentParticipant>,
}

impl From<SignedBy> for LightSignedBy {
    fn from(value: SignedBy) -> Self {
        Self {
            data: value.data.into(),
            signatory: value.signatory.map(|s| {
                LightBillIdentParticipant {
                    // signatories are always identified people
                    t: ContactType::Person,
                    name: s.name,
                    node_id: s.node_id,
                }
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub enum PastPaymentResult {
    Sell(PastPaymentDataSell),
    Payment(PastPaymentDataPayment),
    Recourse(PastPaymentDataRecourse),
}

#[derive(Debug, Clone)]
pub struct PastPaymentDataSell {
    pub time_of_request: Timestamp,
    pub buyer: BillParticipant,
    pub seller: BillParticipant,
    pub sum: Sum,
    pub link_to_pay: String,
    pub address_to_pay: BitcoinAddress,
    pub private_descriptor_to_spend: String,
    pub mempool_link_for_address_to_pay: String,
    pub status: PastPaymentStatus,
    pub payment_deadline: Timestamp,
}

#[derive(Debug, Clone)]
pub struct PastPaymentDataPayment {
    pub time_of_request: Timestamp,
    pub payer: BillIdentParticipant,
    pub payee: BillParticipant,
    pub sum: Sum,
    pub link_to_pay: String,
    pub address_to_pay: BitcoinAddress,
    pub private_descriptor_to_spend: String,
    pub mempool_link_for_address_to_pay: String,
    pub status: PastPaymentStatus,
    pub payment_deadline: Timestamp,
}

#[derive(Debug, Clone)]
pub struct PastPaymentDataRecourse {
    pub time_of_request: Timestamp,
    pub recourser: BillParticipant,
    pub recoursee: BillIdentParticipant,
    pub sum: Sum,
    pub link_to_pay: String,
    pub address_to_pay: BitcoinAddress,
    pub private_descriptor_to_spend: String,
    pub mempool_link_for_address_to_pay: String,
    pub status: PastPaymentStatus,
    pub payment_deadline: Timestamp,
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
    pub block_time: Timestamp,
    pub block_hash: String,
    pub confirmations: u64,
    pub tx_id: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InMempoolData {
    pub tx_id: String,
}
