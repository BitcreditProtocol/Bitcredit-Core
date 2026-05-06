use crate::protocol::{
    Sum,
    blockchain::{
        Blockchain,
        bill::{
            BillBlock, BillBlockchain, BillOpCode, BitcreditBill,
            block::BillOfferToSellBlockData,
            participant::{BillIdentParticipant, BillParticipant},
        },
    },
    crypto::BcrKeys,
};
use bcr_common::core::{BillId, NodeId};
use borsh_derive::{BorshDeserialize, BorshSerialize};
use log::error;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt};

use super::blockchain_event::{BillBlockEvent, ChainInvite};
use super::{Event, EventType, ProtocolError, Result};

#[derive(Clone)]
pub struct BillChainEvent {
    pub bill: BitcreditBill,
    chain: BillBlockchain,
    participants: HashMap<NodeId, usize>,
    pub bill_keys: BcrKeys,
    new_blocks: bool,
    sender_node_id: NodeId,
}

impl BillChainEvent {
    /// Create a new BillChainEvent instance. New blocks indicate whether the given chain contains
    /// new blocks for the bill. If new_blocks is false just action notifications will be sent.
    pub fn new(
        bill: &BitcreditBill,
        chain: &BillBlockchain,
        bill_keys: &BcrKeys,
        new_blocks: bool,
        sender_node_id: &NodeId,
    ) -> Result<Self> {
        let participants = chain
            .get_all_nodes_with_added_block_height(bill_keys)
            .map_err(|e| {
                error!("Failed to get participants from blockchain: {e}");
                ProtocolError::Deserialization(
                    "Failed to get participants from blockchain when creating a new chain event"
                        .to_string(),
                )
            })?;
        Ok(Self {
            bill: bill.clone(),
            chain: chain.clone(),
            participants,
            bill_keys: bill_keys.clone(),
            new_blocks,
            sender_node_id: sender_node_id.to_owned(),
        })
    }

    pub fn sender(&self) -> NodeId {
        self.sender_node_id.clone()
    }

    // Returns the latest block in the chain.
    fn latest_block(&self) -> BillBlock {
        self.chain.get_latest_block().clone()
    }

    pub fn block_height(&self) -> usize {
        self.chain.block_height()
    }

    fn new_participants(&self) -> HashMap<NodeId, usize> {
        let block_height = self.chain.block_height();
        self.participants
            .iter()
            .filter(|(node_id, height)| {
                // Filter out the sender node id and only include new participants.
                node_id != &&self.sender_node_id && **height == block_height
            })
            .map(|(node_id, height)| (node_id.to_owned(), *height))
            .collect()
    }

    /// Returns all participant node IDs in the bill chain
    pub fn get_all_participant_node_ids(&self) -> Vec<NodeId> {
        self.participants.keys().cloned().collect()
    }

    fn sender_name(&self) -> Option<String> {
        if self.bill.drawer.node_id == self.sender_node_id {
            return Some(self.bill.drawer.name.to_string());
        }
        if self.bill.drawee.node_id == self.sender_node_id {
            return Some(self.bill.drawee.name.to_string());
        }
        if let BillParticipant::Ident(ref payee) = self.bill.payee
            && payee.node_id == self.sender_node_id
        {
            return Some(payee.name.to_string());
        }
        if let Some(BillParticipant::Ident(ref ident)) = self.bill.endorsee
            && ident.node_id == self.sender_node_id
        {
            return Some(ident.name.to_string());
        }
        None
    }

    /// Generates bill action events for participants. Individual `node_id`s can be assigned a
    /// specific event and action type by providing an override in `event_overrides`.
    /// If `event_type` and `action` are provided, participants without an override receive that
    /// event. Participants without an override and where `event_type` is `None` will not receive
    /// any event. The recipient `node_id` is the key in the map.
    pub fn generate_action_messages(
        &self,
        event_overrides: HashMap<NodeId, (BillEventType, ActionType)>,
        event_type: Option<BillEventType>,
        action: Option<ActionType>,
    ) -> HashMap<NodeId, Event<BillChainEventPayload>> {
        let sender_node_id = self.sender_node_id.clone();
        let sender_name = self.sender_name();
        self.participants
            .keys()
            .filter_map(|node_id| {
                let (event_type, override_action) = event_overrides
                    .get(node_id)
                    .map(|(event_type, action)| (Some(event_type.clone()), Some(action.clone())))
                    .unwrap_or((event_type.clone(), action.clone()));

                event_type.map(|e| {
                    log::debug!(
                        "Bill transport event: type={:?} sender={} recipient={} action={:?}",
                        e,
                        sender_node_id,
                        node_id,
                        override_action
                    );
                    (
                        node_id.to_owned(),
                        Event::new(
                            EventType::Bill,
                            BillChainEventPayload {
                                event_type: e,
                                bill_id: self.bill.id.to_owned(),
                                action_type: override_action,
                                sum: Some(self.bill.sum.clone()),
                                sender_node_id: Some(sender_node_id.clone()),
                                sender_name: sender_name.clone(),
                            },
                        ),
                    )
                })
            })
            .collect()
    }

    /// generates the latest block event for the bill.
    pub fn generate_blockchain_message(&self) -> Option<Event<BillBlockEvent>> {
        if !self.new_blocks {
            return None;
        }
        Some(Event::new_bill_chain(BillBlockEvent {
            bill_id: self.bill.id.to_owned(),
            block_height: self.block_height(),
            block: self.latest_block(),
        }))
    }

    pub fn generate_bill_invite_events(&self) -> HashMap<NodeId, Event<ChainInvite>> {
        let invite = ChainInvite::bill(self.bill.id.to_string(), self.bill_keys.clone());
        self.new_participants()
            .keys()
            .map(|node_id| (node_id.to_owned(), Event::new_bill_invite(invite.clone())))
            .collect()
    }

    pub fn generate_messages(
        &self,
        event_type: BillEventType,
    ) -> HashMap<NodeId, Event<BillChainEventPayload>> {
        match event_type {
            BillEventType::BillSigned => self.generate_bill_signed_internal(),
            BillEventType::BillAccepted => self.generate_bill_accepted_internal(),
            BillEventType::BillPaymentRequested => self.generate_request_to_pay_internal(),
            BillEventType::BillAcceptanceRequested => self.generate_request_to_accept_internal(),
            BillEventType::BillEndorsed => self.generate_bill_endorsed_internal(),
            BillEventType::BillPaid => self.generate_bill_paid_internal(),
            _ => HashMap::new(),
        }
    }

    fn generate_bill_signed_internal(&self) -> HashMap<NodeId, Event<BillChainEventPayload>> {
        let mut overrides: HashMap<NodeId, (BillEventType, ActionType)> = HashMap::new();

        overrides.insert(
            self.bill.drawee.node_id.clone(),
            (BillEventType::BillSigned, ActionType::AcceptBill),
        );

        overrides.insert(
            self.bill.payee.node_id(),
            (BillEventType::BillSigned, ActionType::CheckBill),
        );

        self.generate_action_messages(overrides, None, None)
    }

    fn generate_bill_accepted_internal(&self) -> HashMap<NodeId, Event<BillChainEventPayload>> {
        let mut overrides: HashMap<NodeId, (BillEventType, ActionType)> = HashMap::new();

        let holder_node_id = self
            .bill
            .endorsee
            .as_ref()
            .map(|e| e.node_id())
            .unwrap_or_else(|| self.bill.payee.node_id());

        if holder_node_id != self.sender_node_id {
            overrides.insert(
                holder_node_id.clone(),
                (BillEventType::BillAccepted, ActionType::CheckBill),
            );
        }

        if self.bill.drawer.node_id != self.sender_node_id
            && self.bill.drawer.node_id != holder_node_id
        {
            overrides.insert(
                self.bill.drawer.node_id.clone(),
                (BillEventType::BillAccepted, ActionType::CheckBill),
            );
        }

        self.generate_action_messages(overrides, None, None)
    }

    fn generate_request_to_pay_internal(&self) -> HashMap<NodeId, Event<BillChainEventPayload>> {
        let mut overrides: HashMap<NodeId, (BillEventType, ActionType)> = HashMap::new();

        if self.bill.drawee.node_id != self.sender_node_id {
            overrides.insert(
                self.bill.drawee.node_id.clone(),
                (BillEventType::BillPaymentRequested, ActionType::PayBill),
            );
        }

        self.generate_action_messages(overrides, None, None)
    }

    fn generate_request_to_accept_internal(&self) -> HashMap<NodeId, Event<BillChainEventPayload>> {
        let mut overrides: HashMap<NodeId, (BillEventType, ActionType)> = HashMap::new();

        if self.bill.drawee.node_id != self.sender_node_id {
            overrides.insert(
                self.bill.drawee.node_id.clone(),
                (
                    BillEventType::BillAcceptanceRequested,
                    ActionType::AcceptBill,
                ),
            );
        }

        self.generate_action_messages(overrides, None, None)
    }

    fn generate_bill_endorsed_internal(&self) -> HashMap<NodeId, Event<BillChainEventPayload>> {
        let mut overrides: HashMap<NodeId, (BillEventType, ActionType)> = HashMap::new();

        if let Some(ref endorsee) = self.bill.endorsee {
            let endorsee_node_id = endorsee.node_id();
            if endorsee_node_id != self.sender_node_id {
                overrides.insert(
                    endorsee_node_id,
                    (BillEventType::BillEndorsed, ActionType::CheckBill),
                );
            }
        }

        self.generate_action_messages(overrides, None, None)
    }

    pub fn generate_offer_to_sell_messages(
        &self,
        buyer: &BillParticipant,
    ) -> HashMap<NodeId, Event<BillChainEventPayload>> {
        let mut overrides: HashMap<NodeId, (BillEventType, ActionType)> = HashMap::new();
        let buyer_node_id = buyer.node_id();

        if buyer_node_id != self.sender_node_id {
            overrides.insert(
                buyer_node_id,
                (BillEventType::BillSellOffered, ActionType::CheckBill),
            );
        }

        self.generate_action_messages(overrides, None, None)
    }

    pub fn generate_bill_sold_messages(
        &self,
        buyer: &BillParticipant,
    ) -> HashMap<NodeId, Event<BillChainEventPayload>> {
        let mut overrides: HashMap<NodeId, (BillEventType, ActionType)> = HashMap::new();
        let buyer_node_id = buyer.node_id();

        if buyer_node_id != self.sender_node_id {
            overrides.insert(
                buyer_node_id,
                (BillEventType::BillSold, ActionType::CheckBill),
            );
        }

        self.generate_action_messages(overrides, None, None)
    }

    pub fn generate_rejected_messages(
        &self,
        rejected_action: ActionType,
    ) -> HashMap<NodeId, Event<BillChainEventPayload>> {
        let event_type = match rejected_action {
            ActionType::AcceptBill => BillEventType::BillAcceptanceRejected,
            ActionType::PayBill => BillEventType::BillPaymentRejected,
            ActionType::BuyBill => BillEventType::BillBuyingRejected,
            ActionType::RecourseBill => BillEventType::BillRecourseRejected,
            _ => return HashMap::new(),
        };

        let mut overrides: HashMap<NodeId, (BillEventType, ActionType)> = HashMap::new();
        let drawee_node_id = self.bill.drawee.node_id.clone();

        let recipient_ids: Vec<NodeId> = match rejected_action {
            ActionType::RecourseBill => {
                // Recourse rejection goes to all NON-BEARER prior holders
                let current_holder = self
                    .bill
                    .endorsee
                    .as_ref()
                    .map(|e| e.node_id())
                    .unwrap_or_else(|| self.bill.payee.node_id());
                match self
                    .chain
                    .get_past_endorsees_for_bill(&self.bill_keys, &current_holder)
                {
                    Ok(endorsees) => endorsees
                        .into_iter()
                        .map(|e| e.pay_to_the_order_of.node_id)
                        .collect(),
                    Err(e) => {
                        error!("Failed to get past endorsees for recourse rejection: {e}");
                        return HashMap::new();
                    }
                }
            }
            _ => {
                // Regular rejection goes to all NON-BEARER participants except drawee
                match self
                    .chain
                    .get_all_ident_nodes_with_added_block_height(&self.bill_keys)
                {
                    Ok(nodes) => nodes.into_keys().collect(),
                    Err(e) => {
                        error!("Failed to get Ident participants for rejection: {e}");
                        return HashMap::new();
                    }
                }
            }
        };

        for node_id in recipient_ids {
            if node_id != self.sender_node_id && node_id != drawee_node_id {
                overrides.insert(node_id, (event_type.clone(), ActionType::CheckBill));
            }
        }

        self.generate_action_messages(overrides, None, None)
    }

    pub fn generate_timeout_messages(
        &self,
        timed_out_action: ActionType,
    ) -> HashMap<NodeId, Event<BillChainEventPayload>> {
        let event_type = match timed_out_action {
            ActionType::AcceptBill => BillEventType::BillAcceptanceTimeout,
            ActionType::PayBill => BillEventType::BillPaymentTimeout,
            ActionType::RecourseBill => BillEventType::BillRecourseTimeout,
            ActionType::BuyBill => BillEventType::BillSellOfferTimeout,
            _ => return HashMap::new(),
        };

        let mut overrides: HashMap<NodeId, (BillEventType, ActionType)> = HashMap::new();

        let recipient_ids: Vec<NodeId> = match timed_out_action {
            ActionType::RecourseBill => {
                // Recourse timeout goes to all NON-BEARER prior holders
                let current_holder = self
                    .bill
                    .endorsee
                    .as_ref()
                    .map(|e| e.node_id())
                    .unwrap_or_else(|| self.bill.payee.node_id());
                match self
                    .chain
                    .get_past_endorsees_for_bill(&self.bill_keys, &current_holder)
                {
                    Ok(endorsees) => endorsees
                        .into_iter()
                        .map(|e| e.pay_to_the_order_of.node_id)
                        .collect(),
                    Err(e) => {
                        error!("Failed to get past endorsees for recourse timeout: {e}");
                        return HashMap::new();
                    }
                }
            }
            ActionType::BuyBill => match self
                .chain
                .get_last_version_block_with_op_code(BillOpCode::OfferToSell)
            {
                Some(offer_block) => {
                    match offer_block
                        .get_decrypted_block::<BillOfferToSellBlockData>(&self.bill_keys)
                    {
                        Ok(block_data) => {
                            let mut ids = vec![];
                            let buyer_node_id = block_data.buyer.node_id();
                            let seller_node_id = block_data.seller.node_id();
                            if buyer_node_id != self.sender_node_id {
                                ids.push(buyer_node_id);
                            }
                            if seller_node_id != self.sender_node_id {
                                ids.push(seller_node_id);
                            }
                            ids
                        }
                        Err(e) => {
                            error!("Failed to decrypt offer to sell block for timeout: {e}");
                            return HashMap::new();
                        }
                    }
                }
                None => {
                    error!("No offer to sell block found for BuyBill timeout");
                    return HashMap::new();
                }
            },
            _ => {
                // Regular timeout goes to all NON-BEARER participants
                match self
                    .chain
                    .get_all_ident_nodes_with_added_block_height(&self.bill_keys)
                {
                    Ok(nodes) => nodes.into_keys().collect(),
                    Err(e) => {
                        error!("Failed to get Ident participants for timeout: {e}");
                        return HashMap::new();
                    }
                }
            }
        };

        for node_id in recipient_ids {
            if node_id != self.sender_node_id {
                overrides.insert(node_id, (event_type.clone(), ActionType::CheckBill));
            }
        }

        self.generate_action_messages(overrides, None, None)
    }

    pub fn generate_recourse_messages(
        &self,
        action: ActionType,
        recoursee: &BillIdentParticipant,
    ) -> HashMap<NodeId, Event<BillChainEventPayload>> {
        let event_type = match action {
            ActionType::AcceptBill => BillEventType::BillAcceptanceRecourse,
            ActionType::PayBill => BillEventType::BillPaymentRecourse,
            _ => return HashMap::new(),
        };

        let mut overrides: HashMap<NodeId, (BillEventType, ActionType)> = HashMap::new();

        if recoursee.node_id != self.sender_node_id {
            overrides.insert(recoursee.node_id.clone(), (event_type, action.clone()));
        }

        self.generate_action_messages(overrides, None, None)
    }

    fn generate_bill_paid_internal(&self) -> HashMap<NodeId, Event<BillChainEventPayload>> {
        let mut overrides: HashMap<NodeId, (BillEventType, ActionType)> = HashMap::new();

        let holder_node_id = self
            .bill
            .endorsee
            .as_ref()
            .map(|e| e.node_id())
            .unwrap_or_else(|| self.bill.payee.node_id());

        if holder_node_id != self.sender_node_id {
            overrides.insert(
                holder_node_id,
                (BillEventType::BillPaid, ActionType::CheckBill),
            );
        }

        self.generate_action_messages(overrides, None, None)
    }
}

/// Used to signal a change in the blockchain of a bill and an optional
/// action event. Given some bill_id, this can signal an action to be
/// performed by the receiver and a change in the blockchain. If the
/// recipient is a new chain participant, the recipient receives the full
/// chain otherwise just the most recent block.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct BillChainEventPayload {
    pub event_type: BillEventType,
    pub bill_id: BillId,
    pub action_type: Option<ActionType>,
    pub sum: Option<Sum>,
    /// The node ID of the participant who triggered this event (sender)
    pub sender_node_id: Option<NodeId>,
    /// The display name of the participant who triggered this event
    pub sender_name: Option<String>,
}

/// The different types of events that can be sent via this service.
/// For now we only have Bill events and this needs some clippy
/// exceptions here. As soon as we have other event topics, we can
/// add new types here and remove the clippy exceptions.
#[derive(
    Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default, BorshSerialize, BorshDeserialize,
)]
#[allow(clippy::enum_variant_names, dead_code)]
pub enum BillEventType {
    BillSigned,
    BillAccepted,
    BillAcceptanceRequested,
    BillAcceptanceRejected,
    BillAcceptanceTimeout,
    BillAcceptanceRecourse,
    BillPaymentRequested,
    BillPaymentRejected,
    BillPaymentRecourse,
    BillRecourseRejected,
    BillRecourseTimeout,
    BillPaymentTimeout,
    BillSellOffered,
    BillSellOfferTimeout,
    BillBuyingRejected,
    BillPaid,
    BillRecoursePaid,
    BillEndorsed,
    BillSold,
    BillMintingRequested,
    BillNewQuote,
    BillQuoteApproved,
    #[default]
    BillBlock,
}

impl BillEventType {
    pub fn all() -> Vec<Self> {
        vec![
            Self::BillSigned,
            Self::BillAccepted,
            Self::BillAcceptanceRequested,
            Self::BillAcceptanceRejected,
            Self::BillAcceptanceTimeout,
            Self::BillAcceptanceRecourse,
            Self::BillPaymentRequested,
            Self::BillPaymentRejected,
            Self::BillPaymentTimeout,
            Self::BillPaymentRecourse,
            Self::BillRecourseTimeout,
            Self::BillRecourseRejected,
            Self::BillSellOffered,
            Self::BillSellOfferTimeout,
            Self::BillBuyingRejected,
            Self::BillPaid,
            Self::BillRecoursePaid,
            Self::BillEndorsed,
            Self::BillSold,
            Self::BillMintingRequested,
            Self::BillNewQuote,
            Self::BillQuoteApproved,
            Self::BillBlock,
        ]
    }

    pub fn is_action_event(&self) -> bool {
        !matches!(self, Self::BillBlock)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[allow(clippy::enum_variant_names, dead_code)]
pub enum ActionType {
    BuyBill,
    RecourseBill,
    AcceptBill,
    CheckBill,
    PayBill,
    CheckQuote,
}

impl BillEventType {
    /// Returns a human-readable description key for the event type.
    pub fn description(&self) -> String {
        match self {
            BillEventType::BillSigned => "bill_signed".to_string(),
            BillEventType::BillAccepted => "bill_accepted".to_string(),
            BillEventType::BillAcceptanceRequested => "bill_should_be_accepted".to_string(),
            BillEventType::BillAcceptanceRejected => "bill_acceptance_rejected".to_string(),
            BillEventType::BillAcceptanceTimeout => "bill_acceptance_timed_out".to_string(),
            BillEventType::BillAcceptanceRecourse => {
                "bill_recourse_acceptance_required".to_string()
            }
            BillEventType::BillPaymentRequested => "bill_payment_required".to_string(),
            BillEventType::BillPaymentRejected => "bill_payment_rejected".to_string(),
            BillEventType::BillPaymentTimeout => "bill_payment_timed_out".to_string(),
            BillEventType::BillPaymentRecourse => "bill_recourse_payment_required".to_string(),
            BillEventType::BillRecourseRejected => "Bill_recourse_rejected".to_string(),
            BillEventType::BillRecourseTimeout => "Bill_recourse_timed_out".to_string(),
            BillEventType::BillSellOffered => "bill_request_to_buy".to_string(),
            BillEventType::BillSellOfferTimeout => "bill_sell_offer_timed_out".to_string(),
            BillEventType::BillBuyingRejected => "bill_buying_rejected".to_string(),
            BillEventType::BillPaid => "bill_paid".to_string(),
            BillEventType::BillRecoursePaid => "bill_recourse_paid".to_string(),
            BillEventType::BillEndorsed => "bill_endorsed".to_string(),
            BillEventType::BillSold => "bill_sold".to_string(),
            BillEventType::BillMintingRequested => "requested_to_mint".to_string(),
            BillEventType::BillNewQuote => "new_quote".to_string(),
            BillEventType::BillQuoteApproved => "quote_approved".to_string(),
            BillEventType::BillBlock => "".to_string(),
        }
    }
}

impl fmt::Display for BillEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl ActionType {
    /// Return a corresponding rejected event type for the action type
    /// if the action has a rejected event type. If not, return None.
    pub fn get_rejected_event_type(&self) -> Option<BillEventType> {
        match self {
            Self::AcceptBill => Some(BillEventType::BillAcceptanceRejected),
            Self::PayBill => Some(BillEventType::BillPaymentRejected),
            Self::BuyBill => Some(BillEventType::BillBuyingRejected),
            Self::RecourseBill => Some(BillEventType::BillRecourseRejected),
            _ => None,
        }
    }

    /// Return a corresponding timeout event type for the action type
    /// if the action has a timeout event type. If not, return None.
    pub fn get_timeout_event_type(&self) -> Option<BillEventType> {
        match self {
            Self::AcceptBill => Some(BillEventType::BillAcceptanceTimeout),
            Self::PayBill => Some(BillEventType::BillPaymentTimeout),
            Self::RecourseBill => Some(BillEventType::BillRecourseTimeout),
            Self::BuyBill => Some(BillEventType::BillSellOfferTimeout),
            _ => None,
        }
    }

    // Return a corresponding recourse event type for the action type
    // if the action has a recourse event type. If not, return None.
    pub fn get_recourse_event_type(&self) -> Option<BillEventType> {
        match self {
            Self::AcceptBill => Some(BillEventType::BillAcceptanceRecourse),
            Self::PayBill => Some(BillEventType::BillPaymentRecourse),
            _ => None,
        }
    }

    pub fn is_actionable(&self) -> bool {
        !matches!(self, Self::CheckBill)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_timeout_event_type() {
        assert_eq!(
            ActionType::AcceptBill.get_timeout_event_type(),
            Some(BillEventType::BillAcceptanceTimeout)
        );
        assert_eq!(
            ActionType::PayBill.get_timeout_event_type(),
            Some(BillEventType::BillPaymentTimeout)
        );
        assert_eq!(
            ActionType::RecourseBill.get_timeout_event_type(),
            Some(BillEventType::BillRecourseTimeout)
        );
        assert_eq!(
            ActionType::BuyBill.get_timeout_event_type(),
            Some(BillEventType::BillSellOfferTimeout)
        );
        assert_eq!(ActionType::CheckBill.get_timeout_event_type(), None);
        assert_eq!(ActionType::CheckQuote.get_timeout_event_type(), None);
    }
}
