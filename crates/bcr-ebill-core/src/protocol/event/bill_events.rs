use crate::protocol::{
    Sum,
    blockchain::{
        Blockchain,
        bill::{BillBlock, BillBlockchain, BitcreditBill},
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
        self.participants
            .keys()
            .filter_map(|node_id| {
                let (event_type, override_action) = event_overrides
                    .get(node_id)
                    .map(|(event_type, action)| (Some(event_type.clone()), Some(action.clone())))
                    .unwrap_or((event_type.clone(), action.clone()));

                event_type.map(|e| {
                    (
                        node_id.to_owned(),
                        Event::new(
                            EventType::Bill,
                            BillChainEventPayload {
                                event_type: e,
                                bill_id: self.bill.id.to_owned(),
                                action_type: override_action,
                                sum: Some(self.bill.sum.clone()),
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
}
