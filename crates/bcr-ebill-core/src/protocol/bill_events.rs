use crate::{
    NodeId,
    bill::{BillId, BillKeys, BitcreditBill},
    blockchain::{
        Blockchain,
        bill::{BillBlock, BillBlockchain},
    },
    notification::{ActionType, BillEventType},
    sum::Sum,
};
use borsh_derive::{BorshDeserialize, BorshSerialize};
use log::error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{
    Event, EventType, ProtocolError, Result,
    blockchain_event::{BillBlockEvent, ChainInvite},
};

pub struct BillChainEvent {
    pub bill: BitcreditBill,
    chain: BillBlockchain,
    participants: HashMap<NodeId, usize>,
    pub bill_keys: BillKeys,
    new_blocks: bool,
    sender_node_id: NodeId,
}

impl BillChainEvent {
    /// Create a new BillChainEvent instance. New blocks indicate whether the given chain contains
    /// new blocks for the bill. If new_blocks is false just action notifications will be sent.
    pub fn new(
        bill: &BitcreditBill,
        chain: &BillBlockchain,
        bill_keys: &BillKeys,
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

    /// Generates bill action events for all participants in the chain. Individual node_ids can be
    /// assigned a specific event and action type by providing an override. The recipient node_id is the
    /// key in the map.
    pub fn generate_action_messages(
        &self,
        event_overrides: HashMap<NodeId, (BillEventType, ActionType)>,
        event_type: Option<BillEventType>,
        action: Option<ActionType>,
    ) -> HashMap<NodeId, Event<BillChainEventPayload>> {
        let base_event = event_type.unwrap_or(BillEventType::BillBlock);
        self.participants
            .keys()
            .map(|node_id| {
                let (event_type, override_action) = event_overrides
                    .get(node_id)
                    .map(|(event_type, action)| (event_type.clone(), Some(action.clone())))
                    .unwrap_or((base_event.clone(), None));
                (
                    node_id.to_owned(),
                    Event::new(
                        EventType::Bill,
                        BillChainEventPayload {
                            event_type,
                            bill_id: self.bill.id.to_owned(),
                            action_type: override_action.or(action.clone()),
                            sum: Some(self.bill.sum.clone()),
                        },
                    ),
                )
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
