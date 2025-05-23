use bcr_ebill_core::{
    bill::{BillKeys, BitcreditBill},
    blockchain::{
        Blockchain,
        bill::{BillBlock, BillBlockchain},
    },
    notification::{ActionType, BillEventType},
};
use log::error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{Error, Result};

use super::{Event, EventType};

pub struct BillChainEvent {
    pub bill: BitcreditBill,
    chain: BillBlockchain,
    participants: HashMap<String, usize>,
    bill_keys: BillKeys,
    new_blocks: bool,
    sender_node_id: String,
}

impl BillChainEvent {
    /// Create a new BillChainEvent instance. New blocks indicate whether the given chain contains
    /// new blocks for the bill. If new_blocks is false events will be populated without a block
    /// and keys.
    pub fn new(
        bill: &BitcreditBill,
        chain: &BillBlockchain,
        bill_keys: &BillKeys,
        new_blocks: bool,
        sender_node_id: &str,
    ) -> Result<Self> {
        let participants = chain
            .get_all_nodes_with_added_block_height(bill_keys)
            .map_err(|e| {
                error!("Failed to get participants from blockchain: {}", e);
                Error::Blockchain(
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

    pub fn sender(&self) -> String {
        self.sender_node_id.clone()
    }

    // Returns the latest block in the chain.
    fn latest_block(&self) -> BillBlock {
        self.chain.get_latest_block().clone()
    }

    // Returns all blocks for newly added participants, otherwise just the latest block or no
    // blocks if the node is not a participant.
    fn get_blocks_for_node(&self, node_id: &str) -> Vec<BillBlock> {
        if !self.new_blocks {
            return Vec::new();
        }
        match self.participants.get(node_id) {
            Some(height) if *height == self.chain.block_height() => self.chain.blocks().clone(),
            Some(_) => vec![self.latest_block()],
            _ => Vec::new(),
        }
    }

    fn get_keys_for_node(&self, node_id: &str) -> Option<BillKeys> {
        if !self.new_blocks {
            return None;
        }
        match self.participants.get(node_id) {
            Some(height) if *height == self.chain.block_height() => Some(self.bill_keys.clone()),
            _ => None,
        }
    }

    /// Generates bill block events for all participants in the chain. Individual node_ids can be
    /// assigned a specific event and action type by providing an override. If include_blocks is
    /// false, the blocks list will be empty in the generated events.
    pub fn generate_action_messages(
        &self,
        event_overrides: HashMap<String, (BillEventType, ActionType)>,
        event_type: Option<BillEventType>,
        action: Option<ActionType>,
    ) -> Vec<Event<BillChainEventPayload>> {
        let base_event = event_type.unwrap_or(BillEventType::BillBlock);
        self.participants
            .keys()
            .map(|node_id| {
                let (event_type, override_action) = event_overrides
                    .get(node_id)
                    .map(|(event_type, action)| (event_type.clone(), Some(action.clone())))
                    .unwrap_or((base_event.clone(), None));
                Event::new(
                    EventType::Bill,
                    node_id,
                    BillChainEventPayload {
                        event_type,
                        bill_id: self.bill.id.to_owned(),
                        action_type: override_action.or(action.clone()),
                        sum: Some(self.bill.sum),
                        blocks: self.get_blocks_for_node(node_id),
                        keys: self.get_keys_for_node(node_id),
                    },
                )
            })
            .collect()
    }
}

/// Used to signal a change in the blockchain of a bill and an optional
/// action event. Given some bill_id, this can signal an action to be
/// performed by the receiver and a change in the blockchain. If the
/// recipient is a new chain participant, the recipient receives the full
/// chain otherwise just the most recent block.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct BillChainEventPayload {
    pub event_type: BillEventType,
    pub bill_id: String,
    pub action_type: Option<ActionType>,
    pub sum: Option<u64>,
    pub keys: Option<BillKeys>,
    pub blocks: Vec<BillBlock>,
}
