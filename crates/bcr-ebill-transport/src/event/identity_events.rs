use bcr_ebill_core::{
    NodeId,
    blockchain::{
        Blockchain,
        identity::{IdentityBlock, IdentityBlockchain},
    },
    identity::Identity,
    util::BcrKeys,
};

use crate::Result;

use super::{Event, blockchain_event::IdentityBlockEvent};

#[derive(Clone, Debug)]
pub struct IdentityChainEvent {
    pub identity: Identity,
    chain: IdentityBlockchain,
    pub keys: BcrKeys,
    new_blocks: bool,
    sender_node_id: NodeId,
}

impl IdentityChainEvent {
    /// Create a new IdentityChainEvent instance. New blocks indicate whether the given chain contains
    /// new blocks for the identity. Currently we only send a message if a new block has been
    /// added.
    pub fn new(
        identity: &Identity,
        chain: &IdentityBlockchain,
        keys: &BcrKeys,
        new_blocks: bool,
    ) -> Result<Self> {
        Ok(Self {
            identity: identity.clone(),
            chain: chain.clone(),
            keys: keys.clone(),
            new_blocks,
            sender_node_id: identity.node_id.to_owned(),
        })
    }

    pub fn sender(&self) -> NodeId {
        self.sender_node_id.clone()
    }

    // Returns the latest block in the chain.
    fn latest_block(&self) -> IdentityBlock {
        self.chain.get_latest_block().clone()
    }

    pub fn block_height(&self) -> usize {
        self.chain.block_height()
    }

    /// generates the latest block event for the bill.
    pub fn generate_blockchain_message(&self) -> Option<Event<IdentityBlockEvent>> {
        if !self.new_blocks {
            return None;
        }
        Some(Event::new_identity_chain(IdentityBlockEvent {
            node_id: self.identity.node_id.clone(),
            block_height: self.block_height(),
            block: self.latest_block(),
        }))
    }
}
