use crate::{protocol::blockchain::identity::IdentityBlock, protocol::crypto::BcrKeys};
use bcr_common::core::NodeId;

use super::{Event, blockchain_event::IdentityBlockEvent};

#[derive(Clone, Debug)]
pub struct IdentityChainEvent {
    pub identity_id: NodeId,
    block: IdentityBlock,
    pub keys: BcrKeys,
    sender_node_id: NodeId,
}

impl IdentityChainEvent {
    /// Create a new IdentityChainEvent instance. New blocks indicate whether the given chain contains
    /// new blocks for the identity. Currently we only send a message if a new block has been
    /// added.
    pub fn new(identity_id: &NodeId, block: &IdentityBlock, keys: &BcrKeys) -> Self {
        Self {
            identity_id: identity_id.clone(),
            block: block.clone(),
            keys: keys.clone(),
            sender_node_id: identity_id.to_owned(),
        }
    }

    pub fn sender(&self) -> NodeId {
        self.sender_node_id.clone()
    }

    /// generates the latest block event for the bill.
    pub fn generate_blockchain_message(&self) -> Option<Event<IdentityBlockEvent>> {
        Some(Event::new_identity_chain(IdentityBlockEvent {
            node_id: self.identity_id.clone(),
            block_height: self.block.id.inner() as usize,
            block: self.block.clone(),
        }))
    }
}
