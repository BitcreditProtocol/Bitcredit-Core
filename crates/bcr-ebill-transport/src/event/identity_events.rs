use bcr_ebill_core::{
    NodeId, blockchain::identity::IdentityBlock, identity::Identity, util::BcrKeys,
};

use super::{Event, blockchain_event::IdentityBlockEvent};

#[derive(Clone, Debug)]
pub struct IdentityChainEvent {
    pub identity: Identity,
    block: IdentityBlock,
    pub keys: BcrKeys,
    sender_node_id: NodeId,
}

impl IdentityChainEvent {
    /// Create a new IdentityChainEvent instance. New blocks indicate whether the given chain contains
    /// new blocks for the identity. Currently we only send a message if a new block has been
    /// added.
    pub fn new(identity: &Identity, block: &IdentityBlock, keys: &BcrKeys) -> Self {
        Self {
            identity: identity.clone(),
            block: block.clone(),
            keys: keys.clone(),
            sender_node_id: identity.node_id.to_owned(),
        }
    }

    pub fn sender(&self) -> NodeId {
        self.sender_node_id.clone()
    }

    /// generates the latest block event for the bill.
    pub fn generate_blockchain_message(&self) -> Option<Event<IdentityBlockEvent>> {
        Some(Event::new_identity_chain(IdentityBlockEvent {
            node_id: self.identity.node_id.clone(),
            block_height: self.block.id as usize,
            block: self.block.clone(),
        }))
    }
}
