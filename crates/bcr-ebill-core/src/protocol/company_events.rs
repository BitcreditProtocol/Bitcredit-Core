use crate::{
    NodeId,
    blockchain::{
        Blockchain,
        company::{CompanyBlock, CompanyBlockchain},
    },
    company::{Company, CompanyKeys},
};

use super::{
    Event,
    blockchain_event::{ChainInvite, CompanyBlockEvent},
};

#[derive(Clone, Debug)]
pub struct CompanyChainEvent {
    pub company: Company,
    chain: CompanyBlockchain,
    pub keys: CompanyKeys,
    new_signatory: Option<NodeId>,
    new_blocks: bool,
    sender_node_id: NodeId,
}

impl CompanyChainEvent {
    /// Create a new CompanyChainEvent instance. New blocks indicate whether the given chain contains
    /// new blocks for the company. Currently we only send a message if a new block has been added.
    pub fn new(
        company: &Company,
        chain: &CompanyBlockchain,
        keys: &CompanyKeys,
        new_signatory: Option<NodeId>,
        new_blocks: bool,
    ) -> Self {
        Self {
            company: company.clone(),
            chain: chain.clone(),
            keys: keys.clone(),
            new_signatory,
            new_blocks,
            sender_node_id: company.id.to_owned(),
        }
    }

    pub fn sender(&self) -> NodeId {
        self.sender_node_id.clone()
    }

    // Returns the latest block in the chain.
    fn latest_block(&self) -> CompanyBlock {
        self.chain.get_latest_block().clone()
    }

    pub fn block_height(&self) -> usize {
        self.chain.block_height()
    }

    /// generates the latest block event for the bill.
    pub fn generate_blockchain_message(&self) -> Option<Event<CompanyBlockEvent>> {
        if !self.new_blocks {
            return None;
        }
        Some(Event::new_company_chain(CompanyBlockEvent {
            node_id: self.company.id.clone(),
            block_height: self.block_height(),
            block: self.latest_block(),
        }))
    }

    pub fn generate_company_invite_message(&self) -> Option<(NodeId, Event<ChainInvite>)> {
        if let Some(node_id) = self.new_signatory.as_ref() {
            let invite = ChainInvite::company(self.company.id.to_string(), self.keys.clone());
            Some((node_id.clone(), Event::new_company_invite(invite)))
        } else {
            None
        }
    }
}
