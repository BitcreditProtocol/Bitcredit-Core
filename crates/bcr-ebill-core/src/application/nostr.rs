use crate::protocol::{
    Sha256Hash,
    blockchain::{Block, Blockchain},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropagationBlockInfo {
    pub block_height: u64,
    pub block_type: String,
}

pub fn find_block_info<C>(chain: &C, block_hash: &Sha256Hash) -> Option<PropagationBlockInfo>
where
    C: Blockchain,
    <C::Block as Block>::OpCode: std::fmt::Debug,
{
    chain
        .blocks()
        .iter()
        .find(|block| block.hash() == block_hash)
        .map(|block| PropagationBlockInfo {
            block_height: block.id().inner(),
            block_type: format!("{:?}", block.op_code()),
        })
}
