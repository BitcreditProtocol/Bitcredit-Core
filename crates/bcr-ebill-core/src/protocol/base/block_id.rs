use borsh_derive::{BorshDeserialize, BorshSerialize};
use std::fmt::Display;

use serde::{Deserialize, Serialize};

#[derive(
    Copy,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    PartialOrd,
    Ord,
    Hash,
)]
#[serde(transparent)]
pub struct BlockId(u64);

const FIRST_BLOCK_ID: u64 = 1;

impl BlockId {
    // Creates a block id for the first block
    pub fn first() -> Self {
        Self(FIRST_BLOCK_ID)
    }

    // Increments the block id from the previous block id
    pub fn next_from_previous_block_id(previous_block_id: &BlockId) -> BlockId {
        BlockId(previous_block_id.0 + 1)
    }

    pub fn validate_with_previous(&self, previous_block_id: &BlockId) -> bool {
        self.0 == (previous_block_id.0 + 1)
    }

    // Calculates the difference between this block id and another one,
    // but only if the other is greater
    pub fn difference_to_smaller(&self, other_block_id: &BlockId) -> Option<u64> {
        if !(self.eq(other_block_id) || self > other_block_id) {
            Some(other_block_id.0 - self.0)
        } else {
            None
        }
    }

    // Adds a value to this block id
    pub fn add(&self, to_add: u64) -> BlockId {
        BlockId(self.0 + to_add)
    }

    pub fn is_first(&self) -> bool {
        self.0 == FIRST_BLOCK_ID
    }

    pub fn inner(&self) -> u64 {
        self.0
    }
}

impl Display for BlockId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::BorshDeserialize;
    use serde::{Deserialize, Serialize};

    #[derive(
        Debug, Clone, Eq, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
    )]
    pub struct TestBlockId {
        pub block_id: BlockId,
    }

    #[test]
    fn test_serialization() {
        let block_id = BlockId::first();
        let test = TestBlockId { block_id };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!("{\"block_id\":1}", json);
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(test, deserialized);
        assert_eq!(block_id, deserialized.block_id);

        let borsh = borsh::to_vec(&block_id).unwrap();
        let borsh_de = BlockId::try_from_slice(&borsh).unwrap();
        assert_eq!(block_id, borsh_de);

        let borsh_test = borsh::to_vec(&test).unwrap();
        let borsh_de_test = TestBlockId::try_from_slice(&borsh_test).unwrap();
        assert_eq!(test, borsh_de_test);
        assert_eq!(block_id, borsh_de_test.block_id);
    }

    #[test]
    fn borsh_test_ok() {
        // test that borsh serializes BlockId(u64) just as u64
        let bytes = 5u64.to_le_bytes().to_vec();
        let res = BlockId::try_from_slice(&bytes).expect("works");
        assert_eq!(res, BlockId(5));
    }

    #[test]
    fn test_block_id() {
        let n = BlockId::first();
        let n_other = BlockId(1);
        assert_eq!(n, n_other);

        let first = BlockId::first();
        let next = BlockId::next_from_previous_block_id(&first);
        assert_eq!(first.0 + 1, next.0);
    }
}
