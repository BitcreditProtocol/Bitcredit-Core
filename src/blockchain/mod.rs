use thiserror::Error;

use crate::util::crypto;
use crate::{external, util};
use borsh::{to_vec, BorshSerialize};
use log::{error, warn};
use std::string::FromUtf8Error;

pub mod bill;
pub mod company;
pub mod identity;

const FIRST_BLOCK_ID: u64 = 1;

/// Generic result type
pub type Result<T> = std::result::Result<T, Error>;

/// Generic error type
#[derive(Debug, Error)]
pub enum Error {
    /// Errors from io handling, or binary serialization/deserialization
    #[error("io error {0}")]
    Io(#[from] std::io::Error),

    /// If a whole chain is not valid
    #[error("Blockchain is invalid")]
    BlockchainInvalid,

    /// If certain block is not valid and can't be added
    #[error("Block is invalid")]
    BlockInvalid,

    /// Errors stemming from cryptography, such as converting keys, encryption and decryption
    #[error("Secp256k1Cryptography error: {0}")]
    Secp256k1Cryptography(#[from] crypto::Error),

    /// Errors stemming from base58 decoding
    #[error("Base 58 Decode error: {0}")]
    Base58Decode(#[from] util::Error),

    /// Errors stemming from converting from utf-8 strings
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] FromUtf8Error),

    /// Errors stemming from dealing with invalid block data, e.g. if within an Endorse block,
    /// there is no endorsee
    #[error("Invalid block data error: {0}")]
    InvalidBlockdata(String),

    /// all errors originating from external APIs
    #[error("External API error: {0}")]
    ExternalApi(#[from] external::Error),
}

/// Generic trait for a Block within a Blockchain
pub trait Block {
    type OpCode: PartialEq + Clone + BorshSerialize;
    type BlockDataToHash: BorshSerialize;

    fn id(&self) -> u64;
    fn timestamp(&self) -> u64;
    fn op_code(&self) -> &Self::OpCode;
    fn hash(&self) -> &str;
    fn previous_hash(&self) -> &str;
    fn data(&self) -> &str;
    fn signature(&self) -> &str;
    fn public_key(&self) -> &str;
    fn get_block_data_to_hash(&self) -> Self::BlockDataToHash;

    /// Calculates the hash over the data to hash for this block
    fn calculate_hash(block_data_to_hash: Self::BlockDataToHash) -> Result<String> {
        let serialized = to_vec(&block_data_to_hash)?;
        Ok(util::sha256_hash(&serialized))
    }

    /// Validates that the block's hash is correct
    fn validate_hash(&self) -> bool {
        match Self::calculate_hash(self.get_block_data_to_hash()) {
            Err(e) => {
                error!("Error calculating hash: {e}");
                false
            }
            Ok(calculated_hash) => self.hash() == calculated_hash,
        }
    }

    /// Verifys the block by checking if the signature is correct
    fn verify(&self) -> bool {
        match crypto::verify(self.hash(), self.signature(), self.public_key()) {
            Err(e) => {
                error!("Error while verifying block id {}: {e}", self.id());
                false
            }
            Ok(res) => res,
        }
    }

    /// Validates the block with a given previous block
    fn validate_with_previous(&self, previous_block: &Self) -> bool {
        if self.previous_hash() != previous_block.hash() {
            warn!("block with id: {} has wrong previous hash", self.id());
            return false;
        } else if self.id() != previous_block.id() + 1 {
            warn!(
                "block with id: {} is not the next block after the latest: {}",
                self.id(),
                previous_block.id()
            );
            return false;
        } else if !self.validate_hash() {
            warn!("block with id: {} has invalid hash", self.id());
            return false;
        } else if !self.verify() {
            warn!("block with id: {} has invalid signature", self.id());
            return false;
        }
        true
    }
}

/// Generic trait for a Blockchain, expects there to always be at least one block after creation
pub trait Blockchain {
    type Block: Block + Clone;

    fn blocks(&self) -> &Vec<Self::Block>;

    fn blocks_mut(&mut self) -> &mut Vec<Self::Block>;

    /// returns the current height of this blockchain
    fn block_height(&self) -> usize {
        self.blocks().len()
    }

    /// Validates the integrity of the blockchain by checking the validity of each block in the chain.
    fn is_chain_valid(&self) -> bool {
        let blocks = self.blocks();
        for i in 0..blocks.len() {
            if i == 0 {
                continue;
            }
            let first = &blocks[i - 1];
            let second = &blocks[i];
            if !second.validate_with_previous(first) {
                return false;
            }
        }
        true
    }

    /// Trys to add a block to the blockchain, checking the block with the current latest block
    ///
    /// # Arguments
    /// * `block` - The `Block` to be added to the list.
    ///
    /// # Returns
    /// * `true` if the block was successfully added to the list.
    /// * `false` if the block was invalid and could not be added.
    ///
    fn try_add_block(&mut self, block: Self::Block) -> bool {
        let latest_block = self.get_latest_block();
        if block.validate_with_previous(latest_block) {
            self.blocks_mut().push(block);
            true
        } else {
            error!("could not add block - invalid");
            false
        }
    }

    /// Retrieves the latest (most recent) block in the blocks list.
    fn get_latest_block(&self) -> &Self::Block {
        self.blocks().last().expect("there is at least one block")
    }

    /// Retrieves the first block in the blocks list.
    fn get_first_block(&self) -> &Self::Block {
        self.blocks().first().expect("there is at least one block")
    }

    /// Returns the blocks that can be safely added from another chain, checking the consistency of
    /// the chain after every block
    fn get_blocks_to_add_from_other_chain(&mut self, other_chain: &Self) -> Vec<Self::Block> {
        let local_chain_last_id = self.get_latest_block().id();
        let other_chain_last_id = other_chain.get_latest_block().id();
        let mut blocks_to_add = vec![];

        // if it's not the same id, and the local chain is shorter
        if !(local_chain_last_id.eq(&other_chain_last_id)
            || local_chain_last_id > other_chain_last_id)
        {
            let difference_in_id = other_chain_last_id - local_chain_last_id;
            for block_id in 1..difference_in_id + 1 {
                let block = other_chain.get_block_by_id(local_chain_last_id + block_id);
                let try_add_block = self.try_add_block(block.clone());
                if try_add_block && self.is_chain_valid() {
                    blocks_to_add.push(block);
                    continue;
                } else {
                    break;
                }
            }
        }
        blocks_to_add
    }

    /// Retrieves the last block with the specified op code.
    fn get_last_version_block_with_op_code(
        &self,
        op_code: <Self::Block as Block>::OpCode,
    ) -> &Self::Block {
        self.blocks()
            .iter()
            .filter(|block| block.op_code() == &op_code)
            .next_back()
            .unwrap_or_else(|| self.get_first_block())
    }

    /// Checks if there is any block with a given operation code in the current blocks list.
    fn block_with_operation_code_exists(&self, op_code: <Self::Block as Block>::OpCode) -> bool {
        self.blocks().iter().any(|b| b.op_code() == &op_code)
    }

    /// Gets the block with the given block number, or the first one, if the given one doesn't
    /// exist
    fn get_block_by_id(&self, id: u64) -> Self::Block {
        self.blocks()
            .iter()
            .find(|b| b.id() == id)
            .cloned()
            .unwrap_or_else(|| self.get_first_block().clone())
    }
}
