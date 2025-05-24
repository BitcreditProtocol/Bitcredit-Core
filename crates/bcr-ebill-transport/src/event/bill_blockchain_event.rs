// TODO:
// - On issue bill publish a kind 1 event with the genesis block (plus potential metadata) and notifiy other participants
// about th bill Nostr event id and keys.
// - On add block publish a kind 1 reply message to either the genesis block or the latest block we
// find on Nostr for the bill. (needs fetching latest before adding block)

use bcr_ebill_core::{
    bill::BillKeys,
    blockchain::{BlockchainType, bill::BillBlock},
    company::CompanyKeys,
    util::BcrKeys,
};
use serde::{Deserialize, Serialize};

/// A chain invite sent to new chain participants via private Nostr DM.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChainInvite {
    pub chain_id: String,
    pub chain_type: BlockchainType,
    pub keys: ChainKeys,
}

impl ChainInvite {
    pub fn bill(chain_id: String, keys: BillKeys) -> Self {
        Self {
            chain_id,
            chain_type: BlockchainType::Bill,
            keys: ChainKeys {
                private_key: keys.private_key,
                public_key: keys.public_key,
            },
        }
    }
    pub fn company(chain_id: String, keys: CompanyKeys) -> Self {
        Self {
            chain_id,
            chain_type: BlockchainType::Company,
            keys: ChainKeys {
                private_key: keys.private_key,
                public_key: keys.public_key,
            },
        }
    }

    pub fn identity(chain_id: String, keys: BcrKeys) -> Self {
        Self {
            chain_id,
            chain_type: BlockchainType::Identity,
            keys: ChainKeys {
                private_key: keys.get_public_key(),
                public_key: keys.get_private_key_string(),
            },
        }
    }
}

/// Generalizes key pairs for different chain types.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChainKeys {
    pub private_key: String,
    pub public_key: String,
}

/// The encrypted BCR payload contained in a public block Nostr event.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BillBlockEvent {
    pub bill_id: String,
    pub block: BillBlock,
}
