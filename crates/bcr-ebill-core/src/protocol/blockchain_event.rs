use crate::{
    NodeId, PublicKey, SecretKey,
    bill::{BillId, BillKeys},
    blockchain::{BlockchainType, bill::BillBlock, company::CompanyBlock, identity::IdentityBlock},
    company::CompanyKeys,
    util::BcrKeys,
};
use borsh_derive::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// A chain invite sent to new chain participants via private Nostr DM.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
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
                private_key: keys.get_private_key(),
                public_key: keys.pub_key(),
            },
        }
    }
}

/// Generalizes key pairs for different chain types.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChainKeys {
    pub private_key: SecretKey,
    pub public_key: PublicKey,
}

impl borsh::BorshSerialize for ChainKeys {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let private_bytes = self.private_key.secret_bytes();
        let public_bytes = self.public_key.serialize();
        borsh::BorshSerialize::serialize(&private_bytes.to_vec(), writer)?;
        borsh::BorshSerialize::serialize(&public_bytes.to_vec(), writer)?;
        Ok(())
    }
}

impl borsh::BorshDeserialize for ChainKeys {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let private_bytes: Vec<u8> = borsh::BorshDeserialize::deserialize_reader(reader)?;
        let public_bytes: Vec<u8> = borsh::BorshDeserialize::deserialize_reader(reader)?;

        let private_key = SecretKey::from_slice(&private_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let public_key = PublicKey::from_slice(&public_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(Self {
            private_key,
            public_key,
        })
    }
}

/// The encrypted BCR bill payload contained in a public block Nostr event.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct BillBlockEvent {
    pub bill_id: BillId,
    pub block_height: usize,
    pub block: BillBlock,
}

/// The encrypted BCR identity payload contained in a public block Nostr event.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct IdentityBlockEvent {
    pub node_id: NodeId,
    pub block_height: usize,
    pub block: IdentityBlock,
}
///
/// The encrypted BCR company payload contained in a public block Nostr event.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct CompanyBlockEvent {
    pub node_id: NodeId,
    pub block_height: usize,
    pub block: CompanyBlock,
}
