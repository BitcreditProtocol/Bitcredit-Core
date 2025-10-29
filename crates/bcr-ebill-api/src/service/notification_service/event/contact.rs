use bcr_ebill_core::NodeId;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};

/// Event payload when keys for contact details are shared. This is used for both personal identity
/// and company. The shared keys are derived from the private key of the identity or company and
/// all the recipents to decrypt the private Nostr profile data that is stored on relays.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContactShareEvent {
    /// The node id of the contact that is shared
    pub node_id: NodeId,
    /// The private key of the contact that is shared
    pub private_key: SecretKey,
}

impl borsh::BorshSerialize for ContactShareEvent {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        borsh::BorshSerialize::serialize(&self.node_id, writer)?;
        let private_bytes = self.private_key.secret_bytes();
        borsh::BorshSerialize::serialize(&private_bytes.to_vec(), writer)?;
        Ok(())
    }
}

impl borsh::BorshDeserialize for ContactShareEvent {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let node_id: NodeId = borsh::BorshDeserialize::deserialize_reader(reader)?;
        let private_bytes: Vec<u8> = borsh::BorshDeserialize::deserialize_reader(reader)?;
        
        let private_key = SecretKey::from_slice(&private_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        
        Ok(Self {
            node_id,
            private_key,
        })
    }
}
