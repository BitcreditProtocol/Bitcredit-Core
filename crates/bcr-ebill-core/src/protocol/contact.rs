use bcr_common::core::NodeId;
use borsh::{BorshDeserialize, BorshSerialize};
use secp256k1::SecretKey;

/// Event payload when keys for contact details are shared. This is used for both personal identity
/// and company. The shared keys are derived from the private key of the identity or company and
/// all the recipents to decrypt the private Nostr profile data that is stored on relays.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ContactShareEvent {
    /// The node id of the contact that is shared
    pub node_id: NodeId,
    /// The private key of the contact that is shared
    #[borsh(
        serialize_with = "crate::util::borsh::serialize_privkey",
        deserialize_with = "crate::util::borsh::deserialize_privkey"
    )]
    pub private_key: SecretKey,
}
