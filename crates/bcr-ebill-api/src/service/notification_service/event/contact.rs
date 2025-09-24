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
