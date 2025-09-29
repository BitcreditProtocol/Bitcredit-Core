use std::collections::BTreeSet;

use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};

use crate::{NodeId, ValidationError, contact::Contact};

/// Make key type clear
pub type NostrPublicKey = nostr::key::PublicKey;

/// Data we need to communicate with a Nostr contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrContact {
    /// Our node id. This is the node id and acts as the primary key.
    pub npub: NostrPublicKey,
    /// The node id of this contact
    pub node_id: NodeId,
    /// The Nostr name of the contact as retreived via Nostr metadata.
    pub name: Option<String>,
    /// The relays we found for this contact either from a message or the result of a relay list
    /// query.
    pub relays: Vec<String>,
    /// The trust level we assign to this contact.
    pub trust_level: TrustLevel,
    /// The handshake status with this contact.
    pub handshake_status: HandshakeStatus,
    /// The keys to decrypt private nostr contact details.
    pub contact_private_key: Option<SecretKey>,
}

impl NostrContact {
    /// Creates a new Nostr contact from a contact. This is used when we have a contact and want to
    /// create the Nostr contact from it. Handshake is set to complete and we trust the contact.
    pub fn from_contact(
        contact: &Contact,
        private_key: Option<SecretKey>,
    ) -> Result<Self, ValidationError> {
        let npub = contact.node_id.npub();
        Ok(Self {
            npub,
            node_id: contact.node_id.clone(),
            name: Some(contact.name.clone()),
            relays: contact.nostr_relays.clone(),
            trust_level: TrustLevel::Trusted,
            handshake_status: HandshakeStatus::Added,
            contact_private_key: private_key,
        })
    }

    /// Merges contact data into a nostr contact. This assumes at that point the handskake is
    /// complete and we trust the contact.
    pub fn merge_contact(&self, contact: &Contact, private_key: Option<SecretKey>) -> Self {
        let mut relays: BTreeSet<String> = BTreeSet::from_iter(self.relays.clone());
        relays.extend(contact.nostr_relays.clone());
        Self {
            npub: self.npub,
            node_id: self.node_id.clone(),
            name: Some(contact.name.clone()),
            relays: relays.into_iter().collect(),
            trust_level: TrustLevel::Trusted,
            handshake_status: HandshakeStatus::Added,
            contact_private_key: private_key.or(self.contact_private_key),
        }
    }
}

/// Trust level we assign for a Nostr contact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    /// No trust at all. We don't know this contact and we don't trust them.
    None,
    /// We encountered this contact in a bill so someone we trust trusted them.
    Participant,
    /// We have done a successful contact handshake with this contact and created a real contact
    /// from it.
    Trusted,
    /// A contact we actively banned from communicating with us.
    Banned,
}

/// Handshake is optional but requires some status tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeStatus {
    /// The contact is not yet in the handshake process.
    None,
    /// The contact is in the handshake process.
    InProgress,
    /// The contact has been added to our contacts.
    Added,
}
