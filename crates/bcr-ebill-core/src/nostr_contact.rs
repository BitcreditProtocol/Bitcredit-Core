use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::contact::Contact;

/// Data we need to communicate with a Nostr contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrContact {
    /// Our node id. This is the node id and acts as the primary key.
    pub node_id: String,
    /// The Nostr name of the contact as retreived via Nostr metadata.
    pub name: Option<String>,
    /// The relays we found for this contact either from a message or the result of a relay list
    /// query.
    pub relays: Vec<String>,
    /// The trust level we assign to this contact.
    pub trust_level: TrustLevel,
    /// The handshake status with this contact.
    pub handshake_status: HandshakeStatus,
}

impl NostrContact {
    /// Creates a new Nostr contact from a contact. This is used when we have a contact and want to
    /// create the Nostr contact from it. Handshake is set to complete and we trust the contact.
    pub fn from_contact(contact: &Contact) -> Self {
        Self {
            node_id: contact.node_id.clone(),
            name: Some(contact.name.clone()),
            relays: contact.nostr_relays.clone(),
            trust_level: TrustLevel::Trusted,
            handshake_status: HandshakeStatus::Added,
        }
    }

    /// Merges contact data into a nostr contact. This assumes at that point the handskake is
    /// complete and we trust the contact.
    pub fn merge_contact(&self, contact: &Contact) -> Self {
        let mut relays: BTreeSet<String> = BTreeSet::from_iter(self.relays.clone());
        relays.extend(contact.nostr_relays.clone());
        Self {
            node_id: self.node_id.clone(),
            name: Some(contact.name.clone()),
            relays: relays.into_iter().collect(),
            trust_level: TrustLevel::Trusted,
            handshake_status: HandshakeStatus::Added,
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
