use crate::{Error, Result};
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::{Sha256Hash, Timestamp, event::EventType},
};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationSubjectType {
    Bill,
    Identity,
    Company,
    Contact,
}

impl PropagationSubjectType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bill => "bill",
            Self::Identity => "identity",
            Self::Company => "company",
            Self::Contact => "contact",
        }
    }
}

/// An operation with fully prepared Nostr events
#[derive(Debug, Clone)]
pub struct PreparedPropagation {
    /// uuid
    pub id: String,
    pub subject_type: PropagationSubjectType,
    /// bill_id, identity_id etc.
    pub subject_id: String,
    pub created_at: Timestamp,
    pub messages: Vec<PreparedPropagationMessage>,
}

/// A signed Nostr event with its intended relay targets
#[derive(Debug, Clone)]
pub struct PreparedPropagationMessage {
    /// uuid
    pub id: String,
    pub event_type: EventType,
    /// Recipient for private events
    pub recipient_id: Option<NodeId>,
    /// Blockchain metadata for chain events
    pub chain_id: Option<String>,
    pub block_hash: Option<Sha256Hash>,
    /// signed Nostr event
    pub event: nostr::event::Event,
    /// relay targets determined during preparation
    pub target_relays: Vec<url::Url>,
}

impl PreparedPropagation {
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty() || self.subject_id.is_empty() {
            return Err(Error::InvalidData(
                "Propagation ID and subject ID are required".into(),
            ));
        }
        if self.messages.is_empty() {
            return Err(Error::InvalidData(
                "Propagation contains no messages".into(),
            ));
        }

        let mut message_ids = HashSet::new();
        for message in &self.messages {
            if message.id.is_empty() || !message_ids.insert(&message.id) {
                return Err(Error::InvalidData(
                    "Empty or duplicate propagation message ID".into(),
                ));
            }
            if message.target_relays.is_empty() {
                return Err(Error::InvalidData(
                    "Propagation message has no target relays".into(),
                ));
            }

            let mut relays = HashSet::new();
            for relay in &message.target_relays {
                // only unique ws/wss relays can be propagated to
                if !matches!(relay.scheme(), "ws" | "wss") {
                    return Err(Error::InvalidData("Invalid propagation relay".into()));
                }
                if !relays.insert(relay.as_str()) {
                    return Err(Error::InvalidData("Duplicate propagation relay".into()));
                }
            }

            let is_chain_event = matches!(
                &message.event_type,
                EventType::BillChain | EventType::IdentityChain | EventType::CompanyChain
            );
            if is_chain_event && (message.chain_id.is_none() || message.block_hash.is_none()) {
                return Err(Error::InvalidData(
                    "Blockchain event requires chain metadata".into(),
                ));
            }
            if message.chain_id.is_some() != message.block_hash.is_some() {
                return Err(Error::InvalidData("Incomplete chain metadata".into()));
            }

            let is_private_event = matches!(
                &message.event_type,
                EventType::Bill
                    | EventType::BillChainInvite
                    | EventType::CompanyChainInvite
                    | EventType::ContactShare
            );
            if is_private_event && message.recipient_id.is_none() {
                return Err(Error::InvalidData(
                    "Private event requires a recipient".into(),
                ));
            }
        }
        Ok(())
    }
}

/// the status of a given propagation
#[derive(Debug, Clone)]
pub struct PropagationStatus {
    /// uuid
    pub id: String,
    pub subject_type: PropagationSubjectType,
    pub subject_id: String,
    pub created_at: Timestamp,
    pub messages: Vec<PropagationMessageStatus>,
}

/// the status of a given propagation message
#[derive(Debug, Clone)]
pub struct PropagationMessageStatus {
    pub id: String,
    pub event_type: EventType,
    pub recipient_id: Option<NodeId>,
    pub chain_id: Option<String>,
    pub block_hash: Option<Sha256Hash>,
    pub nostr_event_id: String,
    pub relays: Vec<RelayPropagationStatus>,
}

/// the status of a given propagation message's relay
#[derive(Debug, Clone)]
pub struct RelayPropagationStatus {
    pub relay_url: url::Url,
    pub accepted_at: Option<Timestamp>,
    pub attempts: u32,
    pub next_try_at: Timestamp,
    pub last_error: Option<String>,
}

/// an actual event delivery for a propagation, message and relay within it
#[derive(Debug, Clone)]
pub struct PendingDelivery {
    pub message_id: String,
    pub propagation_id: String,
    pub relay_url: url::Url,
    pub event: nostr::event::Event,
    pub attempts: u32,
}

#[async_trait]
pub trait NostrPropagationStoreApi: ServiceTraitBounds {
    async fn get_propagation(&self, propagation_id: &str) -> Result<Option<PropagationStatus>>;
    /// ids ordered by newest first
    async fn list_propagation_ids(
        &self,
        subject_type: PropagationSubjectType,
        subject_id: &str,
    ) -> Result<Vec<String>>;
    /// pending deliveries from all propagations
    async fn get_pending_deliveries(
        &self,
        now: Timestamp,
        limit: u64,
    ) -> Result<Vec<PendingDelivery>>;
    /// pending deliveries belonging for a propagation
    async fn get_pending_deliveries_for_propagation(
        &self,
        propagation_id: &str,
        now: Timestamp,
    ) -> Result<Vec<PendingDelivery>>;
    async fn mark_relay_accepted(
        &self,
        message_id: &str,
        relay: &url::Url,
        accepted_at: Timestamp,
    ) -> Result<()>;
    async fn mark_relay_failed(
        &self,
        message_id: &str,
        relay: &url::Url,
        next_try_at: Timestamp,
        error: &str,
    ) -> Result<()>;
    async fn make_pending_deliveries_due_now(&self) -> Result<()>;
}
