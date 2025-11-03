use std::{cmp::Reverse, sync::Arc};

use bcr_ebill_api::service::notification_service::transport::NotificationJsonTransportApi;
use bcr_ebill_core::{
    blockchain::{BlockchainType, bill::BillBlock, company::CompanyBlock, identity::IdentityBlock},
    hash::Sha256Hash,
    protocol::{BillBlockEvent, CompanyBlockEvent, IdentityBlockEvent},
    timestamp::Timestamp,
    util::BcrKeys,
};
use bcr_ebill_persistence::nostr::NostrChainEvent;
use nostr::{
    event::{EventId, TagKind, TagStandard},
    nips::nip10::Marker,
};

use crate::transport::{decrypt_public_chain_event, unwrap_public_chain_event};
use bcr_ebill_api::service::notification_service::{Error, Result};

/// Will query the transport for the public chain events and build up as many chains as needed for
/// the Nostr chain structure. This does not look into the actual blockchain, but will build the
/// chains just from Nostr metadata.
pub async fn resolve_event_chains(
    transport: Arc<dyn NotificationJsonTransportApi>,
    chain_id: &str,
    chain_type: BlockchainType,
    keys: &BcrKeys,
) -> Result<Vec<Vec<EventContainer>>> {
    let events = transport.resolve_public_chain(chain_id, chain_type).await?;
    let mut chains = collect_event_chains(&events, chain_id, chain_type, keys);
    chains.sort_by_key(|v| Reverse(v.len()));
    Ok(chains)
}

// Will build up as many chains as needed for the Nostr chain structure. This does not look into
// the actual blockchain, but will build the chains just from Nostr metadata.
pub fn collect_event_chains(
    events: &[nostr_sdk::Event],
    chain_id: &str,
    chain_type: BlockchainType,
    keys: &BcrKeys,
) -> Vec<Vec<EventContainer>> {
    let mut result = Vec::new();
    let markers: Vec<EventContainer> = events
        .iter()
        .filter_map(|e| ids_and_markers(e, chain_id, chain_type, keys))
        .collect();
    if let Some((root, children)) = split_root(&markers) {
        result = root.resolve_children(&children).as_chains();
    }
    result
}

pub fn split_root(markers: &[EventContainer]) -> Option<(EventContainer, Vec<EventContainer>)> {
    if let Some(root) = markers.iter().find(|v| v.is_root()) {
        let remainder = markers.iter().filter(|v| !v.is_root()).cloned().collect();
        return Some((root.clone(), remainder));
    }
    None
}

// find root and reply note ids of given event
pub fn ids_and_markers(
    event: &nostr_sdk::Event,
    chain_id: &str,
    chain_type: BlockchainType,
    keys: &BcrKeys,
) -> Option<EventContainer> {
    if let Ok(block) = decrypt_block(event.clone(), chain_id, chain_type, keys) {
        let mut result = EventContainer::new(event.clone(), None, None, block);
        event.tags.filter_standardized(TagKind::e()).for_each(|t| {
            if let TagStandard::Event {
                event_id, marker, ..
            } = t
            {
                match marker {
                    Some(Marker::Root) => result.root_id = Some(event_id.to_owned()),
                    Some(Marker::Reply) => result.reply_id = Some(event_id.to_owned()),
                    _ => {}
                }
            }
        });
        Some(result)
    } else {
        None
    }
}

pub fn decrypt_block(
    event: nostr_sdk::Event,
    chain_id: &str,
    chain_type: BlockchainType,
    keys: &BcrKeys,
) -> Result<BlockData> {
    if let Ok(Some(payload)) = unwrap_public_chain_event(Box::new(event.clone())) {
        if (payload.id == chain_id) && (payload.chain_type == chain_type) {
            let decrypted = decrypt_public_chain_event(&payload.payload, keys)?;
            let data = match chain_type {
                BlockchainType::Bill => {
                    BlockData::Bill(borsh::from_slice::<BillBlockEvent>(&decrypted.data)?.block)
                }
                BlockchainType::Identity => BlockData::Identity(
                    borsh::from_slice::<IdentityBlockEvent>(&decrypted.data)?.block,
                ),
                BlockchainType::Company => BlockData::Company(
                    borsh::from_slice::<CompanyBlockEvent>(&decrypted.data)?.block,
                ),
            };
            Ok(data)
        } else {
            Err(Error::Blockchain(format!(
                "Invalid blockchain event {} {} expected {chain_id} {chain_type}",
                &payload.id, payload.chain_type
            )))
        }
    } else {
        Err(Error::Blockchain(
            "Could not unwrap payload from public chain event".to_string(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum BlockData {
    Bill(BillBlock),
    Identity(IdentityBlock),
    Company(CompanyBlock),
}

impl BlockData {
    pub fn get_block_height(&self) -> u64 {
        match self {
            BlockData::Bill(block) => block.id.inner(),
            BlockData::Identity(block) => block.id.inner(),
            BlockData::Company(block) => block.id.inner(),
        }
    }
    pub fn get_block_hash(&self) -> Sha256Hash {
        match self {
            BlockData::Bill(block) => block.hash.clone(),
            BlockData::Identity(block) => block.hash.clone(),
            BlockData::Company(block) => block.hash.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct EventContainer {
    pub event: nostr_sdk::Event,
    pub root_id: Option<EventId>,
    pub reply_id: Option<EventId>,
    pub children: Vec<EventContainer>,
    pub block: BlockData,
    pub block_height: u64,
}

impl EventContainer {
    pub fn new(
        event: nostr_sdk::Event,
        root_id: Option<EventId>,
        reply_id: Option<EventId>,
        block: BlockData,
    ) -> Self {
        let block_height = block.get_block_height();
        Self {
            event,
            root_id,
            reply_id,
            children: Vec::new(),
            block,
            block_height,
        }
    }

    pub fn is_root(&self) -> bool {
        self.root_id.is_none() && self.reply_id.is_none()
    }

    pub fn is_child_of(&self, event_id: &EventId) -> bool {
        match self.reply_id {
            Some(id) => &id == event_id,
            None => self.root_id.filter(|i| i == event_id).is_some(),
        }
    }

    pub fn with_children(self, children: Vec<EventContainer>) -> Self {
        Self {
            event: self.event,
            root_id: self.root_id,
            reply_id: self.reply_id,
            children,
            block: self.block,
            block_height: self.block_height,
        }
    }

    // given all markers recursively resolves all children
    pub fn resolve_children(self, markers: &[EventContainer]) -> Self {
        let mut children = Vec::new();
        markers
            .iter()
            .filter(|m| m.is_child_of(&self.event.id) && m.event.id != self.event.id)
            .for_each(|m| {
                let mut marker = m.clone();
                if m.children.is_empty() {
                    marker = m.clone().resolve_children(markers);
                }
                children.push(marker);
            });
        self.with_children(children)
    }

    // creates one or multiple chains from tree structure
    pub fn as_chains(&self) -> Vec<Vec<Self>> {
        if self.children.is_empty() {
            return vec![vec![self.clone()]];
        }

        let mut result = Vec::new();
        for child in self.children.iter() {
            let local_chain = vec![self.clone()];
            let chains = child.as_chains();
            for mut chain in chains {
                let mut current = local_chain.clone();
                current.append(&mut chain);
                result.push(current);
            }
        }
        result
    }

    pub fn as_chain_store_event(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
        block_height: usize,
        valid: bool,
    ) -> NostrChainEvent {
        NostrChainEvent {
            event_id: self.event.id.to_string(),
            root_id: self.root_id.unwrap_or(self.event.id).to_string(),
            reply_id: self.reply_id.map(|id| id.to_string()),
            author: self.event.pubkey.to_string(),
            chain_id: chain_id.to_string(),
            chain_type,
            block_height,
            block_hash: self.block.get_block_hash(),
            received: Timestamp::now(),
            time: self.event.created_at.into(),
            payload: self.event.clone(),
            valid,
        }
    }
}
