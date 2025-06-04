use std::sync::Arc;

use async_trait::async_trait;
use bcr_ebill_core::{
    ServiceTraitBounds,
    bill::BillKeys,
    blockchain::{BlockchainType, bill::BillBlock},
    util::BcrKeys,
};
use log::{debug, error, warn};
use nostr::{
    event::{EventId, TagKind, TagStandard},
    nips::nip10::Marker,
};

use crate::{
    Event, EventEnvelope, EventType, NotificationJsonTransportApi, Result,
    event::bill_blockchain_event::BillBlockEvent,
    event::bill_blockchain_event::ChainInvite,
    transport::{decrypt_public_chain_event, unwrap_public_chain_event},
};

use super::{BillChainEventProcessorApi, NotificationHandlerApi};

pub struct BillInviteEventHandler {
    transport: Arc<dyn NotificationJsonTransportApi>,
    processor: Arc<dyn BillChainEventProcessorApi>,
}

impl BillInviteEventHandler {
    pub fn new(
        transport: Arc<dyn NotificationJsonTransportApi>,
        processor: Arc<dyn BillChainEventProcessorApi>,
    ) -> Self {
        Self {
            transport,
            processor,
        }
    }
}

impl ServiceTraitBounds for BillInviteEventHandler {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationHandlerApi for BillInviteEventHandler {
    fn handles_event(&self, event_type: &EventType) -> bool {
        event_type == &EventType::BillChainInvite
    }

    async fn handle_event(&self, event: EventEnvelope, node_id: &str) -> Result<()> {
        debug!("incoming bill chain invite for {node_id}");
        if let Ok(decoded) = Event::<ChainInvite>::try_from(event.clone()) {
            if let Ok(keys) = BcrKeys::from_private_key(&decoded.data.keys.private_key) {
                let data = self
                    .transport
                    .resolve_public_chain(&decoded.data.chain_id, decoded.data.chain_type)
                    .await?;
                if let Ok(blocks) = extract_blocks(
                    &data,
                    &keys,
                    &decoded.data.chain_id,
                    decoded.data.chain_type,
                ) {
                    if !blocks.is_empty() {
                        self.processor
                            .process_chain_data(
                                &decoded.data.chain_id,
                                blocks,
                                Some(BillKeys {
                                    public_key: decoded.data.keys.public_key,
                                    private_key: decoded.data.keys.private_key,
                                }),
                            )
                            .await?;
                    }
                }
            } else {
                error!(
                    "Received invalid chain keys for chain {} {}",
                    &decoded.data.chain_id, &decoded.data.chain_type
                );
            }
        } else {
            warn!("Could not decode event to ChainInvite {event:?}");
        }
        Ok(())
    }
}

fn extract_blocks(
    events: &[nostr_sdk::Event],
    keys: &BcrKeys,
    chain_id: &str,
    chain_type: BlockchainType,
) -> Result<Vec<BillBlock>> {
    let mut result = Vec::new();
    for event in events {
        if let Ok(Some(payload)) = unwrap_public_chain_event(Box::new(event.clone())) {
            if (payload.id == chain_id) && (payload.chain_type == chain_type) {
                if let Ok(decrypted) = decrypt_public_chain_event(&payload.payload, keys) {
                    let event: BillBlockEvent = serde_json::from_value(decrypted.data)?;
                    result.push(event.block);
                }
            }
        }
    }
    result.sort_by_key(|v| v.timestamp);
    Ok(result)
}

#[allow(dead_code)]
// assumes that events are sorted by timestamp already. Will build up as many chains as needed
// for the Nostr chain structure. This does not look into the actual blockchain, but will
// the chain just from Nostr metadata.
fn collect_event_chains(events: &[nostr_sdk::Event]) -> Vec<Vec<nostr_sdk::Event>> {
    let mut result = Vec::new();
    let markers: Vec<EventIdMarkers> = events.iter().map(ids_and_markers).collect();
    if let Some((mut root, children)) = split_root(&markers) {
        let chains = root.resolve_children(&children);
        result = chains.resolve_events();
    }
    result
}

fn split_root(markers: &[EventIdMarkers]) -> Option<(EventIdMarkers, Vec<EventIdMarkers>)> {
    if let Some(root) = markers.iter().find(|v| v.is_root()) {
        let remainder = markers.iter().filter(|v| !v.is_root()).cloned().collect();
        return Some((root.clone(), remainder));
    }
    None
}

// find root and reply note ids of given event
fn ids_and_markers(event: &nostr_sdk::Event) -> EventIdMarkers {
    let mut result = EventIdMarkers::new(event.clone(), None, None);
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
    result
}

#[derive(Clone, Debug)]
struct EventIdMarkers {
    pub event: nostr_sdk::Event,
    pub root_id: Option<EventId>,
    pub reply_id: Option<EventId>,
    pub children: Vec<EventIdMarkers>,
}

impl EventIdMarkers {
    fn new(event: nostr_sdk::Event, root_id: Option<EventId>, reply_id: Option<EventId>) -> Self {
        Self {
            event,
            root_id,
            reply_id,
            children: Vec::new(),
        }
    }

    fn is_root(&self) -> bool {
        self.root_id.is_none() && self.reply_id.is_none()
    }

    fn is_child_of(&self, event_id: &EventId) -> bool {
        let compare = Some(event_id.to_owned());
        self.root_id == compare || self.reply_id == compare
    }

    fn with_children(&self, children: Vec<EventIdMarkers>) -> Self {
        Self {
            event: self.event.clone(),
            root_id: self.root_id,
            reply_id: self.reply_id,
            children,
        }
    }

    // given all markers rcursively resolves all children
    fn resolve_children(&mut self, markers: &[EventIdMarkers]) -> Self {
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

    // given all children are resolved, resolve all events and
    // creates one or multiple event chains
    fn resolve_events(&self) -> Vec<Vec<nostr_sdk::Event>> {
        if self.children.is_empty() {
            return vec![vec![self.event.clone()]];
        }

        let mut result = Vec::new();
        for child in self.children.iter() {
            let local_chain = vec![self.event.clone()];
            let chains = child.resolve_events();
            for mut chain in chains {
                let mut current = local_chain.clone();
                current.append(&mut chain);
                result.push(current);
            }
        }
        result
    }
}
