use super::incoming_chain_application::{
    decode_candidate_block, validate_incoming_block_integrity,
};
use crate::transport::root_and_reply_id;
use crate::transport::{decrypt_or_decode_public_chain_event, unwrap_public_chain_event};
use bcr_ebill_api::service::transport_service::transport_client::TransportClientApi;
use bcr_ebill_api::service::transport_service::{Error, Result};
use bcr_ebill_core::protocol::{
    BlockId, Sha256Hash, Timestamp,
    blockchain::{
        Block, BlockchainType, bill::BillBlock, company::CompanyBlock, identity::IdentityBlock,
    },
    crypto::BcrKeys,
    event::{BillBlockEvent, CompanyBlockEvent, IdentityBlockEvent},
};
use bcr_ebill_persistence::NostrChainEventStoreApi;
use bcr_ebill_persistence::traits::nostr::NostrChainEvent;
use nostr::{
    event::EventId,
    nips::nip10::{Marker, Nip10Tag},
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Compares two chains for sorting. Ordering is:
/// 1. Length descending (longer chain wins)
/// 2. Tip timestamp ascending (earlier wins)
/// 3. Tip hash ascending (deterministic tiebreaker)
pub fn compare_chains(a: &[EventContainer], b: &[EventContainer]) -> std::cmp::Ordering {
    b.len()
        .cmp(&a.len())
        .then_with(|| {
            let a_ts = a
                .last()
                .map(|e| e.block.get_block_timestamp())
                .unwrap_or(Timestamp::now());
            let b_ts = b
                .last()
                .map(|e| e.block.get_block_timestamp())
                .unwrap_or(Timestamp::now());
            a_ts.cmp(&b_ts)
        })
        .then_with(|| {
            let a_hash = a.last().map(|e| e.block.get_block_hash());
            let b_hash = b.last().map(|e| e.block.get_block_hash());
            a_hash.cmp(&b_hash)
        })
}

/// Same as compare chains, but on a block-chain level
/// Precedence is:
/// 1. Longer chain wins
/// 2. Earlier tip  wins
/// 3. Fork point at divergent hash
pub fn compare_block_chains<B: Block>(a: &[B], b: &[B]) -> std::cmp::Ordering {
    b.len()
        .cmp(&a.len())
        .then_with(|| match (a.last(), b.last()) {
            (Some(a_tip), Some(b_tip)) => a_tip.timestamp().cmp(&b_tip.timestamp()),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        })
        .then_with(|| match (a.last(), b.last()) {
            (Some(a_tip), Some(b_tip)) => a_tip.hash().cmp(b_tip.hash()),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        })
}

/// Finds the first difference between two chains and returns the block height of the differing block
pub fn find_first_difference<T: Block>(local: &[T], remote: &[T]) -> Option<BlockId> {
    for (local_block, remote_block) in local.iter().zip(remote.iter()) {
        if local_block.id() != remote_block.id() || local_block.hash() != remote_block.hash() {
            return Some(local_block.id());
        }
    }

    // Local chain has more blocks than Nostr, so difference starts at the latest shared block
    if local.len() > remote.len() {
        return Some(local[remote.len()].id());
    }

    None
}

/// Will query the transport for the public chain events and build up as many chains as needed for
/// the Nostr chain structure. This does not look into the actual blockchain, but will build the
/// chains just from Nostr metadata.
pub async fn resolve_event_chains(
    transport: Arc<dyn TransportClientApi>,
    chain_id: &str,
    chain_type: BlockchainType,
    keys: &Option<BcrKeys>,
) -> Result<Vec<Vec<EventContainer>>> {
    let events = transport.resolve_public_chain(chain_id, chain_type).await?;
    let mut chains = collect_event_chains(&events, chain_id, chain_type, keys);
    chains.sort_by(|a, b| compare_chains(a, b));
    Ok(chains)
}

// Will build up as many chains as needed for the Nostr chain structure. This does not look into
// the actual blockchain, but will build the chains just from Nostr metadata.
pub fn collect_event_chains(
    events: &[nostr::event::Event],
    chain_id: &str,
    chain_type: BlockchainType,
    keys: &Option<BcrKeys>,
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
    if let Some(root) = markers.iter().find(|v| v.is_root() && v.block_height == 1) {
        let remainder = markers.iter().filter(|v| !v.is_root()).cloned().collect();
        return Some((root.clone(), remainder));
    }
    None
}

// find root and reply note ids of given event
pub fn ids_and_markers(
    event: &nostr::event::Event,
    chain_id: &str,
    chain_type: BlockchainType,
    keys: &Option<BcrKeys>,
) -> Option<EventContainer> {
    if let Ok(block) = decode_block(event.clone(), chain_id, chain_type, keys) {
        let mut result = EventContainer::new(event.clone(), None, None, block);

        for tag in event
            .tags
            .iter()
            .filter_map(|tag| Nip10Tag::try_from(tag).ok())
        {
            let Nip10Tag::Event { id, marker, .. } = tag;
            match marker {
                Some(Marker::Root) => result.root_id = Some(id.to_owned()),
                Some(Marker::Reply) => result.reply_id = Some(id.to_owned()),
                _ => {}
            }
        }
        Some(result)
    } else {
        None
    }
}

pub fn decode_block(
    event: nostr::event::Event,
    chain_id: &str,
    chain_type: BlockchainType,
    keys: &Option<BcrKeys>,
) -> Result<BlockData> {
    if let Ok(Some(payload)) = unwrap_public_chain_event(&event) {
        if (payload.id == chain_id) && (payload.chain_type == chain_type) {
            let decoded = decrypt_or_decode_public_chain_event(&payload.payload, keys)?;
            let data = match chain_type {
                BlockchainType::Bill => {
                    BlockData::Bill(borsh::from_slice::<BillBlockEvent>(&decoded.data)?.block)
                }
                BlockchainType::Identity => BlockData::Identity(
                    borsh::from_slice::<IdentityBlockEvent>(&decoded.data)?.block,
                ),
                BlockchainType::Company => {
                    BlockData::Company(borsh::from_slice::<CompanyBlockEvent>(&decoded.data)?.block)
                }
            };
            Ok(data)
        } else {
            Err(Error::Blockchain(format!(
                "Invalid blockchain event {} {} expected {chain_id} {chain_type}",
                payload.id, payload.chain_type
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
    pub fn get_block_timestamp(&self) -> Timestamp {
        match self {
            BlockData::Bill(block) => block.timestamp,
            BlockData::Identity(block) => block.timestamp,
            BlockData::Company(block) => block.timestamp,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EventContainer {
    pub event: nostr::event::Event,
    pub root_id: Option<EventId>,
    pub reply_id: Option<EventId>,
    pub children: Vec<EventContainer>,
    pub block: BlockData,
    pub block_height: u64,
}

impl EventContainer {
    pub fn new(
        event: nostr::event::Event,
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
            .filter(|m| {
                let root_id = self.root_id.unwrap_or(self.event.id);
                m.event.id != self.event.id
                    && m.root_id == Some(root_id)
                    && m.is_child_of(&self.event.id)
                    && self.block_height.checked_add(1) == Some(m.block_height)
            })
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
        }
    }
}

fn decode_publishing_metadata(
    event: nostr::event::Event,
    received: Timestamp,
    chain_id: &str,
    chain_type: BlockchainType,
    keys: &Option<BcrKeys>,
) -> Option<(NostrChainEvent, Sha256Hash)> {
    if event.kind != nostr::event::Kind::TextNote || event.verify().is_err() {
        return None;
    }
    let public = unwrap_public_chain_event(&event).ok()??;
    if public.id != chain_id || public.chain_type != chain_type {
        return None;
    }
    let block = decode_candidate_block(&public, &None, event.pubkey)
        .or_else(|error| {
            if keys.is_some() {
                decode_candidate_block(&public, keys, event.pubkey)
            } else {
                Err(error)
            }
        })
        .ok()?;

    let previous_hash = match &block {
        BlockData::Bill(block) => {
            if block.bill_id.to_string() != chain_id {
                return None;
            }

            validate_incoming_block_integrity(block).ok()?;
            block.previous_hash().clone()
        }
        BlockData::Company(block) => {
            if block.company_id.to_string() != chain_id {
                return None;
            }

            validate_incoming_block_integrity(block).ok()?;
            block.previous_hash().clone()
        }
        BlockData::Identity(block) => {
            validate_incoming_block_integrity(block).ok()?;
            block.previous_hash().clone()
        }
    };

    let height = usize::try_from(block.get_block_height()).ok()?;
    if height == 0 {
        return None;
    }
    let (root, reply) = root_and_reply_id(&event);
    if height == 1 {
        if root.is_some() || reply.is_some() {
            return None;
        }
    } else if root.is_none() {
        return None;
    }
    let container = EventContainer::new(event, root, reply, block);
    let mut metadata = container.as_chain_store_event(chain_id, chain_type, height);
    metadata.received = received;
    Some((metadata, previous_hash))
}

pub(crate) fn eligible_publishing_events(
    events: impl IntoIterator<Item = (nostr::event::Event, Timestamp)>,
    chain_id: &str,
    chain_type: BlockchainType,
    keys: &Option<BcrKeys>,
) -> HashMap<String, NostrChainEvent> {
    let mut candidates = events
        .into_iter()
        .filter_map(|(event, received)| {
            decode_publishing_metadata(event, received, chain_id, chain_type, keys)
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(event, _)| event.block_height);
    let mut eligible: HashMap<String, NostrChainEvent> = HashMap::new();
    for (event, previous_hash) in candidates {
        if event.block_height == 1 {
            eligible.entry(event.event_id.clone()).or_insert(event);

            continue;
        }
        // A direct reply to genesis may only have a root tag
        let previous_id = event.reply_id.as_deref().unwrap_or(&event.root_id);
        let Some(previous) = eligible.get(previous_id) else {
            continue;
        };
        if previous.root_id != event.root_id
            || previous.block_hash != previous_hash
            || previous.block_height.checked_add(1) != Some(event.block_height)
        {
            continue;
        }
        eligible.entry(event.event_id.clone()).or_insert(event);
    }
    eligible
}

pub(crate) fn select_publishing_predecessor(
    eligible: &HashMap<String, NostrChainEvent>,
    previous_hash: &Sha256Hash,
    block_height: usize,
) -> (Option<NostrChainEvent>, Option<NostrChainEvent>) {
    let previous = eligible
        .values()
        .filter(|event| {
            &event.block_hash == previous_hash
                && event.block_height.checked_add(1) == Some(block_height)
        })
        .max_by(|a, b| {
            a.received
                .cmp(&b.received)
                .then_with(|| a.event_id.cmp(&b.event_id))
        });
    let Some(previous) = previous else {
        return (None, None);
    };
    let Some(root) = eligible.get(&previous.root_id) else {
        return (None, None);
    };
    (Some(previous.clone()), Some(root.clone()))
}

/// Make sure there is exactly one eligible path to nostr publishing
pub(crate) async fn restore_publishing_metadata<B: Block>(
    transport: &dyn TransportClientApi,
    store: &dyn NostrChainEventStoreApi,
    chain_id: &str,
    chain_type: BlockchainType,
    keys: &BcrKeys,
    local_blocks: &[B],
    up_to_hash: &Sha256Hash,
) -> Result<()> {
    let Some(end) = local_blocks
        .iter()
        .position(|block| block.hash() == up_to_hash)
    else {
        return Err(Error::Blockchain(format!(
            "Cannot restore Nostr metadata for {chain_type} {chain_id}: block {up_to_hash} not found locally"
        )));
    };
    let local_blocks = &local_blocks[..=end];
    let existing = store
        .find_chain_events(chain_id, chain_type)
        .await
        .map_err(|e| Error::Persistence(e.to_string()))?;
    // Deduplicate wrappers, not blockchain blocks
    let existing_ids: HashSet<String> = existing
        .iter()
        .map(|event| event.event_id.clone())
        .collect();
    let remote = transport.resolve_public_chain(chain_id, chain_type).await?;
    let now = Timestamp::now();
    let events = existing
        .into_iter()
        .map(|event| (event.payload, event.received))
        .chain(remote.into_iter().map(|event| (event, now)));
    let eligible = eligible_publishing_events(events, chain_id, chain_type, &Some(keys.clone()));
    let next_height = local_blocks.len() + 1;
    let (previous, _) = select_publishing_predecessor(&eligible, up_to_hash, next_height);
    let Some(mut current) = previous else {
        return Err(Error::Blockchain(format!(
            "Could not restore Nostr metadata for {chain_type} {chain_id}: no Nostr chain matches the local chain"
        )));
    };

    // Recover one complete path, working backwards from the requested predecessor to its actual root
    let mut path = Vec::with_capacity(local_blocks.len());
    loop {
        let local = local_blocks
            .get(current.block_height - 1)
            .ok_or_else(|| Error::Blockchain("Invalid Nostr metadata height".into()))?;
        if local.hash() != &current.block_hash || local.id().inner() != current.block_height as u64
        {
            return Err(Error::Blockchain(
                "Nostr metadata does not match local chain".into(),
            ));
        }
        let is_root = current.block_height == 1;
        let previous_id = current
            .reply_id
            .clone()
            .unwrap_or_else(|| current.root_id.clone());
        path.push(current);
        if is_root {
            break;
        }
        current = eligible
            .get(&previous_id)
            .cloned()
            .ok_or_else(|| Error::Blockchain("Missing eligible Nostr predecessor".into()))?;
    }

    // Insert root first, then its descendants
    path.reverse();
    let mut added = 0;
    for event in path {
        if existing_ids.contains(&event.event_id) {
            continue;
        }
        store
            .add_chain_event(event)
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;
        added += 1;
    }
    log::info!(
        "Restored {added} missing Nostr metadata entries for {chain_type} {chain_id} through {up_to_hash}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bcr_common::core::BillId;
    use bcr_ebill_core::protocol::{
        BlockId, Sha256Hash, Timestamp,
        blockchain::bill::{BillOpCode, block::BillBlock},
        crypto::BcrKeys,
    };
    use nostr::event::FinalizeEvent;
    use std::str::FromStr;

    fn bill_id_test() -> BillId {
        BillId::new(
            bitcoin::secp256k1::PublicKey::from_str(
                "026423b7d36d05b8d50a89a1b4ef2a06c88bcd2c5e650f25e122fa682d3b39686c",
            )
            .unwrap(),
            bitcoin::Network::Testnet,
        )
    }

    fn make_test_block(
        block_id: BlockId,
        prev_hash: Sha256Hash,
        timestamp: Timestamp,
    ) -> BillBlock {
        BillBlock::new(
            bill_id_test(),
            block_id,
            prev_hash,
            Vec::new(),
            BillOpCode::Issue,
            &BcrKeys::new(),
            None,
            &BcrKeys::new(),
            timestamp,
            Sha256Hash::new("test plaintext hash"),
        )
        .unwrap()
    }

    fn make_event_container(block: BillBlock) -> EventContainer {
        let nostr_event = nostr::event::EventBuilder::new(nostr::event::Kind::TextNote, "test")
            .finalize(&nostr::key::Keys::generate())
            .expect("test event");
        EventContainer::new(nostr_event, None, None, BlockData::Bill(block))
    }

    fn sort_chains(chains: &mut [Vec<EventContainer>]) {
        chains.sort_by(|a, b| compare_chains(a, b));
    }

    #[test]
    fn test_get_block_timestamp() {
        let ts = Timestamp::new(1731593928).unwrap();
        let block = make_test_block(BlockId::first(), Sha256Hash::new("genesis"), ts);
        let block_data = BlockData::Bill(block);
        assert_eq!(
            block_data.get_block_timestamp(),
            Timestamp::new(1731593928).unwrap()
        );
    }

    #[test]
    fn test_sort_different_length_chains() {
        let ts = Timestamp::new(1731593928).unwrap();
        let block1 = make_test_block(BlockId::first(), Sha256Hash::new("genesis"), ts);
        let block2 = make_test_block(
            BlockId::next_from_previous_block_id(&block1.id),
            block1.hash.clone(),
            Timestamp::new(1731593929).unwrap(),
        );

        // chain_a has 2 blocks, chain_b has 1 block
        let chain_a = vec![make_event_container(block1), make_event_container(block2)];
        let chain_b = vec![make_event_container(make_test_block(
            BlockId::first(),
            Sha256Hash::new("genesis2"),
            ts,
        ))];

        let mut chains = vec![chain_b, chain_a];
        sort_chains(&mut chains);

        // Longer chain (length 2) should come first
        assert_eq!(chains[0].len(), 2);
        assert_eq!(chains[1].len(), 1);
    }

    #[test]
    fn test_sort_equal_length_earlier_timestamp_wins() {
        let ts_early = Timestamp::new(1731593900).unwrap();
        let ts_late = Timestamp::new(1731593999).unwrap();

        let chain_a = vec![make_event_container(make_test_block(
            BlockId::first(),
            Sha256Hash::new("genesis_a"),
            ts_early,
        ))];
        let chain_b = vec![make_event_container(make_test_block(
            BlockId::first(),
            Sha256Hash::new("genesis_b"),
            ts_late,
        ))];

        let mut chains = vec![chain_b, chain_a];
        sort_chains(&mut chains);

        // Earlier timestamp should come first
        assert_eq!(
            chains[0][0].block.get_block_timestamp(),
            Timestamp::new(1731593900).unwrap()
        );
        assert_eq!(
            chains[1][0].block.get_block_timestamp(),
            Timestamp::new(1731593999).unwrap()
        );
    }

    #[test]
    fn test_sort_equal_length_two_blocks_earlier_timestamp_wins() {
        let ts = Timestamp::new(1731593928).unwrap();
        let ts_early = Timestamp::new(1731593950).unwrap();
        let ts_late = Timestamp::new(1731593999).unwrap();

        // Shared first block
        let block1 = make_test_block(BlockId::first(), Sha256Hash::new("genesis"), ts);

        // Chain A: block1 -> block2a (earlier tip timestamp)
        let block2a = make_test_block(
            BlockId::next_from_previous_block_id(&block1.id),
            block1.hash.clone(),
            ts_early,
        );
        let chain_a = vec![
            make_event_container(block1.clone()),
            make_event_container(block2a),
        ];

        // Chain B: block1 -> block2b (later tip timestamp)
        let block2b = make_test_block(
            BlockId::next_from_previous_block_id(&block1.id),
            block1.hash.clone(),
            ts_late,
        );
        let chain_b = vec![make_event_container(block1), make_event_container(block2b)];

        // Put chain_b first to verify sorting reorders them
        let mut chains = vec![chain_b, chain_a];
        sort_chains(&mut chains);

        // Earlier tip timestamp should come first
        assert_eq!(chains[0].len(), 2);
        assert_eq!(chains[1].len(), 2);
        assert_eq!(
            chains[0].last().unwrap().block.get_block_timestamp(),
            ts_early
        );
        assert_eq!(
            chains[1].last().unwrap().block.get_block_timestamp(),
            ts_late
        );
    }

    #[test]
    fn test_sort_equal_length_same_timestamp_smaller_hash_wins() {
        let ts = Timestamp::new(1731593928).unwrap();

        // Different BcrKeys::new() generates different keys → different hashes
        let chain_a = vec![make_event_container(make_test_block(
            BlockId::first(),
            Sha256Hash::new("genesis_x"),
            ts,
        ))];
        let chain_b = vec![make_event_container(make_test_block(
            BlockId::first(),
            Sha256Hash::new("genesis_y"),
            ts,
        ))];

        let mut chains = vec![chain_a, chain_b];
        sort_chains(&mut chains);

        // The chain with the smaller hash should come first
        assert!(chains[0][0].block.get_block_hash() <= chains[1][0].block.get_block_hash());
    }

    fn make_test_chain_with_timestamps(timestamps: &[u64]) -> Vec<BillBlock> {
        let mut blocks = Vec::new();
        let mut prev_hash = Sha256Hash::new("genesis");
        let mut block_id = BlockId::first();

        for ts in timestamps.iter() {
            let block = make_test_block(block_id, prev_hash.clone(), Timestamp::new(*ts).unwrap());
            prev_hash = block.hash.clone();
            block_id = BlockId::next_from_previous_block_id(&block_id);
            blocks.push(block);
        }
        blocks
    }

    #[test]
    fn test_find_first_difference_identical_chains() {
        let local = make_test_chain_with_timestamps(&[1000, 1500, 2000]);
        let remote = local.clone();

        let result = find_first_difference(&local, &remote);

        assert_eq!(result, None);
    }

    #[test]
    fn test_find_first_difference_remote_longer() {
        let local = make_test_chain_with_timestamps(&[1000, 1500, 2000]);
        let mut remote = local.clone();

        let block4 = make_test_block(
            BlockId::next_from_previous_block_id(&remote[2].id()),
            remote[2].hash.clone(),
            Timestamp::new(2500).unwrap(),
        );
        let block5 = make_test_block(
            BlockId::next_from_previous_block_id(&block4.id()),
            block4.hash.clone(),
            Timestamp::new(3000).unwrap(),
        );

        remote.push(block4);
        remote.push(block5);

        let result = find_first_difference(&local, &remote);

        // take blocks from remote, but nothing needs to change
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_first_difference_local_longer() {
        let remote = make_test_chain_with_timestamps(&[1000, 1500, 2000]);
        let mut local = remote.clone();

        let block4 = make_test_block(
            BlockId::next_from_previous_block_id(&local[2].id()),
            local[2].hash.clone(),
            Timestamp::new(2500).unwrap(),
        );
        let block5 = make_test_block(
            BlockId::next_from_previous_block_id(&block4.id()),
            block4.hash.clone(),
            Timestamp::new(3000).unwrap(),
        );

        local.push(block4);
        local.push(block5);

        let result = find_first_difference(&local, &remote);

        // extra local block 4 needs to be removed, so start at the difference at 3
        assert_eq!(result, Some(local[3].id()));
    }

    #[test]
    fn test_find_first_difference_fork() {
        let shared = make_test_chain_with_timestamps(&[1000, 1500]);

        let mut local = shared.clone();
        let mut remote = shared;

        let local_block3 = make_test_block(
            BlockId::next_from_previous_block_id(&local[1].id()),
            local[1].hash.clone(),
            Timestamp::new(2000).unwrap(),
        );
        let local_block4 = make_test_block(
            BlockId::next_from_previous_block_id(&local_block3.id()),
            local_block3.hash.clone(),
            Timestamp::new(2500).unwrap(),
        );

        let remote_block3 = make_test_block(
            BlockId::next_from_previous_block_id(&remote[1].id()),
            remote[1].hash.clone(),
            Timestamp::new(2100).unwrap(),
        );
        let remote_block4 = make_test_block(
            BlockId::next_from_previous_block_id(&remote_block3.id()),
            remote_block3.hash.clone(),
            Timestamp::new(2600).unwrap(),
        );
        let remote_block5 = make_test_block(
            BlockId::next_from_previous_block_id(&remote_block4.id()),
            remote_block4.hash.clone(),
            Timestamp::new(3000).unwrap(),
        );

        local.push(local_block3);
        local.push(local_block4);

        remote.push(remote_block3);
        remote.push(remote_block4);
        remote.push(remote_block5);

        let result = find_first_difference(&local, &remote);

        assert_eq!(result, Some(local[2].id()));
    }
}
