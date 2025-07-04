use std::{cmp::Reverse, collections::HashMap, str::FromStr, sync::Arc};

use async_trait::async_trait;
use bcr_ebill_core::{
    NodeId, ServiceTraitBounds,
    bill::{BillId, BillKeys},
    blockchain::{BlockchainType, bill::BillBlock},
    util::{BcrKeys, date::now},
};
use bcr_ebill_persistence::{NostrChainEventStoreApi, nostr::NostrChainEvent};
use log::{debug, error, warn};
use nostr::{
    event::{EventId, TagKind, TagStandard},
    nips::nip10::Marker,
};

use crate::{
    Error, Event, EventEnvelope, EventType, NotificationJsonTransportApi, Result,
    event::blockchain_event::{BillBlockEvent, ChainInvite, ChainKeys},
    transport::{decrypt_public_chain_event, unwrap_public_chain_event},
};

use super::{BillChainEventProcessorApi, NotificationHandlerApi};

pub struct BillInviteEventHandler {
    transport: Arc<dyn NotificationJsonTransportApi>,
    processor: Arc<dyn BillChainEventProcessorApi>,
    chain_event_store: Arc<dyn NostrChainEventStoreApi>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationHandlerApi for BillInviteEventHandler {
    fn handles_event(&self, event_type: &EventType) -> bool {
        event_type == &EventType::BillChainInvite
    }

    async fn handle_event(
        &self,
        event: EventEnvelope,
        node_id: &NodeId,
        _: Box<nostr::Event>,
    ) -> Result<()> {
        debug!("incoming bill chain invite for {node_id}");
        if let Ok(decoded) = Event::<ChainInvite>::try_from(event.clone()) {
            let events = self
                .transport
                .resolve_public_chain(&decoded.data.chain_id, decoded.data.chain_type)
                .await?;

            let mut inserted_chain: Vec<EventContainer> = Vec::new();
            if let Ok(chain_data) = self
                .resolve_chain_data(
                    &decoded.data.keys,
                    &decoded.data.chain_id,
                    decoded.data.chain_type,
                    &events,
                )
                .await
            {
                // We try to add shorter and shorter chains until we have a success
                for data in chain_data.iter() {
                    let blocks = data.iter().map(|d| d.block.clone()).collect();
                    if !data.is_empty()
                        && self
                            .processor
                            .process_chain_data(
                                &BillId::from_str(&decoded.data.chain_id)?,
                                blocks,
                                Some(BillKeys {
                                    public_key: decoded.data.keys.public_key.to_owned(),
                                    private_key: decoded.data.keys.private_key.to_owned(),
                                }),
                            )
                            .await
                            .is_ok()
                    {
                        inserted_chain = data.to_owned();
                        break;
                    }
                }
                // we are onboarded to the chain so store all Nostr chain data also the invalid one
                if let Err(e) = self
                    .store_events(
                        &decoded.data.chain_id,
                        decoded.data.chain_type,
                        inserted_chain,
                        &chain_data,
                    )
                    .await
                {
                    error!("Error storing chain events: {e}");
                }
            } else {
                error!("Could not extract chain data for invite event {event:?}");
            }
        } else {
            warn!("Could not decode event to ChainInvite {event:?}");
        }
        Ok(())
    }
}

impl ServiceTraitBounds for BillInviteEventHandler {}

impl BillInviteEventHandler {
    pub fn new(
        transport: Arc<dyn NotificationJsonTransportApi>,
        processor: Arc<dyn BillChainEventProcessorApi>,
        chain_event_store: Arc<dyn NostrChainEventStoreApi>,
    ) -> Self {
        Self {
            transport,
            processor,
            chain_event_store,
        }
    }

    /// Parses chain keys, resolves all Nostr events and builds Nostr chains from it.
    /// Then decrypts the payloads and parses the block contents. Returns all found chains
    /// in descending order by chain length.
    async fn resolve_chain_data(
        &self,
        keys: &ChainKeys,
        chain_id: &str,
        chain_type: BlockchainType,
        events: &[nostr_sdk::Event],
    ) -> Result<Vec<Vec<EventContainer>>> {
        let keys = BcrKeys::from_private_key(&keys.private_key)?;
        let mut chains = collect_event_chains(events, chain_id, chain_type, &keys);
        chains.sort_by_key(|v| Reverse(v.len()));
        Ok(chains)
    }

    async fn store_events(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
        inserted_chain: Vec<EventContainer>,
        chains: &[Vec<EventContainer>],
    ) -> Result<()> {
        let mut to_insert: HashMap<String, NostrChainEvent> = HashMap::new();

        // first store the inserted valid blocks
        for (idx, inserted) in inserted_chain.iter().enumerate() {
            let data = inserted.as_chain_store_event(chain_id, chain_type, idx + 1, true);
            to_insert.insert(data.event_id.to_owned(), data);
        }

        // then store all malicious or invalid blocks with their pretended block height
        for chain in chains {
            for (idx, data) in chain.iter().enumerate() {
                if !to_insert.contains_key(&data.event.id.to_string()) {
                    let data = data.as_chain_store_event(chain_id, chain_type, idx + 1, false);
                    to_insert.insert(data.event_id.to_owned(), data);
                }
            }
        }

        for (_, data) in to_insert {
            if let Err(e) = self.chain_event_store.add_chain_event(data).await {
                debug!("Could not store chain event because {e}")
            }
        }
        Ok(())
    }
}

// Will build up as many chains as needed for the Nostr chain structure. This does not look into
// the actual blockchain, but will build the chains just from Nostr metadata.
fn collect_event_chains(
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

fn split_root(markers: &[EventContainer]) -> Option<(EventContainer, Vec<EventContainer>)> {
    if let Some(root) = markers.iter().find(|v| v.is_root()) {
        let remainder = markers.iter().filter(|v| !v.is_root()).cloned().collect();
        return Some((root.clone(), remainder));
    }
    None
}

// find root and reply note ids of given event
fn ids_and_markers(
    event: &nostr_sdk::Event,
    chain_id: &str,
    chain_type: BlockchainType,
    keys: &BcrKeys,
) -> Option<EventContainer> {
    if let Ok((block, height)) = decrypt_block(event.clone(), chain_id, chain_type, keys) {
        let mut result = EventContainer::new(event.clone(), None, None, block, height);
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

fn decrypt_block(
    event: nostr_sdk::Event,
    chain_id: &str,
    chain_type: BlockchainType,
    keys: &BcrKeys,
) -> Result<(BillBlock, usize)> {
    if let Ok(Some(payload)) = unwrap_public_chain_event(Box::new(event.clone())) {
        if (payload.id == chain_id) && (payload.chain_type == chain_type) {
            let decrypted = decrypt_public_chain_event(&payload.payload, keys)?;
            let event: BillBlockEvent = serde_json::from_value(decrypted.data)?;
            Ok((event.block, event.block_height))
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

#[derive(Clone, Debug)]
struct EventContainer {
    pub event: nostr_sdk::Event,
    pub root_id: Option<EventId>,
    pub reply_id: Option<EventId>,
    pub children: Vec<EventContainer>,
    pub block: BillBlock,
    pub block_height: usize,
}

impl EventContainer {
    fn new(
        event: nostr_sdk::Event,
        root_id: Option<EventId>,
        reply_id: Option<EventId>,
        block: BillBlock,
        block_height: usize,
    ) -> Self {
        Self {
            event,
            root_id,
            reply_id,
            children: Vec::new(),
            block,
            block_height,
        }
    }

    fn is_root(&self) -> bool {
        self.root_id.is_none() && self.reply_id.is_none()
    }

    fn is_child_of(&self, event_id: &EventId) -> bool {
        match self.reply_id {
            Some(id) => &id == event_id,
            None => self.root_id.filter(|i| i == event_id).is_some(),
        }
    }

    fn with_children(self, children: Vec<EventContainer>) -> Self {
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
    fn resolve_children(self, markers: &[EventContainer]) -> Self {
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
    fn as_chains(&self) -> Vec<Vec<Self>> {
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

    fn as_chain_store_event(
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
            block_hash: self.block.hash.to_string(),
            received: now().timestamp() as u64,
            time: self.event.created_at.as_u64(),
            payload: self.event.clone(),
            valid,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        handler::{
            MockBillChainEventProcessorApi,
            test_utils::{
                MockNostrChainEventStore, bill_id_test, get_bill_keys, get_genesis_chain,
                node_id_test, private_key_test,
            },
        },
        transport::{MockNotificationJsonTransportApi, create_public_chain_event},
    };

    use super::*;
    use bcr_ebill_core::{blockchain::Blockchain, util::crypto::BcrKeys};
    use mockall::predicate::eq;

    #[test]
    fn test_single_block() {
        let (keys, chain) = generate_test_chain(1, false);
        let chains = collect_event_chains(
            &chain,
            &bill_id_test().to_string(),
            BlockchainType::Bill,
            &keys,
        );
        assert_eq!(chains.len(), 1, "should contain a single valid chain");
        let result_chain = chains.first().unwrap();
        assert_eq!(result_chain.len(), 1, "chain should contain a single event");
    }

    #[test]
    fn test_multiple_valid_blocks() {
        let (keys, chain) = generate_test_chain(3, false);
        let chains = collect_event_chains(
            &chain,
            &bill_id_test().to_string(),
            BlockchainType::Bill,
            &keys,
        );

        assert_eq!(chains.len(), 1, "should contain a single valid chain");
        let result_chain = chains.first().unwrap();
        assert_eq!(result_chain.len(), 3, "chain should contain 3 events");
    }

    #[test]
    fn test_multiple_chains() {
        let (keys, chain) = generate_test_chain(3, true);
        let chains = collect_event_chains(
            &chain,
            &bill_id_test().to_string(),
            BlockchainType::Bill,
            &keys,
        );

        assert_eq!(chains.len(), 2, "should contain two valid chains");
        for chain in chains {
            assert_eq!(chain.len(), 3, "chain should contain 3 events");
        }
    }

    #[tokio::test]
    async fn test_process_single_event_chain_invite() {
        let (mut transport, mut processor, mut chain_event_store) = get_mocks();

        let node_id = node_id_test();
        let (_, chain) = generate_test_chain(1, false);

        // get events from nostr
        transport
            .expect_resolve_public_chain()
            .with(eq(bill_id_test().to_string()), eq(BlockchainType::Bill))
            .returning(move |_, _| Ok(chain.clone()));

        // process blocks
        processor
            .expect_process_chain_data()
            .withf(|bill_id, blocks, keys| {
                bill_id == &bill_id_test()
                    && blocks.len() == 1
                    && keys.clone().unwrap().public_key.to_string()
                        == get_bill_keys().public_key.to_string()
            })
            .returning(|_, _, _| Ok(()));

        // store events
        chain_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()))
            .times(1);

        let event = generate_test_event(&BcrKeys::new(), None, None, 1);
        let invite = Event::new_invite(ChainInvite::bill(
            bill_id_test().to_string(),
            get_bill_keys(),
        ))
        .try_into()
        .expect("failed to create envelope");

        let handler = BillInviteEventHandler::new(
            Arc::new(transport),
            Arc::new(processor),
            Arc::new(chain_event_store),
        );
        handler
            .handle_event(invite, &node_id, Box::new(event.clone()))
            .await
            .expect("failed to process chain invite event");
    }

    #[tokio::test]
    async fn test_process_single_chain_invite() {
        let (mut transport, mut processor, mut chain_event_store) = get_mocks();

        let node_id = node_id_test();
        let (_, chain) = generate_test_chain(3, false);

        // get events from nostr
        transport
            .expect_resolve_public_chain()
            .with(eq(bill_id_test().to_string()), eq(BlockchainType::Bill))
            .returning(move |_, _| Ok(chain.clone()));

        // process blocks
        processor
            .expect_process_chain_data()
            .withf(|bill_id, blocks, keys| {
                bill_id == &bill_id_test()
                    && blocks.len() == 3
                    && keys.clone().unwrap().public_key.to_string()
                        == get_bill_keys().public_key.to_string()
            })
            .returning(|_, _, _| Ok(()));

        // store events
        chain_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()))
            .times(3);

        let event = generate_test_event(&BcrKeys::new(), None, None, 1);
        let invite = Event::new_invite(ChainInvite::bill(
            bill_id_test().to_string(),
            get_bill_keys(),
        ))
        .try_into()
        .expect("failed to create envelope");

        let handler = BillInviteEventHandler::new(
            Arc::new(transport),
            Arc::new(processor),
            Arc::new(chain_event_store),
        );
        handler
            .handle_event(invite, &node_id, Box::new(event.clone()))
            .await
            .expect("failed to process chain invite event");
    }

    #[tokio::test]
    async fn test_process_multiple_chains_invite() {
        let (mut transport, mut processor, mut chain_event_store) = get_mocks();

        let node_id = node_id_test();
        let (_, chain) = generate_test_chain(3, true);

        // get events from nostr
        transport
            .expect_resolve_public_chain()
            .with(eq(bill_id_test().to_string()), eq(BlockchainType::Bill))
            .returning(move |_, _| Ok(chain.clone()));

        // process blocks
        processor
            .expect_process_chain_data()
            .withf(|bill_id, blocks, keys| {
                bill_id == &bill_id_test()
                    && blocks.len() == 3
                    && keys.clone().unwrap().public_key.to_string()
                        == get_bill_keys().public_key.to_string()
            })
            .returning(|_, _, _| Ok(()));

        // store valid events
        chain_event_store
            .expect_add_chain_event()
            .withf(|e| e.valid)
            .returning(|_| Ok(()))
            .times(3);

        // store invalid events
        chain_event_store
            .expect_add_chain_event()
            .withf(|e| !e.valid)
            .returning(|_| Ok(()))
            .times(1);

        let event = generate_test_event(&BcrKeys::new(), None, None, 1);
        let invite = Event::new_invite(ChainInvite::bill(
            bill_id_test().to_string(),
            get_bill_keys(),
        ))
        .try_into()
        .expect("failed to create envelope");

        let handler = BillInviteEventHandler::new(
            Arc::new(transport),
            Arc::new(processor),
            Arc::new(chain_event_store),
        );
        handler
            .handle_event(invite, &node_id, Box::new(event.clone()))
            .await
            .expect("failed to process chain invite event");
    }

    fn get_mocks() -> (
        MockNotificationJsonTransportApi,
        MockBillChainEventProcessorApi,
        MockNostrChainEventStore,
    ) {
        (
            MockNotificationJsonTransportApi::new(),
            MockBillChainEventProcessorApi::new(),
            MockNostrChainEventStore::new(),
        )
    }

    // generates event chains. If invalid blocks is enabled chains of size 3 will have two equal
    // valid chains. From there on len even gives one valid and N - 2 invalid (shorter) chains.
    // Uneven give two valid (equal len) and N - 1 invalid chains.
    fn generate_test_chain(len: usize, invalid_blocks: bool) -> (BcrKeys, Vec<nostr::Event>) {
        let keys = BcrKeys::from_private_key(&private_key_test())
            .expect("failed to generate keys from private key");
        let mut result = Vec::new();

        let root = generate_test_event(&keys, None, None, 1);
        result.push(root.clone());

        let mut parent = root.clone();
        for idx in 1..len {
            let child =
                generate_test_event(&keys, Some(parent.clone()), Some(root.clone()), idx + 1);
            result.push(child.clone());
            // produce some side chain
            if invalid_blocks && idx % 2 == 0 {
                let invalid =
                    generate_test_event(&keys, Some(parent.clone()), Some(root.clone()), idx + 1);
                result.push(invalid);
            }
            parent = child;
        }

        (keys, result)
    }

    #[allow(dead_code)]
    fn print_chains(chains: Vec<Vec<EventContainer>>) {
        for (idx, chain) in chains.iter().enumerate() {
            println!("CHAIN: {idx}");
            for (edx, evt) in chain.iter().enumerate() {
                println!(
                    "Evt {edx}: {:?} {:?} {:?} {}",
                    evt.root_id,
                    evt.event.id,
                    evt.reply_id,
                    evt.children.len()
                );
            }
        }
    }

    fn generate_test_event(
        keys: &BcrKeys,
        previous: Option<nostr::Event>,
        root: Option<nostr::Event>,
        height: usize,
    ) -> nostr::Event {
        create_public_chain_event(
            &bill_id_test().to_string(),
            generate_test_block(height),
            1000,
            BlockchainType::Bill,
            keys.clone(),
            previous,
            root,
        )
        .expect("could not create chain event")
        .sign_with_keys(&keys.get_nostr_keys())
        .expect("could not sign event")
    }

    fn generate_test_block(block_height: usize) -> EventEnvelope {
        let block = get_genesis_chain(None)
            .blocks()
            .first()
            .expect("could not get block")
            .clone();

        Event::new_chain(BillBlockEvent {
            bill_id: bill_id_test(),
            block: block.clone(),
            block_height,
        })
        .try_into()
        .expect("could not create envelope")
    }
}
