use std::{str::FromStr, sync::Arc};

use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::{
        ProtocolValidationError,
        blockchain::{BlockchainType, bill::BillBlock},
        crypto::BcrKeys,
        event::{ChainInvite, Event, EventEnvelope},
    },
};
use bcr_ebill_persistence::NostrChainEventStoreApi;
use log::{debug, error, warn};

use crate::{
    EventType,
    handler::public_chain_helpers::{BlockData, EventContainer, compare_block_chains},
};
use bcr_ebill_api::service::transport_service::Result;

use super::{BillChainEventProcessorApi, NotificationHandlerApi};

#[derive(Clone)]
pub struct BillInviteEventHandler {
    processor: Arc<dyn BillChainEventProcessorApi>,
    chain_event_store: Arc<dyn NostrChainEventStoreApi>,
}

#[derive(Debug)]
struct BillInviteCandidate {
    chain_index: usize,
    blocks: Vec<BillBlock>,
    accepted_event_count: usize,
}

#[async_trait]
impl NotificationHandlerApi for BillInviteEventHandler {
    fn handles_event(&self, event_type: &EventType) -> bool {
        event_type == &EventType::BillChainInvite
    }

    async fn handle_event(
        &self,
        event: EventEnvelope,
        node_id: &NodeId,
        _sender: Option<nostr::key::PublicKey>,
        _: Option<Box<nostr::event::Event>>,
    ) -> Result<()> {
        debug!("incoming bill chain invite for {node_id}");
        let Ok(decoded) = Event::<ChainInvite>::try_from(event.clone()) else {
            warn!("Could not decode event to ChainInvite {event:?}");
            return Ok(());
        };
        let keys = BcrKeys::from_private_key(&decoded.data.keys.private_key);
        let chain_id =
            BillId::from_str(&decoded.data.chain_id).map_err(ProtocolValidationError::from)?;
        let chain_data = match self.processor.resolve_chain(&chain_id, &keys).await {
            Ok(chains) => chains,
            Err(e) => {
                error!("Could not extract chain data for invite event {event:?}: {e}");
                return Ok(());
            }
        };

        let mut candidates = Vec::new();
        // Validate every Nostr branch before persisting any of them
        for (chain_index, data) in chain_data.iter().enumerate() {
            let mut blocks: Vec<BillBlock> = data
                .iter()
                .filter_map(|event_container| match &event_container.block {
                    BlockData::Bill(block) => Some(block.clone()),
                    _ => None,
                })
                .collect();
            if blocks.is_empty() {
                continue;
            }
            let accepted_count = match self
                .processor
                .valid_chain_prefix_len(&chain_id, &blocks, &keys)
                .await
            {
                Ok(count) if count > 0 => count,
                Ok(_) => continue,
                Err(e) => {
                    debug!(
                        "Ignoring bill invite chain candidate with no valid prefix for {chain_id}: {e}"
                    );
                    continue;
                }
            };

            // truncate blocks and metadata
            blocks.truncate(accepted_count);
            candidates.push(BillInviteCandidate {
                chain_index,
                blocks,
                accepted_event_count: accepted_count,
            });
        }

        // select best chain
        candidates.sort_by(|a, b| compare_block_chains(&a.blocks, &b.blocks));
        let Some(selected) = candidates.into_iter().next() else {
            debug!("No valid bill chain candidate found for invite {chain_id}");
            return Ok(());
        };

        let selected_chain_index = selected.chain_index;
        let accepted_event_count = selected.accepted_event_count;

        // only persist the winning candidate
        self.processor
            .process_chain_data(&chain_id, selected.blocks, Some(keys))
            .await?;

        // we are onboarded to the chain so store all valid Nostr chain data
        if let Err(e) = self
            .store_events(
                &decoded.data.chain_id,
                decoded.data.chain_type,
                &chain_data[selected_chain_index],
                accepted_event_count,
            )
            .await
        {
            error!("Error storing bill chain events: {e}");
        }
        Ok(())
    }
}

impl ServiceTraitBounds for BillInviteEventHandler {}

impl BillInviteEventHandler {
    pub fn new(
        processor: Arc<dyn BillChainEventProcessorApi>,
        chain_event_store: Arc<dyn NostrChainEventStoreApi>,
    ) -> Self {
        Self {
            processor,
            chain_event_store,
        }
    }

    async fn store_events(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
        chain: &[EventContainer],
        accepted_event_count: usize,
    ) -> Result<()> {
        for event_container in chain
            .iter()
            .filter(|event_container| matches!(event_container.block, BlockData::Bill(_)))
            .take(accepted_event_count)
        {
            let data = event_container.as_chain_store_event(
                chain_id,
                chain_type,
                event_container.block.get_block_height() as usize,
            );
            if let Err(e) = self.chain_event_store.add_chain_event(data).await {
                debug!("Could not store bill chain event because {e}");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{
        handler::{
            MockBillChainEventProcessorApi,
            public_chain_helpers::collect_event_chains,
            test_utils::{
                MockNostrChainEventStore, bill_id_test, get_bill_keys, get_genesis_chain,
                node_id_test, private_key_test,
            },
        },
        transport::create_public_chain_event,
    };

    use super::*;
    use bcr_ebill_core::protocol::event::BillBlockEvent;
    use bcr_ebill_core::{
        protocol::Timestamp, protocol::blockchain::Blockchain, protocol::crypto::BcrKeys,
    };
    use mockall::predicate::{always, eq};
    use nostr::event::FinalizeEvent;

    #[test]
    fn test_single_block() {
        let (_keys, chain) = generate_test_chain(1, false);
        let chains = collect_event_chains(
            &chain,
            &bill_id_test().to_string(),
            BlockchainType::Bill,
            &None,
        );
        assert_eq!(chains.len(), 1, "should contain a single valid chain");
        let result_chain = chains.first().unwrap();
        assert_eq!(result_chain.len(), 1, "chain should contain a single event");
    }

    #[test]
    fn test_multiple_valid_blocks() {
        let (_keys, chain) = generate_test_chain(3, false);
        let chains = collect_event_chains(
            &chain,
            &bill_id_test().to_string(),
            BlockchainType::Bill,
            &None,
        );

        assert_eq!(chains.len(), 1, "should contain a single valid chain");
        let result_chain = chains.first().unwrap();
        assert_eq!(result_chain.len(), 3, "chain should contain 3 events");
    }

    #[test]
    fn test_multiple_chains() {
        let (_keys, chain) = generate_test_chain(3, true);
        let chains = collect_event_chains(
            &chain,
            &bill_id_test().to_string(),
            BlockchainType::Bill,
            &None,
        );

        assert_eq!(chains.len(), 2, "should contain two valid chains");
        for chain in chains {
            assert_eq!(chain.len(), 3, "chain should contain 3 events");
        }
    }

    #[tokio::test]
    async fn test_process_single_event_chain_invite() {
        let (mut processor, mut chain_event_store) = get_mocks();

        let node_id = node_id_test();
        let (_bcr_keys, chain) = generate_test_chain(1, false);
        let chains = collect_event_chains(
            &chain,
            &bill_id_test().to_string(),
            BlockchainType::Bill,
            &None,
        );

        // get events from nostr
        processor
            .expect_resolve_chain()
            .with(eq(bill_id_test()), always())
            .returning(move |_, _| Ok(chains.clone()));

        // process blocks
        processor
            .expect_process_chain_data()
            .withf(|bill_id, blocks, keys| {
                bill_id == &bill_id_test()
                    && blocks.len() == 1
                    && keys.clone().unwrap().pub_key().to_string()
                        == get_bill_keys().pub_key().to_string()
            })
            .once()
            .returning(|_, _, _| Ok(()));

        processor
            .expect_valid_chain_prefix_len()
            .withf(|bill_id, blocks, keys| {
                bill_id == &bill_id_test()
                    && blocks.len() == 1
                    && keys.pub_key() == get_bill_keys().pub_key()
            })
            .once()
            .returning(|_, _, _| Ok(1));

        chain_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()))
            .times(1);

        let event = generate_test_event(&BcrKeys::new(), None, None, 1);
        let invite = Event::new_bill_invite(ChainInvite::bill(
            bill_id_test().to_string(),
            get_bill_keys(),
        ))
        .try_into()
        .expect("failed to create envelope");

        let handler = BillInviteEventHandler::new(Arc::new(processor), Arc::new(chain_event_store));
        handler
            .handle_event(invite, &node_id, None, Some(Box::new(event.clone())))
            .await
            .expect("failed to process chain invite event");
    }

    #[tokio::test]
    async fn test_process_single_chain_invite() {
        let (mut processor, mut chain_event_store) = get_mocks();

        let node_id = node_id_test();
        let (_bcr_keys, chain) = generate_test_chain(3, false);
        let chains = collect_event_chains(
            &chain,
            &bill_id_test().to_string(),
            BlockchainType::Bill,
            &None,
        );

        // get events from nostr
        processor
            .expect_resolve_chain()
            .with(eq(bill_id_test()), always())
            .returning(move |_, _| Ok(chains.clone()));

        processor
            .expect_valid_chain_prefix_len()
            .withf(|bill_id, blocks, keys| {
                bill_id == &bill_id_test()
                    && blocks.len() == 3
                    && keys.pub_key() == get_bill_keys().pub_key()
            })
            .once()
            .returning(|_, _, _| Ok(3));

        processor
            .expect_process_chain_data()
            .withf(|bill_id, blocks, keys| {
                bill_id == &bill_id_test()
                    && blocks.len() == 3
                    && keys.as_ref().map(|k| k.pub_key()) == Some(get_bill_keys().pub_key())
            })
            .once()
            .returning(|_, _, _| Ok(()));

        // store events
        chain_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()))
            .times(3);

        let event = generate_test_event(&BcrKeys::new(), None, None, 1);
        let invite = Event::new_bill_invite(ChainInvite::bill(
            bill_id_test().to_string(),
            get_bill_keys(),
        ))
        .try_into()
        .expect("failed to create envelope");

        let handler = BillInviteEventHandler::new(Arc::new(processor), Arc::new(chain_event_store));
        handler
            .handle_event(invite, &node_id, None, Some(Box::new(event.clone())))
            .await
            .expect("failed to process chain invite event");
    }

    #[tokio::test]
    async fn test_process_multiple_chains_invite() {
        let (mut processor, mut chain_event_store) = get_mocks();

        let node_id = node_id_test();
        let (_bcr_keys, chain) = generate_test_chain(3, true);
        let chains = collect_event_chains(
            &chain,
            &bill_id_test().to_string(),
            BlockchainType::Bill,
            &None,
        );

        // get events from nostr
        processor
            .expect_resolve_chain()
            .with(eq(bill_id_test()), always())
            .returning(move |_, _| Ok(chains.clone()));

        processor
            .expect_valid_chain_prefix_len()
            .withf(|bill_id, blocks, keys| {
                bill_id == &bill_id_test()
                    && blocks.len() == 3
                    && keys.pub_key() == get_bill_keys().pub_key()
            })
            .times(2)
            .returning(|_, _, _| Ok(3));

        processor
            .expect_process_chain_data()
            .withf(|bill_id, blocks, keys| {
                bill_id == &bill_id_test() && blocks.len() == 3 && keys.is_some()
            })
            .once()
            .returning(|_, _, _| Ok(()));

        // store events
        chain_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()))
            .times(3);

        let event = generate_test_event(&BcrKeys::new(), None, None, 1);
        let invite = Event::new_bill_invite(ChainInvite::bill(
            bill_id_test().to_string(),
            get_bill_keys(),
        ))
        .try_into()
        .expect("failed to create envelope");

        let handler = BillInviteEventHandler::new(Arc::new(processor), Arc::new(chain_event_store));
        handler
            .handle_event(invite, &node_id, None, Some(Box::new(event.clone())))
            .await
            .expect("failed to process chain invite event");
    }

    #[tokio::test]
    async fn test_bill_invite_stores_only_valid_event_prefix() {
        let (mut processor, mut chain_event_store) = get_mocks();
        let node_id = node_id_test();
        let (_keys, chain) = generate_test_chain(4, false);
        let rejected_event_id = chain[3].id.to_string();
        let chains = collect_event_chains(
            &chain,
            &bill_id_test().to_string(),
            BlockchainType::Bill,
            &None,
        );
        processor
            .expect_resolve_chain()
            .with(eq(bill_id_test()), always())
            .once()
            .returning(move |_, _| Ok(chains.clone()));
        processor
            .expect_valid_chain_prefix_len()
            .withf(|bill_id, blocks, _| bill_id == &bill_id_test() && blocks.len() == 4)
            .once()
            .returning(|_, _, _| Ok(3));
        processor
            .expect_process_chain_data()
            .withf(|bill_id, blocks, _| bill_id == &bill_id_test() && blocks.len() == 3)
            .once()
            .returning(|_, _, _| Ok(()));
        chain_event_store
            .expect_add_chain_event()
            .withf(move |event| event.event_id != rejected_event_id)
            .times(3)
            .returning(|_| Ok(()));
        let event = generate_test_event(&BcrKeys::new(), None, None, 1);
        let invite = Event::new_bill_invite(ChainInvite::bill(
            bill_id_test().to_string(),
            get_bill_keys(),
        ))
        .try_into()
        .unwrap();
        let handler = BillInviteEventHandler::new(Arc::new(processor), Arc::new(chain_event_store));
        handler
            .handle_event(invite, &node_id, None, Some(Box::new(event)))
            .await
            .expect("bill invite should accept valid prefix");
    }

    #[tokio::test]
    async fn test_bill_invite_selects_best_valid_prefix_not_longest_raw_branch() {
        let (mut processor, mut chain_event_store) = get_mocks();
        let node_id = node_id_test();
        let keys = BcrKeys::from_private_key(&private_key_test());
        let root = generate_test_event_at(&keys, None, None, 1, 1000);
        let event2 = generate_test_event_at(&keys, Some(root.clone()), Some(root.clone()), 2, 1001);

        // Candidate A
        // length 6, accepted length 3
        let a3 = generate_test_event_at(&keys, Some(event2.clone()), Some(root.clone()), 3, 1100);
        let a4 = generate_test_event_at(&keys, Some(a3.clone()), Some(root.clone()), 4, 1101);
        let a5 = generate_test_event_at(&keys, Some(a4.clone()), Some(root.clone()), 5, 1102);
        let a6 = generate_test_event_at(&keys, Some(a5.clone()), Some(root.clone()), 6, 1103);

        // Candidate B
        // length 5, accepted length 5
        let b3 = generate_test_event_at(&keys, Some(event2.clone()), Some(root.clone()), 3, 1200);
        let b4 = generate_test_event_at(&keys, Some(b3.clone()), Some(root.clone()), 4, 1201);
        let b5 = generate_test_event_at(&keys, Some(b4.clone()), Some(root.clone()), 5, 1202);

        let all_events = vec![
            root.clone(),
            event2.clone(),
            a3,
            a4,
            a5,
            a6,
            b3.clone(),
            b4.clone(),
            b5.clone(),
        ];

        let chains = collect_event_chains(
            &all_events,
            &bill_id_test().to_string(),
            BlockchainType::Bill,
            &None,
        );
        assert_eq!(chains.len(), 2, "fixture should produce two raw branches");
        processor
            .expect_resolve_chain()
            .once()
            .returning(move |_, _| Ok(chains.clone()));

        // A is longer but its valid prefix is shorter
        processor
            .expect_valid_chain_prefix_len()
            .times(2)
            .returning(|_, blocks, _| match blocks.len() {
                6 => Ok(3),
                5 => Ok(5),
                other => panic!("unexpected raw candidate length: {other}"),
            });

        // only B is persistenced
        processor
            .expect_process_chain_data()
            .withf(|bill_id, blocks, _| bill_id == &bill_id_test() && blocks.len() == 5)
            .once()
            .returning(|_, _, _| Ok(()));

        let selected_ids: HashSet<String> = [
            root.id.to_string(),
            event2.id.to_string(),
            b3.id.to_string(),
            b4.id.to_string(),
            b5.id.to_string(),
        ]
        .into_iter()
        .collect();

        chain_event_store
            .expect_add_chain_event()
            .withf(move |event| selected_ids.contains(&event.event_id))
            .times(5)
            .returning(|_| Ok(()));

        let invite_event = generate_test_event(&BcrKeys::new(), None, None, 1);
        let invite = Event::new_bill_invite(ChainInvite::bill(
            bill_id_test().to_string(),
            get_bill_keys(),
        ))
        .try_into()
        .unwrap();
        let handler = BillInviteEventHandler::new(Arc::new(processor), Arc::new(chain_event_store));
        handler
            .handle_event(invite, &node_id, None, Some(Box::new(invite_event)))
            .await
            .expect("best protocol-valid bill prefix should win");
    }

    fn get_mocks() -> (MockBillChainEventProcessorApi, MockNostrChainEventStore) {
        (
            MockBillChainEventProcessorApi::new(),
            MockNostrChainEventStore::new(),
        )
    }

    fn generate_test_event_at(
        keys: &BcrKeys,
        previous: Option<nostr::event::Event>,
        root: Option<nostr::event::Event>,
        height: usize,
        timestamp: u64,
    ) -> nostr::event::Event {
        create_public_chain_event(
            &bill_id_test().to_string(),
            generate_test_block(height),
            Timestamp::new(timestamp).unwrap(),
            BlockchainType::Bill,
            previous,
            root,
        )
        .expect("could not create chain event")
        .finalize(&keys.get_nostr_keys())
        .expect("could not sign event")
    }

    // generates event chains. If invalid blocks is enabled chains of size 3 will have two equal
    // valid chains. From there on len even gives one valid and N - 2 invalid (shorter) chains.
    // Uneven give two valid (equal len) and N - 1 invalid chains.
    fn generate_test_chain(
        len: usize,
        invalid_blocks: bool,
    ) -> (BcrKeys, Vec<nostr::event::Event>) {
        let keys = BcrKeys::from_private_key(&private_key_test());
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
        previous: Option<nostr::event::Event>,
        root: Option<nostr::event::Event>,
        height: usize,
    ) -> nostr::event::Event {
        create_public_chain_event(
            &bill_id_test().to_string(),
            generate_test_block(height),
            Timestamp::new(1000).unwrap(),
            BlockchainType::Bill,
            previous,
            root,
        )
        .expect("could not create chain event")
        .finalize(&keys.get_nostr_keys())
        .expect("could not sign event")
    }

    fn generate_test_block(block_height: usize) -> EventEnvelope {
        let block = get_genesis_chain(None)
            .blocks()
            .first()
            .expect("could not get block")
            .clone();

        Event::new_bill_chain(BillBlockEvent {
            bill_id: bill_id_test(),
            block: block.clone(),
            block_height,
        })
        .try_into()
        .expect("could not create envelope")
    }
}
