use std::{collections::HashMap, str::FromStr, sync::Arc};

use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_api::service::transport_service::transport_client::TransportClientApi;
use bcr_ebill_core::{
    ServiceTraitBounds, ValidationError,
    blockchain::{BlockchainType, company::CompanyBlock},
    company::CompanyKeys,
    protocol::{ChainInvite, Event},
    util::BcrKeys,
};
use bcr_ebill_persistence::{NostrChainEventStoreApi, nostr::NostrChainEvent};
use log::{debug, error, trace, warn};

use crate::{
    EventType,
    handler::public_chain_helpers::{BlockData, EventContainer, resolve_event_chains},
};
use bcr_ebill_api::service::transport_service::Result;
use bcr_ebill_core::protocol::EventEnvelope;

use super::{CompanyChainEventProcessorApi, NotificationHandlerApi};

#[derive(Clone)]
pub struct CompanyInviteEventHandler {
    transport: Arc<dyn TransportClientApi>,
    processor: Arc<dyn CompanyChainEventProcessorApi>,
    chain_event_store: Arc<dyn NostrChainEventStoreApi>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationHandlerApi for CompanyInviteEventHandler {
    fn handles_event(&self, event_type: &EventType) -> bool {
        event_type == &EventType::CompanyChainInvite
    }

    async fn handle_event(
        &self,
        event: EventEnvelope,
        node_id: &NodeId,
        _: Option<Box<nostr::Event>>,
    ) -> Result<()> {
        debug!("incoming company chain invite for {node_id}");
        if let Ok(decoded) = Event::<ChainInvite>::try_from(event.clone()) {
            let keys = BcrKeys::from_private_key(&decoded.data.keys.private_key)?;

            let mut inserted_chain: Vec<EventContainer> = Vec::new();
            if let Ok(chain_data) = resolve_event_chains(
                self.transport.clone(),
                &decoded.data.chain_id,
                decoded.data.chain_type,
                &keys,
            )
            .await
            {
                // We try to add shorter and shorter chains until we have a success
                for data in chain_data.iter() {
                    trace!("Processing company chain data with block {data:#?}");
                    let blocks: Vec<CompanyBlock> = data
                        .iter()
                        .filter_map(|d| match d.block.clone() {
                            BlockData::Company(block) => Some(block),
                            _ => None,
                        })
                        .collect();
                    trace!("Processing company chain data with {} blocks", blocks.len());
                    if !data.is_empty()
                        && self
                            .processor
                            .process_chain_data(
                                &NodeId::from_str(&decoded.data.chain_id)
                                    .map_err(ValidationError::from)?,
                                blocks,
                                Some(CompanyKeys {
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
                error!("Could not extract chain data for company invite event {event:?}");
            }
        } else {
            warn!("Could not decode event to company ChainInvite {event:?}");
        }
        Ok(())
    }
}

impl ServiceTraitBounds for CompanyInviteEventHandler {}

impl CompanyInviteEventHandler {
    pub fn new(
        transport: Arc<dyn TransportClientApi>,
        processor: Arc<dyn CompanyChainEventProcessorApi>,
        chain_event_store: Arc<dyn NostrChainEventStoreApi>,
    ) -> Self {
        Self {
            transport,
            processor,
            chain_event_store,
        }
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

#[cfg(test)]
mod tests {
    use crate::{
        handler::{
            MockCompanyChainEventProcessorApi,
            public_chain_helpers::collect_event_chains,
            test_utils::{
                MockNostrChainEventStore, get_bill_keys, get_company_data, node_id_test,
                private_key_test,
            },
        },
        test_utils::MockNotificationJsonTransport,
        transport::create_public_chain_event,
    };

    use super::*;
    use bcr_ebill_core::protocol::CompanyBlockEvent;
    use bcr_ebill_core::{
        blockchain::{
            Blockchain,
            company::{CompanyBlockchain, CompanyCreateBlockData},
        },
        company::Company,
        timestamp::Timestamp,
        util::crypto::BcrKeys,
    };
    use mockall::predicate::eq;

    #[test]
    fn test_single_block() {
        let (keys, chain) = generate_test_chain(1, false);
        let chains = collect_event_chains(
            &chain,
            &node_id_test().to_string(),
            BlockchainType::Company,
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
            &node_id_test().to_string(),
            BlockchainType::Company,
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
            &node_id_test().to_string(),
            BlockchainType::Company,
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
        let (keys, chain) = generate_test_chain(1, false);

        // get events from nostr
        transport
            .expect_resolve_public_chain()
            .with(eq(node_id_test().to_string()), eq(BlockchainType::Company))
            .returning(move |_, _| Ok(chain.clone()));

        let keys_clone = keys.clone();
        // process blocks
        processor
            .expect_process_chain_data()
            .withf(move |node_id, blocks, keys| {
                node_id == &node_id_test()
                    && blocks.len() == 1
                    && keys.clone().unwrap().public_key.to_string()
                        == keys_clone.get_key_pair().public_key().to_string()
            })
            .returning(|_, _, _| Ok(()));

        // store events
        chain_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()))
            .times(1);

        let event = generate_test_event(&BcrKeys::new(), None, None, 1);
        let invite = Event::new_company_invite(ChainInvite::company(
            node_id_test().to_string(),
            CompanyKeys {
                public_key: keys.get_key_pair().public_key(),
                private_key: keys.get_private_key(),
            },
        ))
        .try_into()
        .expect("failed to create envelope");

        let handler = CompanyInviteEventHandler::new(
            Arc::new(transport),
            Arc::new(processor),
            Arc::new(chain_event_store),
        );
        handler
            .handle_event(invite, &node_id, Some(Box::new(event.clone())))
            .await
            .expect("failed to process chain invite event");
    }

    #[tokio::test]
    async fn test_process_single_chain_invite() {
        let (mut transport, mut processor, mut chain_event_store) = get_mocks();

        let node_id = node_id_test();
        let (keys, chain) = generate_test_chain(3, false);

        // get events from nostr
        transport
            .expect_resolve_public_chain()
            .with(eq(node_id_test().to_string()), eq(BlockchainType::Company))
            .returning(move |_, _| Ok(chain.clone()));

        // process blocks
        processor
            .expect_process_chain_data()
            .withf(|node_id, blocks, keys| {
                node_id == &node_id_test()
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
        let invite = Event::new_company_invite(ChainInvite::company(
            node_id_test().to_string(),
            CompanyKeys {
                public_key: keys.get_key_pair().public_key(),
                private_key: keys.get_private_key(),
            },
        ))
        .try_into()
        .expect("failed to create envelope");

        let handler = CompanyInviteEventHandler::new(
            Arc::new(transport),
            Arc::new(processor),
            Arc::new(chain_event_store),
        );
        handler
            .handle_event(invite, &node_id, Some(Box::new(event.clone())))
            .await
            .expect("failed to process chain invite event");
    }

    #[tokio::test]
    async fn test_process_multiple_chains_invite() {
        let (mut transport, mut processor, mut chain_event_store) = get_mocks();

        let node_id = node_id_test();
        let (keys, chain) = generate_test_chain(3, true);

        // get events from nostr
        transport
            .expect_resolve_public_chain()
            .with(eq(node_id_test().to_string()), eq(BlockchainType::Company))
            .returning(move |_, _| Ok(chain.clone()));

        // process blocks
        processor
            .expect_process_chain_data()
            .withf(|node_id, blocks, keys| {
                node_id == &node_id_test()
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
        let invite = Event::new_company_invite(ChainInvite::company(
            node_id_test().to_string(),
            CompanyKeys {
                public_key: keys.get_key_pair().public_key(),
                private_key: keys.get_private_key(),
            },
        ))
        .try_into()
        .expect("failed to create envelope");

        let handler = CompanyInviteEventHandler::new(
            Arc::new(transport),
            Arc::new(processor),
            Arc::new(chain_event_store),
        );
        handler
            .handle_event(invite, &node_id, Some(Box::new(event.clone())))
            .await
            .expect("failed to process chain invite event");
    }

    fn get_mocks() -> (
        MockNotificationJsonTransport,
        MockCompanyChainEventProcessorApi,
        MockNostrChainEventStore,
    ) {
        (
            MockNotificationJsonTransport::new(),
            MockCompanyChainEventProcessorApi::new(),
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
            &node_id_test().to_string(),
            generate_test_block(height),
            Timestamp::new(1000).unwrap(),
            BlockchainType::Company,
            keys.clone(),
            previous,
            root,
        )
        .expect("could not create chain event")
        .sign_with_keys(&keys.get_nostr_keys())
        .expect("could not sign event")
    }

    fn generate_test_block(block_height: usize) -> EventEnvelope {
        let (id, (company, keys)) = get_company_data();
        let block = get_valid_company_chain(&company, &keys)
            .get_latest_block()
            .clone();

        Event::new_company_invite(CompanyBlockEvent {
            node_id: id,
            block,
            block_height,
        })
        .try_into()
        .expect("could not create envelope")
    }

    pub fn get_valid_company_chain(company: &Company, keys: &CompanyKeys) -> CompanyBlockchain {
        CompanyBlockchain::new(
            &CompanyCreateBlockData::from(company.to_owned()),
            &BcrKeys::new(),
            keys,
            Timestamp::new(1731593928).unwrap(),
        )
        .unwrap()
    }
}
