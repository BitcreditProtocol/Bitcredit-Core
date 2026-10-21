use std::{str::FromStr, sync::Arc};

use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_api::service::transport_service::transport_client::TransportClientApi;
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::{
        ProtocolValidationError,
        blockchain::{BlockchainType, company::CompanyBlock},
        crypto::BcrKeys,
        event::{ChainInvite, Event},
    },
};
use bcr_ebill_persistence::NostrChainEventStoreApi;
use log::{debug, error, trace, warn};

use crate::{
    EventType,
    handler::public_chain_helpers::{
        BlockData, EventContainer, compare_block_chains, resolve_event_chains,
    },
};
use bcr_ebill_api::service::transport_service::Result;
use bcr_ebill_core::protocol::event::EventEnvelope;

use super::{CompanyChainEventProcessorApi, NotificationHandlerApi};

#[derive(Clone)]
pub struct CompanyInviteEventHandler {
    transport: Arc<dyn TransportClientApi>,
    processor: Arc<dyn CompanyChainEventProcessorApi>,
    chain_event_store: Arc<dyn NostrChainEventStoreApi>,
}

#[derive(Debug)]
struct CompanyInviteCandidate {
    chain_index: usize,
    blocks: Vec<CompanyBlock>,
    accepted_event_count: usize,
}

#[async_trait]
impl NotificationHandlerApi for CompanyInviteEventHandler {
    fn handles_event(&self, event_type: &EventType) -> bool {
        event_type == &EventType::CompanyChainInvite
    }

    async fn handle_event(
        &self,
        event: EventEnvelope,
        node_id: &NodeId,
        _sender: Option<nostr::key::PublicKey>,
        _: Option<Box<nostr::event::Event>>,
    ) -> Result<()> {
        debug!("incoming company chain invite for {node_id}");
        let Ok(decoded) = Event::<ChainInvite>::try_from(event.clone()) else {
            warn!("Could not decode event to company ChainInvite {event:?}");
            return Ok(());
        };

        let company_id =
            NodeId::from_str(&decoded.data.chain_id).map_err(ProtocolValidationError::from)?;
        let keys = BcrKeys::from_private_key(&decoded.data.keys.private_key);

        let Ok(chain_data) = resolve_event_chains(
            self.transport.clone(),
            &decoded.data.chain_id,
            decoded.data.chain_type,
            &Some(keys.clone()),
        )
        .await
        else {
            error!("Could not extract chain data for company invite event {event:?}");
            return Ok(());
        };

        let mut candidates = Vec::new();

        // Validate every Nostr branch before persisting any of them
        for (chain_index, data) in chain_data.iter().enumerate() {
            trace!(
                "Processing company chain candidate with {} raw events",
                data.len()
            );
            let mut blocks: Vec<CompanyBlock> = data
                .iter()
                .filter_map(|event_container| match &event_container.block {
                    BlockData::Company(block) => Some(block.clone()),
                    _ => None,
                })
                .collect();

            if blocks.is_empty() {
                continue;
            }

            let accepted_count = match self
                .processor
                .valid_chain_prefix_len(&company_id, &blocks, &keys)
                .await
            {
                Ok(count) if count > 0 => count,
                Ok(_) => continue,
                Err(e) => {
                    debug!(
                        "Ignoring company invite candidate with no valid prefix for {company_id}: {e}"
                    );
                    continue;
                }
            };

            // truncate blocks and metadata
            blocks.truncate(accepted_count);
            candidates.push(CompanyInviteCandidate {
                chain_index,
                blocks,
                accepted_event_count: accepted_count,
            });
        }

        // select best chain
        candidates.sort_by(|a, b| compare_block_chains(&a.blocks, &b.blocks));
        let Some(selected) = candidates.into_iter().next() else {
            debug!("No valid company chain candidate found for invite {company_id}");
            return Ok(());
        };

        let selected_chain_index = selected.chain_index;
        let accepted_event_count = selected.accepted_event_count;
        // only persist the winning candidate
        self.processor
            .process_chain_data(&company_id, selected.blocks, Some(keys))
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
            error!("Error storing chain events: {e}");
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
        chain: &[EventContainer],
        accepted_event_count: usize,
    ) -> Result<()> {
        for event_container in chain
            .iter()
            .filter(|event_container| matches!(event_container.block, BlockData::Company(_)))
            .take(accepted_event_count)
        {
            let data = event_container.as_chain_store_event(
                chain_id,
                chain_type,
                event_container.block.get_block_height() as usize,
            );
            if let Err(e) = self.chain_event_store.add_chain_event(data).await {
                debug!("Could not store chain event because {e}");
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
            MockCompanyChainEventProcessorApi,
            public_chain_helpers::collect_event_chains,
            test_utils::{
                MockNostrChainEventStore, get_bill_keys, get_company_data, node_id_test,
                private_key_test,
            },
        },
        test_utils::{MockNotificationJsonTransport, test_ts},
        transport::create_public_chain_event,
    };

    use super::*;
    use bcr_ebill_core::protocol::event::CompanyBlockEvent;
    use bcr_ebill_core::{
        application::company::Company,
        protocol::Timestamp,
        protocol::blockchain::{
            Blockchain,
            company::{CompanyBlockchain, block::CompanyCreateBlockData},
        },
        protocol::crypto::BcrKeys,
    };
    use mockall::predicate::eq;
    use nostr::event::FinalizeEvent;

    #[test]
    fn test_single_block() {
        let (_keys, chain) = generate_test_chain(1, false);
        let chains = collect_event_chains(
            &chain,
            &node_id_test().to_string(),
            BlockchainType::Company,
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
            &node_id_test().to_string(),
            BlockchainType::Company,
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
            &node_id_test().to_string(),
            BlockchainType::Company,
            &None,
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
                    && keys.clone().unwrap().pub_key().to_string()
                        == keys_clone.get_key_pair().public_key().to_string()
            })
            .returning(|_, _, _| Ok(()));

        processor
            .expect_valid_chain_prefix_len()
            .withf(|company_id, blocks, _| company_id == &node_id_test() && blocks.len() == 1)
            .once()
            .returning(|_, _, _| Ok(1));

        // store events
        chain_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()))
            .times(1);

        let event = generate_test_event(&BcrKeys::new(), None, None, 1);
        let invite = Event::new_company_invite(ChainInvite::company(
            node_id_test().to_string(),
            BcrKeys::from_private_key(&keys.get_private_key()),
        ))
        .try_into()
        .expect("failed to create envelope");

        let handler = CompanyInviteEventHandler::new(
            Arc::new(transport),
            Arc::new(processor),
            Arc::new(chain_event_store),
        );
        handler
            .handle_event(invite, &node_id, None, Some(Box::new(event.clone())))
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
                    && keys.clone().unwrap().pub_key().to_string()
                        == get_bill_keys().pub_key().to_string()
            })
            .returning(|_, _, _| Ok(()));

        processor
            .expect_valid_chain_prefix_len()
            .withf(|company_id, blocks, _| company_id == &node_id_test() && blocks.len() == 3)
            .once()
            .returning(|_, _, _| Ok(3));

        // store events
        chain_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()))
            .times(3);

        let event = generate_test_event(&BcrKeys::new(), None, None, 1);
        let invite = Event::new_company_invite(ChainInvite::company(
            node_id_test().to_string(),
            BcrKeys::from_private_key(&keys.get_private_key()),
        ))
        .try_into()
        .expect("failed to create envelope");

        let handler = CompanyInviteEventHandler::new(
            Arc::new(transport),
            Arc::new(processor),
            Arc::new(chain_event_store),
        );
        handler
            .handle_event(invite, &node_id, None, Some(Box::new(event.clone())))
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
        processor
            .expect_valid_chain_prefix_len()
            .withf(|company_id, blocks, _| company_id == &node_id_test() && blocks.len() == 3)
            .times(2)
            .returning(|_, _, _| Ok(3));

        // process blocks
        processor
            .expect_process_chain_data()
            .withf(|company_id, blocks, _| company_id == &node_id_test() && blocks.len() == 3)
            .once()
            .returning(|_, _, _| Ok(()));

        chain_event_store
            .expect_add_chain_event()
            .returning(|_| Ok(()))
            .times(3);

        let event = generate_test_event(&BcrKeys::new(), None, None, 1);
        let invite = Event::new_company_invite(ChainInvite::company(
            node_id_test().to_string(),
            BcrKeys::from_private_key(&keys.get_private_key()),
        ))
        .try_into()
        .expect("failed to create envelope");

        let handler = CompanyInviteEventHandler::new(
            Arc::new(transport),
            Arc::new(processor),
            Arc::new(chain_event_store),
        );
        handler
            .handle_event(invite, &node_id, None, Some(Box::new(event.clone())))
            .await
            .expect("failed to process chain invite event");
    }

    #[tokio::test]
    async fn test_company_invite_stores_only_valid_event_prefix() {
        let (mut transport, mut processor, mut chain_event_store) = get_mocks();
        let node_id = node_id_test();
        let (keys, chain) = generate_test_chain(4, false);
        let rejected_event_id = chain[3].id.to_string();
        // 4 event branch
        transport
            .expect_resolve_public_chain()
            .with(eq(node_id_test().to_string()), eq(BlockchainType::Company))
            .once()
            .returning(move |_, _| Ok(chain.clone()));

        // accepts only the first three blocks
        processor
            .expect_valid_chain_prefix_len()
            .withf(|company_id, blocks, _| company_id == &node_id_test() && blocks.len() == 4)
            .once()
            .returning(|_, _, _| Ok(3));
        let expected_pub_key = keys.pub_key();
        // only persist the validated ones
        processor
            .expect_process_chain_data()
            .withf(move |company_id, blocks, provided_keys| {
                company_id == &node_id_test()
                    && blocks.len() == 3
                    && provided_keys.as_ref().map(|keys| keys.pub_key()) == Some(expected_pub_key)
            })
            .once()
            .returning(|_, _, _| Ok(()));

        // only persist the accepted events
        chain_event_store
            .expect_add_chain_event()
            .withf(move |event| event.event_id != rejected_event_id)
            .times(3)
            .returning(|_| Ok(()));
        let event = generate_test_event(&BcrKeys::new(), None, None, 1);
        let invite = Event::new_company_invite(ChainInvite::company(
            node_id_test().to_string(),
            BcrKeys::from_private_key(&keys.get_private_key()),
        ))
        .try_into()
        .expect("failed to create company invite envelope");
        let handler = CompanyInviteEventHandler::new(
            Arc::new(transport),
            Arc::new(processor),
            Arc::new(chain_event_store),
        );
        handler
            .handle_event(invite, &node_id, None, Some(Box::new(event)))
            .await
            .expect("failed to process company chain invite");
    }

    #[tokio::test]
    async fn test_company_invite_selects_best_valid_prefix_not_longest_raw_branch() {
        let (mut transport, mut processor, mut chain_event_store) = get_mocks();
        let node_id = node_id_test();
        let keys = BcrKeys::from_private_key(&private_key_test());
        let root = generate_test_event(&keys, None, None, 1);
        let event_2 = generate_test_event(&keys, Some(root.clone()), Some(root.clone()), 2);

        // Candidate A
        // Raw length = 6
        // Valid prefix will be mocked as 3
        let a3 = generate_test_event(&keys, Some(event_2.clone()), Some(root.clone()), 3);
        let a4 = generate_test_event(&keys, Some(a3.clone()), Some(root.clone()), 4);
        let a5 = generate_test_event(&keys, Some(a4.clone()), Some(root.clone()), 5);
        let a6 = generate_test_event(&keys, Some(a5.clone()), Some(root.clone()), 6);

        // Candidate B
        // Raw length = 5
        // Valid prefix = all 5
        let b3 = generate_test_event(&keys, Some(event_2.clone()), Some(root.clone()), 3);
        let b4 = generate_test_event(&keys, Some(b3.clone()), Some(root.clone()), 4);
        let b5 = generate_test_event(&keys, Some(b4.clone()), Some(root.clone()), 5);
        let nostr_events = vec![
            root.clone(),
            event_2.clone(),
            a3,
            a4,
            a5,
            a6,
            b3.clone(),
            b4.clone(),
            b5.clone(),
        ];
        transport
            .expect_resolve_public_chain()
            .with(eq(node_id_test().to_string()), eq(BlockchainType::Company))
            .once()
            .returning(move |_, _| Ok(nostr_events.clone()));

        // A: raw 6 -> valid 3
        // B: raw 5 -> valid 5
        processor
            .expect_valid_chain_prefix_len()
            .times(2)
            .returning(|_, blocks, _| match blocks.len() {
                6 => Ok(3),
                5 => Ok(5),
                other => panic!(
                    "unexpected candidate \
                         length {other}"
                ),
            });
        let expected_pub_key = keys.pub_key();
        // 5 blocks - so B was selected
        processor
            .expect_process_chain_data()
            .withf(move |company_id, blocks, provided_keys| {
                company_id == &node_id_test()
                    && blocks.len() == 5
                    && provided_keys.as_ref().map(|keys| keys.pub_key()) == Some(expected_pub_key)
            })
            .once()
            .returning(|_, _, _| Ok(()));

        // metadata also B only
        let selected_event_ids: HashSet<String> = [
            root.id.to_string(),
            event_2.id.to_string(),
            b3.id.to_string(),
            b4.id.to_string(),
            b5.id.to_string(),
        ]
        .into_iter()
        .collect();
        chain_event_store
            .expect_add_chain_event()
            .withf(move |event| selected_event_ids.contains(&event.event_id))
            .times(5)
            .returning(|_| Ok(()));
        let invite_event = generate_test_event(&BcrKeys::new(), None, None, 1);
        let invite = Event::new_company_invite(ChainInvite::company(
            node_id_test().to_string(),
            BcrKeys::from_private_key(&keys.get_private_key()),
        ))
        .try_into()
        .expect("failed to create company invite envelope");
        let handler = CompanyInviteEventHandler::new(
            Arc::new(transport),
            Arc::new(processor),
            Arc::new(chain_event_store),
        );
        handler
            .handle_event(invite, &node_id, None, Some(Box::new(invite_event)))
            .await
            .expect("failed to process company chain invite");
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
            &node_id_test().to_string(),
            generate_test_block(height),
            Timestamp::new(1000).unwrap(),
            BlockchainType::Company,
            previous,
            root,
        )
        .expect("could not create chain event")
        .finalize(&keys.get_nostr_keys())
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

    pub fn get_valid_company_chain(company: &Company, keys: &BcrKeys) -> CompanyBlockchain {
        CompanyBlockchain::new(
            &CompanyCreateBlockData {
                id: company.id.to_owned(),
                name: company.name.to_owned(),
                country_of_registration: company.country_of_registration.to_owned(),
                city_of_registration: company.city_of_registration.to_owned(),
                postal_address: company.postal_address.to_owned(),
                email: company.email.to_owned(),
                registration_number: company.registration_number.to_owned(),
                registration_date: company.registration_date.to_owned(),
                proof_of_registration_file: company.proof_of_registration_file.to_owned(),
                logo_file: company.logo_file.to_owned(),
                creation_time: test_ts(),
                creator: node_id_test(),
            },
            &BcrKeys::from_private_key(&private_key_test()),
            keys,
            test_ts(),
        )
        .unwrap()
    }
}
