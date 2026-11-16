use super::{
    IdentityChainEventProcessorApi,
    public_chain_helpers::{BlockData, EventContainer, resolve_event_chains},
};
use crate::handler::{DirectMessageEventProcessorApi, public_chain_helpers::compare_block_chains};
use crate::incoming_verification::VerifiedChainIngestionApi;
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_api::service::transport_service::propagation::RelayQuorumSnapshot;
use bcr_ebill_api::service::transport_service::{
    Result, restore::RestoreAccountApi, transport_client::TransportClientApi,
};
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::blockchain::{BlockchainType, identity::IdentityBlock},
    protocol::crypto::BcrKeys,
};
use log::{debug, error, info};
use nostr::filter::Filter;
use std::sync::Arc;

#[allow(dead_code)]
pub struct RestoreAccountService {
    nostr: Arc<dyn TransportClientApi>,
    identity_chain_processor: Arc<dyn IdentityChainEventProcessorApi>,
    dm_processor: Arc<dyn DirectMessageEventProcessorApi>,
    verified_ingestion: Arc<dyn VerifiedChainIngestionApi>,
    relay_snapshot: RelayQuorumSnapshot,
    keys: BcrKeys,
    node_id: NodeId,
}

#[derive(Debug, Clone)]
struct IdentityRestoreCandidate {
    chain_idx: usize,
    blocks: Vec<IdentityBlock>,
    accepted_event_count: usize,
}

#[allow(dead_code)]
impl RestoreAccountService {
    pub async fn new(
        nostr: Arc<dyn TransportClientApi>,
        identity_chain_processor: Arc<dyn IdentityChainEventProcessorApi>,
        dm_processor: Arc<dyn DirectMessageEventProcessorApi>,
        verified_ingestion: Arc<dyn VerifiedChainIngestionApi>,
        relay_snapshot: RelayQuorumSnapshot,
        keys: BcrKeys,
        node_id: NodeId,
    ) -> Self {
        Self {
            nostr,
            identity_chain_processor,
            dm_processor,
            verified_ingestion,
            relay_snapshot,
            keys,
            node_id,
        }
    }

    async fn restore_primary_account(&self) -> Result<()> {
        // restores identity and all our own companies
        self.restore_identity().await?;

        // restore bills and companies primary account was invited to
        self.process_private_events().await?;
        Ok(())
    }

    async fn process_private_events(&self) -> Result<()> {
        let events = self
            .nostr
            .resolve_private_events(Filter::new().since(nostr::types::Timestamp::zero()))
            .await?;
        info!("found private {} dms for primary account", events.len());
        for event in events {
            if let Err(e) = self
                .dm_processor
                .process_direct_message(Box::new(event))
                .await
            {
                error!("Failed to process direct message with: {e}");
            }
        }
        Ok(())
    }

    async fn restore_identity(&self) -> Result<()> {
        info!("restoring identity chain");
        let chains = resolve_event_chains(
            self.nostr.clone(),
            &self.node_id.to_string(),
            BlockchainType::Identity,
            &Some(self.keys.to_owned()),
        )
        .await?;
        info!("found {} chains for primary account", chains.len());

        let mut candidates = Vec::new();

        for (chain_idx, chain) in chains.iter().enumerate() {
            let valid_event_count = self.valid_identity_chain_events_len(chain);

            if valid_event_count == 0 {
                continue;
            }

            let sender_valid_events = &chain[..valid_event_count];
            let mut blocks: Vec<IdentityBlock> = sender_valid_events
                .iter()
                .filter_map(|d| match d.block.clone() {
                    BlockData::Identity(block) => Some(block),
                    _ => None,
                })
                .collect();

            if blocks.is_empty() {
                continue;
            }

            // only keep protocol-valid blocks
            let valid_block_count = match self.identity_chain_processor.valid_chain_prefix_len(
                &self.node_id,
                &blocks,
                &self.keys,
            ) {
                Ok(len) => len,
                Err(e) => {
                    debug!("Ignoring identity restore candidate that has no valid prefix: {e}");
                    continue;
                }
            };

            if valid_block_count == 0 {
                continue;
            }
            // truncate blocks and metadata
            blocks.truncate(valid_block_count);
            let accepted_event_count = valid_block_count;

            candidates.push(IdentityRestoreCandidate {
                chain_idx,
                blocks,
                accepted_event_count,
            });
        }

        // select best chain
        candidates.sort_by(|a, b| compare_block_chains(&a.blocks, &b.blocks));
        let Some(selected) = candidates.into_iter().next() else {
            info!("no valid identity chain found for primary account");
            return Ok(());
        };

        let selected_chain = &chains[selected.chain_idx];
        let selected_events: Vec<nostr::event::Event> = selected_chain
            .iter()
            .filter(|entry| matches!(entry.block, BlockData::Identity(_)))
            .take(selected.accepted_event_count)
            .map(|entry| entry.event.clone())
            .collect();
        debug_assert_eq!(selected_events.len(), selected.blocks.len(),);

        let progress = self
            .verified_ingestion
            .ingest_verified_chain(
                BlockchainType::Identity,
                &self.node_id.to_string(),
                selected_events,
                self.relay_snapshot.clone(),
            )
            .await?;

        if progress.is_complete() {
            info!(
                "Identity restoration complete: {} blocks applied",
                progress.applied_prefix,
            );
        } else {
            info!(
                "Identity partially restored: {} of {} blocks applied, {} waiting for background recovery",
                progress.applied_prefix,
                progress.enqueued,
                progress.remaining(),
            );
        }

        Ok(())
    }

    // calculate the length of the chain of valid identity chain events for this list of events
    fn valid_identity_chain_events_len(&self, events: &[EventContainer]) -> usize {
        events
            .iter()
            .take_while(|event| {
                self.identity_chain_processor
                    .validate_chain_event_and_sender(&self.node_id, event.event.pubkey)
            })
            .count()
    }
}

impl ServiceTraitBounds for RestoreAccountService {}

#[async_trait]
impl RestoreAccountApi for RestoreAccountService {
    async fn restore_account(&self) -> Result<()> {
        info!("restoring primary account");
        self.restore_primary_account().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::incoming_verification::{
        MockVerifiedChainIngestionApi, VerifiedChainIngestionProgress,
    };
    use crate::{
        handler::{
            MockDirectMessageEventProcessorApi, MockIdentityChainEventProcessorApi,
            test_utils::{get_baseline_identity, private_key_test},
        },
        test_utils::{MockNotificationJsonTransport, node_id_test, test_ts},
        transport::create_public_chain_event,
    };
    use bcr_ebill_core::{
        application::identity::Identity,
        protocol::Timestamp,
        protocol::blockchain::{
            Blockchain,
            identity::{IdentityBlockchain, IdentityCreateBlockData},
        },
        protocol::event::{Event, EventEnvelope, IdentityBlockEvent},
    };
    use mockall::predicate::{always, eq};
    use nostr::event::FinalizeEvent;
    use url::Url;

    fn test_snapshot() -> RelayQuorumSnapshot {
        RelayQuorumSnapshot {
            relays: vec![
                Url::parse("wss://r1.example").unwrap(),
                Url::parse("wss://r2.example").unwrap(),
                Url::parse("wss://r3.example").unwrap(),
            ],
            required: 2,
        }
    }

    #[tokio::test]
    async fn test_service() {
        let mut nostr = MockNotificationJsonTransport::new();
        let processor = MockIdentityChainEventProcessorApi::new();
        let dm_processor = MockDirectMessageEventProcessorApi::new();
        let keys = BcrKeys::new();
        let mut ingestion = MockVerifiedChainIngestionApi::new();
        ingestion.expect_ingest_verified_chain().never();

        nostr
            .expect_resolve_public_chain()
            .returning(|_, _| Ok(vec![]))
            .once();

        nostr
            .expect_resolve_private_events()
            .returning(|_| Ok(vec![]))
            .once();

        let service = RestoreAccountService::new(
            Arc::new(nostr),
            Arc::new(processor),
            Arc::new(dm_processor),
            Arc::new(ingestion),
            test_snapshot(),
            keys,
            node_id_test(),
        )
        .await;

        service
            .restore_account()
            .await
            .expect("could not restore account");
    }

    #[tokio::test]
    async fn test_create_identity() {
        let (keys, events) = generate_test_chain(1, false);
        let mut nostr = MockNotificationJsonTransport::new();
        let mut processor = MockIdentityChainEventProcessorApi::new();
        let dm_processor = MockDirectMessageEventProcessorApi::new();
        let mut ingestion = MockVerifiedChainIngestionApi::new();
        ingestion
            .expect_ingest_verified_chain()
            .once()
            .withf(move |chain_type, _chain_id, events, snapshot| {
                *chain_type == BlockchainType::Identity
                    && snapshot.required == 2
                    && events.len() == 1
            })
            .returning(|_, _, events, _| {
                Ok(VerifiedChainIngestionProgress {
                    enqueued: events.len(),
                    applied_prefix: events.len(),
                })
            });

        let _return_events = events.clone();
        nostr
            .expect_resolve_public_chain()
            .returning(move |_, _| Ok(_return_events.clone()))
            .once();

        // should validate the event sender
        processor
            .expect_validate_chain_event_and_sender()
            .with(eq(node_id_test()), eq(keys.get_nostr_keys().public_key()))
            .returning(|_, _| true)
            .times(events.len());

        processor.expect_process_chain_data().never();

        processor
            .expect_valid_chain_prefix_len()
            .with(eq(node_id_test()), always(), eq(keys.clone()))
            .returning(|_, _, _| Ok(1))
            .once();

        nostr
            .expect_resolve_private_events()
            .returning(|_| Ok(vec![]))
            .once();

        let service = RestoreAccountService::new(
            Arc::new(nostr),
            Arc::new(processor),
            Arc::new(dm_processor),
            Arc::new(ingestion),
            test_snapshot(),
            keys,
            node_id_test(),
        )
        .await;

        service
            .restore_account()
            .await
            .expect("could not restore account");
    }

    #[tokio::test]
    async fn test_restore_identity_selects_best_valid_prefix_not_longest_raw_chain() {
        let keys = BcrKeys::from_private_key(&private_key_test());
        let root = generate_test_event_at(&keys, None, None, 1, 1000);

        // candidate A: length 6, but processor says only 3 are valid
        let a2 = generate_test_event_at(&keys, Some(root.clone()), Some(root.clone()), 2, 1001);
        let a3 = generate_test_event_at(&keys, Some(a2.clone()), Some(root.clone()), 3, 1002);
        let a4 = generate_test_event_at(&keys, Some(a3.clone()), Some(root.clone()), 4, 1003);
        let a5 = generate_test_event_at(&keys, Some(a4.clone()), Some(root.clone()), 5, 1004);
        let a6 = generate_test_event_at(&keys, Some(a5.clone()), Some(root.clone()), 6, 1005);

        // candidate B: length 5, protocol-valid prefix length 4
        let b2 = generate_test_event_at(&keys, Some(root.clone()), Some(root.clone()), 2, 2001);
        let b3 = generate_test_event_at(&keys, Some(b2.clone()), Some(root.clone()), 3, 2002);
        let b4 = generate_test_event_at(&keys, Some(b3.clone()), Some(root.clone()), 4, 2003);
        let b5 = generate_test_event_at(&keys, Some(b4.clone()), Some(root.clone()), 5, 2004);

        let all_events = vec![
            root.clone(),
            a2,
            a3,
            a4,
            a5,
            a6,
            b2.clone(),
            b3.clone(),
            b4.clone(),
            b5,
        ];

        let mut nostr = MockNotificationJsonTransport::new();
        let mut processor = MockIdentityChainEventProcessorApi::new();
        let dm_processor = MockDirectMessageEventProcessorApi::new();
        let mut ingestion = MockVerifiedChainIngestionApi::new();

        let expected_event_ids: HashSet<String> = [
            root.id.to_string(),
            b2.id.to_string(),
            b3.id.to_string(),
            b4.id.to_string(),
        ]
        .into_iter()
        .collect();

        ingestion
            .expect_ingest_verified_chain()
            .once()
            .withf(move |chain_type, _chain_id, events, snapshot| {
                *chain_type == BlockchainType::Identity
                    && snapshot.required == 2
                    && events.len() == 4
                    && events
                        .iter()
                        .map(|event| event.id.to_string())
                        .collect::<HashSet<_>>()
                        == expected_event_ids
            })
            .returning(|_, _, events, _| {
                Ok(VerifiedChainIngestionProgress {
                    enqueued: events.len(),
                    applied_prefix: events.len(),
                })
            });
        nostr
            .expect_resolve_public_chain()
            .once()
            .returning(move |_, _| Ok(all_events.clone()));

        // resolve_event_chains() yields both branches, shared root is validated once per candidate = 11
        processor
            .expect_validate_chain_event_and_sender()
            .returning(|_, _| true)
            .times(11);
        processor
            .expect_valid_chain_prefix_len()
            .times(2)
            .returning(|_, blocks, _| match blocks.len() {
                6 => Ok(3), // poisoned A
                5 => Ok(4), // B wins after validation
                other => panic!("unexpected candidate length {other}"),
            });

        let service = RestoreAccountService::new(
            Arc::new(nostr),
            Arc::new(processor),
            Arc::new(dm_processor),
            Arc::new(ingestion),
            test_snapshot(),
            keys,
            node_id_test(),
        )
        .await;
        service
            .restore_identity()
            .await
            .expect("identity restore should select best valid prefix");
    }

    #[tokio::test]
    async fn test_restore_identity_recovers_prefix_before_invalid_sender() {
        let keys = BcrKeys::from_private_key(&private_key_test());
        let wrong_keys = BcrKeys::new();
        let root = generate_test_event_at(&keys, None, None, 1, 1000);
        let event2 = generate_test_event_at(&keys, Some(root.clone()), Some(root.clone()), 2, 1001);
        let invalid_sender_event = generate_test_event_at(
            &wrong_keys,
            Some(event2.clone()),
            Some(root.clone()),
            3,
            1002,
        );

        // valid, but it is after the invalid sender and therefore must not be recovered
        let event4 = generate_test_event_at(
            &keys,
            Some(invalid_sender_event.clone()),
            Some(root.clone()),
            4,
            1003,
        );

        let events = vec![root.clone(), event2.clone(), invalid_sender_event, event4];
        let valid_pubkey = keys.get_nostr_keys().public_key();

        let mut nostr = MockNotificationJsonTransport::new();
        let mut processor = MockIdentityChainEventProcessorApi::new();
        let dm_processor = MockDirectMessageEventProcessorApi::new();
        let mut ingestion = MockVerifiedChainIngestionApi::new();
        ingestion
            .expect_ingest_verified_chain()
            .once()
            .withf(move |chain_type, _chain_id, events, snapshot| {
                *chain_type == BlockchainType::Identity
                    && snapshot.required == 2
                    && events.len() == 2
            })
            .returning(|_, _, events, _| {
                Ok(VerifiedChainIngestionProgress {
                    enqueued: events.len(),
                    applied_prefix: events.len(),
                })
            });

        nostr
            .expect_resolve_public_chain()
            .once()
            .returning(move |_, _| Ok(events.clone()));
        // take_while stops after the third call
        processor
            .expect_validate_chain_event_and_sender()
            .times(3)
            .returning(move |_, sender| sender == valid_pubkey);
        processor
            .expect_valid_chain_prefix_len()
            .withf(|_, blocks, _| blocks.len() == 2)
            .once()
            .returning(|_, _, _| Ok(2));

        let service = RestoreAccountService::new(
            Arc::new(nostr),
            Arc::new(processor),
            Arc::new(dm_processor),
            Arc::new(ingestion),
            test_snapshot(),
            keys,
            node_id_test(),
        )
        .await;

        service
            .restore_identity()
            .await
            .expect("valid sender prefix should still be restored");
    }

    #[tokio::test]
    async fn restore_does_not_process_dms_before_identity_completion() {
        let (keys, events) = generate_test_chain(1, false);
        let mut nostr = MockNotificationJsonTransport::new();
        nostr
            .expect_resolve_public_chain()
            .once()
            .returning(move |_, _| Ok(events.clone()));
        // DM recovery must not begin if identity restore fails
        nostr.expect_resolve_private_events().never();
        let mut processor = MockIdentityChainEventProcessorApi::new();
        processor
            .expect_validate_chain_event_and_sender()
            .once()
            .returning(|_, _| true);
        processor
            .expect_valid_chain_prefix_len()
            .once()
            .returning(|_, _, _| Ok(1));
        processor.expect_process_chain_data().never();

        let mut ingestion = MockVerifiedChainIngestionApi::new();
        ingestion
            .expect_ingest_verified_chain()
            .once()
            .returning(|_, _, _, _| {
                Err(bcr_ebill_api::service::transport_service::Error::Network(
                    "relay quorum unavailable".into(),
                ))
            });

        let service = RestoreAccountService::new(
            Arc::new(nostr),
            Arc::new(processor),
            Arc::new(MockDirectMessageEventProcessorApi::new()),
            Arc::new(ingestion),
            test_snapshot(),
            keys,
            node_id_test(),
        )
        .await;

        let result = service.restore_account().await;
        assert!(matches!(
            result,
            Err(bcr_ebill_api::service::transport_service::Error::Network(_))
        ));
    }

    #[tokio::test]
    async fn partial_identity_restore_still_processes_private_events() {
        let (keys, events) = generate_test_chain(3, false);
        let mut nostr = MockNotificationJsonTransport::new();
        nostr
            .expect_resolve_public_chain()
            .once()
            .returning(move |_, _| Ok(events.clone()));

        let dm =
            nostr::event::EventBuilder::new(nostr::event::Kind::GiftWrap, "test private event")
                .finalize(&nostr::key::Keys::generate())
                .unwrap();
        nostr
            .expect_resolve_private_events()
            .once()
            .returning(move |_| Ok(vec![dm.clone()]));

        let mut processor = MockIdentityChainEventProcessorApi::new();
        processor
            .expect_validate_chain_event_and_sender()
            .times(3)
            .returning(|_, _| true);
        processor
            .expect_valid_chain_prefix_len()
            .once()
            .returning(|_, blocks, _| Ok(blocks.len()));
        processor.expect_process_chain_data().never();

        let mut ingestion = MockVerifiedChainIngestionApi::new();
        ingestion
            .expect_ingest_verified_chain()
            .once()
            .withf(|chain_type, _, events, _| {
                *chain_type == BlockchainType::Identity && events.len() == 3
            })
            .returning(|_, _, _, _| {
                Ok(VerifiedChainIngestionProgress {
                    enqueued: 3,
                    applied_prefix: 2,
                })
            });

        let mut dm_processor = MockDirectMessageEventProcessorApi::new();
        // DM recovery proceeds despite the third identity block being pending
        dm_processor
            .expect_process_direct_message()
            .once()
            .returning(|_| Ok(()));
        let service = RestoreAccountService::new(
            Arc::new(nostr),
            Arc::new(processor),
            Arc::new(dm_processor),
            Arc::new(ingestion),
            test_snapshot(),
            keys,
            node_id_test(),
        )
        .await;
        service.restore_account().await.unwrap();
    }

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
            BlockchainType::Identity,
            previous,
            root,
        )
        .expect("could not create chain event")
        .finalize(&keys.get_nostr_keys())
        .expect("could not sign event")
    }

    fn generate_test_block(block_height: usize) -> EventEnvelope {
        let identity = get_baseline_identity();
        let block = get_valid_identity_chain(&identity.identity, &identity.key_pair)
            .get_latest_block()
            .clone();

        Event::new_identity_chain(IdentityBlockEvent {
            node_id: identity.identity.node_id.clone(),
            block,
            block_height,
        })
        .try_into()
        .expect("could not create envelope")
    }

    pub fn get_valid_identity_chain(identity: &Identity, keys: &BcrKeys) -> IdentityBlockchain {
        IdentityBlockchain::new(
            &IdentityCreateBlockData::from(identity.to_owned()),
            keys,
            test_ts(),
        )
        .unwrap()
    }

    fn generate_test_event_at(
        keys: &BcrKeys,
        previous: Option<nostr::event::Event>,
        root: Option<nostr::event::Event>,
        height: usize,
        timestamp: u64,
    ) -> nostr::event::Event {
        create_public_chain_event(
            &node_id_test().to_string(),
            generate_test_block(height),
            Timestamp::new(timestamp).unwrap(),
            BlockchainType::Identity,
            previous,
            root,
        )
        .expect("could not create chain event")
        .finalize(&keys.get_nostr_keys())
        .expect("could not sign event")
    }
}
