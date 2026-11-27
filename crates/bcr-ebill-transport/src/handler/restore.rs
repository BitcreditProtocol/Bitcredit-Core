use super::{IdentityChainEventProcessorApi, public_chain_helpers::decode_block};
use crate::chain_keys::ChainKeyServiceApi;
use crate::handler::DirectMessageEventProcessorApi;
use crate::incoming_verification::VerifiedChainIngestionApi;
use crate::transport::unwrap_public_chain_event;
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_api::service::transport_service::Error;
use bcr_ebill_api::service::transport_service::propagation::RelayQuorumSnapshot;
use bcr_ebill_api::service::transport_service::{
    Result, restore::RestoreAccountApi, transport_client::TransportClientApi,
};
use bcr_ebill_core::{
    application::ServiceTraitBounds, protocol::blockchain::BlockchainType,
    protocol::crypto::BcrKeys,
};
use log::{info, warn};
use std::collections::HashSet;
use std::sync::Arc;

pub struct RestoreAccountService {
    nostr: Arc<dyn TransportClientApi>,
    identity_chain_processor: Arc<dyn IdentityChainEventProcessorApi>,
    dm_processor: Arc<dyn DirectMessageEventProcessorApi>,
    verified_ingestion: Arc<dyn VerifiedChainIngestionApi>,
    chain_keys: Arc<dyn ChainKeyServiceApi>,
    relay_snapshot: RelayQuorumSnapshot,
    keys: BcrKeys,
    node_id: NodeId,
}

impl RestoreAccountService {
    pub async fn new(
        nostr: Arc<dyn TransportClientApi>,
        identity_chain_processor: Arc<dyn IdentityChainEventProcessorApi>,
        dm_processor: Arc<dyn DirectMessageEventProcessorApi>,
        verified_ingestion: Arc<dyn VerifiedChainIngestionApi>,
        chain_keys: Arc<dyn ChainKeyServiceApi>,
        relay_snapshot: RelayQuorumSnapshot,
        keys: BcrKeys,
        node_id: NodeId,
    ) -> Self {
        Self {
            nostr,
            identity_chain_processor,
            dm_processor,
            verified_ingestion,
            chain_keys,
            relay_snapshot,
            keys,
            node_id,
        }
    }

    async fn restore_primary_account(&self) -> Result<()> {
        // Recover identity and its child-chain references
        // Non-verified events are queued for later
        self.restore_identity().await?;

        // Recover invitations addressed to the primary identity and dynamically discovered company signers
        if let Err(e) = self.dm_processor.catch_up_private_events().await {
            warn!(
                "Private-history recovery could not complete: {e} - periodic DM catch-up will retry after initialization"
            );
        }

        // Companies can contain references to issued bills.
        self.restore_known_chains(BlockchainType::Company).await?;

        // Try again to include keys recovered from the company chains above.
        self.restore_known_chains(BlockchainType::Bill).await?;

        Ok(())
    }

    async fn restore_identity(&self) -> Result<()> {
        self.restore_chain(
            &self.node_id.to_string(),
            BlockchainType::Identity,
            &self.keys,
        )
        .await
    }

    async fn restore_chain(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
        keys: &BcrKeys,
    ) -> Result<()> {
        info!("Restoring {chain_type} chain {chain_id}");
        let events = self
            .nostr
            .resolve_public_chain(chain_id, chain_type)
            .await?;
        let keys = Some(keys.clone());
        let mut seen = HashSet::new();
        let mut candidates = Vec::new();
        for event in events {
            if !seen.insert(event.id) {
                continue;
            }
            if event.verify().is_err() {
                continue;
            }
            let Ok(Some(public)) = unwrap_public_chain_event(&event) else {
                continue;
            };
            if public.id != chain_id || public.chain_type != chain_type {
                continue;
            }

            // Identity events must originate from the recovered primary identity
            if chain_type == BlockchainType::Identity
                && !self
                    .identity_chain_processor
                    .validate_chain_event_and_sender(&self.node_id, event.pubkey)
            {
                continue;
            }

            // Establish application order using block height not Nostr publication time
            let height = decode_block(event.clone(), chain_id, chain_type, &keys)
                .map(|block| block.get_block_height())
                .unwrap_or(u64::MAX);
            candidates.push((height, event));
        }

        if candidates.is_empty() {
            info!("No events found for {chain_type} {chain_id}");
            return Ok(());
        }
        candidates.sort_by_key(|(height, event)| (*height, event.id));
        let events = candidates.into_iter().map(|(_, event)| event).collect();
        let progress = self
            .verified_ingestion
            .ingest_verified_chain(chain_type, chain_id, events, self.relay_snapshot.clone())
            .await?;
        info!(
            "{chain_type} {chain_id} restoration: {} of {} discovered events applied, {} not applied",
            progress.applied_prefix,
            progress.enqueued,
            progress.remaining(),
        );
        Ok(())
    }

    async fn restore_known_chains(&self, chain_type: BlockchainType) -> Result<()> {
        let chains = self.chain_keys.list_known_chains().await?;
        for chain in chains {
            if chain.chain_type != chain_type {
                continue;
            }
            let Some(keys) = self
                .chain_keys
                .get_chain_keys(&chain.chain_id, chain_type)
                .await?
            else {
                warn!("Keys unavailable for {chain_type} {}", chain.chain_id,);
                continue;
            };
            match self.restore_chain(&chain.chain_id, chain_type, &keys).await {
                Ok(()) => {}
                Err(Error::Network(e)) => {
                    warn!(
                        "Could not fully restore {chain_type} {}: {e} background catch-up will retry",
                        chain.chain_id,
                    );
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
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
    use super::*;
    use crate::chain_keys::MockChainKeyServiceApi;
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
    use mockall::predicate::eq;
    use nostr::event::FinalizeEvent;
    use std::collections::HashSet;
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
    async fn test_create_identity() {
        let (keys, events) = generate_test_chain(1, false);
        let mut nostr = MockNotificationJsonTransport::new();
        let mut processor = MockIdentityChainEventProcessorApi::new();
        let mut dm_processor = MockDirectMessageEventProcessorApi::new();
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
        processor.expect_apply_verified_block().never();

        dm_processor
            .expect_catch_up_private_events()
            .once()
            .returning(|| Ok(()));

        let mut chain_key_service = MockChainKeyServiceApi::new();
        chain_key_service
            .expect_list_known_chains()
            .returning(|| Ok(vec![]));

        let service = RestoreAccountService::new(
            Arc::new(nostr),
            Arc::new(processor),
            Arc::new(dm_processor),
            Arc::new(ingestion),
            Arc::new(chain_key_service),
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
    async fn test_restore_identity_enqueues_all_discovered_branches() {
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

        let expected_event_ids: HashSet<String> = all_events
            .iter()
            .map(|event| event.id.to_string())
            .collect();

        ingestion
            .expect_ingest_verified_chain()
            .once()
            .withf(move |chain_type, _chain_id, events, snapshot| {
                *chain_type == BlockchainType::Identity
                    && snapshot.required == 2
                    && events.len() == 10
                    && events
                        .iter()
                        .map(|event| event.id.to_string())
                        .collect::<HashSet<_>>()
                        == expected_event_ids
            })
            .returning(|_, _, events, _| {
                Ok(VerifiedChainIngestionProgress {
                    enqueued: events.len(),
                    applied_prefix: 4,
                })
            });
        nostr
            .expect_resolve_public_chain()
            .once()
            .returning(move |_, _| Ok(all_events.clone()));

        processor
            .expect_validate_chain_event_and_sender()
            .times(10)
            .returning(|_, _| true);

        let mut chain_key_service = MockChainKeyServiceApi::new();
        chain_key_service
            .expect_list_known_chains()
            .returning(|| Ok(vec![]));

        let service = RestoreAccountService::new(
            Arc::new(nostr),
            Arc::new(processor),
            Arc::new(dm_processor),
            Arc::new(ingestion),
            Arc::new(chain_key_service),
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
    async fn test_restore_identity_excludes_invalid_sender() {
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
                    && events.len() == 3
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
        processor
            .expect_validate_chain_event_and_sender()
            .times(4)
            .returning(move |_, sender| sender == valid_pubkey);

        let mut chain_key_service = MockChainKeyServiceApi::new();
        chain_key_service
            .expect_list_known_chains()
            .returning(|| Ok(vec![]));

        let service = RestoreAccountService::new(
            Arc::new(nostr),
            Arc::new(processor),
            Arc::new(dm_processor),
            Arc::new(ingestion),
            Arc::new(chain_key_service),
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
        let mut processor = MockIdentityChainEventProcessorApi::new();
        processor
            .expect_validate_chain_event_and_sender()
            .once()
            .returning(|_, _| true);
        processor.expect_apply_verified_block().never();
        let mut ingestion = MockVerifiedChainIngestionApi::new();
        ingestion
            .expect_ingest_verified_chain()
            .once()
            .returning(|_, _, _, _| {
                Err(bcr_ebill_api::service::transport_service::Error::Network(
                    "relay quorum unavailable".into(),
                ))
            });

        let mut dm_processor = MockDirectMessageEventProcessorApi::new();

        dm_processor.expect_catch_up_private_events().never();
        let mut chain_key_service = MockChainKeyServiceApi::new();
        chain_key_service
            .expect_list_known_chains()
            .returning(|| Ok(vec![]));

        let service = RestoreAccountService::new(
            Arc::new(nostr),
            Arc::new(processor),
            Arc::new(dm_processor),
            Arc::new(ingestion),
            Arc::new(chain_key_service),
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

        let mut processor = MockIdentityChainEventProcessorApi::new();
        processor
            .expect_validate_chain_event_and_sender()
            .times(3)
            .returning(|_, _| true);
        processor.expect_apply_verified_block().never();
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
            .expect_catch_up_private_events()
            .once()
            .returning(|| Ok(()));

        let mut chain_key_service = MockChainKeyServiceApi::new();
        chain_key_service
            .expect_list_known_chains()
            .returning(|| Ok(vec![]));
        let service = RestoreAccountService::new(
            Arc::new(nostr),
            Arc::new(processor),
            Arc::new(dm_processor),
            Arc::new(ingestion),
            Arc::new(chain_key_service),
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

    #[tokio::test]
    async fn incomplete_private_catchup_does_not_fail_restoration() {
        let mut nostr = MockNotificationJsonTransport::new();
        // No identity chain available
        nostr
            .expect_resolve_public_chain()
            .once()
            .returning(|_, _| Ok(vec![]));
        let mut dm_processor = MockDirectMessageEventProcessorApi::new();
        dm_processor
            .expect_catch_up_private_events()
            .once()
            .returning(|| {
                Err(bcr_ebill_api::service::transport_service::Error::Network(
                    "relay temporarily unavailable".into(),
                ))
            });
        let mut ingestion = MockVerifiedChainIngestionApi::new();
        ingestion.expect_ingest_verified_chain().never();

        let mut chain_key_service = MockChainKeyServiceApi::new();
        chain_key_service
            .expect_list_known_chains()
            .returning(|| Ok(vec![]));
        let service = RestoreAccountService::new(
            Arc::new(nostr),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(dm_processor),
            Arc::new(ingestion),
            Arc::new(chain_key_service),
            test_snapshot(),
            BcrKeys::new(),
            node_id_test(),
        )
        .await;
        // A failed private-history query doesnt prevent reinitialization and subsequent automatic catch-up
        service.restore_account().await.unwrap();
    }
}
