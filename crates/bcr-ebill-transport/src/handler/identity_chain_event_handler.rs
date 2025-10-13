use std::sync::Arc;

use async_trait::async_trait;
use bcr_ebill_api::service::notification_service::event::IdentityBlockEvent;
use bcr_ebill_core::{NodeId, ServiceTraitBounds, blockchain::BlockchainType, util::date::now};
use bcr_ebill_persistence::identity::IdentityStoreApi;
use bcr_ebill_persistence::{NostrChainEventStoreApi, nostr::NostrChainEvent};
use log::{debug, error, trace, warn};

use crate::{EventType, transport::root_and_reply_id};
use bcr_ebill_api::service::notification_service::event::Event;
use bcr_ebill_api::service::notification_service::{Result, event::EventEnvelope};

use super::{IdentityChainEventProcessorApi, NotificationHandlerApi};

#[derive(Clone)]
pub struct IdentityChainEventHandler {
    identity_store: Arc<dyn IdentityStoreApi>,
    processor: Arc<dyn IdentityChainEventProcessorApi>,
    chain_event_store: Arc<dyn NostrChainEventStoreApi>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationHandlerApi for IdentityChainEventHandler {
    fn handles_event(&self, event_type: &EventType) -> bool {
        event_type == &EventType::IdentityChain
    }

    async fn handle_event(
        &self,
        event: EventEnvelope,
        node_id: &NodeId,
        original_event: Option<Box<nostr::Event>>,
    ) -> Result<()> {
        debug!("incoming identity chain event for {node_id}");
        if let Ok(decoded) = Event::<IdentityBlockEvent>::try_from(event.clone()) {
            if let Ok(keys) = self.identity_store.get_key_pair().await {
                let valid = self
                    .processor
                    .process_chain_data(
                        &decoded.data.node_id,
                        vec![decoded.data.block.clone()],
                        Some(keys.clone()),
                    )
                    .await
                    .inspect_err(|e| error!("Received invalid block {e}"))
                    .is_ok();
                if let Some(original_event) = original_event {
                    self.store_event(
                        original_event,
                        decoded.data.block_height,
                        &decoded.data.block.hash,
                        &decoded.data.node_id.to_string(),
                        valid,
                    )
                    .await?;
                }
            } else {
                trace!("no keys for incoming identity block {node_id}");
            }
        } else {
            warn!("Could not decode event to IdentityBlockEvent {event:?}");
        }
        Ok(())
    }
}
impl ServiceTraitBounds for IdentityChainEventHandler {}

#[allow(unused)]
impl IdentityChainEventHandler {
    pub fn new(
        identity_store: Arc<dyn IdentityStoreApi>,
        processor: Arc<dyn IdentityChainEventProcessorApi>,
        chain_event_store: Arc<dyn NostrChainEventStoreApi>,
    ) -> Self {
        Self {
            identity_store,
            processor,
            chain_event_store,
        }
    }
    async fn store_event(
        &self,
        event: Box<nostr::Event>,
        block_height: usize,
        block_hash: &str,
        chain_id: &str,
        valid: bool,
    ) -> Result<()> {
        let (root, reply) = root_and_reply_id(&event);
        if let Err(e) = self
            .chain_event_store
            .add_chain_event(NostrChainEvent {
                event_id: event.id.to_string(),
                root_id: root
                    .map(|id| id.to_string())
                    .unwrap_or(event.id.to_string()),
                reply_id: reply.map(|id| id.to_string()),
                author: event.pubkey.to_string(),
                chain_id: chain_id.to_string(),
                chain_type: BlockchainType::Identity,
                block_height,
                block_hash: block_hash.to_string(),
                received: now().timestamp() as u64,
                time: event.created_at.as_u64(),
                payload: *event.clone(),
                valid,
            })
            .await
        {
            error!("Failed to store bill chain nostr event into event store {e}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use bcr_ebill_core::{
        blockchain::{
            Blockchain,
            identity::{IdentityBlock, IdentityBlockchain, IdentityUpdateBlockData},
        },
        identity::IdentityWithAll,
        name::Name,
    };
    use mockall::predicate::always;

    use crate::handler::{
        MockIdentityChainEventProcessorApi,
        identity_chain_event_processor::tests::{
            get_identity_create_block, get_identity_update_block,
        },
        test_utils::{
            MockIdentityStore, MockNostrChainEventStore, get_baseline_identity,
            get_test_nostr_event, node_id_test,
        },
    };

    use super::*;

    #[tokio::test]
    async fn test_handle_update_event() {
        let (mut store, mut processor, mut chain_event_store) = create_mocks();
        let full = get_baseline_identity();
        let identity = full.identity.clone();
        let keys = full.key_pair.clone();
        let chain = create_identity_chain(full.clone());
        let data = IdentityUpdateBlockData {
            name: Some(Name::new("new_name").unwrap()),
            ..Default::default()
        };
        let block = get_identity_update_block(chain.get_latest_block(), &keys, &data);
        let original_event = Box::new(get_test_nostr_event());

        let event = Event::new_company_chain(IdentityBlockEvent {
            node_id: node_id_test(),
            block_height: 1,
            block: block.clone(),
        });

        // see if we have chain keys
        store
            .expect_get_key_pair()
            .returning(move || Ok(keys.clone()))
            .once();

        // should process the chain data
        processor
            .expect_process_chain_data()
            .withf(|node_id, blocks, company_keys| {
                node_id == &node_id.clone() && !blocks.is_empty() && company_keys.is_some()
            })
            .returning(|_, _, _| Ok(()))
            .once();

        // and store the nostr event
        chain_event_store
            .expect_add_chain_event()
            .with(always())
            .returning(|_| Ok(()))
            .once();

        let handler = IdentityChainEventHandler::new(
            Arc::new(store),
            Arc::new(processor),
            Arc::new(chain_event_store),
        );

        handler
            .handle_event(
                event.try_into().unwrap(),
                &identity.node_id,
                Some(original_event),
            )
            .await
            .expect("failed to handle event");
    }

    #[tokio::test]
    async fn test_handle_no_chain_event() {
        let (mut store, mut processor, chain_event_store) = create_mocks();
        let full = get_baseline_identity();
        let identity = full.identity.clone();
        let keys = full.key_pair.clone();
        let node_id = identity.node_id.clone();
        let chain = create_identity_chain(full.clone());
        let data = IdentityUpdateBlockData {
            name: Some(Name::new("new_name").unwrap()),
            ..Default::default()
        };
        let block = IdentityBlock::create_block_for_update(
            chain.get_latest_block(),
            &data,
            &keys,
            1731593928,
        )
        .expect("could not create block");

        let original_event = Box::new(get_test_nostr_event());

        let event = Event::new_identity_chain(IdentityBlockEvent {
            node_id: node_id.clone(),
            block_height: 1,
            block: block.clone(),
        });

        // no chain keys so we should be done here
        store
            .expect_get_key_pair()
            .returning(move || Err(bcr_ebill_persistence::Error::NoIdentity))
            .once();

        processor.expect_process_chain_data().never();

        let handler = IdentityChainEventHandler::new(
            Arc::new(store),
            Arc::new(processor),
            Arc::new(chain_event_store),
        );

        handler
            .handle_event(event.try_into().unwrap(), &node_id, Some(original_event))
            .await
            .expect("failed to handle event");
    }

    fn create_identity_chain(full: IdentityWithAll) -> IdentityBlockchain {
        let blocks = vec![get_identity_create_block(full.identity, &full.key_pair)];
        IdentityBlockchain::new_from_blocks(blocks).expect("could not create chain")
    }

    fn create_mocks() -> (
        MockIdentityStore,
        MockIdentityChainEventProcessorApi,
        MockNostrChainEventStore,
    ) {
        (
            MockIdentityStore::default(),
            MockIdentityChainEventProcessorApi::default(),
            MockNostrChainEventStore::default(),
        )
    }
}
