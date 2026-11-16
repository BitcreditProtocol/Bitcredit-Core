use std::{str::FromStr, sync::Arc};

use super::{BillChainEventProcessorApi, NotificationHandlerApi};
use crate::EventType;
use crate::chain_keys::KnownChain;
use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_api::service::transport_service::{Error, Result};
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::{
        ProtocolValidationError,
        blockchain::BlockchainType,
        crypto::BcrKeys,
        event::{ChainInvite, Event, EventEnvelope},
    },
};
use bcr_ebill_persistence::traits::propagation::IncomingPropagationStoreApi;
use log::debug;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct BillInviteEventHandler {
    processor: Arc<dyn BillChainEventProcessorApi>,
    incoming_store: Arc<dyn IncomingPropagationStoreApi>,
    catchup_hints: Option<broadcast::Sender<KnownChain>>,
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
        let decoded = Event::<ChainInvite>::try_from(event)
            .map_err(|e| Error::Message(format!("Could not decode chain invitation: {e}")))?;
        if decoded.data.chain_type != BlockchainType::Bill {
            return Err(Error::Message(
                "Unexpected chain type in bill invite".into(),
            ));
        }
        let bill_id =
            BillId::from_str(&decoded.data.chain_id).map_err(ProtocolValidationError::from)?;
        let keys = BcrKeys::from_private_key(&decoded.data.keys.private_key);

        // persist invite keys
        self.processor.persist_invite_keys(&bill_id, &keys).await?;

        // best-effort notification to fetch chain events once we have the keys for faster processing
        if let Some(hints) = &self.catchup_hints {
            let _ = hints.send(KnownChain {
                chain_type: BlockchainType::Bill,
                chain_id: bill_id.to_string(),
            });
        }

        // wait up blocks potentially waiting for these keys
        self.incoming_store
            .wake_application_for_keys("bill", &bill_id.to_string())
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

        debug!("Persisted keys for bill {bill_id}");
        Ok(())
    }
}

impl ServiceTraitBounds for BillInviteEventHandler {}

impl BillInviteEventHandler {
    pub fn new(
        processor: Arc<dyn BillChainEventProcessorApi>,
        incoming_store: Arc<dyn IncomingPropagationStoreApi>,
    ) -> Self {
        Self {
            processor,
            incoming_store,
            catchup_hints: None,
        }
    }

    pub fn with_catchup_hints(mut self, hints: broadcast::Sender<KnownChain>) -> Self {
        self.catchup_hints = Some(hints);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        handler::{
            MockBillChainEventProcessorApi,
            public_chain_helpers::collect_event_chains,
            test_utils::{
                MockIncomingPropagationStore, bill_id_test, get_bill_keys, get_genesis_chain,
                node_id_test, private_key_test,
            },
        },
        transport::create_public_chain_event,
    };
    use bcr_ebill_core::protocol::event::BillBlockEvent;
    use bcr_ebill_core::{
        protocol::Timestamp, protocol::blockchain::Blockchain, protocol::crypto::BcrKeys,
    };
    use nostr::event::FinalizeEvent;
    use std::sync::atomic::{AtomicBool, Ordering};

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
    async fn bill_invite_persists_keys_and_wakes_application() {
        let persisted = Arc::new(AtomicBool::new(false));
        let did_persist = persisted.clone();
        let (tx, mut rx) = tokio::sync::broadcast::channel(8);

        let mut processor = MockBillChainEventProcessorApi::new();
        processor
            .expect_persist_invite_keys()
            .once()
            .returning(move |_, _| {
                did_persist.store(true, Ordering::SeqCst);
                Ok(())
            });

        // invite must never fetch or apply chain blocks
        processor.expect_resolve_chain().never();
        processor.expect_process_chain_data().never();
        processor.expect_valid_chain_prefix_len().never();

        let mut store = MockIncomingPropagationStore::new();
        let check = persisted.clone();
        let expected_id = bill_id_test().to_string();
        store
            .expect_wake_application_for_keys()
            .once()
            .withf(move |chain_type, chain_id| {
                check.load(Ordering::SeqCst) && chain_type == "bill" && chain_id == expected_id
            })
            .returning(|_, _| Ok(()));

        let handler = BillInviteEventHandler::new(Arc::new(processor), Arc::new(store))
            .with_catchup_hints(tx);
        let invite: EventEnvelope = Event::new_bill_invite(ChainInvite::bill(
            bill_id_test().to_string(),
            get_bill_keys(),
        ))
        .try_into()
        .unwrap();
        handler
            .handle_event(invite, &node_id_test(), None, None)
            .await
            .unwrap();
        assert_eq!(
            rx.try_recv().unwrap(),
            KnownChain {
                chain_type: BlockchainType::Bill,
                chain_id: bill_id_test().to_string(),
            },
        );
        assert!(persisted.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn failed_key_persistence_does_not_wake_application() {
        let mut processor = MockBillChainEventProcessorApi::new();
        processor
            .expect_persist_invite_keys()
            .once()
            .returning(|_, _| Err(Error::Persistence("simulated database failure".into())));
        let (tx, mut rx) = tokio::sync::broadcast::channel(8);

        let mut store = MockIncomingPropagationStore::new();
        store.expect_wake_application_for_keys().never();
        let handler = BillInviteEventHandler::new(Arc::new(processor), Arc::new(store))
            .with_catchup_hints(tx);
        let invite: EventEnvelope = Event::new_bill_invite(ChainInvite::bill(
            bill_id_test().to_string(),
            get_bill_keys(),
        ))
        .try_into()
        .unwrap();

        let result = handler
            .handle_event(invite, &node_id_test(), None, None)
            .await;
        assert!(matches!(result, Err(Error::Persistence(_))));
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
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
