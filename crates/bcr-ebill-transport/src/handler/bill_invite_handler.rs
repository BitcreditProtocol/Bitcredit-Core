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

        // wait up blocks potentially waiting for these keys
        self.incoming_store
            .wake_application_for_keys("bill", &bill_id.to_string())
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

        // best-effort notification to fetch chain events once we have the keys for faster processing
        if let Some(hints) = &self.catchup_hints {
            let _ = hints.send(KnownChain {
                chain_type: BlockchainType::Bill,
                chain_id: bill_id.to_string(),
            });
        }

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
    use crate::handler::{
        MockBillChainEventProcessorApi,
        test_utils::{MockIncomingPropagationStore, bill_id_test, get_bill_keys, node_id_test},
    };
    use std::sync::atomic::{AtomicBool, Ordering};

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
        processor.expect_apply_verified_block().never();

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
}
