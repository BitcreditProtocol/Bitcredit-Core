use super::{CompanyChainEventProcessorApi, NotificationHandlerApi};
use crate::EventType;
use crate::chain_keys::KnownChain;
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_api::service::transport_service::transport_client::TransportClientApi;
use bcr_ebill_api::service::transport_service::{Error, Result};
use bcr_ebill_core::protocol::event::EventEnvelope;
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::{
        ProtocolValidationError,
        blockchain::BlockchainType,
        crypto::BcrKeys,
        event::{ChainInvite, Event},
    },
};
use bcr_ebill_persistence::traits::propagation::IncomingPropagationStoreApi;
use log::debug;
use std::{str::FromStr, sync::Arc};
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct CompanyInviteEventHandler {
    transport: Arc<dyn TransportClientApi>,
    processor: Arc<dyn CompanyChainEventProcessorApi>,
    incoming_store: Arc<dyn IncomingPropagationStoreApi>,
    catchup_hints: Option<broadcast::Sender<KnownChain>>,
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
        let decoded = Event::<ChainInvite>::try_from(event)
            .map_err(|e| Error::Message(format!("Could not decode chain invitation: {e}")))?;
        if decoded.data.chain_type != BlockchainType::Company {
            return Err(Error::Message(
                "Unexpected chain type in company invite".into(),
            ));
        }
        let company_id =
            NodeId::from_str(&decoded.data.chain_id).map_err(ProtocolValidationError::from)?;
        let keys = BcrKeys::from_private_key(&decoded.data.keys.private_key);
        // persist invite keys
        self.processor
            .persist_invite_keys(&company_id, &keys)
            .await?;

        // wait up blocks potentially waiting for these keys
        self.incoming_store
            .wake_application_for_keys("company", &company_id.to_string())
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

        // best-effort notification to fetch chain events once we have the keys for faster processing
        if let Some(hints) = &self.catchup_hints {
            let _ = hints.send(KnownChain {
                chain_type: BlockchainType::Company,
                chain_id: company_id.to_string(),
            });
        }

        // a company could receive private Nostr events before its public blockchain has been initialized
        self.transport
            .add_identity(company_id.clone(), keys)
            .await?;

        debug!("Persisted keys and registered company {company_id}");

        Ok(())
    }
}

impl ServiceTraitBounds for CompanyInviteEventHandler {}

impl CompanyInviteEventHandler {
    pub fn new(
        transport: Arc<dyn TransportClientApi>,
        processor: Arc<dyn CompanyChainEventProcessorApi>,
        incoming_store: Arc<dyn IncomingPropagationStoreApi>,
    ) -> Self {
        Self {
            transport,
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
        MockCompanyChainEventProcessorApi, test_utils::MockIncomingPropagationStore,
    };
    use crate::test_utils::{MockNotificationJsonTransport, node_id_test};
    use bcr_ebill_core::protocol::crypto::BcrKeys;

    #[tokio::test]
    async fn company_invite_registers_signer_without_applying_chain() {
        let keys = BcrKeys::new();
        let company_id = NodeId::new(keys.pub_key(), bitcoin::Network::Testnet);

        let (tx, mut rx) = tokio::sync::broadcast::channel(8);

        let mut processor = MockCompanyChainEventProcessorApi::new();
        processor
            .expect_persist_invite_keys()
            .once()
            .returning(|_, _| Ok(()));
        processor.expect_apply_verified_block().never();
        let mut store = MockIncomingPropagationStore::new();
        let expected_id = company_id.to_string();
        store
            .expect_wake_application_for_keys()
            .once()
            .withf(move |chain_type, chain_id| chain_type == "company" && chain_id == expected_id)
            .returning(|_, _| Ok(()));
        let mut transport = MockNotificationJsonTransport::new();
        transport.expect_resolve_public_chain().never();
        let expected_company_id = company_id.clone();
        let expected_pub_key = keys.pub_key();
        transport
            .expect_add_identity()
            .once()
            .withf(move |id, keys| id == &expected_company_id && keys.pub_key() == expected_pub_key)
            .returning(|_, _| Ok(()));

        let handler = CompanyInviteEventHandler::new(
            Arc::new(transport),
            Arc::new(processor),
            Arc::new(store),
        )
        .with_catchup_hints(tx);
        let invite: EventEnvelope =
            Event::new_company_invite(ChainInvite::company(company_id.to_string(), keys))
                .try_into()
                .unwrap();
        handler
            .handle_event(invite, &node_id_test(), None, None)
            .await
            .unwrap();
        assert_eq!(
            rx.try_recv().unwrap(),
            KnownChain {
                chain_type: BlockchainType::Company,
                chain_id: company_id.to_string(),
            },
        );
    }
}
