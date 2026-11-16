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

        // best-effort notification to fetch chain events once we have the keys for faster processing
        if let Some(hints) = &self.catchup_hints {
            let _ = hints.send(KnownChain {
                chain_type: BlockchainType::Company,
                chain_id: company_id.to_string(),
            });
        }

        // wait up blocks potentially waiting for these keys
        self.incoming_store
            .wake_application_for_keys("company", &company_id.to_string())
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;

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
    use crate::{
        handler::{
            public_chain_helpers::collect_event_chains,
            test_utils::{get_company_data, private_key_test},
        },
        test_utils::test_ts,
        transport::create_public_chain_event,
    };
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
    async fn company_invite_registers_signer_without_applying_chain() {
        let keys = BcrKeys::new();
        let company_id = NodeId::new(keys.pub_key(), bitcoin::Network::Testnet);

        let (tx, mut rx) = tokio::sync::broadcast::channel(8);

        let mut processor = MockCompanyChainEventProcessorApi::new();
        processor
            .expect_persist_invite_keys()
            .once()
            .returning(|_, _| Ok(()));
        processor.expect_process_chain_data().never();
        processor.expect_valid_chain_prefix_len().never();
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
