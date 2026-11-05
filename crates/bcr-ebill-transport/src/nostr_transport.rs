use std::collections::HashMap;
use std::sync::Arc;

use bcr_common::core::NodeId;
use bcr_ebill_api::Config;
use bcr_ebill_api::service::transport_service::transport_client::TransportClientApi;
use bcr_ebill_api::util::validate_node_id_network;
use bcr_ebill_core::application::ServiceTraitBounds;
use bcr_ebill_core::application::nostr_contact::TrustLevel;
use bcr_ebill_core::protocol::Address;
use bcr_ebill_core::protocol::City;
use bcr_ebill_core::protocol::Country;
use bcr_ebill_core::protocol::Name;
use bcr_ebill_core::protocol::Sha256Hash;
use bcr_ebill_core::protocol::blockchain::BlockchainType;
use bcr_ebill_core::protocol::blockchain::bill::{
    block::ContactType,
    participant::{BillAnonParticipant, BillIdentParticipant, BillParticipant},
};
use bcr_ebill_core::protocol::crypto::BcrKeys;
use bcr_ebill_core::protocol::event::{BillChainEventPayload, Event, EventEnvelope};
use bcr_ebill_persistence::ContactStoreApi;
use bcr_ebill_persistence::traits::nostr::{
    NostrChainEvent, NostrChainEventStoreApi, NostrContactStoreApi,
};
use bcr_ebill_persistence::traits::propagation::PreparedPropagationMessage;
use log::{debug, error, warn};

use bcr_ebill_api::service::transport_service::{Error, Result};
use bcr_ebill_core::protocol::PostalAddress;

/// Transport implementation for Nostr
#[derive(Clone)]
pub struct NostrTransportService {
    nostr_client: Arc<dyn TransportClientApi>,
    contact_store: Arc<dyn ContactStoreApi>,
    nostr_contact_store: Arc<dyn NostrContactStoreApi>,
    chain_event_store: Arc<dyn NostrChainEventStoreApi>,
    nostr_relays: Vec<url::Url>,
    config: Arc<Config>,
}

impl ServiceTraitBounds for NostrTransportService {}

impl NostrTransportService {
    pub fn new(
        nostr_client: Arc<dyn TransportClientApi>,
        contact_store: Arc<dyn ContactStoreApi>,
        nostr_contact_store: Arc<dyn NostrContactStoreApi>,
        chain_event_store: Arc<dyn NostrChainEventStoreApi>,
        nostr_relays: Vec<url::Url>,
        config: Arc<Config>,
    ) -> Self {
        Self {
            nostr_client,
            contact_store,
            nostr_contact_store,
            chain_event_store,
            nostr_relays,
            config,
        }
    }

    pub(crate) fn get_node_transport(&self, _node_id: &NodeId) -> Arc<dyn TransportClientApi> {
        // With single shared client, we return it for any node_id
        // The client internally handles multi-identity
        self.nostr_client.clone()
    }

    pub(crate) fn get_first_transport(&self) -> Arc<dyn TransportClientApi> {
        // With single client, just return it
        self.nostr_client.clone()
    }

    pub(crate) fn get_local_identity(&self, node_id: &NodeId) -> Option<BillParticipant> {
        // Check if this node_id is one of the local identities managed by the client.
        // Only return Some if the node_id exists in the signers map.
        if self.nostr_client.has_local_signer(node_id) {
            Some(BillParticipant::Ident(BillIdentParticipant {
                // we create an ident, but it doesn't matter, since we just need the node id and nostr relay
                t: ContactType::Person,
                node_id: node_id.to_owned(),
                email: None,
                name: Name::new("default name").expect("is a valid name"),
                postal_address: PostalAddress {
                    country: Country::AT,
                    city: City::new("default city").expect("is valid city"),
                    zip: None,
                    address: Address::new("default address").expect("is valid address"),
                },
                nostr_relays: self.nostr_relays.clone(),
            }))
        } else {
            None
        }
    }

    pub(crate) async fn resolve_identity(&self, node_id: &NodeId) -> Option<BillParticipant> {
        match self.get_local_identity(node_id) {
            Some(id) => Some(id),
            None => {
                if let Some(identity) = self.resolve_node_contact(node_id).await {
                    Some(identity)
                } else if let Ok(Some(nostr)) = self.nostr_contact_store.by_node_id(node_id).await
                    && nostr.trust_level != TrustLevel::None
                {
                    // we have no contact but a nostr contact of a participant
                    Some(BillParticipant::Anon(BillAnonParticipant {
                        node_id: node_id.to_owned(),
                        nostr_relays: nostr.relays,
                    }))
                } else {
                    None
                }
            }
        }
    }

    pub(crate) async fn resolve_node_contact(&self, node_id: &NodeId) -> Option<BillParticipant> {
        if validate_node_id_network(node_id, self.config.bitcoin_network()).is_err() {
            return None;
        }
        if let Ok(Some(identity)) = self.contact_store.get(node_id).await {
            identity.try_into().ok()
        } else {
            None
        }
    }

    pub(crate) async fn add_identity(&self, node_id: &NodeId, keys: &BcrKeys) -> Result<()> {
        debug!("Adding identity for node_id: {node_id}");
        self.nostr_client
            .add_identity(node_id.clone(), keys.clone())
            .await?;
        Ok(())
    }

    pub(crate) async fn send_private_event(
        &self,
        sender: &NodeId,
        recipient: &NodeId,
        relays: &[url::Url],
        message: EventEnvelope,
    ) -> Result<()> {
        let transport = self.get_node_transport(sender);
        let recipient = BillParticipant::Anon(BillAnonParticipant {
            node_id: recipient.to_owned(),
            nostr_relays: relays.to_vec(),
        });
        transport
            .send_private_event(sender, &recipient, message)
            .await?;
        Ok(())
    }

    pub(crate) async fn find_root_and_previous_event(
        &self,
        previous_hash: &Sha256Hash,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> Result<(Option<NostrChainEvent>, Option<NostrChainEvent>)> {
        // find potential previous block event
        let previous_event = self
            .chain_event_store
            .find_by_block_hash(previous_hash)
            .await
            .map_err(|e| Error::Persistence(format!("failed to read from chain events: {e}")))?;

        // if there is a previous and it is not the root event, also get the root event
        let root_event = if previous_event.clone().is_some_and(|f| !f.is_root_event()) {
            self.chain_event_store
                .find_root_event(chain_id, chain_type)
                .await
                .map_err(|e| Error::Persistence(format!("failed to read from chain events: {e}")))?
        } else {
            previous_event.clone()
        };
        Ok((previous_event, root_event))
    }

    pub(crate) async fn connect(&self) {
        // With single multi-identity client, just connect it
        if let Err(e) = self.nostr_client.connect().await {
            error!("Failed to connect to transport: {e}");
        }
    }

    pub(crate) async fn prepare_private_propagation_message_to(
        &self,
        sender: &NodeId,
        recipient: &BillParticipant,
        envelope: EventEnvelope,
    ) -> Result<PreparedPropagationMessage> {
        let event_type = envelope.event_type.clone();
        let prepared = self
            .get_node_transport(sender)
            .prepare_private_event(sender, recipient, envelope)
            .await?;
        Ok(PreparedPropagationMessage {
            id: uuid::Uuid::new_v4().to_string(),
            event_type,
            recipient_id: Some(recipient.node_id()),
            chain_id: None,
            block_hash: None,
            event: prepared.event,
            target_relays: prepared.target_relays,
        })
    }

    pub(crate) async fn prepare_private_propagation_message(
        &self,
        sender: &NodeId,
        recipient_id: &NodeId,
        envelope: EventEnvelope,
    ) -> Result<PreparedPropagationMessage> {
        let recipient = self.resolve_identity(recipient_id).await.ok_or_else(|| {
            Error::Message(format!(
                "Cannot prepare Nostr message: recipient {recipient_id} could not be resolved"
            ))
        })?;
        self.prepare_private_propagation_message_to(sender, &recipient, envelope)
            .await
    }

    /// failure to prepare a notification for one recipient doesn't affect other recipients - we just log an error
    pub(crate) async fn prepare_bill_private_messages(
        &self,
        sender: &NodeId,
        events: &HashMap<NodeId, Event<BillChainEventPayload>>,
    ) -> Result<Vec<PreparedPropagationMessage>> {
        let mut recipients = events.iter().collect::<Vec<_>>();
        recipients.sort_by_key(|(a, _)| a.to_string());
        let mut prepared = Vec::with_capacity(recipients.len());
        for (recipient_id, event) in recipients {
            let envelope: EventEnvelope = match event.clone().try_into() {
                Ok(envelope) => envelope,
                Err(e) => {
                    warn!(
                        "Could not serialize bill notification for recipient {recipient_id}: {e}"
                    );
                    continue;
                }
            };
            match self
                .prepare_private_propagation_message(sender, recipient_id, envelope)
                .await
            {
                Ok(message) => prepared.push(message),
                Err(e) => {
                    warn!("Could not prepare bill notification for recipient {recipient_id}: {e}");
                }
            }
        }
        Ok(prepared)
    }
}
