use crate::service::{Error, Result, transport_service::TransportServiceApi};
use bcr_ebill_core::protocol::{Timestamp, blockchain::BlockchainType, event::EventType};
use bcr_ebill_persistence::traits::{
    nostr::NostrChainEvent,
    propagation::{PreparedPropagation, PreparedPropagationMessage, PropagationSubjectType},
    transaction::PersistenceTransactionApi,
};
use uuid::Uuid;

pub(crate) struct PreparedChainPropagation {
    pub propagation: PreparedPropagation,
    pub chain_events: Vec<NostrChainEvent>,
    required_message_ids: Vec<String>,
}

impl PreparedChainPropagation {
    pub fn new(
        subject_type: PropagationSubjectType,
        subject_id: String,
        chain_events: Vec<NostrChainEvent>,
        invites: Vec<PreparedPropagationMessage>,
        public_relays: Vec<url::Url>,
    ) -> Result<Self> {
        if chain_events.is_empty() {
            return Err(Error::Internal(
                "Cannot prepare an empty chain propagation".into(),
            ));
        }
        let mut messages = Vec::new();
        for event in &chain_events {
            let event_type = match &event.chain_type {
                BlockchainType::Identity => EventType::IdentityChain,
                BlockchainType::Company => EventType::CompanyChain,
                BlockchainType::Bill => EventType::BillChain,
            };
            messages.push(PreparedPropagationMessage {
                id: Uuid::new_v4().to_string(),
                event_type,
                recipient_id: None,
                chain_id: Some(event.chain_id.clone()),
                block_hash: Some(event.block_hash.clone()),
                event: event.payload.clone(),
                target_relays: public_relays.clone(),
            });
        }
        messages.extend(invites);
        let required_message_ids = messages
            .iter()
            .map(|message| message.id.clone())
            .collect::<Vec<_>>();
        let propagation = PreparedPropagation {
            id: Uuid::new_v4().to_string(),
            subject_type,
            subject_id,
            created_at: Timestamp::now(),
            messages,
        };
        propagation.validate()?;
        Ok(Self {
            propagation,
            chain_events,
            required_message_ids,
        })
    }

    pub async fn enqueue(&self, tx: &mut dyn PersistenceTransactionApi) -> Result<()> {
        for event in &self.chain_events {
            tx.add_chain_event(event).await?;
        }
        tx.enqueue_propagation(&self.propagation).await?;
        Ok(())
    }

    pub async fn attempt_after_commit(&self, transport: &dyn TransportServiceApi) {
        if let Err(e) = transport
            .attempt_propagation(&self.propagation.id, &self.required_message_ids)
            .await
        {
            log::error!(
                "Transaction committed, but propagation {} encountered an error: {e}",
                self.propagation.id,
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::PreparedChainPropagation;
    use crate::service::transport_service::{Error as TransportError, MockTransportServiceApi};
    use bcr_ebill_core::protocol::{
        Sha256Hash, Timestamp,
        blockchain::BlockchainType,
        event::{CompanyChainEvent, EventType, IdentityChainEvent},
    };
    use bcr_ebill_persistence::traits::propagation::PropagationSubjectType;
    use bcr_ebill_persistence::traits::{
        nostr::NostrChainEvent, propagation::PreparedPropagationMessage,
    };
    use nostr::{
        event::{EventBuilder, FinalizeEvent, Kind},
        key::Keys,
    };
    use uuid::Uuid;

    fn relay_urls() -> Vec<url::Url> {
        vec![url::Url::parse("wss://relay.example").unwrap()]
    }

    fn signed_chain_event(
        chain_id: String,
        chain_type: BlockchainType,
        height: usize,
        block_hash: Sha256Hash,
        previous: Option<&NostrChainEvent>,
    ) -> NostrChainEvent {
        let event = EventBuilder::new(Kind::TextNote, format!("test {chain_id} block {height}"))
            .finalize(&Keys::generate())
            .unwrap();
        let event_id = event.id.to_string();
        let time: Timestamp = event.created_at.into();
        let root_id = previous.map(|p| p.root_id.clone()).unwrap_or_else(|| {
            if height == 1 {
                event_id.clone()
            } else {
                "existing-root".to_owned()
            }
        });
        let reply_id = previous
            .map(|p| p.event_id.clone())
            .or_else(|| (height > 1).then(|| "existing-previous".into()));
        NostrChainEvent {
            event_id,
            root_id,
            reply_id,
            author: event.pubkey.to_string(),
            chain_id,
            chain_type,
            block_height: height,
            block_hash,
            received: time,
            time,
            payload: event,
        }
    }

    fn identity_events(events: &[IdentityChainEvent]) -> Vec<NostrChainEvent> {
        let mut result = Vec::with_capacity(events.len());
        for event in events {
            let message = event
                .generate_blockchain_message()
                .expect("identity event must contain a block");
            result.push(signed_chain_event(
                message.data.node_id.to_string(),
                BlockchainType::Identity,
                message.data.block.id.inner() as usize,
                message.data.block.hash.clone(),
                result.last(),
            ));
        }
        result
    }

    fn company_events(events: &[CompanyChainEvent]) -> Vec<NostrChainEvent> {
        let mut result = Vec::with_capacity(events.len());
        for event in events {
            let message = event
                .generate_blockchain_message()
                .expect("company event must contain a block");
            result.push(signed_chain_event(
                message.data.node_id.to_string(),
                BlockchainType::Company,
                message.data.block.id.inner() as usize,
                message.data.block.hash.clone(),
                result.last(),
            ));
        }
        result
    }

    fn company_invites(event: &CompanyChainEvent) -> Vec<PreparedPropagationMessage> {
        event
            .generate_company_invite_message()
            .map(|(recipient_id, _)| {
                let signed = EventBuilder::new(Kind::GiftWrap, "mock company chain invite")
                    .finalize(&Keys::generate())
                    .unwrap();
                PreparedPropagationMessage {
                    id: Uuid::new_v4().to_string(),
                    event_type: EventType::CompanyChainInvite,
                    recipient_id: Some(recipient_id),
                    chain_id: None,
                    block_hash: None,
                    event: signed,
                    target_relays: relay_urls(),
                }
            })
            .into_iter()
            .collect()
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum InviteBehavior {
        Prepare,
        Missing,
        Error,
    }

    pub fn expect_identity_preparation(
        transport: &mut MockTransportServiceApi,
        block_count: usize,
    ) {
        transport
            .expect_writable_relay_urls()
            .times(0..=1)
            .returning(|| Ok(relay_urls()));
        transport.expect_on_block_transport(move |block| {
            block
                .expect_prepare_identity_chain_events()
                .withf(move |events| events.len() == block_count)
                .once()
                .returning(|events| Ok(identity_events(events)));
        });
    }

    pub fn expect_company_preparation(
        transport: &mut MockTransportServiceApi,
        identity_count: usize,
        company_count: usize,
        invite_behavior: InviteBehavior,
    ) {
        transport
            .expect_writable_relay_urls()
            .times(0..=1)
            .returning(|| Ok(relay_urls()));
        transport.expect_on_block_transport(move |block| {
            block
                .expect_prepare_identity_chain_events()
                .withf(move |events| events.len() == identity_count)
                .once()
                .returning(|events| Ok(identity_events(events)));
            block
                .expect_prepare_company_chain_events()
                .withf(move |events| events.len() == company_count)
                .once()
                .returning(|events| Ok(company_events(events)));
            let invites = block.expect_prepare_company_chain_invites();
            if invite_behavior == InviteBehavior::Error {
                invites.times(0..=company_count);
            } else {
                invites.times(company_count);
            }
            invites.returning(move |event| match invite_behavior {
                InviteBehavior::Prepare => Ok(company_invites(event)),
                InviteBehavior::Missing => Ok(Vec::new()),
                InviteBehavior::Error => {
                    Err(TransportError::Message("invite preparation failure".into()))
                }
            });
        });
    }

    #[test]
    fn company_propagation_contains_all_public_events() {
        let company_id = "test-company".to_owned();
        let create = signed_chain_event(
            company_id.clone(),
            BlockchainType::Company,
            1,
            Sha256Hash::from_bytes(b"company-create"),
            None,
        );
        let proof = signed_chain_event(
            company_id.clone(),
            BlockchainType::Company,
            2,
            Sha256Hash::from_bytes(b"company-proof"),
            Some(&create),
        );
        let identity = signed_chain_event(
            "test-identity".into(),
            BlockchainType::Identity,
            4,
            Sha256Hash::from_bytes(b"identity-create-company"),
            None,
        );

        let prepared = PreparedChainPropagation::new(
            PropagationSubjectType::Company,
            company_id,
            vec![identity, create.clone(), proof.clone()],
            Vec::new(),
            relay_urls(),
        )
        .unwrap();
        assert_eq!(prepared.chain_events.len(), 3);
        assert_eq!(prepared.propagation.messages.len(), 3);
        assert_eq!(proof.reply_id, Some(create.event_id.clone()));
        assert_eq!(proof.root_id, create.event_id);

        let company_messages = prepared
            .propagation
            .messages
            .iter()
            .filter(|m| m.event_type == EventType::CompanyChain)
            .count();
        assert_eq!(company_messages, 2);

        for message in &prepared.propagation.messages {
            assert!(!message.target_relays.is_empty());
            assert_eq!(
                message.event.id.to_string(),
                prepared
                    .chain_events
                    .iter()
                    .find(|e| { e.block_hash == message.block_hash.clone().unwrap() })
                    .unwrap()
                    .event_id
            );
        }
    }

    #[test]
    fn public_propagation_without_relay_targets_is_rejected() {
        use super::PreparedChainPropagation;
        use bcr_ebill_persistence::traits::propagation::PropagationSubjectType;
        let event = signed_chain_event(
            "test-identity".into(),
            BlockchainType::Identity,
            1,
            Sha256Hash::from_bytes(b"identity-create"),
            None,
        );
        let result = PreparedChainPropagation::new(
            PropagationSubjectType::Identity,
            "test-identity".into(),
            vec![event],
            Vec::new(),
            Vec::new(),
        );
        assert!(result.is_err());
    }
}
