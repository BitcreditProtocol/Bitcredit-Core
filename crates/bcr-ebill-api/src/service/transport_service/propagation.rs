use crate::service::transport_service::{Error, Result, transport_client::TransportClientApi};
use bcr_ebill_core::protocol::event::EventType;
use bcr_ebill_persistence::traits::propagation::PropagationStatus;
use futures::{StreamExt, stream};
use nostr::event::EventId;
use std::time::Duration;
use url::Url;

pub const BLOCK_PROPAGATION_THRESHOLD: PropagationThreshold = PropagationThreshold::StrictMajority;
const RELAY_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PARALLEL_CHECKS: usize = 5;

/// The threshold we use to determine, if a given Nostr message can be considered propagated in the network
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationThreshold {
    AtLeast(usize),
    StrictMajority,
}

impl PropagationThreshold {
    pub fn required(self, total_relays: usize) -> Option<usize> {
        if total_relays == 0 {
            return None;
        }
        let required = match self {
            Self::AtLeast(n) => n,
            Self::StrictMajority => total_relays / 2 + 1,
        };
        (required > 0 && required <= total_relays).then_some(required)
    }
}

/// Availability-descriptor for any given event on Nostr
#[derive(Debug)]
pub struct RelayAvailability {
    pub required: usize,
    pub total_relays: usize,
    pub confirmed: Vec<Url>,
    pub missing: Vec<Url>,
    pub errors: Vec<(Url, String)>,
}

impl RelayAvailability {
    pub fn is_propagated(&self) -> bool {
        self.confirmed.len() >= self.required
    }
}

pub async fn verify_event_availability(
    transport: &dyn TransportClientApi,
    event_id: EventId,
    configured_relays: &[Url],
    threshold: PropagationThreshold,
) -> Result<RelayAvailability> {
    // count once per relay
    let relays = unique_relays(configured_relays);
    let required = threshold
        .required(relays.len())
        .ok_or_else(|| Error::Message("invalid Nostr propagation threshold".to_owned()))?;
    let total_relays = relays.len();
    // check N relays in parallel
    let results = stream::iter(relays)
        .map(|relay| async move {
            let result = match tokio::time::timeout(
                RELAY_VERIFICATION_TIMEOUT,
                transport.event_available_on_relay(event_id, &relay),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(Error::Network(format!(
                    "Timed out verifying event availability on {relay}"
                ))),
            };
            (relay, result)
        })
        .buffer_unordered(MAX_PARALLEL_CHECKS)
        .collect::<Vec<_>>()
        .await;
    let mut confirmed = Vec::new();
    let mut missing = Vec::new();
    let mut errors = Vec::new();
    for (relay, result) in results {
        match result {
            Ok(true) => confirmed.push(relay),
            Ok(false) => missing.push(relay),
            Err(e) => errors.push((relay, e.to_string())),
        }
    }
    confirmed.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    missing.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    Ok(RelayAvailability {
        required,
        total_relays,
        confirmed,
        missing,
        errors,
    })
}

/// The status of propagatedness of an outgoing propagation
#[derive(Debug, Clone)]
pub struct OutgoingChainQuorum {
    pub required: usize,
    pub total_relays: usize,
    pub confirmed_relays: Vec<Url>,
}

impl OutgoingChainQuorum {
    pub fn is_propagated(&self) -> bool {
        self.confirmed_relays.len() >= self.required
    }
}

/// Evaluates all events belonging to one outgoing propagation against its relay set
/// Returns None if there are no chain events
pub fn evaluate_outgoing_chain_quorum(
    status: &PropagationStatus,
    configured_relays: &[Url],
    threshold: PropagationThreshold,
) -> Result<Option<OutgoingChainQuorum>> {
    let chain_messages = status
        .messages
        .iter()
        .filter(|message| {
            matches!(
                &message.event_type,
                EventType::BillChain | EventType::IdentityChain | EventType::CompanyChain
            )
        })
        .collect::<Vec<_>>();
    if chain_messages.is_empty() {
        return Ok(None);
    }
    let relays = unique_relays(configured_relays);
    let required = threshold
        .required(relays.len())
        .ok_or_else(|| Error::Message("Invalid propagation quorum configuration".into()))?;
    // All chain events in this propagation have to be acked for a relay to count as acked
    let confirmed_relays = relays
        .iter()
        .filter(|relay| {
            chain_messages.iter().all(|message| {
                message.relays.iter().any(|delivery| {
                    delivery.relay_url.as_str() == relay.as_str() && delivery.accepted_at.is_some()
                })
            })
        })
        .cloned()
        .collect();
    Ok(Some(OutgoingChainQuorum {
        required,
        total_relays: relays.len(),
        confirmed_relays,
    }))
}

/// Snapshot taken when a candidate event comes in
#[derive(Debug, Clone)]
pub struct RelayQuorumSnapshot {
    pub relays: Vec<Url>,
    pub required: usize,
}

pub fn relay_quorum_snapshot(
    configured_relays: &[Url],
    threshold: PropagationThreshold,
) -> Result<RelayQuorumSnapshot> {
    let relays = unique_relays(configured_relays);
    if relays
        .iter()
        .any(|relay| !matches!(relay.scheme(), "ws" | "wss"))
    {
        return Err(Error::Message("Invalid verification relay URL".into()));
    }
    let required = threshold
        .required(relays.len())
        .ok_or_else(|| Error::Message("Invalid propagation quorum configuration".into()))?;
    Ok(RelayQuorumSnapshot { relays, required })
}

fn unique_relays(configured: &[Url]) -> Vec<Url> {
    let mut relays = configured.to_vec();
    relays.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    relays.dedup();
    relays
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::transport_service::MockTransportClientApi;
    use bcr_ebill_core::protocol::Timestamp;
    use bcr_ebill_persistence::traits::propagation::{
        PropagationMessageStatus, PropagationSubjectType, RelayPropagationStatus,
    };
    use nostr::{
        event::{EventBuilder, FinalizeEvent, Kind},
        key::Keys,
    };

    fn relay(n: usize) -> Url {
        Url::parse(&format!("wss://r{n}.example")).unwrap()
    }

    #[test]
    fn strict_majority() {
        let policy = PropagationThreshold::StrictMajority;
        assert_eq!(policy.required(0), None);
        assert_eq!(policy.required(1), Some(1));
        assert_eq!(policy.required(2), Some(2));
        assert_eq!(policy.required(3), Some(2));
        assert_eq!(policy.required(4), Some(3));
        assert_eq!(policy.required(5), Some(3));
    }

    #[test]
    fn fixed_threshold() {
        let policy = PropagationThreshold::AtLeast(2);
        assert_eq!(policy.required(0), None);
        assert_eq!(policy.required(1), None);
        assert_eq!(policy.required(2), Some(2));
        assert_eq!(policy.required(5), Some(2));
        assert_eq!(PropagationThreshold::AtLeast(0).required(3), None);
    }

    fn message(
        id: &str,
        event_type: EventType,
        relays: &[Url],
        accepted_indices: &[usize],
    ) -> PropagationMessageStatus {
        PropagationMessageStatus {
            id: id.into(),
            event_type,
            recipient_id: None,
            chain_id: Some("bill-1".into()),
            block_hash: None,
            nostr_event_id: format!("nostr-{id}"),
            relays: relays
                .iter()
                .enumerate()
                .map(|(index, url)| RelayPropagationStatus {
                    relay_url: url.clone(),
                    accepted_at: accepted_indices.contains(&index).then(Timestamp::now),
                    attempts: 0,
                    next_try_at: Timestamp::zero(),
                    last_error: None,
                })
                .collect(),
        }
    }

    fn status(messages: Vec<PropagationMessageStatus>) -> PropagationStatus {
        PropagationStatus {
            id: "operation-1".into(),
            subject_type: PropagationSubjectType::Bill,
            subject_id: "bill-1".into(),
            created_at: Timestamp::now(),
            messages,
        }
    }

    #[test]
    fn all_blocks_must_share_sufficient_confirmed_relays() {
        let relays = vec![relay(1), relay(2), relay(3)];
        let operation = status(vec![
            message("issue", EventType::BillChain, &relays, &[0, 1]),
            message("accept", EventType::BillChain, &relays, &[0, 2]),
        ]);
        let result =
            evaluate_outgoing_chain_quorum(&operation, &relays, PropagationThreshold::AtLeast(2))
                .unwrap()
                .unwrap();
        assert_eq!(result.required, 2);
        assert_eq!(result.confirmed_relays, vec![relay(1)]);
        assert!(!result.is_propagated());
    }

    #[test]
    fn quorum_is_met_when_two_relays_have_every_block() {
        let relays = vec![relay(1), relay(2), relay(3)];
        let operation = status(vec![
            message("issue", EventType::BillChain, &relays, &[0, 1]),
            message("accept", EventType::BillChain, &relays, &[0, 1]),
        ]);
        let result = evaluate_outgoing_chain_quorum(
            &operation,
            &relays,
            PropagationThreshold::StrictMajority,
        )
        .unwrap()
        .unwrap();
        assert_eq!(result.confirmed_relays.len(), 2);
        assert!(result.is_propagated());
    }

    #[test]
    fn duplicate_configured_relays_do_not_inflate_quorum() {
        let relays = vec![relay(1), relay(2), relay(2)];
        let operation = status(vec![message(
            "issue",
            EventType::BillChain,
            &relays[..2],
            &[0],
        )]);
        let result = evaluate_outgoing_chain_quorum(
            &operation,
            &relays,
            PropagationThreshold::StrictMajority,
        )
        .unwrap()
        .unwrap();
        assert_eq!(result.total_relays, 2);
        assert_eq!(result.required, 2);
        assert!(!result.is_propagated());
    }

    #[tokio::test]
    async fn event_is_available_when_quorum_replies() {
        let event = EventBuilder::new(Kind::TextNote, "test event")
            .finalize(&Keys::generate())
            .unwrap();
        let relays = vec![
            Url::parse("wss://r1.example").unwrap(),
            Url::parse("wss://r2.example").unwrap(),
            Url::parse("wss://r3.example").unwrap(),
        ];
        let mut transport = MockTransportClientApi::new();
        transport
            .expect_event_available_on_relay()
            .times(3)
            .returning(|_, relay| match relay.host_str() {
                Some("r1.example" | "r2.example") => Ok(true),
                _ => Err(Error::Network("Relay unavailable".into())),
            });
        let result = verify_event_availability(
            &transport,
            event.id,
            &relays,
            PropagationThreshold::StrictMajority,
        )
        .await
        .unwrap();
        assert_eq!(result.required, 2);
        assert_eq!(result.total_relays, 3);
        assert_eq!(result.confirmed.len(), 2);
        assert_eq!(result.errors.len(), 1);
        assert!(result.is_propagated());
    }

    #[tokio::test]
    async fn one_confirmation_does_not_meet_majority() {
        let event = EventBuilder::new(Kind::TextNote, "another event")
            .finalize(&Keys::generate())
            .unwrap();
        let relays = vec![
            Url::parse("wss://r1.example").unwrap(),
            Url::parse("wss://r2.example").unwrap(),
            Url::parse("wss://r3.example").unwrap(),
        ];
        let mut transport = MockTransportClientApi::new();
        transport
            .expect_event_available_on_relay()
            .times(3)
            .returning(|_, relay| match relay.host_str() {
                Some("r1.example") => Ok(true),
                Some("r2.example") => Ok(false),
                _ => Err(Error::Network("Relay unavailable".into())),
            });
        let result = verify_event_availability(
            &transport,
            event.id,
            &relays,
            PropagationThreshold::StrictMajority,
        )
        .await
        .unwrap();

        assert_eq!(result.confirmed.len(), 1);
        assert_eq!(result.missing.len(), 1);
        assert_eq!(result.errors.len(), 1);
        assert!(!result.is_propagated());
    }
}
