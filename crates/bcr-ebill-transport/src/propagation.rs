use bcr_ebill_api::service::transport_service::{
    Error, Result, transport_client::TransportClientApi,
};
use bcr_ebill_core::protocol::Timestamp;
use bcr_ebill_persistence::traits::propagation::{
    NostrPropagationStoreApi, PendingDelivery, PropagationStatus, PropagationSubjectType,
};
use futures::stream::FuturesUnordered;
use futures::{StreamExt, stream};
use log::{error, info, warn};
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::sync::Notify;
use tokio::{sync::watch, time::MissedTickBehavior};

const MAX_PARALLEL_DELIVERIES: usize = 8;
const RETRY_BATCH_SIZE: u64 = 64;
const RETRY_INTERVAL: Duration = Duration::from_secs(10);
const ERROR_MSG_BOUND: usize = 512;
const INITIAL_WAIT_TIMEOUT: Duration = Duration::from_secs(3);
const PER_RELAY_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct NostrPropagationService {
    store: Arc<dyn NostrPropagationStoreApi>,
    transport: Arc<dyn TransportClientApi>,
    bitcoin_network: bitcoin::Network,
    retry_wakeup: Arc<Notify>,
}

impl NostrPropagationService {
    pub fn new(
        store: Arc<dyn NostrPropagationStoreApi>,
        transport: Arc<dyn TransportClientApi>,
        bitcoin_network: bitcoin::Network,
    ) -> Self {
        Self {
            store,
            transport,
            bitcoin_network,
            retry_wakeup: Arc::new(Notify::new()),
        }
    }

    /// attempt delivery for all pending relays in a propagation - should be run directly after transaction commitment
    /// returns when ack_threshold have been delivered
    pub async fn attempt_propagation(
        &self,
        propagation_id: &str,
        required_message_ids: &[String],
    ) -> Result<()> {
        let (updated_tx, updated_rx) = watch::channel(0_u64);

        let service = self.clone();
        let id = propagation_id.to_owned();

        // returning from this method does NOT cancel the task
        let btc_network = self.bitcoin_network;
        tokio::spawn(async move {
            if let Err(e) = service.deliver_group_until_idle(&id, &updated_tx).await {
                error!(
                    "[{}] Immediate propagation worker for {id} failed: {e}",
                    btc_network
                );
            }
        });

        let threshold = self.transport.relay_ack_threshold().max(1);
        // The deadline limits only the waiting caller - delivery continues independently
        let wait_result = tokio::time::timeout(
            INITIAL_WAIT_TIMEOUT,
            self.wait_for_required_acks(
                propagation_id,
                required_message_ids,
                threshold,
                updated_rx,
            ),
        )
        .await;

        match wait_result {
            Ok(Ok(true)) => {
                log::debug!(
                    "[{}] Propagation {propagation_id} reached the initial sending threshold",
                    self.bitcoin_network
                );
            }
            Ok(Ok(false)) => {
                // The worker ran out of work - failed deliveries remain in the DB for retries
                log::debug!(
                    "[{}] Propagation {propagation_id} finished its attempts below threshold",
                    self.bitcoin_network
                );
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                log::debug!(
                    "[{}] Propagation {propagation_id} continuing in the background after initial deadline",
                    self.bitcoin_network
                );
            }
        }

        Ok(())
    }

    /// attempt pending deliveries
    pub async fn retry_due_once(&self) -> Result<usize> {
        let deliveries = self
            .store
            .get_pending_deliveries(Timestamp::now(), RETRY_BATCH_SIZE)
            .await
            .map_err(persistence_error)?;
        self.send_deliveries(deliveries).await
    }

    // attempt deliveries in parallel
    // no locks needed - duplicate events are rejected by the relay
    // we don't overwrite accepted deliveries - if they're accepted, they stay accepted
    async fn send_deliveries(&self, deliveries: Vec<PendingDelivery>) -> Result<usize> {
        let count = deliveries.len();
        let results = stream::iter(deliveries)
            .map(|delivery| self.send_one(delivery))
            .buffer_unordered(MAX_PARALLEL_DELIVERIES)
            .collect::<Vec<_>>()
            .await;
        let mut first_error = None;
        for result in results {
            if let Err(e) = result {
                error!(
                    "[{}] Could not persist Nostr delivery result: {e}",
                    self.bitcoin_network
                );
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        if let Some(e) = first_error {
            return Err(e);
        }
        Ok(count)
    }

    // send one delivery with a timeout, recording it's sending status
    async fn send_one(&self, delivery: PendingDelivery) -> Result<()> {
        let result = match tokio::time::timeout(
            PER_RELAY_ATTEMPT_TIMEOUT,
            self.transport
                .send_signed_event_to_relay(&delivery.event, &delivery.relay_url),
        )
        .await
        {
            Ok(result) => result,

            Err(_) => Err(Error::Network(format!(
                "[{}] Timed out sending event {} to relay {}",
                delivery.event.id, delivery.relay_url, self.bitcoin_network
            ))),
        };
        match result {
            Ok(()) => {
                self.store
                    .mark_relay_accepted(
                        &delivery.message_id,
                        &delivery.relay_url,
                        Timestamp::now(),
                    )
                    .await
                    .map_err(persistence_error)?;
            }
            Err(e) => {
                warn!(
                    "Nostr event {} not acknowledged by {}: {e}",
                    delivery.event.id, delivery.relay_url,
                );
                let next_try_at = Timestamp::now() + retry_delay(delivery.attempts);
                // only take part of the error message
                let error_message = e
                    .to_string()
                    .chars()
                    .take(ERROR_MSG_BOUND)
                    .collect::<String>();

                self.store
                    .mark_relay_failed(
                        &delivery.message_id,
                        &delivery.relay_url,
                        next_try_at,
                        &error_message,
                    )
                    .await
                    .map_err(persistence_error)?;
            }
        }
        Ok(())
    }

    /// background loop running as a job
    pub async fn run_retry_loop(&self, mut shutdown: watch::Receiver<bool>) {
        info!(
            "[{}] Nostr propagation retry worker started",
            self.bitcoin_network
        );
        if *shutdown.borrow() {
            return;
        }
        let mut interval = tokio::time::interval(RETRY_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // periodic retry - executed below
                }
                _ = self.retry_wakeup.notified() => {
                    // user-requested immediate retry - executed below
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                    continue;
                }
            }

            if *shutdown.borrow() {
                break;
            }

            if let Err(e) = self.retry_due_once().await {
                log::error!("Nostr propagation retry failed: {e}");
            }
        }
        info!(
            "[{}] Nostr propagation retry worker stopped",
            self.bitcoin_network
        );
    }

    pub async fn get_propagation_status(
        &self,
        propagation_id: &str,
    ) -> Result<Option<PropagationStatus>> {
        self.store
            .get_propagation(propagation_id)
            .await
            .map_err(persistence_error)
    }

    pub async fn get_latest_propagation(
        &self,
        subject_type: PropagationSubjectType,
        subject_id: &str,
    ) -> Result<Option<PropagationStatus>> {
        let ids = self
            .store
            .list_propagation_ids(subject_type, subject_id)
            .await
            .map_err(persistence_error)?;
        let Some(id) = ids.first() else {
            return Ok(None);
        };
        self.get_propagation_status(id).await
    }

    async fn wait_for_required_acks(
        &self,
        propagation_id: &str,
        required_message_ids: &[String],
        threshold: usize,
        mut updates: watch::Receiver<u64>,
    ) -> Result<bool> {
        loop {
            let status = self
                .store
                .get_propagation(propagation_id)
                .await
                .map_err(persistence_error)?
                .ok_or_else(|| Error::Message(format!("Unknown propagation: {propagation_id}")))?;

            // don't wait for a message that was never persisted
            for id in required_message_ids {
                if !status.messages.iter().any(|m| &m.id == id) {
                    return Err(Error::Message(format!(
                        "Required propagation message not found: {id}"
                    )));
                }
            }
            if required_ack_threshold_reached(&status, required_message_ids, threshold) {
                return Ok(true);
            }
            // delivery worker has finished - nothing more to wait for
            if updates.changed().await.is_err() {
                return Ok(false);
            }
        }
    }

    /// this takes care of dependent events for every relay, e.g. if both Issue & Accept (promissory note) are to be propagated
    /// it first tries issue and if a relay accepted issue, will attempt Accept afterwards
    async fn deliver_group_until_idle(
        &self,
        propagation_id: &str,
        updated: &watch::Sender<u64>,
    ) -> Result<()> {
        // each message/relay pair is attempted at most once by this initial worker
        let mut attempted = HashSet::new();
        let mut in_flight = FuturesUnordered::new();
        let mut first_error = None;
        loop {
            if in_flight.len() < MAX_PARALLEL_DELIVERIES {
                let deliveries = self
                    .store
                    .get_pending_deliveries_for_propagation(propagation_id, Timestamp::now())
                    .await
                    .map_err(persistence_error)?;
                for delivery in deliveries {
                    if in_flight.len() >= MAX_PARALLEL_DELIVERIES {
                        break;
                    }
                    let key = (
                        delivery.message_id.clone(),
                        delivery.relay_url.as_str().to_owned(),
                    );
                    if !attempted.insert(key) {
                        continue;
                    }
                    in_flight.push(self.send_one(delivery));
                }
            }
            // Wait for a single result, not the whole batch
            let Some(result) = in_flight.next().await else {
                break;
            };

            if let Err(e) = result {
                error!(
                    "[{}] Failed to persist Nostr delivery result: {e}",
                    self.bitcoin_network
                );
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }

            // Notify the caller after the DB update - caller re-reads persisted status
            updated.send_modify(|version| {
                *version = version.wrapping_add(1);
            });

            // Re-check - a dependent block may have made another event eligible on this relay
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }

    pub async fn retry_pending_now(&self) -> Result<()> {
        self.store
            .make_pending_deliveries_due_now()
            .await
            .map_err(persistence_error)?;
        // wake the existing worker. No new task is spawned
        self.retry_wakeup.notify_one();
        Ok(())
    }
}

fn persistence_error(error: bcr_ebill_persistence::Error) -> Error {
    Error::Persistence(error.to_string())
}

/// Exponential backoff 5s, 10s, 20s, 40s, ... up to 15 minutes
/// We retry forever
fn retry_delay(previous_attempts: u32) -> Duration {
    let exponent = previous_attempts.min(8);
    let seconds = 5_u64.saturating_mul(1_u64 << exponent).min(15 * 60);

    Duration::from_secs(seconds)
}

// check threshold for each event individually
fn required_ack_threshold_reached(
    status: &PropagationStatus,
    required_message_ids: &[String],
    threshold: usize,
) -> bool {
    required_message_ids.iter().all(|id| {
        let Some(message) = status.messages.iter().find(|message| &message.id == id) else {
            return false;
        };
        // between 1 and num of relays
        let required_acks = threshold.max(1).min(message.relays.len());
        required_acks > 0
            && message
                .relays
                .iter()
                .filter(|relay| relay.accepted_at.is_some())
                .count()
                >= required_acks
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{MockNostrPropagationStoreApiMock, MockNotificationJsonTransport};
    use bcr_ebill_core::protocol::event::EventType;
    use bcr_ebill_persistence::traits::propagation::{
        PropagationMessageStatus, PropagationSubjectType, RelayPropagationStatus,
    };
    use nostr::{
        event::{Event, EventBuilder, FinalizeEvent, Kind},
        key::Keys,
    };
    use std::{
        collections::HashSet,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use url::Url;

    type Acks = Arc<Mutex<HashSet<(String, String)>>>;

    fn relay(n: usize) -> Url {
        Url::parse(&format!("wss://r{n}.example")).unwrap()
    }

    fn signed_event(content: &str) -> Event {
        EventBuilder::new(Kind::TextNote, content)
            .finalize(&Keys::generate())
            .unwrap()
    }

    fn acknowledged(acks: &Acks, id: &str, relay: &Url) -> bool {
        acks.lock()
            .unwrap()
            .contains(&(id.to_owned(), relay.to_string()))
    }

    fn propagation_store(
        events: Vec<(&'static str, Event)>,
        relays: Vec<Url>,
    ) -> (MockNostrPropagationStoreApiMock, Acks) {
        let mut store = MockNostrPropagationStoreApiMock::new();
        let acks: Acks = Arc::new(Mutex::new(HashSet::new()));

        // select pending deliveries
        // dependent -  Accept is eligible on a relay only after Issue is acknowledged on that relay etc.
        let due_acks = acks.clone();
        let due_events = events.clone();
        let due_relays = relays.clone();

        store
            .expect_get_pending_deliveries_for_propagation()
            .returning(move |id, _| {
                assert_eq!(id, "p1");
                let mut pending = Vec::new();
                for (message_id, event) in &due_events {
                    for relay in &due_relays {
                        if acknowledged(&due_acks, message_id, relay) {
                            continue;
                        }
                        if *message_id == "accept" && !acknowledged(&due_acks, "issue", relay) {
                            continue;
                        }
                        pending.push(PendingDelivery {
                            message_id: message_id.to_string(),
                            propagation_id: "p1".into(),
                            relay_url: relay.clone(),
                            event: event.clone(),
                            attempts: 0,
                        });
                    }
                }
                Ok(pending)
            });

        // return acknowledgment state to the waiter
        let status_acks = acks.clone();
        store.expect_get_propagation().returning(move |id| {
            assert_eq!(id, "p1");
            Ok(Some(PropagationStatus {
                id: "p1".into(),
                subject_type: PropagationSubjectType::Bill,
                subject_id: "bill-1".into(),
                created_at: Timestamp::now(),
                messages: events
                    .iter()
                    .map(|(message_id, event)| PropagationMessageStatus {
                        id: message_id.to_string(),
                        event_type: EventType::BillChain,
                        recipient_id: None,
                        chain_id: Some("bill-1".into()),
                        block_hash: None,
                        nostr_event_id: event.id.to_string(),
                        relays: relays
                            .iter()
                            .map(|relay| {
                                let accepted = acknowledged(&status_acks, message_id, relay);
                                RelayPropagationStatus {
                                    relay_url: relay.clone(),
                                    accepted_at: accepted.then(Timestamp::now),
                                    attempts: u32::from(accepted),
                                    next_try_at: Timestamp::now(),
                                    last_error: None,
                                }
                            })
                            .collect(),
                    })
                    .collect(),
            }))
        });
        let write_acks = acks.clone();
        store
            .expect_mark_relay_accepted()
            .returning(move |id, relay, _| {
                write_acks
                    .lock()
                    .unwrap()
                    .insert((id.to_owned(), relay.to_string()));
                Ok(())
            });
        store
            .expect_mark_relay_failed()
            .returning(|_, _, _, _| Ok(()));
        (store, acks)
    }

    fn test_message(id: &str, accepted: &[bool]) -> PropagationMessageStatus {
        let now = Timestamp::now();
        PropagationMessageStatus {
            id: id.to_owned(),
            event_type: EventType::BillChain,
            recipient_id: None,
            chain_id: None,
            block_hash: None,
            nostr_event_id: format!("nostr-{id}"),
            relays: accepted
                .iter()
                .enumerate()
                .map(|(i, accepted)| RelayPropagationStatus {
                    relay_url: url::Url::parse(&format!("wss://relay-{i}.example")).unwrap(),
                    accepted_at: accepted.then(|| now),
                    attempts: u32::from(*accepted),
                    next_try_at: now,
                    last_error: None,
                })
                .collect(),
        }
    }

    fn test_status(messages: Vec<PropagationMessageStatus>) -> PropagationStatus {
        PropagationStatus {
            id: "propagation-1".into(),
            subject_type: PropagationSubjectType::Bill,
            subject_id: "bill-1".into(),
            created_at: Timestamp::now(),
            messages,
        }
    }

    #[test]
    fn initial_threshold_ignores_offline_relays() {
        let status = test_status(vec![
            test_message("issue", &[true, true, false, false]),
            test_message("accept", &[true, true, false, false]),
        ]);
        let required = vec!["issue".to_owned(), "accept".to_owned()];
        assert!(required_ack_threshold_reached(&status, &required, 2,));
        assert!(!required_ack_threshold_reached(&status, &required, 3,));
    }

    #[test]
    fn every_required_message_needs_its_own_threshold() {
        let status = test_status(vec![
            test_message("issue", &[true, true, false]),
            test_message("accept", &[true, false, false]),
        ]);
        assert!(!required_ack_threshold_reached(
            &status,
            &["issue".into(), "accept".into()],
            2,
        ));
    }

    #[test]
    fn optional_notifications_do_not_delay_response() {
        let status = test_status(vec![
            test_message("bill-block", &[true, true, false]),
            test_message("notification", &[false, false, false]),
        ]);
        assert!(required_ack_threshold_reached(
            &status,
            &["bill-block".into()],
            2,
        ));
    }

    #[test]
    fn threshold_is_limited_to_message_target_count() {
        let status = test_status(vec![test_message("invite", &[true])]);
        // invite has just one target relay
        assert!(required_ack_threshold_reached(
            &status,
            &["invite".into()],
            3,
        ));
    }

    #[test]
    fn retry_backoff_is_exponential_and_capped() {
        assert_eq!(retry_delay(0), Duration::from_secs(5));
        assert_eq!(retry_delay(1), Duration::from_secs(10));
        assert_eq!(retry_delay(2), Duration::from_secs(20));
        assert_eq!(retry_delay(3), Duration::from_secs(40));
        assert_eq!(retry_delay(8), Duration::from_secs(15 * 60));
        assert_eq!(retry_delay(100), Duration::from_secs(15 * 60));
    }

    #[tokio::test]
    async fn initial_propagation_returns_at_threshold() {
        let relays = (1..=4).map(relay).collect::<Vec<_>>();
        let issue = signed_event("issue");
        let (store, acks) = propagation_store(vec![("issue", issue)], relays.clone());
        let mut transport = MockNotificationJsonTransport::new();
        transport.expect_relay_ack_threshold().returning(|| 2);
        transport
            .expect_send_signed_event_to_relay()
            .returning(|_, relay| match relay.host_str() {
                Some("r1.example" | "r2.example") => Ok(()),
                _ => Err(Error::Network("relay unavailable".into())),
            });

        let publisher = NostrPropagationService::new(
            Arc::new(store),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );
        tokio::time::timeout(
            Duration::from_secs(1),
            publisher.attempt_propagation("p1", &["issue".into()]),
        )
        .await
        .expect("initial propagation timed out")
        .unwrap();
        // 2 successful relay ACKs are enough
        assert!(acknowledged(&acks, "issue", &relays[0]));
        assert!(acknowledged(&acks, "issue", &relays[1]));
        // the other relays have not acknowledged the event
        assert!(!acknowledged(&acks, "issue", &relays[2]));
        assert!(!acknowledged(&acks, "issue", &relays[3]));
    }

    #[tokio::test]
    async fn accept_waits_for_issue_ack_on_each_relay() {
        let r1 = relay(1);
        let r2 = relay(2);
        let r3 = relay(3);

        let issue = signed_event("issue");
        let accept = signed_event("accept");
        let accept_event_id = accept.id.to_string();
        let issue_event_id = issue.id.to_string();
        let (store, acks) = propagation_store(
            vec![("issue", issue), ("accept", accept)],
            vec![r1.clone(), r2.clone(), r3.clone()],
        );

        let mut transport = MockNotificationJsonTransport::new();
        transport.expect_relay_ack_threshold().returning(|| 2);
        let observed_acks = acks.clone();
        let r3_clone = r3.clone();
        transport
            .expect_send_signed_event_to_relay()
            .returning(move |event, relay| {
                let event_id = event.id.to_string();
                if event_id == accept_event_id {
                    // Accept can only be sent after Issue was acknowledged on this relay
                    assert!(
                        acknowledged(&observed_acks, "issue", relay),
                        "Accept sent before Issue on {relay}"
                    );
                }

                if relay == &r3_clone {
                    // r3 never acknowledges Issue
                    assert_eq!(event_id, issue_event_id, "Accept must not be sent to r3");
                    return Err(Error::Network("r3 unavailable".into()));
                }

                Ok(())
            });

        let publisher = NostrPropagationService::new(
            Arc::new(store),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );
        tokio::time::timeout(
            Duration::from_secs(1),
            publisher.attempt_propagation("p1", &["issue".into(), "accept".into()]),
        )
        .await
        .expect("Issue/Accept propagation timed out")
        .unwrap();

        // Issue is acknowledged on r1 and r2
        assert!(acknowledged(&acks, "issue", &r1));
        assert!(acknowledged(&acks, "issue", &r2));
        // Accept also reaches r1 and r2
        assert!(acknowledged(&acks, "accept", &r1));
        assert!(acknowledged(&acks, "accept", &r2));
        // Neither event was acknowledged on r3
        assert!(!acknowledged(&acks, "issue", &r3));
        assert!(!acknowledged(&acks, "accept", &r3));
    }

    #[tokio::test]
    async fn manual_retry_reschedules_and_notifies_worker() {
        let mut store = MockNostrPropagationStoreApiMock::new();
        store
            .expect_make_pending_deliveries_due_now()
            .once()
            .returning(|| Ok(()));
        let transport = MockNotificationJsonTransport::new();
        let service = NostrPropagationService::new(
            Arc::new(store),
            Arc::new(transport),
            bitcoin::Network::Testnet,
        );
        let notified = service.retry_wakeup.notified();
        service.retry_pending_now().await.unwrap();
        tokio::time::timeout(Duration::from_millis(100), notified)
            .await
            .expect("Retry worker was not notified");
    }
}
