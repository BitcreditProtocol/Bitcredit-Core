use bcr_ebill_api::service::transport_service::{
    Error, Result, transport_client::TransportClientApi,
};
use bcr_ebill_core::protocol::Timestamp;
use bcr_ebill_persistence::traits::propagation::{
    NostrPropagationStoreApi, PendingDelivery, PropagationStatus, PropagationSubjectType,
};
use futures::{StreamExt, stream};
use log::{error, warn};
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::{sync::watch, time::MissedTickBehavior};

const MAX_PARALLEL_DELIVERIES: usize = 8;
const RETRY_BATCH_SIZE: u64 = 64;
const RETRY_INTERVAL: Duration = Duration::from_secs(10);
const ERROR_MSG_BOUND: usize = 512;

#[derive(Clone)]
pub struct NostrPropagationService {
    store: Arc<dyn NostrPropagationStoreApi>,
    transport: Arc<dyn TransportClientApi>,
}

impl NostrPropagationService {
    pub fn new(
        store: Arc<dyn NostrPropagationStoreApi>,
        transport: Arc<dyn TransportClientApi>,
    ) -> Self {
        Self { store, transport }
    }

    /// attempt delivery for all pending relays in a propagation - should be run directly after transaction commitment
    /// this takes care of dependent events, e.g. if both Issue & Accept (promissory note) are to be propagated
    /// it first tries issue and if a relay accepted issue, will attempt Accept afterwards
    pub async fn attempt_propagation(&self, propagation_id: &str) -> Result<usize> {
        let mut attempted = HashSet::new();
        let mut total = 0;

        loop {
            let mut deliveries = self
                .store
                .get_pending_deliveries_for_propagation(propagation_id, Timestamp::now())
                .await
                .map_err(persistence_error)?;

            // One immediate attempt per message/relay pair
            // A failure scheduled for later must not be retried repeatedly during this call
            deliveries.retain(|delivery| {
                attempted.insert((delivery.message_id.clone(), delivery.relay_url.to_string()))
            });

            if deliveries.is_empty() {
                break;
            }
            total += deliveries.len();

            // Persist all acknowledgments from this stage before querying for newly eligible children
            self.send_deliveries(deliveries).await?;
        }

        Ok(total)
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
                error!("Could not persist Nostr delivery result: {e}");
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

    async fn send_one(&self, delivery: PendingDelivery) -> Result<()> {
        let result = self
            .transport
            .send_signed_event_to_relay(&delivery.event, &delivery.relay_url)
            .await;
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
        if *shutdown.borrow() {
            return;
        }
        let mut interval = tokio::time::interval(RETRY_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.retry_due_once().await {
                        error!(
                            "Nostr propagation retry failed: {e}"
                        );
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_backoff_is_exponential_and_capped() {
        assert_eq!(retry_delay(0), Duration::from_secs(5));
        assert_eq!(retry_delay(1), Duration::from_secs(10));
        assert_eq!(retry_delay(2), Duration::from_secs(20));
        assert_eq!(retry_delay(3), Duration::from_secs(40));
        assert_eq!(retry_delay(8), Duration::from_secs(15 * 60));
        assert_eq!(retry_delay(100), Duration::from_secs(15 * 60));
    }
}
