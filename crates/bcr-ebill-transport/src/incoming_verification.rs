use crate::{
    chain_keys::{ChainKeyServiceApi, KnownChain},
    handler::{IncomingChainApplicationApi, IncomingChainApplyResult, IncomingChainDependency},
    transport::{chain_filter, root_and_reply_id, unwrap_public_chain_event},
};
use async_trait::async_trait;
use bcr_ebill_api::service::transport_service::{
    Error, Result,
    propagation::{PropagationThreshold, RelayQuorumSnapshot, verify_event_availability},
    transport_client::TransportClientApi,
};
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::{Timestamp, blockchain::BlockchainType},
};
use bcr_ebill_persistence::NostrEventOffsetStoreApi;
use bcr_ebill_persistence::traits::propagation::{
    ApplicationWaitReason, IncomingChainCandidate, IncomingPropagationStoreApi,
};
use futures::{StreamExt, stream};
use log::{debug, error, info, warn};
use nostr::event::{Event, EventId, Kind};
use std::collections::HashSet;
use std::{sync::Arc, time::Duration};
use tokio::sync::broadcast;
use tokio::{
    sync::{Mutex, Notify},
    time::MissedTickBehavior,
};
use url::Url;

const INITIAL_DELAY: Duration = Duration::from_secs(1);
const SCAN_INTERVAL: Duration = Duration::from_secs(5);
const DUE_BATCH_SIZE: u64 = 16;
const MAX_CONCURRENT_CANDIDATES: usize = 2;
const ERROR_MESSAGE_LIMIT: usize = 512;
const RETRY_BASELINE_SECS: u64 = 60;
/// if we have a verified candidate, but are missing keys - retry with a backoff delay
const MISSING_KEYS_RETRY_DELAYS: [u64; 5] = [15, 30, 60, 120, 300];
const RETRY_DEFERRED_INTERVAL: Duration = Duration::from_secs(60);
/// Predecessor-lookup and repair
const GAP_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PARALLEL_GAP_RELAYS: usize = 4;
const MAX_GAP_REPAIRS_PER_PASS: usize = 2;
/// Chain catch-up
const CATCHUP_PAGE_SIZE: usize = 256;
const MAX_CATCHUP_PAGES_PER_RELAY: usize = 10;
const CATCHUP_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const CATCHUP_INTERVAL: Duration = Duration::from_secs(5 * 60);
const MAX_CHAINS_PER_CATCHUP: usize = 4;
/// Fork selection
const FORK_SELECTION_RETRY_INTERVAL: Duration = Duration::from_secs(5);

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait IncomingChainCatchupApi: ServiceTraitBounds {
    /// Discover and enqueue events for one chain
    async fn catch_up_chain(
        &self,
        chain: &KnownChain,
        snapshot: &RelayQuorumSnapshot,
    ) -> Result<usize>;
}

#[cfg(test)]
impl ServiceTraitBounds for MockIncomingChainCatchupApi {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedChainIngestionProgress {
    /// Discovered signed events added to the incoming queue
    pub enqueued: usize,
    /// Signed events successfully applied during ingestion
    /// Competing branches and duplicate block events mean
    /// this is not necessarily the height of the restored chain
    pub applied_prefix: usize,
}

impl VerifiedChainIngestionProgress {
    pub fn remaining(&self) -> usize {
        self.enqueued - self.applied_prefix
    }
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait VerifiedChainIngestionApi: ServiceTraitBounds {
    /// Durably queues all discovered events, establishes quorum
    /// for the available candidates, then applies the preferred
    /// valid verified continuation through the normal application pipeline
    /// Non-quorum events and unresolved dependencies remain queued
    /// Competing branches do not replace committed local history
    async fn ingest_verified_chain(
        &self,
        chain_type: BlockchainType,
        chain_id: &str,
        events: Vec<Event>,
        snapshot: RelayQuorumSnapshot,
    ) -> Result<VerifiedChainIngestionProgress>;
}

#[cfg(test)]
impl ServiceTraitBounds for MockVerifiedChainIngestionApi {}

impl ServiceTraitBounds for IncomingPropagationVerifier {}

/// Check relay availability of incoming chain events
/// Candidates remain persisted until they are applied to a local chain
#[derive(Clone)]
pub struct IncomingPropagationVerifier {
    store: Arc<dyn IncomingPropagationStoreApi>,
    transport: Arc<dyn TransportClientApi>,
    application: Arc<dyn IncomingChainApplicationApi>,
    // only run one verifier at once
    run_lock: Arc<Mutex<()>>,
    // only run one catch up run at once
    catchup_lock: Arc<Mutex<()>>,
    catchup_next_chain: Arc<Mutex<usize>>,
    catchup_cursors: Option<Arc<dyn NostrEventOffsetStoreApi>>,
    wakeup: Arc<Notify>,
}

#[derive(Debug, Clone, Copy)]
struct ApplicationAttempt {
    applied: bool,
    needs_gap_repair: bool,
}

impl IncomingPropagationVerifier {
    pub fn new(
        store: Arc<dyn IncomingPropagationStoreApi>,
        transport: Arc<dyn TransportClientApi>,
        application: Arc<dyn IncomingChainApplicationApi>,
    ) -> Self {
        Self {
            store,
            transport,
            application,
            run_lock: Arc::new(Mutex::new(())),
            catchup_lock: Arc::new(Mutex::new(())),
            catchup_next_chain: Arc::new(Mutex::new(0)),
            catchup_cursors: None,
            wakeup: Arc::new(Notify::new()),
        }
    }

    pub fn with_catchup_cursors(mut self, store: Arc<dyn NostrEventOffsetStoreApi>) -> Self {
        self.catchup_cursors = Some(store);
        self
    }

    pub async fn enqueue(
        &self,
        event: nostr::event::Event,
        chain_type: &str,
        chain_id: &str,
        snapshot: RelayQuorumSnapshot,
    ) -> Result<()> {
        event
            .verify()
            .map_err(|e| Error::Message(format!("Invalid incoming Nostr event: {e}")))?;
        let candidate = IncomingChainCandidate {
            event,
            chain_type: chain_type.to_owned(),
            chain_id: chain_id.to_owned(),
            relays: snapshot.relays,
            required_relays: snapshot.required,
            attempts: 0,
            application_attempts: 0,
        };
        let first_try_at = Timestamp::now() + INITIAL_DELAY;
        self.store
            .upsert_candidate(&candidate, first_try_at)
            .await
            .map_err(persistence_error)?;
        self.wakeup.notify_one();
        Ok(())
    }

    /// Process a batch concurrently
    pub async fn verify_due_once(&self) -> Result<usize> {
        // only check when we're online
        if !self.transport.has_connected_read_relay().await {
            debug!("skipping incoming verification: no connected read relays");
            return Ok(0);
        }

        let candidates = self
            .store
            .get_due_candidates(Timestamp::now(), DUE_BATCH_SIZE)
            .await
            .map_err(persistence_error)?;
        let candidates_count = candidates.len();
        let results = stream::iter(candidates)
            .map(|candidate| self.verify_one(candidate))
            .buffer_unordered(MAX_CONCURRENT_CANDIDATES)
            .collect::<Vec<_>>()
            .await;
        let mut first_error = None;
        for result in results {
            if let Err(e) = result {
                error!("incoming Nostr quorum verification failed: {e}");
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        if let Some(err) = first_error {
            return Err(err);
        }
        Ok(candidates_count)
    }

    /// verifies a candidate and returns true if it was verified
    async fn verify_one(&self, candidate: IncomingChainCandidate) -> Result<bool> {
        let event_id = candidate.event.id.to_string();
        // reject invalid Nostr events
        if let Err(e) = candidate.event.verify() {
            self.store
                .mark_rejected(&event_id, &format!("Invalid Nostr signature: {e}"))
                .await
                .map_err(persistence_error)?;
            return Ok(false);
        }

        // verify against relays snapshot
        let result = verify_event_availability(
            self.transport.as_ref(),
            candidate.event.id,
            &candidate.relays,
            PropagationThreshold::AtLeast(candidate.required_relays),
        )
        .await;

        match result {
            Ok(availability) if availability.is_propagated() => {
                debug!(
                    "Incoming event {event_id} verified on {}/{} relays (required {})",
                    availability.confirmed.len(),
                    availability.total_relays,
                    availability.required,
                );
                self.store
                    .mark_verified(&event_id, Timestamp::now(), &availability.confirmed)
                    .await
                    .map_err(persistence_error)?;
                Ok(true)
            }
            result => {
                let reason = match result {
                    Ok(availability) => format!(
                        "Relay quorum not reached: confirmed {} of {} (required {}), {} errors",
                        availability.confirmed.len(),
                        availability.total_relays,
                        availability.required,
                        availability.errors.len(),
                    ),
                    Err(e) => format!("Relay verification error: {e}"),
                };
                let retry_at = Timestamp::now() + verification_retry_delay(candidate.attempts);
                warn!("Incoming event {event_id}: {reason}; retry at {retry_at:?}");
                self.store
                    .mark_pending_retry(
                        &event_id,
                        retry_at,
                        &reason.chars().take(ERROR_MESSAGE_LIMIT).collect::<String>(),
                    )
                    .await
                    .map_err(persistence_error)?;
                Ok(false)
            }
        }
    }

    /// run DB scan regularly since it's cheap - only do network requests if something is due
    pub async fn run_loop(&self) {
        let Ok(_guard) = self.run_lock.try_lock() else {
            warn!("Incoming Nostr quorum verification worker already running");
            return;
        };
        info!("Incoming Nostr quorum verification worker started");
        let mut interval = tokio::time::interval(SCAN_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = self.wakeup.notified() => {
                    // Allow freshly published events to reach the other relays and coalesce incoming bursts
                    tokio::time::sleep(INITIAL_DELAY).await;
                }
            }

            // first verify
            if let Err(e) = self.verify_due_once().await {
                error!("Incoming Nostr quorum verification batch error: {e}");
            }

            // then apply
            if let Err(e) = self.apply_due_once().await {
                error!("Incoming Nostr application batch error: {e}");
            }
        }
    }

    /// Apply verified candidates sequentially and afterwards attempt gap repair
    pub async fn apply_due_once(&self) -> Result<usize> {
        let candidates = self
            .store
            .get_verified_candidates(Timestamp::now(), DUE_BATCH_SIZE)
            .await
            .map_err(persistence_error)?;
        let count = candidates.len();
        let mut first_error = None;
        let mut gap_candidates = Vec::new();
        // all local applications are sequential
        // The bounded batch determines which chains can run
        let mut groups: Vec<Vec<IncomingChainCandidate>> = Vec::new();
        for candidate in candidates {
            match groups.iter_mut().find(|group| {
                group[0].chain_type == candidate.chain_type
                    && group[0].chain_id == candidate.chain_id
            }) {
                Some(group) => group.push(candidate),
                None => groups.push(vec![candidate]),
            }
        }

        for group in groups {
            let first = &group[0];
            let mut all = match self
                .store
                .get_verified_candidates_for_chain(&first.chain_type, &first.chain_id)
                .await
                .map_err(persistence_error)
            {
                Ok(all) => all,
                Err(e) => {
                    let reason: String = format!(
                        "Could not load verified candidates for {} {}: {e}",
                        first.chain_type, first.chain_id,
                    )
                    .chars()
                    .take(ERROR_MESSAGE_LIMIT)
                    .collect();
                    error!("{reason}");
                    first_error.get_or_insert(e);
                    // Fork selection requires all eligible verified candidates
                    // Release this chain's batch slots so unrelated chains can still make progress
                    for candidate in &group {
                        let retry_at =
                            Timestamp::now() + retry_with_backoff(candidate.application_attempts);
                        if let Err(e) = self
                            .store
                            .mark_application_deferred(
                                &candidate.event.id.to_string(),
                                Some(retry_at),
                                ApplicationWaitReason::Transient,
                                &reason,
                            )
                            .await
                            .map_err(persistence_error)
                        {
                            error!(
                                "Could not defer incoming candidate {}: {e}",
                                candidate.event.id,
                            );
                        }
                    }
                    continue;
                }
            };

            // Prefer a pending event when several Nostr events carry the same block
            all.sort_by_key(|candidate| {
                !group.iter().any(|due| due.event.id == candidate.event.id)
            });
            if let Err(e) = self
                .apply_chain_group(&group, &all, &mut gap_candidates)
                .await
            {
                first_error.get_or_insert(e);
            }
        }
        // after local application - we attempt gap repair if necessary
        if !gap_candidates.is_empty() && self.transport.has_connected_read_relay().await {
            let results = stream::iter(gap_candidates)
                .map(|candidate| async move { self.repair_missing_predecessor(&candidate).await })
                .buffer_unordered(MAX_GAP_REPAIRS_PER_PASS)
                .collect::<Vec<_>>()
                .await;
            for result in results {
                if let Err(e) = result {
                    error!("Incoming predecessor repair failed: {e}");
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }
        if let Some(e) = first_error {
            return Err(e);
        }
        Ok(count)
    }

    /// Applies one chain's pending candidates
    /// `all` includes verified candidates that are not pending yet
    /// They participate in selection, but are not applied before their retry deadline
    /// Returns the number of successfully applied event candidates
    async fn apply_chain_group(
        &self,
        due: &[IncomingChainCandidate],
        all: &[IncomingChainCandidate],
        gap_candidates: &mut Vec<IncomingChainCandidate>,
    ) -> Result<usize> {
        if due.is_empty() {
            return Ok(0);
        }

        let preferred = if all.len() > 1 {
            match self.application.preferred_verified_branch(all).await {
                Ok(preferred) => preferred,
                Err(e) => {
                    // Validation error on a potential branch - defer application
                    let reason: String = format!("Incoming fork selection failed: {e}")
                        .chars()
                        .take(ERROR_MESSAGE_LIMIT)
                        .collect();

                    warn!("{reason}");

                    for candidate in due {
                        self.store
                            .mark_application_deferred(
                                &candidate.event.id.to_string(),
                                Some(
                                    Timestamp::now()
                                        + retry_with_backoff(candidate.application_attempts),
                                ),
                                ApplicationWaitReason::Transient,
                                &reason,
                            )
                            .await
                            .map_err(persistence_error)?;
                    }
                    return Ok(0);
                }
            }
        } else {
            Vec::new()
        };

        let selected = !preferred.is_empty();
        let ordered: Vec<&IncomingChainCandidate> = if selected {
            // Apply only the pending prefix of the winner
            preferred
                .iter()
                .map(|&index| &all[index])
                .map_while(|preferred| {
                    due.iter()
                        .find(|candidate| candidate.event.id == preferred.event.id)
                })
                .collect()
        } else {
            // No fork preference - retain the normal application
            due.iter().collect()
        };

        let mut attempted = HashSet::new();
        let mut applied = 0;
        let mut first_error = None;
        for candidate in ordered {
            attempted.insert(candidate.event.id);
            match self.apply_one(candidate).await {
                Ok(attempt) => {
                    if attempt.applied {
                        applied += 1;
                    }
                    if attempt.needs_gap_repair && gap_candidates.len() < MAX_GAP_REPAIRS_PER_PASS {
                        gap_candidates.push(candidate.clone());
                    }
                    if selected && !attempt.applied {
                        // Don't fall back to a losing branch if application fails
                        break;
                    }
                }
                Err(e) => {
                    error!("Incoming chain application batch error: {e}");

                    first_error.get_or_insert(e);

                    if selected {
                        break;
                    }
                }
            }
        }

        if selected {
            // Candidates skipped because of forking shouldnt occupy the oldest slots of the due batch forever
            // Dont mark them  as ConflictingFork yet, winning branch could not have committed yet
            // Once committed, they will be marked as ConflictingFork
            let retry_at = Timestamp::now() + FORK_SELECTION_RETRY_INTERVAL;
            for candidate in due {
                if attempted.contains(&candidate.event.id) {
                    continue;
                }
                if let Err(e) = self
                    .store
                    .mark_application_deferred(
                        &candidate.event.id.to_string(),
                        Some(retry_at),
                        ApplicationWaitReason::Transient,
                        "Waiting for preferred verified continuation",
                    )
                    .await
                    .map_err(persistence_error)
                {
                    first_error.get_or_insert(e);
                }
            }
        }
        if let Some(e) = first_error {
            return Err(e);
        }
        Ok(applied)
    }

    async fn apply_one(&self, candidate: &IncomingChainCandidate) -> Result<ApplicationAttempt> {
        let event_id = candidate.event.id.to_string();
        let outcome = self.application.apply_verified_chain_event(candidate).await;
        let applied = matches!(
            &outcome,
            Ok(IncomingChainApplyResult::Applied) | Ok(IncomingChainApplyResult::AlreadyApplied)
        );

        // detect if this candidate needs gap repair (missing predecessor block(s))
        let needs_gap_repair = matches!(
            &outcome,
            Ok(IncomingChainApplyResult::Deferred(
                IncomingChainDependency::MissingPredecessor
                    | IncomingChainDependency::ChainNotInitialized
            ))
        );

        match outcome {
            Ok(IncomingChainApplyResult::Applied)
            | Ok(IncomingChainApplyResult::AlreadyApplied) => {
                self.store
                    .mark_applied(&event_id)
                    .await
                    .map_err(persistence_error)?;
                // if we apply a block, it might unblock another one waiting for predecessor
                self.store
                    .wake_application_for_predecessor(&candidate.chain_type, &candidate.chain_id)
                    .await
                    .map_err(persistence_error)?;
                self.wakeup.notify_one();
                debug!("Applied incoming chain event {event_id}");
            }
            Ok(IncomingChainApplyResult::Rejected(reason)) => {
                self.store
                    .mark_rejected(&event_id, &reason)
                    .await
                    .map_err(persistence_error)?;
                warn!("Rejected incoming chain event {event_id}: {reason}");
            }
            Ok(IncomingChainApplyResult::Deferred(IncomingChainDependency::MissingKeys)) => {
                let next =
                    next_missing_keys_retry(Timestamp::now(), candidate.application_attempts);
                self.store
                    .mark_application_deferred(
                        &event_id,
                        next,
                        ApplicationWaitReason::MissingKeys,
                        "Waiting for chain keys",
                    )
                    .await
                    .map_err(persistence_error)?;
            }
            Ok(IncomingChainApplyResult::Deferred(
                IncomingChainDependency::MissingPredecessor
                | IncomingChainDependency::ChainNotInitialized,
            )) => {
                self.store
                    .mark_application_deferred(
                        &event_id,
                        Some(Timestamp::now() + RETRY_DEFERRED_INTERVAL),
                        ApplicationWaitReason::MissingPredecessor,
                        "Waiting for chain predecessor",
                    )
                    .await
                    .map_err(persistence_error)?;
            }
            Ok(IncomingChainApplyResult::Deferred(IncomingChainDependency::ConflictingFork)) => {
                self.store
                    .mark_application_deferred(
                        &event_id,
                        None,
                        ApplicationWaitReason::ConflictingFork,
                        "Waiting for fork reconciliation",
                    )
                    .await
                    .map_err(persistence_error)?;
            }
            Err(e) => {
                let reason = e.to_string();
                let reason: String = reason.chars().take(ERROR_MESSAGE_LIMIT).collect();
                let next = Timestamp::now() + retry_with_backoff(candidate.application_attempts);
                warn!(
                    "Incoming chain event {event_id} application failed: {reason}; scheduling retry"
                );
                self.store
                    .mark_application_deferred(
                        &event_id,
                        Some(next),
                        ApplicationWaitReason::Transient,
                        &reason,
                    )
                    .await
                    .map_err(persistence_error)?;
            }
        }
        Ok(ApplicationAttempt {
            applied,
            needs_gap_repair,
        })
    }

    async fn repair_missing_predecessor(&self, candidate: &IncomingChainCandidate) -> Result<()> {
        let Some(predecessor) = find_direct_predecessor(self.transport.as_ref(), candidate).await
        else {
            debug!(
                "No referenced predecessor found for {} {} (event {})",
                candidate.chain_type, candidate.chain_id, candidate.event.id,
            );
            return Ok(());
        };
        let predecessor_id = predecessor.id;
        // same policy as the ancestor - quorum has to be reached independently
        let snapshot = RelayQuorumSnapshot {
            relays: candidate.relays.clone(),
            required: candidate.required_relays,
        };
        self.enqueue(
            predecessor,
            &candidate.chain_type,
            &candidate.chain_id,
            snapshot,
        )
        .await?;
        info!(
            "Enqueued recovered predecessor {} for incoming event {}",
            predecessor_id, candidate.event.id,
        );
        Ok(())
    }

    /// fetch a page of catch-up events for a given chain from a given relay
    async fn fetch_catchup_page(
        &self,
        chain: &KnownChain,
        relay: &Url,
        since: Option<u64>,
        until: u64,
    ) -> Result<Vec<Event>> {
        let mut filter = chain_filter(&chain.chain_id, chain.chain_type)
            .limit(CATCHUP_PAGE_SIZE)
            .until(nostr::types::Timestamp::from_secs(until));
        if let Some(since) = since {
            filter = filter.since(nostr::types::Timestamp::from_secs(since));
        }
        let events = tokio::time::timeout(
            CATCHUP_FETCH_TIMEOUT,
            self.transport.fetch_events_from_relay(filter, relay),
        )
        .await
        .map_err(|_| Error::Network(format!("Catch-up query timed out on relay {relay}")))??;
        if events.len() > CATCHUP_PAGE_SIZE {
            return Err(Error::Network(format!(
                "Relay {relay} returned more events than requested"
            )));
        }
        if events.iter().any(|event| {
            !matching_catchup_event(event, chain)
                || event.created_at.as_secs() > until
                || since.is_some_and(|lower| event.created_at.as_secs() < lower)
        }) {
            return Err(Error::Network(format!(
                "Relay {relay} returned an invalid or mismatched catch-up page for {} {}",
                chain.chain_type, chain.chain_id
            )));
        }
        Ok(events)
    }

    /// fetch and queue catch-up events from a given relay
    async fn catch_up_chain_on_relay(
        &self,
        chain: &KnownChain,
        relay: &Url,
        snapshot: &RelayQuorumSnapshot,
    ) -> Result<usize> {
        let cursors = self.catchup_cursors.as_ref().ok_or_else(|| {
            Error::Persistence("Public-chain catch-up cursor store not configured".into())
        })?;
        let scope = chain.chain_type.to_string(); // independent cursor per chain type
        let saved_until = cursors
            .get_catchup_until(&scope, &chain.chain_id, relay)
            .await
            .map_err(persistence_error)?;
        let mut until = saved_until.unwrap_or_else(|| Timestamp::now().inner());
        let mut discovered = 0;

        // Fast discovery while scanning old history
        if saved_until.is_some() {
            let head = self
                .fetch_catchup_page(chain, relay, None, Timestamp::now().inner())
                .await?;
            for event in head {
                self.enqueue(event, &scope, &chain.chain_id, snapshot.clone())
                    .await?;
                discovered += 1;
            }
        }

        for _ in 0..MAX_CATCHUP_PAGES_PER_RELAY {
            let events = self.fetch_catchup_page(chain, relay, None, until).await?;
            if events.is_empty() {
                cursors
                    .set_catchup_until(&scope, &chain.chain_id, relay, None)
                    .await
                    .map_err(persistence_error)?;
                return Ok(discovered);
            }
            let oldest_timestamp = events
                .iter()
                .map(|event| event.created_at.as_secs())
                .min()
                .expect("nonempty page");
            // events are added but if they are already there, this is a no-op
            for event in events {
                self.enqueue(
                    event,
                    &chain.chain_type.to_string(),
                    &chain.chain_id,
                    snapshot.clone(),
                )
                .await?;
                discovered += 1;
            }

            // handle a NIP-01 edge case, where timestamp boundaries are inclusive
            // we need to explicitly fetch the events at the boundary to the next page
            let boundary_events = self
                .fetch_catchup_page(chain, relay, Some(oldest_timestamp), oldest_timestamp)
                .await?;
            let next_until = next_catchup_until(oldest_timestamp, boundary_events.len())?;
            for event in boundary_events {
                self.enqueue(
                    event,
                    &chain.chain_type.to_string(),
                    &chain.chain_id,
                    snapshot.clone(),
                )
                .await?;
                discovered += 1;
            }
            match next_until {
                Some(next) => {
                    cursors
                        .set_catchup_until(&scope, &chain.chain_id, relay, Some(next))
                        .await
                        .map_err(persistence_error)?;
                    until = next;
                }
                None => {
                    cursors
                        .set_catchup_until(&scope, &chain.chain_id, relay, None)
                        .await
                        .map_err(persistence_error)?;
                    return Ok(discovered);
                }
            }
        }
        // exit at some point to avoid loading forever against DOS
        Err(Error::Network(format!(
            "Catch-up for {} {} on {relay} exceeded {} pages; historical scan is incomplete",
            chain.chain_type, chain.chain_id, MAX_CATCHUP_PAGES_PER_RELAY
        )))
    }

    pub async fn catch_up_known_chains_once(
        &self,
        chain_keys: &dyn ChainKeyServiceApi,
        snapshot: &RelayQuorumSnapshot,
    ) -> Result<usize> {
        // only attempt catch-up if we're online
        if !self.transport.has_connected_read_relay().await {
            return Ok(0);
        }
        let chains = chain_keys.list_known_chains().await?;
        // only attempt catch-up if we have chains to catch up
        if chains.is_empty() {
            return Ok(0);
        }
        let count = chains.len().min(MAX_CHAINS_PER_CATCHUP);
        // round-robin across known chains
        let start = {
            let mut next = self.catchup_next_chain.lock().await;
            let start = *next % chains.len();
            *next = (start + count) % chains.len();
            start
        };
        let mut discovered = 0;
        let mut first_error = None;

        for index in 0..count {
            let chain = &chains[(start + index) % chains.len()];
            match self.catch_up_chain_once(chain, snapshot).await {
                Ok(count) => discovered += count,
                Err(e) => {
                    warn!(
                        "Catch-up incomplete for {} {}: {e}",
                        chain.chain_type, chain.chain_id,
                    );
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }
        if let Some(e) = first_error {
            return Err(e);
        }
        Ok(discovered)
    }

    /// Discover events for one known chain on all configured relays - only enqueues
    pub async fn catch_up_chain_once(
        &self,
        chain: &KnownChain,
        snapshot: &RelayQuorumSnapshot,
    ) -> Result<usize> {
        if !self.transport.has_connected_read_relay().await {
            return Ok(0);
        }
        let mut discovered = 0;
        let mut first_error = None;
        for relay in &snapshot.relays {
            match self.catch_up_chain_on_relay(chain, relay, snapshot).await {
                Ok(count) => discovered += count,
                Err(e) => {
                    warn!(
                        "Catch-up failed for {} {} on {relay}: {e}",
                        chain.chain_type, chain.chain_id,
                    );
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }
        if let Some(e) = first_error {
            return Err(e);
        }
        Ok(discovered)
    }

    pub async fn run_catchup_loop(
        &self,
        chain_keys: Arc<dyn ChainKeyServiceApi>,
        snapshot: RelayQuorumSnapshot,
        mut hints: Option<broadcast::Receiver<KnownChain>>,
    ) {
        let Ok(_guard) = self.catchup_lock.try_lock() else {
            warn!("Incoming Nostr catch-up worker already running");
            return;
        };
        info!("Incoming Nostr catch-up started");
        let mut interval = tokio::time::interval(CATCHUP_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                // standard periodic recovery for all known chains
                _ = interval.tick() => {
                    match self
                        .catch_up_known_chains_once(
                            chain_keys.as_ref(),
                            &snapshot,
                        )
                        .await
                    {
                        Ok(count) if count > 0 => {
                            info!(
                                "Incoming Nostr periodic catch-up replayed {count} event discoveries"
                            );
                        }
                        Ok(_) => {}
                        Err(e) => {
                            warn!(
                                "Incoming Nostr historical catch-up incomplete: {e}"
                            );
                        }
                    }
                }

                // fast-path discovery for newly received chain keys
                result = async {
                    match hints.as_mut() {
                        Some(receiver) => receiver.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match result {
                        Ok(chain) => {
                            debug!(
                                "Immediate catch-up requested for {} {}",
                                chain.chain_type,
                                chain.chain_id,
                            );
                            self.wakeup.notify_one();
                            match self
                                .catch_up_chain_once(&chain, &snapshot)
                                .await
                            {
                                Ok(count) => {
                                    debug!(
                                        "Immediate catch-up for {} {} replayed {count} event discoveries",
                                        chain.chain_type,
                                        chain.chain_id,
                                    );
                                }
                                Err(e) => {
                                    warn!(
                                        "Immediate catch-up failed for {} {}: {e}",
                                        chain.chain_type,
                                        chain.chain_id,
                                    );
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(
                                "Dropped {skipped} incoming catch-up hints"
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            // continue without fast-path if closed
                            hints = None;
                        }
                    }
                }
            }
        }
    }
}

#[async_trait]
impl VerifiedChainIngestionApi for IncomingPropagationVerifier {
    async fn ingest_verified_chain(
        &self,
        chain_type: BlockchainType,
        chain_id: &str,
        events: Vec<Event>,
        snapshot: RelayQuorumSnapshot,
    ) -> Result<VerifiedChainIngestionProgress> {
        let chain_type_text = chain_type.to_string();
        let candidates: Vec<IncomingChainCandidate> = events
            .into_iter()
            .map(|event| IncomingChainCandidate {
                event,
                chain_type: chain_type_text.clone(),
                chain_id: chain_id.to_owned(),
                relays: snapshot.relays.clone(),
                required_relays: snapshot.required,
                attempts: 0,
                application_attempts: 0,
            })
            .collect();

        // First pass - enqueue the complete discovered chain
        for candidate in &candidates {
            self.enqueue(
                candidate.event.clone(),
                &chain_type_text,
                chain_id,
                snapshot.clone(),
            )
            .await?;
        }

        let enqueued = candidates.len();
        // Verify discovered candidates before committing any branch
        let mut verified = Vec::new();
        for candidate in candidates {
            if self.verify_one(candidate.clone()).await? {
                verified.push(candidate);
            }
        }

        // All verified candidates are eligible for application in the one-shot restore lifecycle
        let mut gap_candidates = Vec::new();
        let applied_prefix = self
            .apply_chain_group(&verified, &verified, &mut gap_candidates)
            .await?;

        let progress = VerifiedChainIngestionProgress {
            enqueued,
            applied_prefix,
        };

        info!(
            "Verified chain ingestion for {} {}: {} applied, {} remaining",
            chain_type_text,
            chain_id,
            progress.applied_prefix,
            progress.remaining(),
        );

        Ok(progress)
    }
}

#[async_trait]
impl IncomingChainCatchupApi for IncomingPropagationVerifier {
    async fn catch_up_chain(
        &self,
        chain: &KnownChain,
        snapshot: &RelayQuorumSnapshot,
    ) -> Result<usize> {
        self.catch_up_chain_once(chain, snapshot).await
    }
}

// calculate retry time with exponential backoff, clamped to 10 min
fn retry_with_backoff(previous_failures: u32) -> Duration {
    Duration::from_secs(
        (RETRY_BASELINE_SECS.saturating_mul(1 << previous_failures.min(4))).min(600),
    )
}

fn persistence_error(e: bcr_ebill_persistence::Error) -> Error {
    Error::Persistence(e.to_string())
}

fn next_missing_keys_retry(now: Timestamp, previous_attempts: u32) -> Option<Timestamp> {
    let seconds = MISSING_KEYS_RETRY_DELAYS
        .get(previous_attempts as usize)
        .copied()
        .unwrap_or(300);
    Some(now + Duration::from_secs(seconds))
}

fn matching_chain_predecessor(
    candidate: &IncomingChainCandidate,
    requested_id: EventId,
    event: &Event,
) -> bool {
    if event.id != requested_id || event.kind != Kind::TextNote || event.verify().is_err() {
        return false;
    }
    matches!(
        unwrap_public_chain_event(event),
        Ok(Some(public))
            if public.id == candidate.chain_id
                && public.chain_type.to_string()
                    == candidate.chain_type
    )
}

/// Find a directly referenced predecessor candidate using the reply_id of an existing candidate
async fn find_direct_predecessor(
    transport: &dyn TransportClientApi,
    candidate: &IncomingChainCandidate,
) -> Option<Event> {
    let (root_id, reply_id) = root_and_reply_id(&candidate.event);
    // direct reply to the root uses the "root" marker, deeper replies use the "reply" marker
    let predecessor_id = reply_id.or(root_id)?;
    // no self-reference
    if predecessor_id == candidate.event.id {
        return None;
    }
    // concurrently look for the predecessor on the different relays with a timeout
    stream::iter(candidate.relays.iter().cloned())
        .map(|relay| async move {
            let result = tokio::time::timeout(
                GAP_LOOKUP_TIMEOUT,
                transport.fetch_event_from_relay(predecessor_id, &relay),
            )
            .await;
            match result {
                Ok(Ok(Some(event)))
                    if matching_chain_predecessor(candidate, predecessor_id, &event) =>
                {
                    Some(event)
                }
                Ok(Ok(Some(_))) => {
                    debug!("Relay {relay} returned a mismatched predecessor for {predecessor_id}");
                    None
                }
                Ok(Ok(None)) => None,
                Ok(Err(e)) => {
                    debug!("Predecessor lookup on {relay} failed: {e}");
                    None
                }
                Err(_) => {
                    debug!("Predecessor lookup on {relay} timed out");
                    None
                }
            }
        })
        .buffer_unordered(MAX_PARALLEL_GAP_RELAYS)
        .filter_map(std::future::ready)
        .next()
        .await
}

fn matching_catchup_event(event: &Event, chain: &KnownChain) -> bool {
    if event.kind != Kind::TextNote || event.verify().is_err() {
        return false;
    }
    matches!(
        unwrap_public_chain_event(event),
        Ok(Some(public))
            if public.id == chain.chain_id
                && public.chain_type == chain.chain_type
    )
}

fn next_catchup_until(oldest_timestamp: u64, boundary_events: usize) -> Result<Option<u64>> {
    if boundary_events >= CATCHUP_PAGE_SIZE {
        return Err(Error::Network(
            "Catch-up timestamp contains too many events to paginate without risking data loss"
                .into(),
        ));
    }
    Ok(oldest_timestamp.checked_sub(1))
}

// one fast check, then with backoff
fn verification_retry_delay(previous_failures: u32) -> Duration {
    if previous_failures == 0 {
        Duration::from_secs(5)
    } else {
        retry_with_backoff(previous_failures - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::IncomingPropagationVerifier;
    use super::VerifiedChainIngestionApi;
    use super::matching_catchup_event;
    use super::retry_with_backoff;
    use super::verification_retry_delay;
    use super::{CATCHUP_PAGE_SIZE, next_catchup_until};
    use super::{find_direct_predecessor, matching_chain_predecessor};
    use crate::chain_keys::KnownChain;
    use crate::handler::IncomingChainApplyResult;
    use crate::handler::IncomingChainDependency;
    use crate::handler::{
        MockIncomingChainApplicationApi, test_utils::MockIncomingPropagationStore,
    };
    use crate::incoming_verification::VerifiedChainIngestionProgress;
    use crate::incoming_verification::next_missing_keys_retry;
    use crate::test_utils::MockNostrEventOffsetStore;
    use crate::test_utils::MockNotificationJsonTransport;
    use crate::transport::{create_public_chain_event, root_and_reply_id};
    use bcr_ebill_api::service::transport_service::Error;
    use bcr_ebill_api::service::transport_service::propagation::RelayQuorumSnapshot;
    use bcr_ebill_core::protocol::Timestamp;
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use bcr_ebill_core::protocol::{
        blockchain::BlockchainType,
        event::{EventEnvelope, EventType},
    };
    use bcr_ebill_persistence::traits::propagation::ApplicationWaitReason;
    use bcr_ebill_persistence::traits::propagation::IncomingChainCandidate;
    use bcr_ebill_persistence::{
        EncryptionContext,
        sqlite::{SqliteConfig, SqlitePersistence},
        traits::propagation::IncomingPropagationStoreApi,
    };
    use nostr::event::{EventBuilder, FinalizeEvent};
    use nostr::{event::Event, key::Keys};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::{
        Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;
    use url::Url;

    fn chain_event(chain_id: &str, previous: Option<Event>) -> Event {
        let root = previous.clone();
        let envelope = EventEnvelope {
            event_type: EventType::BillChain,
            version: "1.0".into(),
            data: vec![],
        };
        create_public_chain_event(
            chain_id,
            envelope,
            Timestamp::now(),
            BlockchainType::Bill,
            previous,
            root,
        )
        .unwrap()
        .finalize(&Keys::generate())
        .unwrap()
    }

    fn gap_candidate(event: Event) -> IncomingChainCandidate {
        IncomingChainCandidate {
            event,
            chain_type: "bill".into(),
            chain_id: "test-chain".into(),
            relays: ["wss://r1.example", "wss://r2.example"]
                .into_iter()
                .map(|url| Url::parse(url).unwrap())
                .collect(),
            required_relays: 2,
            attempts: 0,
            application_attempts: 0,
        }
    }

    #[test]
    fn incoming_verification_backoff() {
        assert_eq!(retry_with_backoff(0), Duration::from_secs(60));
        assert_eq!(retry_with_backoff(1), Duration::from_secs(120));
        assert_eq!(retry_with_backoff(2), Duration::from_secs(240));
        assert_eq!(retry_with_backoff(3), Duration::from_secs(480));
        assert_eq!(retry_with_backoff(4), Duration::from_secs(600));
        assert_eq!(retry_with_backoff(100), Duration::from_secs(600));
    }

    #[test]
    fn missing_keys_retries_are_capped_but_never_stop() {
        let now = Timestamp::now();
        for (attempt, expected) in [
            (0, 15),
            (1, 30),
            (2, 60),
            (3, 120),
            (4, 300),
            (5, 300),
            (100, 300),
        ] {
            assert_eq!(
                next_missing_keys_retry(now, attempt),
                Some(now + Duration::from_secs(expected)),
            );
        }
    }

    #[tokio::test]
    async fn gap_repair_finds_exact_predecessor_on_snapshot_relays() {
        let parent = chain_event("test-chain", None);
        let unrelated = chain_event("other-chain", None);
        let child = chain_event("test-chain", Some(parent.clone()));
        let candidate = gap_candidate(child);
        let expected_id = parent.id;
        let mut transport = MockNotificationJsonTransport::new();
        transport
            .expect_fetch_event_from_relay()
            .times(2)
            .returning(move |event_id, relay| {
                assert_eq!(event_id, expected_id);
                match relay.host_str() {
                    Some("r1.example") => Ok(Some(unrelated.clone())),
                    Some("r2.example") => Ok(Some(parent.clone())),
                    other => {
                        panic!("Unexpected relay: {other:?}")
                    }
                }
            });
        let recovered = find_direct_predecessor(&transport, &candidate)
            .await
            .expect("should find matching parent");
        assert_eq!(recovered.id, expected_id);
    }

    #[tokio::test]
    async fn gap_repair_without_reply_reference_does_not_query_relays() {
        let genesis = chain_event("test-chain", None);
        let candidate = gap_candidate(genesis);
        let mut transport = MockNotificationJsonTransport::new();
        transport.expect_fetch_event_from_relay().never();
        let result = find_direct_predecessor(&transport, &candidate).await;
        assert!(result.is_none());
    }

    #[test]
    fn gap_repair_rejects_invalid_predecessor_signature() {
        let parent = chain_event("test-chain", None);
        let child = chain_event("test-chain", Some(parent.clone()));
        let candidate = gap_candidate(child);
        let mut corrupted = parent.clone();
        corrupted.content.push_str("tampered");
        assert!(!matching_chain_predecessor(
            &candidate, parent.id, &corrupted,
        ));
    }

    #[tokio::test]
    async fn gap_repair_network_failure_returns_no_parent() {
        let parent = chain_event("test-chain", None);
        let child = chain_event("test-chain", Some(parent));
        let candidate = gap_candidate(child);
        let mut transport = MockNotificationJsonTransport::new();
        transport
            .expect_fetch_event_from_relay()
            .times(2)
            .returning(|_, _| {
                Err(bcr_ebill_api::service::transport_service::Error::Network(
                    "relay unavailable".into(),
                ))
            });
        let result = find_direct_predecessor(&transport, &candidate).await;
        assert!(result.is_none());
    }

    #[test]
    fn direct_reply_to_root_has_no_reply_marker() {
        let parent = chain_event("test-chain", None);
        let child = chain_event("test-chain", Some(parent.clone()));
        let (root_id, reply_id) = root_and_reply_id(&child);
        assert_eq!(root_id, Some(parent.id));
        assert_eq!(reply_id, None);
        assert_eq!(reply_id.or(root_id), Some(parent.id));
    }

    #[test]
    fn catchup_accepts_only_matching_signed_chain_events() {
        let chain = KnownChain {
            chain_type: BlockchainType::Bill,
            chain_id: "test-chain".into(),
        };
        let correct = chain_event("test-chain", None);
        assert!(matching_catchup_event(&correct, &chain));
        let unrelated = chain_event("other-chain", None);
        assert!(!matching_catchup_event(&unrelated, &chain));
        let mut corrupted = correct.clone();
        corrupted.content.push_str("tampered");
        assert!(!matching_catchup_event(&corrupted, &chain));
    }

    #[test]
    fn catchup_does_not_skip_ambiguous_timestamp_boundary() {
        // events at boundary second are retrieved
        assert_eq!(
            next_catchup_until(100, CATCHUP_PAGE_SIZE - 1).unwrap(),
            Some(99),
        );
        // could contain additional events, don't move to timestamp 99
        assert!(next_catchup_until(100, CATCHUP_PAGE_SIZE).is_err());
        // zero is the beginning of the history
        assert_eq!(next_catchup_until(0, 1).unwrap(), None,);
    }

    #[test]
    fn catchup_does_not_require_predecessor_reference() {
        let event = chain_event("test-chain", None);
        let chain = KnownChain {
            chain_type: BlockchainType::Bill,
            chain_id: "test-chain".into(),
        };
        let (root, reply) = root_and_reply_id(&event);
        assert!(root.is_none());
        assert!(reply.is_none());
        assert!(matching_catchup_event(&event, &chain));
    }

    #[tokio::test]
    async fn targeted_catchup_enqueues_discovered_chain_event() {
        let relay1 = Url::parse("wss://r1.example").unwrap();
        let relay2 = Url::parse("wss://r2.example").unwrap();

        let event = chain_event("test-chain", None);
        let expected_id = event.id;

        let mut cursors = MockNostrEventOffsetStore::new();
        cursors
            .expect_get_catchup_until()
            .times(2)
            .returning(|_, _, _| Ok(None));
        cursors
            .expect_set_catchup_until()
            .times(3)
            .returning(|_, _, _, _| Ok(()));

        let mut transport = MockNotificationJsonTransport::new();
        transport
            .expect_has_connected_read_relay()
            .once()
            .returning(|| true);
        transport
            .expect_fetch_events_from_relay()
            .times(4)
            .returning(move |filter, relay| match relay.host_str() {
                Some("r1.example") => {
                    let includes_event = filter
                        .until
                        .is_some_and(|until| until.as_secs() >= event.created_at.as_secs());
                    if includes_event {
                        Ok(vec![event.clone()])
                    } else {
                        Ok(vec![])
                    }
                }
                Some("r2.example") => Ok(vec![]),
                other => panic!("Unexpected relay: {other:?}"),
            });

        let mut store = MockIncomingPropagationStore::new();
        store
            .expect_upsert_candidate()
            .times(2)
            .withf(move |candidate, _first_try_at| {
                candidate.event.id == expected_id
                    && candidate.chain_type == "bill"
                    && candidate.chain_id == "test-chain"
                    && candidate.required_relays == 2
                    && candidate.relays.len() == 2
            })
            .returning(|_, _| Ok(()));
        let verifier = IncomingPropagationVerifier::new(
            Arc::new(store),
            Arc::new(transport),
            Arc::new(MockIncomingChainApplicationApi::new()),
        )
        .with_catchup_cursors(Arc::new(cursors));
        let snapshot = RelayQuorumSnapshot {
            relays: vec![relay1, relay2],
            required: 2,
        };
        let chain = KnownChain {
            chain_type: BlockchainType::Bill,
            chain_id: "test-chain".into(),
        };
        let discovered = verifier
            .catch_up_chain_once(&chain, &snapshot)
            .await
            .unwrap();
        assert_eq!(discovered, 2);
    }

    #[tokio::test]
    async fn public_catchup_short_pages_reach_older_events() {
        // Fetch event at timestamp 1000
        // Confirm the 1000 boundary, save cursor 999
        // Fetch event at timestamp 900
        // Confirm the 900 boundary, save cursor 899
        // Fetch at 899, receive empty history, reset cursor
        let relay = Url::parse("wss://r1.example").unwrap();
        let envelope = EventEnvelope {
            event_type: EventType::BillChain,
            version: "1.0".into(),
            data: vec![],
        };
        let event_at = |seconds| {
            create_public_chain_event(
                "test-chain",
                envelope.clone(),
                Timestamp::new(seconds).unwrap(),
                BlockchainType::Bill,
                None,
                None,
            )
            .unwrap()
            .finalize(&Keys::generate())
            .unwrap()
        };
        let newer = event_at(1000);
        let older = event_at(900);
        let newer_id = newer.id;
        let older_id = older.id;
        let cursor_writes = Arc::new(StdMutex::new(Vec::<Option<u64>>::new()));
        let recorded_writes = cursor_writes.clone();
        let mut cursors = MockNostrEventOffsetStore::new();
        cursors
            .expect_get_catchup_until()
            .once()
            .returning(|_, _, _| Ok(None));
        cursors
            .expect_set_catchup_until()
            .times(3)
            .returning(move |_, _, _, until| {
                recorded_writes.lock().unwrap().push(until);
                Ok(())
            });
        let enqueued = Arc::new(StdMutex::new(Vec::new()));
        let recorded_events = enqueued.clone();
        let mut store = MockIncomingPropagationStore::new();
        store
            .expect_upsert_candidate()
            .times(4)
            .returning(move |candidate, _| {
                assert_eq!(candidate.chain_type, "bill");
                assert_eq!(candidate.chain_id, "test-chain");
                recorded_events.lock().unwrap().push(candidate.event.id);

                Ok(())
            });
        let mut transport = MockNotificationJsonTransport::new();
        transport
            .expect_has_connected_read_relay()
            .once()
            .returning(|| true);
        transport
            .expect_fetch_events_from_relay()
            .times(5)
            .returning(move |filter, queried_relay| {
                assert_eq!(queried_relay.host_str(), Some("r1.example"),);
                let since = filter.since.map(|t| t.as_secs());
                let until = filter.until.unwrap().as_secs();
                match (since, until) {
                    (None, t) if t >= 1000 => Ok(vec![newer.clone()]),
                    (Some(1000), 1000) => Ok(vec![newer.clone()]),
                    (None, 999) => Ok(vec![older.clone()]),
                    (Some(900), 900) => Ok(vec![older.clone()]),
                    (None, 899) => Ok(vec![]),
                    _ => panic!("Unexpected public query: {since:?}, {until}"),
                }
            });
        let verifier = IncomingPropagationVerifier::new(
            Arc::new(store),
            Arc::new(transport),
            Arc::new(MockIncomingChainApplicationApi::new()),
        )
        .with_catchup_cursors(Arc::new(cursors));
        let snapshot = RelayQuorumSnapshot {
            relays: vec![relay],
            required: 1,
        };
        let chain = KnownChain {
            chain_type: BlockchainType::Bill,
            chain_id: "test-chain".into(),
        };
        let discovered = verifier
            .catch_up_chain_once(&chain, &snapshot)
            .await
            .unwrap();
        assert_eq!(discovered, 4);
        assert_eq!(
            *cursor_writes.lock().unwrap(),
            vec![Some(999), Some(899), None],
        );
        assert_eq!(
            *enqueued.lock().unwrap(),
            vec![newer_id, newer_id, older_id, older_id],
        );
    }

    #[tokio::test]
    async fn targeted_catchup_offline_does_not_fetch_events() {
        let mut transport = MockNotificationJsonTransport::new();
        transport
            .expect_has_connected_read_relay()
            .once()
            .returning(|| false);
        transport.expect_fetch_events_from_relay().never();
        let verifier = IncomingPropagationVerifier::new(
            Arc::new(MockIncomingPropagationStore::new()),
            Arc::new(transport),
            Arc::new(MockIncomingChainApplicationApi::new()),
        );
        let snapshot = RelayQuorumSnapshot {
            relays: vec![Url::parse("wss://r1.example").unwrap()],
            required: 1,
        };
        let chain = KnownChain {
            chain_type: BlockchainType::Bill,
            chain_id: "test-chain".into(),
        };
        assert_eq!(
            verifier
                .catch_up_chain_once(&chain, &snapshot)
                .await
                .unwrap(),
            0,
        );
    }

    #[tokio::test]
    async fn restore_ingestion_never_applies_without_quorum() {
        let event = chain_event("test-chain", None);
        let mut transport = MockNotificationJsonTransport::new();
        transport
            .expect_event_available_on_relay()
            .times(2)
            .returning(|_, _| Ok(false));
        let mut store = MockIncomingPropagationStore::new();
        store
            .expect_upsert_candidate()
            .once()
            .returning(|_, _| Ok(()));
        store
            .expect_mark_pending_retry()
            .once()
            .returning(|_, _, _| Ok(()));
        let mut application = MockIncomingChainApplicationApi::new();
        application.expect_apply_verified_chain_event().never();
        let verifier = IncomingPropagationVerifier::new(
            Arc::new(store),
            Arc::new(transport),
            Arc::new(application),
        );
        let result = verifier
            .ingest_verified_chain(
                BlockchainType::Bill,
                "test-chain",
                vec![event],
                RelayQuorumSnapshot {
                    relays: vec![
                        Url::parse("wss://r1.example").unwrap(),
                        Url::parse("wss://r2.example").unwrap(),
                    ],
                    required: 2,
                },
            )
            .await;
        assert_eq!(
            result.unwrap(),
            VerifiedChainIngestionProgress {
                enqueued: 1,
                applied_prefix: 0,
            },
        );
    }

    #[tokio::test]
    async fn restore_ingestion_applies_after_quorum() {
        let event = chain_event("test-chain", None);
        let mut transport = MockNotificationJsonTransport::new();
        transport
            .expect_event_available_on_relay()
            .times(2)
            .returning(|_, _| Ok(true));
        let mut store = MockIncomingPropagationStore::new();
        store
            .expect_upsert_candidate()
            .once()
            .returning(|_, _| Ok(()));
        store
            .expect_mark_verified()
            .once()
            .returning(|_, _, _| Ok(()));
        store.expect_mark_applied().once().returning(|_| Ok(()));
        store
            .expect_wake_application_for_predecessor()
            .once()
            .returning(|_, _| Ok(()));
        let mut application = MockIncomingChainApplicationApi::new();
        application
            .expect_apply_verified_chain_event()
            .once()
            .returning(|_| Ok(IncomingChainApplyResult::Applied));
        let verifier = IncomingPropagationVerifier::new(
            Arc::new(store),
            Arc::new(transport),
            Arc::new(application),
        );
        let snapshot = RelayQuorumSnapshot {
            relays: vec![
                Url::parse("wss://r1.example").unwrap(),
                Url::parse("wss://r2.example").unwrap(),
            ],
            required: 2,
        };
        let progress = verifier
            .ingest_verified_chain(BlockchainType::Bill, "test-chain", vec![event], snapshot)
            .await
            .unwrap();
        assert_eq!(
            progress,
            VerifiedChainIngestionProgress {
                enqueued: 1,
                applied_prefix: 1,
            },
        );
    }

    #[tokio::test]
    async fn restore_enqueues_all_events_and_applies_verified_prefix() {
        let first = chain_event("test-chain", None);
        let second = chain_event("test-chain", Some(first.clone()));
        let third = chain_event("test-chain", Some(second.clone()));
        let third_id = third.id;
        let first_id = first.id;
        let second_id = second.id;

        let enqueued = Arc::new(AtomicUsize::new(0));
        let enqueued_for_store = enqueued.clone();

        let mut store = MockIncomingPropagationStore::new();
        // all three events must be durably enqueued
        store
            .expect_upsert_candidate()
            .times(3)
            .returning(move |_, _| {
                enqueued_for_store.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });
        // only the first two reach quorum
        store
            .expect_mark_verified()
            .times(2)
            .returning(|_, _, _| Ok(()));
        store
            .expect_mark_pending_retry()
            .once()
            .returning(|_, _, _| Ok(()));
        store.expect_mark_applied().times(2).returning(|_| Ok(()));
        store
            .expect_wake_application_for_predecessor()
            .times(2)
            .returning(|_, _| Ok(()));

        let mut transport = MockNotificationJsonTransport::new();
        let enqueued_for_transport = enqueued.clone();
        transport
            .expect_event_available_on_relay()
            .times(6)
            .returning(move |event_id, _| {
                // all events must already be stored before the first availability check occurs
                assert_eq!(enqueued_for_transport.load(Ordering::SeqCst), 3);
                Ok(event_id != third_id)
            });
        let applied = Arc::new(StdMutex::new(Vec::new()));
        let applied_for_mock = applied.clone();

        let mut application = MockIncomingChainApplicationApi::new();
        application
            .expect_preferred_verified_branch()
            .returning(|_| Ok(Vec::new()));
        application
            .expect_apply_verified_chain_event()
            .times(2)
            .returning(move |candidate| {
                applied_for_mock.lock().unwrap().push(candidate.event.id);
                Ok(IncomingChainApplyResult::Applied)
            });

        let verifier = IncomingPropagationVerifier::new(
            Arc::new(store),
            Arc::new(transport),
            Arc::new(application),
        );
        let progress = verifier
            .ingest_verified_chain(
                BlockchainType::Bill,
                "test-chain",
                vec![first, second, third],
                RelayQuorumSnapshot {
                    relays: vec![
                        Url::parse("wss://r1.example").unwrap(),
                        Url::parse("wss://r2.example").unwrap(),
                    ],
                    required: 2,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            progress,
            VerifiedChainIngestionProgress {
                enqueued: 3,
                applied_prefix: 2,
            }
        );
        assert_eq!(progress.remaining(), 1);
        // application order is exactly the chain order
        assert_eq!(*applied.lock().unwrap(), vec![first_id, second_id],);
        // third block was not applied
        assert_eq!(enqueued.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn incoming_quorum_recovers_after_relay_replication() {
        // Integration Test with real SQLite
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("incoming-quorum.sqlite");
        let encryption = Arc::new(EncryptionContext::new(BcrKeys::new()));
        let db = SqlitePersistence::open(SqliteConfig::new(db_path.clone()))
            .await
            .unwrap();
        let store = Arc::new(db.incoming_propagation_store(encryption.clone()));
        let event = chain_event("test-chain", None);
        let event_id = event.id.to_string();
        let expected_event_id = event.id;
        let snapshot = RelayQuorumSnapshot {
            relays: vec![
                Url::parse("wss://r1.example").unwrap(),
                Url::parse("wss://r2.example").unwrap(),
                Url::parse("wss://r3.example").unwrap(),
            ],
            required: 2,
        };

        let candidate = IncomingChainCandidate {
            event,
            chain_type: "bill".into(),
            chain_id: "test-chain".into(),
            relays: snapshot.relays.clone(),
            required_relays: snapshot.required,
            attempts: 0,
            application_attempts: 0,
        };
        // Initially only relay 1 has the event
        // Later relay 2 receives the exact same signed event
        let relay2_available = Arc::new(AtomicBool::new(false));
        let relay2_for_transport = relay2_available.clone();
        let mut transport = MockNotificationJsonTransport::new();
        transport
            .expect_has_connected_read_relay()
            .returning(|| true);
        transport
            .expect_event_available_on_relay()
            .times(6) // 3 relays, 2 verification attempts
            .returning(move |id, relay| {
                assert_eq!(id, expected_event_id);
                match relay.host_str() {
                    Some("r1.example") => Ok(true),
                    Some("r2.example") => Ok(relay2_for_transport.load(Ordering::SeqCst)),
                    Some("r3.example") => Ok(false),
                    other => panic!("Unexpected relay: {other:?}"),
                }
            });

        // called once after quorum has been reached
        let applied = Arc::new(AtomicUsize::new(0));
        let applied_for_mock = applied.clone();
        let mut application = MockIncomingChainApplicationApi::new();
        application
            .expect_apply_verified_chain_event()
            .once()
            .returning(move |candidate| {
                assert_eq!(candidate.event.id, expected_event_id);
                assert_eq!(candidate.chain_type, "bill");
                assert_eq!(candidate.chain_id, "test-chain");
                assert_eq!(candidate.required_relays, 2);
                assert_eq!(candidate.relays.len(), 3);
                applied_for_mock.fetch_add(1, Ordering::SeqCst);
                Ok(IncomingChainApplyResult::Applied)
            });

        let transport = Arc::new(transport);
        let application = Arc::new(application);
        let verifier =
            IncomingPropagationVerifier::new(store.clone(), transport.clone(), application.clone());

        // 1. Signed event is persisted before verification
        store
            .upsert_candidate(&candidate, Timestamp::zero())
            .await
            .unwrap();
        assert_eq!(
            store
                .get_due_candidates(Timestamp::now(), 10)
                .await
                .unwrap()
                .len(),
            1,
        );
        // 2. Only 1 of 3 relays confirms availability - stays unverified
        assert_eq!(verifier.verify_due_once().await.unwrap(), 1);
        assert_eq!(verifier.apply_due_once().await.unwrap(), 0);
        assert_eq!(applied.load(Ordering::SeqCst), 0);

        assert!(
            store
                .get_verified_candidates(Timestamp::now() + Duration::from_secs(61), 10,)
                .await
                .unwrap()
                .is_empty(),
        );

        // scheduled for later retry
        let pending = store
            .get_due_candidates(Timestamp::now() + Duration::from_secs(61), 10)
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].event.id, expected_event_id);
        assert_eq!(pending[0].attempts, 1);
        assert_eq!(pending[0].required_relays, 2);
        assert_eq!(pending[0].relays, snapshot.relays);

        // 3. Simulate restart
        drop(verifier);
        drop(store);
        db.close().await;

        let reopened = SqlitePersistence::open(SqliteConfig::new(db_path))
            .await
            .unwrap();
        let store = Arc::new(reopened.incoming_propagation_store(encryption));

        // The exact event and its original relay snapshot survived the restart
        let pending = store
            .get_due_candidates(Timestamp::now() + Duration::from_secs(61), 10)
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].event.id, expected_event_id);
        assert_eq!(pending[0].required_relays, 2);
        assert_eq!(pending[0].relays, snapshot.relays);

        // 4. The event has now reached a second relay
        relay2_available.store(true, Ordering::SeqCst);

        // retry uses exponential backoff
        store
            .mark_pending_retry(
                &event_id,
                Timestamp::zero(),
                "test: trigger scheduled retry now",
            )
            .await
            .unwrap();
        let verifier = IncomingPropagationVerifier::new(store.clone(), transport, application);

        // 5. persisted event now meets the original 2-of-3 requirement
        assert_eq!(verifier.verify_due_once().await.unwrap(), 1);
        assert!(
            store
                .get_due_candidates(Timestamp::now(), 10)
                .await
                .unwrap()
                .is_empty(),
        );
        let verified = store
            .get_verified_candidates(Timestamp::now(), 10)
            .await
            .unwrap();
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].event.id, expected_event_id);

        // 6. it can be applied now
        assert_eq!(verifier.apply_due_once().await.unwrap(), 1);
        assert_eq!(applied.load(Ordering::SeqCst), 1);
        // Neither pending nor verified work remains
        assert!(
            store
                .get_due_candidates(Timestamp::now() + Duration::from_secs(600), 10,)
                .await
                .unwrap()
                .is_empty(),
        );
        assert!(
            store
                .get_verified_candidates(Timestamp::now() + Duration::from_secs(600), 10,)
                .await
                .unwrap()
                .is_empty(),
        );

        // 7. Duplicate delivery cannot reset an applied event
        store
            .upsert_candidate(&candidate, Timestamp::zero())
            .await
            .unwrap();
        assert_eq!(verifier.verify_due_once().await.unwrap(), 0);
        assert_eq!(verifier.apply_due_once().await.unwrap(), 0);
        assert_eq!(applied.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn verified_missing_predecessor_survives_sqlite_restart() {
        // Integration Test with real SQLite
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("incoming-restart.sqlite");
        let encryption = Arc::new(EncryptionContext::new(BcrKeys::new()));
        let db = SqlitePersistence::open(SqliteConfig::new(db_path.clone()))
            .await
            .unwrap();
        let store = Arc::new(db.incoming_propagation_store(encryption.clone()));

        let parent = chain_event("test-chain", None);
        let child = chain_event("test-chain", Some(parent.clone()));
        let parent_id = parent.id;
        let child_id = child.id;
        let parent_candidate = gap_candidate(parent);
        let child_candidate = gap_candidate(child);

        // 2. child arrives before predecessor - both relays have the child, verification succeeds
        let mut transport = MockNotificationJsonTransport::new();
        transport
            .expect_has_connected_read_relay()
            .returning(|| true);
        transport
            .expect_event_available_on_relay()
            .times(2)
            .returning(move |id, _| {
                assert_eq!(id, child_id);
                Ok(true)
            });
        // predecessor is not discoverable through the network gap-repair mechanism
        transport
            .expect_fetch_event_from_relay()
            .returning(|_, _| Ok(None));

        let mut application = MockIncomingChainApplicationApi::new();
        application
            .expect_preferred_verified_branch()
            .returning(|_| Ok(Vec::new()));
        application
            .expect_apply_verified_chain_event()
            .once()
            .returning(move |candidate| {
                assert_eq!(candidate.event.id, child_id);
                Ok(IncomingChainApplyResult::Deferred(
                    IncomingChainDependency::MissingPredecessor,
                ))
            });
        let verifier = IncomingPropagationVerifier::new(
            store.clone(),
            Arc::new(transport),
            Arc::new(application),
        );
        store
            .upsert_candidate(&child_candidate, Timestamp::zero())
            .await
            .unwrap();
        assert_eq!(verifier.verify_due_once().await.unwrap(), 1);
        assert_eq!(verifier.apply_due_once().await.unwrap(), 1);

        // child remains verified, but cannot be applied yet
        assert!(
            store
                .get_verified_candidates(Timestamp::now(), 10)
                .await
                .unwrap()
                .is_empty(),
        );
        let waiting = store
            .get_verified_candidates(Timestamp::now() + Duration::from_secs(120), 10)
            .await
            .unwrap();
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].event.id, child_id);
        assert_eq!(waiting[0].relays, child_candidate.relays);
        assert_eq!(waiting[0].required_relays, 2);

        // 3. predecessor is now discovered and enqueued, but the process stops before verifying it
        store
            .upsert_candidate(&parent_candidate, Timestamp::zero())
            .await
            .unwrap();
        let pending = store
            .get_due_candidates(Timestamp::now(), 10)
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].event.id, parent_id);

        // 4. process shutdown and database reinit
        drop(verifier);
        drop(store);
        db.close().await;
        let reopened = SqlitePersistence::open(SqliteConfig::new(db_path))
            .await
            .unwrap();
        let store = Arc::new(reopened.incoming_propagation_store(encryption));

        // Both states must survive the restart independently
        let pending = store
            .get_due_candidates(Timestamp::now(), 10)
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].event.id, parent_id);
        let waiting = store
            .get_verified_candidates(Timestamp::now() + Duration::from_secs(120), 10)
            .await
            .unwrap();
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].event.id, child_id);
        assert_eq!(waiting[0].relays, child_candidate.relays);
        assert_eq!(waiting[0].required_relays, 2);
        assert!(
            store
                .get_verified_candidates(Timestamp::now(), 10)
                .await
                .unwrap()
                .is_empty(),
            "Restart must preserve the child's deferred retry time",
        );
        // 5. Construct a new transport and application - only the predecessor needs relay verification
        let mut transport = MockNotificationJsonTransport::new();
        transport
            .expect_has_connected_read_relay()
            .returning(|| true);
        transport
            .expect_event_available_on_relay()
            .times(2)
            .returning(move |id, _| {
                assert_eq!(
                    id, parent_id,
                    "Already-verified child must not be verified again",
                );
                Ok(true)
            });
        transport.expect_fetch_event_from_relay().never();
        let applied = Arc::new(StdMutex::new(Vec::new()));
        let applied_for_mock = applied.clone();
        let mut application = MockIncomingChainApplicationApi::new();
        application
            .expect_preferred_verified_branch()
            .returning(|_| Ok(Vec::new()));
        application
            .expect_apply_verified_chain_event()
            .times(2)
            .returning(move |candidate| {
                applied_for_mock.lock().unwrap().push(candidate.event.id);
                Ok(IncomingChainApplyResult::Applied)
            });
        let verifier = IncomingPropagationVerifier::new(
            store.clone(),
            Arc::new(transport),
            Arc::new(application),
        );

        // 6. Verify and apply predecessor
        assert_eq!(verifier.verify_due_once().await.unwrap(), 1);
        assert_eq!(verifier.apply_due_once().await.unwrap(), 1);

        // Applying the predecessor must wake the child immediately
        let awakened = store
            .get_verified_candidates(Timestamp::now(), 10)
            .await
            .unwrap();
        assert_eq!(awakened.len(), 1);
        assert_eq!(awakened[0].event.id, child_id);

        // 7. Apply the verified child
        assert_eq!(verifier.apply_due_once().await.unwrap(), 1);
        assert_eq!(*applied.lock().unwrap(), vec![parent_id, child_id],);

        // No pending work remains
        assert!(
            store
                .get_due_candidates(Timestamp::now() + Duration::from_secs(600), 10,)
                .await
                .unwrap()
                .is_empty(),
        );
        assert!(
            store
                .get_verified_candidates(Timestamp::now() + Duration::from_secs(600), 10,)
                .await
                .unwrap()
                .is_empty(),
        );

        // 8. Duplicate delivery after restart is harmless
        store
            .upsert_candidate(&child_candidate, Timestamp::zero())
            .await
            .unwrap();
        assert_eq!(verifier.verify_due_once().await.unwrap(), 0);
        assert_eq!(verifier.apply_due_once().await.unwrap(), 0);
        assert_eq!(*applied.lock().unwrap(), vec![parent_id, child_id],);
    }

    #[tokio::test]
    async fn partial_restoration_resumes_from_sqlite_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("partial-restore.sqlite");
        let encryption = Arc::new(EncryptionContext::new(BcrKeys::new()));
        let db = SqlitePersistence::open(SqliteConfig::new(db_path.clone()))
            .await
            .unwrap();
        let store = Arc::new(db.incoming_propagation_store(encryption.clone()));

        let chain_id = "restoration-identity";
        let signer = Keys::generate();
        let mut events: Vec<Event> = Vec::new();
        for index in 0..5_u64 {
            let event = create_public_chain_event(
                chain_id,
                EventEnvelope {
                    event_type: EventType::IdentityChain,
                    version: "1.0".into(),
                    data: vec![],
                },
                Timestamp::new(1000 + index).unwrap(),
                BlockchainType::Identity,
                events.last().cloned(),
                events.first().cloned(),
            )
            .unwrap()
            .finalize(&signer)
            .unwrap();
            events.push(event);
        }

        let ids: Vec<_> = events.iter().map(|e| e.id).collect();
        let head_ids = ids[..3].to_vec();
        let fourth_id = ids[3];
        let fifth_id = ids[4];
        let snapshot = RelayQuorumSnapshot {
            relays: vec![
                Url::parse("wss://r1.example").unwrap(),
                Url::parse("wss://r2.example").unwrap(),
                Url::parse("wss://r3.example").unwrap(),
            ],
            required: 2,
        };

        // During restoration, the first 3 events have quorum
        // The 4th has only one confirmation
        // The 5th must not be checked by the synchronous pass
        let mut transport = MockNotificationJsonTransport::new();
        transport
            .expect_event_available_on_relay()
            .times(15)
            .returning(move |id, relay| match relay.host_str() {
                Some("r1.example") => Ok(true),
                Some("r2.example") => Ok(head_ids.contains(&id)),
                Some("r3.example") => Ok(false),
                other => panic!("Unexpected relay: {other:?}"),
            });
        let applied = Arc::new(StdMutex::new(Vec::new()));
        let applied_during_restore = applied.clone();
        let expected_head = ids[..3].to_vec();
        let mut application = MockIncomingChainApplicationApi::new();
        application
            .expect_preferred_verified_branch()
            .returning(|_| Ok(Vec::new()));
        application
            .expect_apply_verified_chain_event()
            .times(3)
            .returning(move |candidate| {
                assert_eq!(candidate.chain_type, "identity");
                assert_eq!(candidate.chain_id, chain_id);
                let mut seen = applied_during_restore.lock().unwrap();
                // The synchronous restore applies a contiguous chain
                assert_eq!(candidate.event.id, expected_head[seen.len()],);
                seen.push(candidate.event.id);
                Ok(IncomingChainApplyResult::Applied)
            });
        let verifier = IncomingPropagationVerifier::new(
            store.clone(),
            Arc::new(transport),
            Arc::new(application),
        );

        // All 5 must be enqueued before the immediate restoration pass attempts quorum verification
        let progress = verifier
            .ingest_verified_chain(
                BlockchainType::Identity,
                chain_id,
                events.clone(),
                snapshot.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            progress,
            VerifiedChainIngestionProgress {
                enqueued: 5,
                applied_prefix: 3,
            },
        );
        assert_eq!(progress.remaining(), 2);
        assert_eq!(*applied.lock().unwrap(), ids[..3].to_vec());

        // 4th and 5th remain durably pending
        let pending = store
            .get_due_candidates(Timestamp::now() + Duration::from_secs(300), 10)
            .await
            .unwrap();
        assert_eq!(pending.len(), 2);
        for candidate in &pending {
            assert!(candidate.event.id == fourth_id || candidate.event.id == fifth_id,);
            assert_eq!(candidate.chain_type, "identity");
            assert_eq!(candidate.chain_id, chain_id);
            assert_eq!(candidate.relays, snapshot.relays);
            assert_eq!(candidate.required_relays, 2);
        }
        assert!(
            store
                .get_verified_candidates(Timestamp::now() + Duration::from_secs(300), 10,)
                .await
                .unwrap()
                .is_empty(),
        );

        // library shutdown and a fresh database pool
        drop(verifier);
        drop(store);
        db.close().await;
        let reopened = SqlitePersistence::open(SqliteConfig::new(db_path))
            .await
            .unwrap();
        let store = Arc::new(reopened.incoming_propagation_store(encryption));

        // unfinished restoration survives reinitialization
        let pending = store
            .get_due_candidates(Timestamp::now() + Duration::from_secs(300), 10)
            .await
            .unwrap();
        assert_eq!(pending.len(), 2);
        assert!(pending.iter().any(|c| c.event.id == fourth_id),);
        assert!(pending.iter().any(|c| c.event.id == fifth_id),);

        // Relay availability has improved after restart Both remaining events now reach 2/3
        let mut transport = MockNotificationJsonTransport::new();
        transport
            .expect_has_connected_read_relay()
            .returning(|| true);
        transport
            .expect_event_available_on_relay()
            .times(6)
            .returning(move |id, relay| {
                assert!(
                    id == fourth_id || id == fifth_id,
                    "Previously applied prefix must not be verified again",
                );
                Ok(matches!(
                    relay.host_str(),
                    Some("r1.example" | "r2.example")
                ))
            });

        // If the 5th event is attempted before the 4th, it's a missing-predecessor
        transport
            .expect_fetch_event_from_relay()
            .returning(|_, _| Ok(None));
        let applied_after_restart = applied.clone();
        let mut application = MockIncomingChainApplicationApi::new();
        application
            .expect_preferred_verified_branch()
            .returning(|_| Ok(Vec::new()));
        application
            .expect_apply_verified_chain_event()
            .returning(move |candidate| {
                let id = candidate.event.id;
                let mut seen = applied_after_restart.lock().unwrap();
                if id == fourth_id {
                    assert_eq!(seen.len(), 3);
                    seen.push(id);
                    return Ok(IncomingChainApplyResult::Applied);
                }
                assert_eq!(id, fifth_id);
                if seen.last().copied() == Some(fourth_id) {
                    seen.push(id);
                    Ok(IncomingChainApplyResult::Applied)
                } else {
                    Ok(IncomingChainApplyResult::Deferred(
                        IncomingChainDependency::MissingPredecessor,
                    ))
                }
            });
        let verifier = IncomingPropagationVerifier::new(
            store.clone(),
            Arc::new(transport),
            Arc::new(application),
        );
        for id in &ids[3..] {
            store
                .mark_pending_retry(
                    &id.to_string(),
                    Timestamp::zero(),
                    "test: make recovery candidate immediately due",
                )
                .await
                .unwrap();
        }
        assert_eq!(verifier.verify_due_once().await.unwrap(), 2);
        // Application is sequential. The 5th event may defer, but application of the 4th wakes it
        for _ in 0..3 {
            verifier.apply_due_once().await.unwrap();
        }
        assert_eq!(*applied.lock().unwrap(), ids);
        assert!(
            store
                .get_due_candidates(Timestamp::now() + Duration::from_secs(600), 10,)
                .await
                .unwrap()
                .is_empty(),
        );
        assert!(
            store
                .get_verified_candidates(Timestamp::now() + Duration::from_secs(600), 10,)
                .await
                .unwrap()
                .is_empty(),
        );
        // Duplicate discovery must not reset applied candidates
        for event in &events {
            verifier
                .enqueue(event.clone(), "identity", chain_id, snapshot.clone())
                .await
                .unwrap();
        }
        assert_eq!(verifier.verify_due_once().await.unwrap(), 0);
        assert_eq!(verifier.apply_due_once().await.unwrap(), 0);
        assert_eq!(*applied.lock().unwrap(), ids);
    }

    #[tokio::test]
    async fn incoming_fork_selection_does_not_fallback_after_failure() {
        let dir = tempfile::tempdir().unwrap();
        let db = SqlitePersistence::open(SqliteConfig::new(
            dir.path().join("fork-application-failure.sqlite"),
        ))
        .await
        .unwrap();
        let store = Arc::new(
            db.incoming_propagation_store(Arc::new(EncryptionContext::new(BcrKeys::new()))),
        );
        let a = gap_candidate(chain_event("test-chain", None));
        let b = gap_candidate(chain_event("test-chain", None));
        let c = gap_candidate(chain_event("test-chain", Some(b.event.clone())));
        let b_id = b.event.id;
        let c_id = c.event.id;
        assert_ne!(a.event.id, b_id);
        for candidate in [&a, &b, &c] {
            store
                .upsert_candidate(candidate, Timestamp::zero())
                .await
                .unwrap();

            store
                .mark_verified(
                    &candidate.event.id.to_string(),
                    Timestamp::zero(),
                    &candidate.relays,
                )
                .await
                .unwrap();
        }
        let mut application = MockIncomingChainApplicationApi::new();
        application
            .expect_preferred_verified_branch()
            .once()
            .returning(move |candidates| {
                assert_eq!(candidates.len(), 3);

                let b = candidates
                    .iter()
                    .position(|candidate| candidate.event.id == b_id)
                    .unwrap();

                let c = candidates
                    .iter()
                    .position(|candidate| candidate.event.id == c_id)
                    .unwrap();

                Ok(vec![b, c])
            });

        // Only B may be attempted. Neither A nor C may be attempted after B's application fails
        application
            .expect_apply_verified_chain_event()
            .once()
            .withf(move |candidate| candidate.event.id == b_id)
            .returning(|_| Err(Error::Network("Temporary application failure".into())));
        let verifier = IncomingPropagationVerifier::new(
            store.clone(),
            Arc::new(MockNotificationJsonTransport::new()),
            Arc::new(application),
        );
        let before_application = Timestamp::now();
        assert_eq!(verifier.apply_due_once().await.unwrap(), 3,);
        let status = store
            .get_chain_queue_status(&a.chain_type, &a.chain_id)
            .await
            .unwrap();
        assert_eq!(status.applied, 0);
        assert_eq!(status.verified, 3);
        assert_eq!(status.conflicting_forks, 0);
        // All three remain retryable, but must not continuously occupy the original due batch
        assert!(
            store
                .get_verified_candidates(before_application, 16,)
                .await
                .unwrap()
                .is_empty(),
        );
    }

    #[tokio::test]
    async fn incoming_fork_selection_considers_candidates_outside_batch() {
        let dir = tempfile::tempdir().unwrap();
        let db = SqlitePersistence::open(SqliteConfig::new(
            dir.path().join("fork-batch-limit.sqlite"),
        ))
        .await
        .unwrap();
        let store = Arc::new(
            db.incoming_propagation_store(Arc::new(EncryptionContext::new(BcrKeys::new()))),
        );
        let mut candidates = Vec::new();
        for index in 0..18 {
            let event = EventBuilder::new(
                nostr::event::Kind::TextNote,
                format!("Fork selection candidate {index}"),
            )
            .finalize(&nostr::key::Keys::generate())
            .unwrap();
            let candidate = gap_candidate(event);
            store
                .upsert_candidate(&candidate, Timestamp::zero())
                .await
                .unwrap();

            // The first 16 candidates sort ahead of B and C
            // All 18 candidates are already due
            let application_at = if index < 16 {
                Timestamp::zero()
            } else {
                Timestamp::new(1).unwrap()
            };
            store
                .mark_verified(
                    &candidate.event.id.to_string(),
                    application_at,
                    &candidate.relays,
                )
                .await
                .unwrap();
            candidates.push(candidate);
        }

        let b_id = candidates[16].event.id;
        let c_id = candidates[17].event.id;
        let before_application = Timestamp::now();
        let due = store
            .get_verified_candidates(before_application, 16)
            .await
            .unwrap();
        assert_eq!(due.len(), 16);
        assert!(
            due.iter()
                .all(|candidate| { candidate.event.id != b_id && candidate.event.id != c_id }),
        );
        let mut application = MockIncomingChainApplicationApi::new();
        application
            .expect_preferred_verified_branch()
            .once()
            .returning(move |all| {
                // Selection must see all 18 verified candidates, not just the 16 returned by the due query
                assert_eq!(all.len(), 18);

                let b = all
                    .iter()
                    .position(|candidate| candidate.event.id == b_id)
                    .unwrap();

                let c = all
                    .iter()
                    .position(|candidate| candidate.event.id == c_id)
                    .unwrap();

                Ok(vec![b, c])
            });

        // The preferred branch is outside this application batch. Nothing from the losing batch may be applied
        application.expect_apply_verified_chain_event().never();
        let verifier = IncomingPropagationVerifier::new(
            store.clone(),
            Arc::new(MockNotificationJsonTransport::new()),
            Arc::new(application),
        );
        assert_eq!(verifier.apply_due_once().await.unwrap(), 16,);

        // Skipping the first batch releases its scheduling slots, allowing the winning branch to appear in the next batch
        let next_due = store
            .get_verified_candidates(before_application, 16)
            .await
            .unwrap();
        assert_eq!(next_due.len(), 2);
        assert!(
            next_due
                .iter()
                .any(|candidate| { candidate.event.id == b_id }),
        );
        assert!(
            next_due
                .iter()
                .any(|candidate| { candidate.event.id == c_id }),
        );
    }

    #[tokio::test]
    async fn unreadable_verified_chain_does_not_starve_other_chains() {
        let dir = tempfile::tempdir().unwrap();
        let db = SqlitePersistence::open(SqliteConfig::new(
            dir.path().join("unreadable-chain.sqlite"),
        ))
        .await
        .unwrap();
        let store = Arc::new(
            db.incoming_propagation_store(Arc::new(EncryptionContext::new(BcrKeys::new()))),
        );
        let other_key_store =
            db.incoming_propagation_store(Arc::new(EncryptionContext::new(BcrKeys::new())));
        let unreadable = gap_candidate(chain_event("test-chain", None));
        let unreadable_id = unreadable.event.id.to_string();

        other_key_store
            .upsert_candidate(&unreadable, Timestamp::zero())
            .await
            .unwrap();
        other_key_store
            .mark_verified(&unreadable_id, Timestamp::zero(), &unreadable.relays)
            .await
            .unwrap();
        // Not due, but still eligible for fork selection
        other_key_store
            .mark_application_deferred(
                &unreadable_id,
                Some(Timestamp::now() + Duration::from_secs(600)),
                ApplicationWaitReason::Transient,
                "Previously unreadable candidate",
            )
            .await
            .unwrap();

        // Fill the entire global due batch with readable candidates belonging to the affected chain
        for _ in 0..16 {
            let candidate = gap_candidate(chain_event("test-chain", None));
            store
                .upsert_candidate(&candidate, Timestamp::zero())
                .await
                .unwrap();
            store
                .mark_verified(
                    &candidate.event.id.to_string(),
                    Timestamp::zero(),
                    &candidate.relays,
                )
                .await
                .unwrap();
        }

        // unrelated healthy chain is behind those 16 rows
        let mut healthy = gap_candidate(chain_event("healthy-chain", None));
        healthy.chain_id = "healthy-chain".into();
        store
            .upsert_candidate(&healthy, Timestamp::zero())
            .await
            .unwrap();
        store
            .mark_verified(
                &healthy.event.id.to_string(),
                Timestamp::new(1).unwrap(),
                &healthy.relays,
            )
            .await
            .unwrap();

        let healthy_id = healthy.event.id;
        let mut application = MockIncomingChainApplicationApi::new();
        // affected chain cannot be safely selected
        application.expect_preferred_verified_branch().never();
        application
            .expect_apply_verified_chain_event()
            .once()
            .withf(move |candidate| candidate.event.id == healthy_id)
            .returning(|_| Ok(IncomingChainApplyResult::Applied));
        let verifier = IncomingPropagationVerifier::new(
            store.clone(),
            Arc::new(MockNotificationJsonTransport::new()),
            Arc::new(application),
        );

        // First batch cannot safely apply the affected chain
        assert!(matches!(
            verifier.apply_due_once().await,
            Err(Error::Persistence(_)),
        ));
        let status = store
            .get_chain_queue_status("bill", "test-chain")
            .await
            .unwrap();
        assert_eq!(status.applied, 0);
        assert_eq!(status.verified, 17);
        assert_eq!(status.rejected, 0);
        assert_eq!(status.transient_application_failures, 17);

        // All 16 blocked candidates have released their scheduling slots
        let due = store
            .get_verified_candidates(Timestamp::now(), 16)
            .await
            .unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].event.id, healthy_id);
        // The next pass can apply the independent chain
        assert_eq!(verifier.apply_due_once().await.unwrap(), 1,);
        let status = store
            .get_chain_queue_status("bill", "healthy-chain")
            .await
            .unwrap();
        assert_eq!(status.applied, 1);
        assert_eq!(status.verified, 0);
    }

    #[test]
    fn incoming_verification_has_one_fast_retry() {
        for (attempts, seconds) in [
            (0, 5),
            (1, 60),
            (2, 120),
            (3, 240),
            (4, 480),
            (5, 600),
            (100, 600),
        ] {
            assert_eq!(
                verification_retry_delay(attempts),
                Duration::from_secs(seconds),
            );
        }
    }
}
