use crate::ffi::context::get_ctx;
use bcr_ebill_core::protocol::Timestamp;
use log::{error, info, warn};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{task::JoinHandle, time::Instant};
use tokio_util::sync::CancellationToken;

const BILL_PAYMENT_CHECK_INTERVAL_SECS: u64 = 60;
const BILL_TIMEOUT_CHECK_INTERVAL_SECS: u64 = 60;
const NOSTR_MESSAGE_QUEUE_INTERVAL_SECS: u64 = 60;
const RELAY_RETRY_SYNC_INTERVAL_SECS: u64 = 120;
const MINT_STATE_CHECK_INTERVAL_SECS: u64 = 300;
const RELAY_SYNC_INTERVAL_SECS: u64 = 300;

type JobFuture = Pin<Box<dyn Future<Output = bool> + Send + 'static>>;
type JobFn = fn() -> JobFuture;

struct Job {
    name: &'static str,
    interval: Duration,
    last_started_at: Option<Instant>,
    is_running: Arc<AtomicBool>,
    run: JobFn,
}

impl Job {
    fn new(name: &'static str, interval_secs: u64, run: JobFn) -> Self {
        Self {
            name,
            interval: Duration::from_secs(interval_secs),
            last_started_at: None,
            is_running: Arc::new(AtomicBool::new(false)),
            run,
        }
    }

    fn try_spawn(&mut self, now: Instant) {
        if self.is_running.load(Ordering::Acquire) {
            warn!(
                "Skipping {} because the previous run is still active",
                self.name
            );
            return;
        }

        if let Some(last_started_at) = self.last_started_at
            && now.duration_since(last_started_at) < self.interval
        {
            return;
        }

        self.is_running.store(true, Ordering::Release);
        self.last_started_at = Some(now);

        let name = self.name;
        let run = self.run;
        let is_running = Arc::clone(&self.is_running);

        flutter_rust_bridge::spawn(async move {
            info!("Running {name}");

            let did_run = run().await;

            if did_run {
                info!("Finished running {name}");
            }

            is_running.store(false, Ordering::Release);
        });
    }
}

pub fn start_jobs(
    job_interval_secs: u64,
    job_initial_delay_secs: u64,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    let scheduler_interval_secs = job_interval_secs.max(1);

    flutter_rust_bridge::spawn(async move {
        info!(
            "Waiting {job_initial_delay_secs} seconds to run jobs for the first time. Afterwards, the job scheduler will check for due jobs every {scheduler_interval_secs} seconds."
        );

        tokio::select! {
            _ = tokio::time::sleep(
                Duration::from_secs(job_initial_delay_secs)
            ) => {}

            _ = cancel.cancelled() => {
                info!("Job runner cancelled before startup");
                return;
            }
        }

        // Before the first run, ensure we have a connection to the
        // transports, since some jobs depend on it.
        get_ctx().await.transport_service.connect().await;

        let mut jobs = create_jobs();

        let mut ticker = tokio::time::interval(Duration::from_secs(scheduler_interval_secs));
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("Stopping job runner");
                    break;
                }

                now = ticker.tick() => {
                    for job in &mut jobs {
                        job.try_spawn(now);
                    }
                }
            }
        }

        info!("Job runner stopped");
    })
}

fn create_jobs() -> Vec<Job> {
    vec![
        Job::new(
            "Check Mint State Job",
            MINT_STATE_CHECK_INTERVAL_SECS,
            || Box::pin(run_check_mint_state_job()),
        ),
        Job::new(
            "Check Bill Payment Job",
            BILL_PAYMENT_CHECK_INTERVAL_SECS,
            || Box::pin(run_check_bill_payment_job()),
        ),
        Job::new(
            "Check Bill Offer To Sell Payment Job",
            BILL_PAYMENT_CHECK_INTERVAL_SECS,
            || Box::pin(run_check_bill_offer_to_sell_payment_job()),
        ),
        Job::new(
            "Check Bill Recourse Payment Job",
            BILL_PAYMENT_CHECK_INTERVAL_SECS,
            || Box::pin(run_check_bill_recourse_payment_job()),
        ),
        Job::new(
            "Process Nostr Message Queue Job",
            NOSTR_MESSAGE_QUEUE_INTERVAL_SECS,
            || Box::pin(run_process_nostr_message_queue_job()),
        ),
        Job::new("Relay Sync Job", RELAY_SYNC_INTERVAL_SECS, || {
            Box::pin(run_relay_sync_job())
        }),
        Job::new(
            "Relay Retry Sync Job",
            RELAY_RETRY_SYNC_INTERVAL_SECS,
            || Box::pin(run_relay_retry_sync_job()),
        ),
        Job::new(
            "Check Bill Timeouts Job",
            BILL_TIMEOUT_CHECK_INTERVAL_SECS,
            || Box::pin(run_check_bill_timeouts()),
        ),
    ]
}

async fn run_check_mint_state_job() -> bool {
    if let Err(e) = get_ctx()
        .await
        .bill_service
        .check_mint_state_for_all_bills()
        .await
    {
        error!("Error while running Check Mint State Job: {e}");
    }

    true
}

async fn run_check_bill_payment_job() -> bool {
    if let Err(e) = get_ctx().await.bill_service.check_bills_payment().await {
        error!("Error while running Check Bill Payment Job: {e}");
    }

    true
}

async fn run_check_bill_offer_to_sell_payment_job() -> bool {
    if let Err(e) = get_ctx()
        .await
        .bill_service
        .check_bills_offer_to_sell_payment()
        .await
    {
        error!("Error while running Check Bill Offer to Sell Payment Job: {e}");
    }

    true
}

async fn run_check_bill_recourse_payment_job() -> bool {
    if let Err(e) = get_ctx()
        .await
        .bill_service
        .check_bills_in_recourse_payment()
        .await
    {
        error!("Error while running Check Bill Recourse Payment Job: {e}");
    }

    true
}

async fn run_check_bill_timeouts() -> bool {
    let current_time = Timestamp::now();

    if let Err(e) = get_ctx()
        .await
        .bill_service
        .check_bills_timeouts(current_time)
        .await
    {
        error!("Error while running Check Bill Timeouts Job: {e}");
    }

    true
}

async fn run_process_nostr_message_queue_job() -> bool {
    if let Err(e) = get_ctx()
        .await
        .transport_service
        .send_retry_messages()
        .await
    {
        error!("Error while running Process Nostr Message Queue Job: {e}");
    }

    true
}

async fn run_relay_sync_job() -> bool {
    if let Err(e) = get_ctx().await.transport_service.sync_relays().await {
        error!("Error while running Relay Sync Job: {e}");
    }

    true
}

async fn run_relay_retry_sync_job() -> bool {
    if let Err(e) = get_ctx().await.transport_service.retry_failed_syncs().await {
        error!("Error while running Relay Retry Sync Job: {e}");
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_job() -> JobFuture {
        Box::pin(async { true })
    }

    #[test]
    fn job_is_due_before_first_run() {
        let job = Job::new("Test Job", 60, test_job);

        assert!(job.last_started_at.is_none());
        assert!(!job.is_running.load(Ordering::Acquire));
    }

    #[test]
    fn job_interval_not_elapsed() {
        let now = Instant::now();

        let job = Job {
            name: "Test Job",
            interval: Duration::from_secs(60),
            last_started_at: Some(now - Duration::from_secs(50)),
            is_running: Arc::new(AtomicBool::new(false)),
            run: test_job,
        };

        let due = job
            .last_started_at
            .map(|last_started_at| now.duration_since(last_started_at) >= job.interval)
            .unwrap_or(true);

        assert!(!due);
    }

    #[test]
    fn job_interval_elapsed() {
        let now = Instant::now();

        let job = Job {
            name: "Test Job",
            interval: Duration::from_secs(60),
            last_started_at: Some(now - Duration::from_secs(60)),
            is_running: Arc::new(AtomicBool::new(false)),
            run: test_job,
        };

        let due = job
            .last_started_at
            .map(|last_started_at| now.duration_since(last_started_at) >= job.interval)
            .unwrap_or(true);

        assert!(due);
    }

    #[test]
    fn running_job_is_not_available() {
        let job = Job {
            name: "Test Job",
            interval: Duration::from_secs(60),
            last_started_at: None,
            is_running: Arc::new(AtomicBool::new(true)),
            run: test_job,
        };

        assert!(job.is_running.load(Ordering::Acquire));
    }
}
