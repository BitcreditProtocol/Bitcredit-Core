use std::{cell::RefCell, future::Future, pin::Pin, time::Duration};

use bcr_ebill_core::protocol::Timestamp;
use log::{error, info, warn};

use crate::context::get_ctx;

const BILL_PAYMENT_CHECK_INTERVAL_SECS: u64 = 60;
const BILL_TIMEOUT_CHECK_INTERVAL_SECS: u64 = 60;
const NOSTR_MESSAGE_QUEUE_INTERVAL_SECS: u64 = 60;
const RELAY_RETRY_SYNC_INTERVAL_SECS: u64 = 120;
const MINT_STATE_CHECK_INTERVAL_SECS: u64 = 300;
const RELAY_SYNC_INTERVAL_SECS: u64 = 300;

#[derive(Clone, Copy)]
struct JobState {
    last_started_at: Option<Duration>,
    is_running: bool,
}

impl JobState {
    const fn new() -> Self {
        Self {
            last_started_at: None,
            is_running: false,
        }
    }
}

type JobFuture = Pin<Box<dyn Future<Output = bool> + 'static>>;

thread_local! {
    static CHECK_MINT_STATE_JOB: RefCell<JobState> = const { RefCell::new(JobState::new()) };
    static CHECK_BILL_PAYMENT_JOB: RefCell<JobState> = const { RefCell::new(JobState::new()) };
    static CHECK_BILL_OFFER_TO_SELL_PAYMENT_JOB: RefCell<JobState> = const { RefCell::new(JobState::new()) };
    static CHECK_BILL_RECOURSE_PAYMENT_JOB: RefCell<JobState> = const { RefCell::new(JobState::new()) };
    static PROCESS_NOSTR_MESSAGE_QUEUE_JOB: RefCell<JobState> = const { RefCell::new(JobState::new()) };
    static RELAY_SYNC_JOB: RefCell<JobState> = const { RefCell::new(JobState::new()) };
    static RELAY_RETRY_SYNC_JOB: RefCell<JobState> = const { RefCell::new(JobState::new()) };
    static CHECK_BILL_TIMEOUTS_JOB: RefCell<JobState> = const { RefCell::new(JobState::new()) };
}

pub fn run_jobs() {
    let now = Duration::from_secs(Timestamp::now().inner());

    spawn_job_if_due(
        &CHECK_MINT_STATE_JOB,
        "Check Mint State Job",
        MINT_STATE_CHECK_INTERVAL_SECS,
        now,
        || Box::pin(run_check_mint_state_job()),
    );
    spawn_job_if_due(
        &CHECK_BILL_PAYMENT_JOB,
        "Check Bill Payment Job",
        BILL_PAYMENT_CHECK_INTERVAL_SECS,
        now,
        || Box::pin(run_check_bill_payment_job()),
    );
    spawn_job_if_due(
        &CHECK_BILL_OFFER_TO_SELL_PAYMENT_JOB,
        "Check Bill Offer To Sell Payment Job",
        BILL_PAYMENT_CHECK_INTERVAL_SECS,
        now,
        || Box::pin(run_check_bill_offer_to_sell_payment_job()),
    );
    spawn_job_if_due(
        &CHECK_BILL_RECOURSE_PAYMENT_JOB,
        "Check Bill Recourse Payment Job",
        BILL_PAYMENT_CHECK_INTERVAL_SECS,
        now,
        || Box::pin(run_check_bill_recourse_payment_job()),
    );
    spawn_job_if_due(
        &PROCESS_NOSTR_MESSAGE_QUEUE_JOB,
        "Process Nostr Message Queue Job",
        NOSTR_MESSAGE_QUEUE_INTERVAL_SECS,
        now,
        || Box::pin(run_process_nostr_message_queue_job()),
    );
    spawn_job_if_due(
        &RELAY_SYNC_JOB,
        "Relay Sync Job",
        RELAY_SYNC_INTERVAL_SECS,
        now,
        || Box::pin(run_relay_sync_job()),
    );
    spawn_job_if_due(
        &RELAY_RETRY_SYNC_JOB,
        "Relay Retry Sync Job",
        RELAY_RETRY_SYNC_INTERVAL_SECS,
        now,
        || Box::pin(run_relay_retry_sync_job()),
    );
    spawn_job_if_due(
        &CHECK_BILL_TIMEOUTS_JOB,
        "Check Bill Timeouts Job",
        BILL_TIMEOUT_CHECK_INTERVAL_SECS,
        now,
        || Box::pin(run_check_bill_timeouts()),
    );
}

fn spawn_job_if_due(
    state: &'static std::thread::LocalKey<RefCell<JobState>>,
    job_name: &'static str,
    interval_secs: u64,
    now: Duration,
    run: impl FnOnce() -> JobFuture + 'static,
) {
    let should_run = state.with(|state| {
        let mut state = state.borrow_mut();

        if state.is_running {
            warn!("Skipping {job_name} because the previous run is still active");
            return false;
        }

        if let Some(last_started_at) = state.last_started_at
            && now.saturating_sub(last_started_at) < Duration::from_secs(interval_secs)
        {
            return false;
        }

        state.last_started_at = Some(now);
        state.is_running = true;
        true
    });

    if !should_run {
        return;
    }

    wasm_bindgen_futures::spawn_local(async move {
        info!("Running {job_name}");
        let did_run = run().await;
        if did_run {
            info!("Finished running {job_name}");
        }

        state.with(|state| {
            state.borrow_mut().is_running = false;
        });
    });
}

async fn run_check_mint_state_job() -> bool {
    if let Err(e) = get_ctx()
        .bill_service
        .check_mint_state_for_all_bills()
        .await
    {
        error!("Error while running Check Mint State Job: {e}");
    }
    true
}

async fn run_check_bill_payment_job() -> bool {
    if let Err(e) = get_ctx().bill_service.check_bills_payment().await {
        error!("Error while running Check Bill Payment Job: {e}");
    }
    true
}

async fn run_check_bill_offer_to_sell_payment_job() -> bool {
    if let Err(e) = get_ctx()
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
        .bill_service
        .check_bills_timeouts(current_time)
        .await
    {
        error!("Error while running Check Bill Timeouts Job: {e}");
    }
    true
}

async fn run_process_nostr_message_queue_job() -> bool {
    if let Err(e) = get_ctx().transport_service.send_retry_messages().await {
        error!("Error while running process Nostr message queue Job: {e}");
    }
    true
}

async fn run_relay_sync_job() -> bool {
    if let Err(e) = get_ctx().transport_service.sync_relays().await {
        error!("Error while running Relay Sync Job: {e}");
    }
    true
}

async fn run_relay_retry_sync_job() -> bool {
    if let Err(e) = get_ctx().transport_service.retry_failed_syncs().await {
        error!("Error while running Relay Retry Sync Job: {e}");
    }
    true
}
