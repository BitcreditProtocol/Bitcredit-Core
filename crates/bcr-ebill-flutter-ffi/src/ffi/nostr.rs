use crate::ffi::{InstanceRuntimeState, context::Context};
use bcr_common::core::NodeId;
use bcr_ebill_api::constants::DEFAULT_INITIAL_SUBSCRIPTION_DELAY_SECONDS;
use bcr_ebill_core::protocol::Timestamp;
use flutter_rust_bridge::JoinHandle;
use log::{debug, info, warn};
use std::{sync::Arc, time::Duration};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// Minimum time between contact data publish checks to avoid excessive network calls
/// in flaky network conditions. Set to 5 minutes.
const CONTACT_PUBLISH_CHECK_INTERVAL_SEC: u64 = 3600;

pub(super) fn start_subscription(
    ctx: Arc<Context>,
    state: Arc<InstanceRuntimeState>,
    default_mint_node_id: NodeId,
    job_interval_secs: u64,
    nostr_initial_delay_secs: Option<u32>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    let network = ctx.cfg.bitcoin_network.clone();
    flutter_rust_bridge::spawn(async move {
        let initial_delay =
            nostr_initial_delay_secs.unwrap_or(DEFAULT_INITIAL_SUBSCRIPTION_DELAY_SECONDS) as u64;
        info!("[{network}] Waiting {initial_delay} seconds to start nostr consumer.");
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancel.cancelled() => {
                info!("[{network}] Nostr consumer cancelled before startup");
                return;
            }
        }

        let reconnect_interval_seconds = job_interval_secs.max(1);
        state.set_transport_connected(false);

        loop {
            if cancel.is_cancelled() {
                break;
            }

            // before subscription we ensure if we have a connection to the transports
            info!("[{network}] Connecting to Nostr transport..");
            // connect, unless shutdown is requested
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("[{network}] Nostr connection cancelled");
                    break;
                }
                _ = ctx.transport_service.connect() => {}
            }

            // publish contacts, unless shutdown is requested
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("[{network}] Contact publish cancelled");
                    break;
                }
                _ = ensure_transport_contact_data_published(
                    ctx.clone(),
                    state.clone(),
                    &default_mint_node_id,
                ) => {}
            }

            let mut handle = tokio::select! {
                _ = cancel.cancelled() => {
                    info!("[{network}] Nostr consumer cancelled");
                    break;
                }

                result = ctx.nostr_consumer.start() => match result {
                    Ok(handle) => {
                        state.set_transport_connected(true);
                        info!("[{network}] Nostr transport connected");
                        handle
                    },
                    Err(e) => {
                        warn!("[{network}] Could not start Nostr consumer: {e}");

                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = tokio::time::sleep(Duration::from_secs(reconnect_interval_seconds)) => {}
                        }

                        continue;
                    }
                },
            };

            let cancelled = supervise_consumer_tasks(&mut handle, &cancel, &network).await;
            state.set_transport_connected(false);
            if cancelled {
                break;
            }
            warn!(
                "[{network}] Nostr consumer stopped, reconnecting in {reconnect_interval_seconds} seconds..."
            );

            // reconnect or cancel
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("[{network}] Nostr reconnect cancelled");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(reconnect_interval_seconds)) => {}
            }
        }
        state.set_transport_connected(false);
    })
}

/// Ensures contact data is published to Nostr, with rate limiting to avoid excessive
/// network calls during flaky network conditions.
async fn ensure_transport_contact_data_published(
    ctx: Arc<Context>,
    state: Arc<InstanceRuntimeState>,
    default_mint_node_id: &NodeId,
) {
    let network = ctx.cfg.bitcoin_network.clone();
    // Check if we've already done a publish check recently
    let now = Timestamp::now().inner();
    let last = state.get_last_contact_publish_check();
    let should_skip = if now.saturating_sub(last) < CONTACT_PUBLISH_CHECK_INTERVAL_SEC {
        debug!("[{network}] Skipping contact data publish check - last check was recent");
        true
    } else {
        state.set_last_contact_publish_check(now);
        false
    };

    if should_skip {
        return;
    }

    if let Ok(full_identity) = ctx.identity_service.get_full_identity().await
        && let Err(e) = ctx
            .identity_service
            .publish_contact(&full_identity.identity, &full_identity.key_pair)
            .await
    {
        warn!("[{network}] Could not publish identity details to Nostr: {e}")
    }

    if let Ok(companies) = ctx.company_service.get_list_of_companies().await {
        for c in companies.iter() {
            if let Ok((company, keys)) = ctx.company_service.get_company_and_keys_by_id(&c.id).await
                && let Err(e) = ctx.company_service.publish_contact(&company, &keys).await
            {
                warn!("[{network}] Could not publish company details to Nostr: {e}")
            }
        }
    }

    ctx.transport_service
        .contact_transport()
        .ensure_nostr_contact(default_mint_node_id)
        .await;
}

/// All consumer tasks form one supervised group
/// An unexpected exit of any member requires restarting
/// the entire group. Never start a replacement group
/// while tasks from the previous group are still active.
async fn supervise_consumer_tasks(
    tasks: &mut JoinSet<()>,
    cancel: &CancellationToken,
    network: &str,
) -> bool {
    let cancelled = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            info!("[{network}] Nostr consumer cancelled");
            true
        }
        result = tasks.join_next() => {
            match result {
                Some(Ok(())) => {
                    warn!(
                        "[{network}] Nostr consumer task exited unexpectedly"
                    );
                }
                Some(Err(e)) => {
                    warn!(
                        "[{network}] Nostr consumer task failed: {e}"
                    );
                }
                None => {
                    warn!(
                        "[{network}] No Nostr consumer tasks remain"
                    );
                }
            }
            false
        }
    };
    // Abort and join every remaining task before returning
    tasks.shutdown().await;
    info!("[{network}] Nostr consumer shutdown completed");
    cancelled || cancel.is_cancelled()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn consumer_restarts_when_one_task_exits() {
        let cancel = CancellationToken::new();
        let mut tasks = JoinSet::new();
        // One task exits while another would run forever
        tasks.spawn(async {});
        tasks.spawn(std::future::pending::<()>());
        let cancelled = tokio::time::timeout(
            Duration::from_secs(2),
            supervise_consumer_tasks(&mut tasks, &cancel, "testnet"),
        )
        .await
        .expect("Supervisor waited for every task to exit");
        assert!(!cancelled);
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn consumer_cancellation_joins_all_tasks() {
        let cancel = CancellationToken::new();
        let mut tasks = JoinSet::new();
        for _ in 0..4 {
            tasks.spawn(std::future::pending::<()>());
        }
        cancel.cancel();
        let cancelled = supervise_consumer_tasks(&mut tasks, &cancel, "testnet").await;
        assert!(cancelled);
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn consumer_restarts_after_worker_panic() {
        let cancel = CancellationToken::new();
        let mut tasks = JoinSet::new();
        tasks.spawn(async {
            panic!("Simulated worker failure");
        });
        tasks.spawn(std::future::pending::<()>());
        let cancelled = tokio::time::timeout(
            Duration::from_secs(2),
            supervise_consumer_tasks(&mut tasks, &cancel, "testnet"),
        )
        .await
        .unwrap();
        assert!(!cancelled);
        assert!(tasks.is_empty());
    }
}
