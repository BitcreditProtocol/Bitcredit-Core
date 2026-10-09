use crate::ffi::{InstanceRuntimeState, context::Context};
use bcr_common::core::NodeId;
use bcr_ebill_api::constants::DEFAULT_INITIAL_SUBSCRIPTION_DELAY_SECONDS;
use bcr_ebill_core::protocol::Timestamp;
use flutter_rust_bridge::JoinHandle;
use log::{debug, info, warn};
use std::{sync::Arc, time::Duration};
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
    flutter_rust_bridge::spawn(async move {
        let initial_delay =
            nostr_initial_delay_secs.unwrap_or(DEFAULT_INITIAL_SUBSCRIPTION_DELAY_SECONDS) as u64;
        info!("Waiting {initial_delay} seconds to start nostr consumer.");
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancel.cancelled() => {
                info!("Nostr consumer cancelled before startup");
                return;
            }
        }

        let reconnect_interval_seconds = job_interval_secs.max(1);
        state.set_transport_connected(false);

        loop {
            if cancel.is_cancelled() {
                break;
            }

            info!("Connecting to Nostr transport..");
            // before subscription we ensure if we have a connection to the transports
            ctx.transport_service.connect().await;
            ensure_transport_contact_data_published(
                ctx.clone(),
                state.clone(),
                &default_mint_node_id,
            )
            .await;

            let mut handle = tokio::select! {
                _ = cancel.cancelled() => {
                    info!("Nostr consumer cancelled");
                    break;
                }

                result = ctx.nostr_consumer.start() => match result {
                    Ok(handle) => {
                        state.set_transport_connected(true);
                        info!("Nostr transport connected");
                        handle
                    },
                    Err(e) => {
                        warn!("Could not start Nostr consumer: {e}");

                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = tokio::time::sleep(Duration::from_secs(reconnect_interval_seconds)) => {}
                        }

                        continue;
                    }
                },
            };

            // wait for nostr consumer to fail and restart, or cancel the whole process
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("Nostr consumer cancelled");
                    handle.abort_all();
                    state.set_transport_connected(false);
                    break;
                }

                _ = async {
                    while let Some(result) = handle.join_next().await {
                        match result {
                            Ok(()) => {
                                info!("Nostr consumer task shutdown with success");
                            }
                            Err(e) if e.is_cancelled() => {
                                info!("Nostr consumer task was cancelled");
                            }
                            Err(e) => {
                                warn!("Nostr consumer task shutdown with error: {e}");
                            }
                        }
                    }
                } => {
                    state.set_transport_connected(false);
                    warn!("Nostr consumer stopped, reconnecting in {reconnect_interval_seconds} seconds...");
                }
            }

            // reconnect or cancel
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("Nostr reconnect cancelled");
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
    // Check if we've already done a publish check recently
    let now = Timestamp::now().inner();
    let last = state.get_last_contact_publish_check();
    let should_skip = if now.saturating_sub(last) < CONTACT_PUBLISH_CHECK_INTERVAL_SEC {
        debug!("Skipping contact data publish check - last check was recent");
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
        warn!("Could not publish identity details to Nostr: {e}")
    }

    if let Ok(companies) = ctx.company_service.get_list_of_companies().await {
        for c in companies.iter() {
            if let Ok((company, keys)) = ctx.company_service.get_company_and_keys_by_id(&c.id).await
                && let Err(e) = ctx.company_service.publish_contact(&company, &keys).await
            {
                warn!("Could not publish company details to Nostr: {e}")
            }
        }
    }

    ctx.transport_service
        .contact_transport()
        .ensure_nostr_contact(default_mint_node_id)
        .await;
}
