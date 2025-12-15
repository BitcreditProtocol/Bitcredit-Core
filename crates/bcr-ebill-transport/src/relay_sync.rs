use crate::nostr::NostrClient;
use bcr_ebill_api::{
    constants::{RELAY_SYNC_EVENT_DELAY_MS, RELAY_SYNC_GAP_THRESHOLD_SECONDS},
    service::transport_service::{Error, Result},
};
use bcr_ebill_core::protocol::Timestamp;
use bcr_ebill_persistence::nostr::{NostrStoreApi, SyncStatus};
use log::{debug, info, warn};
use nostr_sdk::{Filter, Kind, PublicKey};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

/// Helper to convert persistence errors to transport errors
fn to_transport_error(e: bcr_ebill_persistence::Error) -> Error {
    Error::Message(format!("Persistence error: {}", e))
}

/// Type of filter for querying events
enum FilterType {
    Pubkey,  // For private messages TO us
    Author,  // For public events FROM us
}

/// Syncs all pending relays by streaming events and publishing to targets
pub async fn sync_pending_relays(
    client: &NostrClient,
    user_relays: &[url::Url],
    nostr_store: &Arc<dyn NostrStoreApi>,
) -> Result<()> {
    // Get all relays that need syncing
    let pending_relays = nostr_store.get_pending_relays().await.map_err(to_transport_error)?;
    
    if pending_relays.is_empty() {
        debug!("No pending relays to sync");
        return Ok(());
    }
    
    info!("Starting sync for {} relays", pending_relays.len());
    
    // Source relays = all user relays EXCEPT pending ones
    let source_relays: Vec<url::Url> = user_relays
        .iter()
        .filter(|r| !pending_relays.contains(r))
        .cloned()
        .collect();
    
    if source_relays.is_empty() {
        warn!("No source relays available to sync from");
        return Ok(());
    }
    
    // Mark all as InProgress
    for relay in &pending_relays {
        nostr_store.update_relay_sync_status(relay, SyncStatus::InProgress).await.map_err(to_transport_error)?;
    }
    
    // Find earliest resume timestamp
    let earliest_timestamp = calculate_earliest_resume_timestamp(nostr_store, &pending_relays).await?;
    
    info!(
        "Syncing from {} source relays to {} target relays, starting from timestamp {}",
        source_relays.len(),
        pending_relays.len(),
        earliest_timestamp.inner()
    );
    
    // Get all identities' public keys
    let all_pubkeys: Vec<PublicKey> = client
        .get_all_node_ids()
        .iter()
        .map(|n| n.npub())
        .collect();
    
    // Sync private messages
    let private_synced = sync_event_type_to_multiple(
        client,
        &pending_relays,
        &source_relays,
        &all_pubkeys,
        vec![Kind::GiftWrap, Kind::EncryptedDirectMessage],
        FilterType::Pubkey,
        earliest_timestamp,
        nostr_store,
        Duration::from_millis(RELAY_SYNC_EVENT_DELAY_MS),
    )
    .await?;
    
    info!("Synced {} private messages", private_synced);
    
    // Sync public chain events
    let public_synced = sync_event_type_to_multiple(
        client,
        &pending_relays,
        &source_relays,
        &all_pubkeys,
        vec![Kind::TextNote],
        FilterType::Author,
        earliest_timestamp,
        nostr_store,
        Duration::from_millis(RELAY_SYNC_EVENT_DELAY_MS),
    )
    .await?;
    
    info!("Synced {} public chain events", public_synced);
    
    // Mark all as Completed
    for relay in &pending_relays {
        nostr_store.update_relay_sync_status(relay, SyncStatus::Completed).await.map_err(to_transport_error)?;
    }
    
    info!("Relay sync completed successfully");
    Ok(())
}

/// Calculate the earliest resume timestamp across all pending relays
async fn calculate_earliest_resume_timestamp(
    nostr_store: &Arc<dyn NostrStoreApi>,
    pending_relays: &[url::Url],
) -> Result<Timestamp> {
    let mut earliest = Timestamp::now();
    
    for relay in pending_relays {
        if let Some(status) = nostr_store.get_relay_sync_status(relay).await.map_err(to_transport_error)? {
            // Check if this relay was removed and re-added (gap detection)
            let gap_threshold = Timestamp::now().inner() - RELAY_SYNC_GAP_THRESHOLD_SECONDS;
            let has_gap = status.last_seen_in_config.inner() < gap_threshold;
            
            if let Some(last_synced) = status.last_synced_timestamp {
                if !has_gap && last_synced < earliest {
                    earliest = last_synced;
                }
            } else {
                // No previous sync, start from beginning
                earliest = Timestamp::zero();
                break;
            }
        } else {
            // No status record, start from beginning
            earliest = Timestamp::zero();
            break;
        }
    }
    
    Ok(earliest)
}

/// Sync a specific event type to multiple target relays
async fn sync_event_type_to_multiple(
    client: &NostrClient,
    target_relays: &[url::Url],
    source_relays: &[url::Url],
    pubkeys: &[PublicKey],
    kinds: Vec<Kind>,
    filter_type: FilterType,
    since: Timestamp,
    nostr_store: &Arc<dyn NostrStoreApi>,
    delay: Duration,
) -> Result<usize> {
    let filter = match filter_type {
        FilterType::Pubkey => Filter::new().pubkeys(pubkeys.to_vec()),
        FilterType::Author => Filter::new().authors(pubkeys.to_vec()),
    }
    .kinds(kinds)
    .since(since.into());
    
    // Fetch events from source relays (batch instead of streaming)
    let events = client
        .fetch_events(filter, None, Some(source_relays.to_vec()))
        .await?;
    
    let mut total_synced = 0;
    
    for event in events {
        // Publish to all target relays in parallel
        let mut tasks = Vec::new();
        
        for target_relay in target_relays {
            // Check if this relay should skip this event
            if should_skip_event(nostr_store, target_relay, &event).await? {
                continue;
            }
            
            let client_clone = client.clone();
            let target = target_relay.clone();
            let evt = event.clone();
            let store = nostr_store.clone();
            
            let task = tokio::spawn(async move {
                match client_clone.send_event_to(vec![target.clone()], &evt).await {
                    Ok(_) => {
                        // Update progress
                        if let Err(e) = store
                            .update_relay_sync_progress(&target, evt.created_at.into())
                            .await
                        {
                            warn!("Failed to update sync progress for {}: {}", target, e);
                        }
                        Ok(())
                    }
                    Err(e) => {
                        warn!("Failed to sync event {} to {}: {}", evt.id, target, e);
                        // Add to retry queue
                        if let Err(e) = store.add_failed_relay_sync(&target, evt.clone()).await {
                            warn!("Failed to add to retry queue: {}", e);
                        }
                        Err(e)
                    }
                }
            });
            
            tasks.push(task);
        }
        
        // Wait for all publishes
        for task in tasks {
            if task.await.is_ok() {
                total_synced += 1;
            }
        }
        
        // Rate limiting
        sleep(delay).await;
    }
    
    Ok(total_synced)
}

/// Check if an event should be skipped (already synced)
async fn should_skip_event(
    nostr_store: &Arc<dyn NostrStoreApi>,
    relay: &url::Url,
    event: &nostr_sdk::Event,
) -> Result<bool> {
    if let Some(status) = nostr_store.get_relay_sync_status(relay).await.map_err(to_transport_error)? {
        if let Some(last_ts) = status.last_synced_timestamp {
            let event_ts: Timestamp = event.created_at.into();
            return Ok(event_ts <= last_ts);
        }
    }
    Ok(false)
}
