// Validation
pub const MAX_DOCUMENT_FILE_SIZE_BYTES: usize = 10_000_000; // ~10 MB
pub const MAX_PICTURE_FILE_SIZE_BYTES: usize = 20_000; // ~20 KB
pub const MAX_BILL_ATTACHMENTS: usize = 20;
pub const MAX_FILE_NAME_CHARACTERS: usize = 200;
pub const VALID_FILE_MIME_TYPES: [&str; 3] = ["image/jpeg", "image/png", "application/pdf"];

// When subscribing events we subtract this from the last received event time
pub const NOSTR_EVENT_TIME_SLACK: u64 = 3600 * 24 * 7; // 1 week
pub const DEFAULT_INITIAL_SUBSCRIPTION_DELAY_SECONDS: u32 = 1;
pub const NOSTR_MAX_RELAYS: usize = 200;

/// Delay between individual event publishes during relay sync (milliseconds)
pub const RELAY_SYNC_EVENT_DELAY_MS: u64 = 50;

/// Maximum retry attempts for failed event syncs
pub const RELAY_SYNC_MAX_RETRIES: usize = 10;

/// Number of events to fetch per retry batch
pub const RELAY_SYNC_RETRY_BATCH_SIZE: usize = 100;

/// Gap threshold for detecting removed and re-added relays (seconds)
/// If last_seen_in_config is older than this, consider it a gap and re-sync
pub const RELAY_SYNC_GAP_THRESHOLD_SECONDS: u64 = 86400; // 24 hours
