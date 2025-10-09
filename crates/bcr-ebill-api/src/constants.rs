// Validation
pub const MAX_DOCUMENT_FILE_SIZE_BYTES: usize = 1_000_000; // ~1 MB
pub const MAX_PICTURE_FILE_SIZE_BYTES: usize = 20_000; // ~20 KB
pub const MAX_BILL_ATTACHMENTS: usize = 100;
pub const MAX_FILE_NAME_CHARACTERS: usize = 200;
pub const VALID_FILE_MIME_TYPES: [&str; 3] = ["image/jpeg", "image/png", "application/pdf"];

// When subscribing events we subtract this from the last received event time
pub const NOSTR_EVENT_TIME_SLACK: u64 = 3600 * 24 * 7; // 1 week
pub const DEFAULT_INITIAL_SUBSCRIPTION_DELAY_SECONDS: u32 = 1;
pub use bcr_ebill_core::constants::CURRENCY_SAT;
