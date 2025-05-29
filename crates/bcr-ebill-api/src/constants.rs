// Validation
pub const MAX_FILE_SIZE_BYTES: usize = 1_000_000; // ~1 MB
pub const MAX_FILE_NAME_CHARACTERS: usize = 200;
pub const VALID_FILE_MIME_TYPES: [&str; 3] = ["image/jpeg", "image/png", "application/pdf"];

// When subscribing events we subtract this from the last received event time
pub const NOSTR_EVENT_TIME_SLACK: u64 = 3600; // 1 hour
pub const CURRENCY_CRSAT: &str = "crsat";
pub const CURRENCY_SAT: &str = "sat";
