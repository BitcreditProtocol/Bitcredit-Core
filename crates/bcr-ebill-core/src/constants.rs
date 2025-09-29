pub const PAYMENT_DEADLINE_SECONDS: u64 = 86400 * 2; // 2 days
pub const ACCEPT_DEADLINE_SECONDS: u64 = 86400 * 2; // 2 days
pub const RECOURSE_DEADLINE_SECONDS: u64 = 86400 * 2; // 2 days

pub const CURRENCY_SAT: &str = "sat";
pub const VALID_CURRENCIES: [&str; 1] = [CURRENCY_SAT];

// the chain prefix we use when tagging our events on Nostr
pub const BCR_NOSTR_CHAIN_PREFIX: &str = "bitcredit";
