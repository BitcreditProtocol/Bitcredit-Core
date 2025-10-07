pub const DAY_IN_SECS: u64 = 86400;
pub const PAYMENT_DEADLINE_SECONDS: u64 = DAY_IN_SECS * 2; // 48 hours
pub const ACCEPT_DEADLINE_SECONDS: u64 = DAY_IN_SECS * 2; // 48 hours
pub const RECOURSE_DEADLINE_SECONDS: u64 = DAY_IN_SECS * 2; // 48 hours

pub const CURRENCY_SAT: &str = "sat";
pub const VALID_CURRENCIES: [&str; 1] = [CURRENCY_SAT];

// the chain prefix we use when tagging our events on Nostr
pub const BCR_NOSTR_CHAIN_PREFIX: &str = "bitcredit";
