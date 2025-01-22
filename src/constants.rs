use std::net::Ipv4Addr;

// General
pub const BILLS_PREFIX: &str = "BILLS";
pub const BILL_PREFIX: &str = "BILL";
pub const BILL_ATTACHMENT_PREFIX: &str = "BILLATT";
pub const KEY_PREFIX: &str = "KEY";
pub const COMPANIES_PREFIX: &str = "COMPANIES";
pub const COMPANY_PREFIX: &str = "COMPANY";
pub const COMPANY_KEY_PREFIX: &str = "COMPANYKEY";
pub const COMPANY_CHAIN_PREFIX: &str = "COMPANYCHAIN";
pub const COMPANY_LOGO_PREFIX: &str = "COMPANYLOGO";
pub const COMPANY_PROOF_PREFIX: &str = "COMPANYPROOF";
pub const SHUTDOWN_GRACE_PERIOD_MS: u64 = 1500;
pub const DEFAULT_DATE_TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S";
pub const DEFAULT_DATE_FORMAT: &str = "%Y-%m-%d";
pub const PAYMENT_DEADLINE_SECONDS: u64 = 86400 * 2; // 2 days

// Validation
pub const MAX_FILE_SIZE_BYTES: usize = 1_000_000; // ~1 MB
pub const MAX_FILE_NAME_CHARACTERS: usize = 50;
pub const VALID_FILE_MIME_TYPES: [&str; 3] = ["image/jpeg", "image/png", "application/pdf"];

// Paths
pub const QUOTES_MAP_FOLDER_PATH: &str = "quotes";
pub const BOOTSTRAP_FOLDER_PATH: &str = "bootstrap";
pub const QUOTE_MAP_FILE_PATH: &str = "quotes/quotes";
pub const BOOTSTRAP_NODES_FILE_PATH: &str = "bootstrap/bootstrap_nodes.json";

// Relay
pub const RELAY_BOOTSTRAP_NODE_ONE_IP: Ipv4Addr = Ipv4Addr::new(45, 147, 248, 87);
pub const RELAY_BOOTSTRAP_NODE_ONE_TCP: u16 = 1908;
pub const RELAY_BOOTSTRAP_NODE_ONE_PEER_ID: &str =
    "12D3KooWL5y2jyVFtk541g9ySSoKGjNf61GEPG1XbPhop5MRfyA8";

// DB constants
pub const DB_TABLE: &str = "table";

pub const DB_BLOCK_ID: &str = "block_id";
pub const DB_HASH: &str = "hash";
pub const DB_PREVIOUS_HASH: &str = "previous_hash";
pub const DB_SIGNATURE: &str = "signature";
pub const DB_TIMESTAMP: &str = "timestamp";
pub const DB_PUBLIC_KEY: &str = "public_key";
pub const DB_SIGNATORY_NODE_ID: &str = "signatory_node_id";
pub const DB_DATA: &str = "data";
pub const DB_OP_CODE: &str = "op_code";

pub const DB_COMPANY_ID: &str = "company_id";
pub const DB_BILL_ID: &str = "bill_id";
