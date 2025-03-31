// DB constants
pub const DB_TABLE: &str = "table";
pub const DB_IDS: &str = "ids";
pub const DB_LIMIT: &str = "limit";
pub const DB_NOTIFICATION_TYPE: &str = "notification_type";
pub const DB_ACTIVE: &str = "active";

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
pub const DB_SEARCH_TERM: &str = "search_term";

pub const DB_ENTITY_ID: &str = "entity_id";
pub const DB_FILE_NAME: &str = "file_name";
pub const DB_FILE_UPLOAD_ID: &str = "file_upload_id";

#[cfg(target_arch = "wasm32")]
pub const SURREAL_DB_CON_INDXDB_DATA: &str = "indxdb://data";
#[cfg(target_arch = "wasm32")]
pub const SURREAL_DB_INDXDB_DB_DATA: &str = "data";
#[cfg(target_arch = "wasm32")]
pub const SURREAL_DB_INDXDB_NS_DATA: &str = "";

#[cfg(target_arch = "wasm32")]
pub const SURREAL_DB_CON_INDXDB_FILES: &str = "indxdb://files";
#[cfg(target_arch = "wasm32")]
pub const SURREAL_DB_INDXDB_DB_FILES: &str = "files";
#[cfg(target_arch = "wasm32")]
pub const SURREAL_DB_INDXDB_NS_FILES: &str = "";
