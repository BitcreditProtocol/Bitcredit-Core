use anyhow::{Result, anyhow};
use bcr_ebill_core::NodeId;
use bitcoin::Network;
use std::sync::OnceLock;

mod blockchain;
pub mod constants;
pub mod data;
pub mod external;
pub mod persistence;
pub mod service;
#[cfg(test)]
mod tests;
pub mod util;

pub use blockchain::Block;
pub use blockchain::Blockchain;
pub use persistence::DbContext;
pub use persistence::Error as PersistenceError;
pub use persistence::db::SurrealDbConfig;
pub use persistence::get_db_context;
pub use persistence::notification::NotificationFilter;

#[derive(Debug, Clone)]
pub struct Config {
    pub app_url: url::Url,
    pub bitcoin_network: String,
    pub esplora_base_url: String,
    pub db_config: SurrealDbConfig,
    pub data_dir: String,
    pub nostr_config: NostrConfig,
    pub mint_config: MintConfig,
    pub payment_config: PaymentConfig,
}

static CONFIG: OnceLock<Config> = OnceLock::new();

impl Config {
    pub fn bitcoin_network(&self) -> Network {
        match self.bitcoin_network.as_str() {
            "mainnet" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "testnet4" => Network::Testnet4,
            "regtest" => Network::Regtest,
            _ => Network::Testnet,
        }
    }
}

/// Payment specific configuration
#[derive(Debug, Clone, Default)]
pub struct PaymentConfig {
    /// Amount of confirmations until we consider an on-chain payment as paid
    pub num_confirmations_for_payment: usize,
}

/// Nostr specific configuration
#[derive(Debug, Clone, Default)]
pub struct NostrConfig {
    /// Only known contacts can message us via DM.
    pub only_known_contacts: bool,
    /// All relays we want to publish our messages to and receive messages from.
    pub relays: Vec<String>,
}

/// Mint configuration
#[derive(Debug, Clone)]
pub struct MintConfig {
    /// URL of the default mint
    pub default_mint_url: String,
    /// Node Id of the default mint
    pub default_mint_node_id: NodeId,
}

impl MintConfig {
    pub fn new(default_mint_url: String, default_mint_node_id: NodeId) -> Result<Self> {
        reqwest::Url::parse(&default_mint_url)
            .map_err(|e| anyhow!("Invalid Default Mint URL: {e}"))?;
        Ok(Self {
            default_mint_url,
            default_mint_node_id,
        })
    }
}

pub fn init(conf: Config) -> Result<()> {
    CONFIG
        .set(conf)
        .map_err(|e| anyhow!("Could not initialize E-Bill API: {e:?}"))?;
    Ok(())
}

pub fn get_config() -> &'static Config {
    CONFIG.get().expect("E-Bill API is not initialized")
}
