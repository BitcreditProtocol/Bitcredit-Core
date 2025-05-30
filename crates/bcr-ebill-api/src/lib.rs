use anyhow::{Result, anyhow};
use bitcoin::Network;
use std::sync::OnceLock;

mod blockchain;
pub mod constants;
pub mod data;
pub mod external;
mod persistence;
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

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub bitcoin_network: String,
    pub esplora_base_url: String,
    pub db_config: SurrealDbConfig,
    pub data_dir: String,
    pub nostr_config: NostrConfig,
    pub mint_config: MintConfig,
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

/// Nostr specific configuration
#[derive(Debug, Clone, Default)]
pub struct NostrConfig {
    /// Only known contacts can message us via DM.
    pub only_known_contacts: bool,
    /// All relays we want to publish our messages to and receive messages from.
    pub relays: Vec<String>,
}

/// Mint configuration
#[derive(Debug, Clone, Default)]
pub struct MintConfig {
    /// URL of the default mint
    pub default_mint_url: String,
    /// Node Id of the default mint
    pub default_mint_node_id: String,
}

impl MintConfig {
    pub fn new(default_mint_url: String, default_mint_node_id: String) -> Result<Self> {
        util::crypto::validate_pub_key(&default_mint_node_id)?;
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
