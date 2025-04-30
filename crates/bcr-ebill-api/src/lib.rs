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

#[derive(Debug, Clone)]
pub struct Config {
    pub bitcoin_network: String,
    pub esplora_base_url: String,
    pub nostr_relay: String,
    pub surreal_db_connection: String,
    pub data_dir: String,
}

static CONFIG: OnceLock<Config> = OnceLock::new();

impl Config {
    pub fn bitcoin_network(&self) -> Network {
        match self.bitcoin_network.as_str() {
            "mainnet" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            _ => Network::Testnet,
        }
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
