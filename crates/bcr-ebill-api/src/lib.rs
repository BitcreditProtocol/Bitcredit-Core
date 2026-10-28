#![recursion_limit = "256"]
use anyhow::{Result, anyhow};
use bcr_common::core::NodeId;
use bcr_ebill_core::protocol::crypto::BcrKeys;
use bcr_ebill_persistence::{
    ContactStoreApi, FileReferenceStoreApi, NostrChainEventStoreApi, NostrContactStoreApi,
    NostrEventOffsetStoreApi, NotificationStoreApi,
    traits::{
        bill::{BillChainStoreApi, BillStoreApi},
        company::{CompanyChainStoreApi, CompanyStoreApi},
        file_upload::FileUploadStoreApi,
        identity::{IdentityChainStoreApi, IdentityStoreApi},
        mint::MintStoreApi,
        nostr::NostrQueuedMessageStoreApi,
        notification::EmailNotificationStoreApi,
        transaction::TransactionManagerApi,
    },
};
use bcr_ebill_persistence::{DbConfig, EncryptionContext};
use bitcoin::Network;
use log::error;
use std::sync::Arc;

#[cfg(not(any(feature = "sqlite", feature = "postgres")))]
compile_error!("Either feature `sqlite` or `postgres` must be enabled.");

pub mod constants;
pub mod external;
pub mod service;
#[cfg(test)]
mod tests;
pub mod util;

#[derive(Debug, Clone)]
pub struct Config {
    pub bitcoin_network: String,
    /// List of Esplora API base URLs (in order of priority).
    /// The first URL is used for API requests with fallback to subsequent URLs on failure.
    /// The first URL is also used for user-facing links (e.g., mempool explorer links).
    pub esplora_base_urls: Vec<url::Url>,
    /// The database config
    pub db_conf: DbConfig,
    pub nostr_config: NostrConfig,
    pub mint_config: MintConfig,
    pub payment_config: PaymentConfig,
    pub dev_mode_config: DevModeConfig,
    pub court_config: CourtConfig,
}

impl Config {
    pub fn bitcoin_network(&self) -> Network {
        self.try_bitcoin_network()
            .expect("bitcoin network must be validated during API initialization")
    }

    /// Rejects unsupported network names; config builders call this before using the config.
    pub fn try_bitcoin_network(&self) -> Result<Network> {
        Self::try_bitcoin_network_value(&self.bitcoin_network)
    }

    fn try_bitcoin_network_value(configured: &str) -> Result<Network> {
        match configured {
            "mainnet" | "bitcoin" => Ok(Network::Bitcoin),
            "testnet" => Ok(Network::Testnet),
            "testnet4" => Ok(Network::Testnet4),
            "regtest" => Ok(Network::Regtest),
            unsupported => Err(anyhow!(
                "Unsupported bitcoin network '{unsupported}'; expected bitcoin, mainnet, testnet, testnet4, or regtest"
            )),
        }
    }
}

#[cfg(test)]
mod config_network_tests {
    use super::Config;
    use bitcoin::Network;

    #[test]
    fn parses_every_supported_bitcoin_network_explicitly() {
        let cases = [
            ("bitcoin", Network::Bitcoin),
            ("mainnet", Network::Bitcoin),
            ("testnet", Network::Testnet),
            ("testnet4", Network::Testnet4),
            ("regtest", Network::Regtest),
        ];

        for (configured, expected) in cases {
            let parsed = Config::try_bitcoin_network_value(configured).unwrap();
            assert_eq!(parsed, expected);
        }
    }

    #[test]
    fn rejects_unknown_bitcoin_network_instead_of_falling_back() {
        let error = Config::try_bitcoin_network_value("testnett").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Unsupported bitcoin network 'testnett'")
        );
    }
}

/// Court specific configuration
#[derive(Debug, Clone)]
pub struct CourtConfig {
    /// The default court URL
    pub default_url: url::Url,
}

/// Developer Mode specific configuration
#[derive(Debug, Clone)]
pub struct DevModeConfig {
    /// Whether dev mode is on
    pub on: bool,
    /// Whether mandatory email confirmations should be enabled (disable for easier testing)
    pub mandatory_email_confirmations: bool,
}

/// Payment specific configuration
#[derive(Debug, Clone, Default)]
pub struct PaymentConfig {
    /// Amount of confirmations until we consider an on-chain payment as paid
    pub num_confirmations_for_payment: usize,
}

/// Nostr specific configuration
#[derive(Debug, Clone)]
pub struct NostrConfig {
    /// Only known contacts can message us via DM.
    pub only_known_contacts: bool,
    /// All relays we want to publish our messages to and receive messages from.
    pub relays: Vec<url::Url>,
    /// Blossom servers we want to publish and use for file storage.
    pub blossom_servers: Vec<url::Url>,
    /// Maximum number of contact relays to add (in addition to user relays which are always included).
    /// Defaults to 50 if not specified.
    pub max_relays: Option<usize>,
    /// Number of relay acknowledgements required before an optimistic broadcast
    /// returns to the caller. The remaining relays continue publishing in the background.
    pub relay_ack_threshold: usize,
}

impl Default for NostrConfig {
    fn default() -> Self {
        Self {
            only_known_contacts: false,
            relays: vec![],
            blossom_servers: vec![],
            max_relays: Some(50),
            relay_ack_threshold: 1,
        }
    }
}

/// Mint configuration
#[derive(Debug, Clone)]
pub struct MintConfig {
    /// URL of the default mint
    pub default_mint_url: url::Url,
    /// Node Id of the default mint
    pub default_mint_node_id: NodeId,
    /// Explicit additional Mints. The default remains the service Mint.
    pub mints: Vec<ConfiguredMint>,
}

#[derive(Debug, Clone)]
pub struct ConfiguredMint {
    pub name: String,
    pub node_id: NodeId,
    pub url: url::Url,
}

impl MintConfig {
    pub fn new(default_mint_url: String, default_mint_node_id: NodeId) -> Result<Self> {
        let url = url::Url::parse(&default_mint_url)
            .map_err(|e| anyhow!("Invalid Default Mint URL: {e}"))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(anyhow!("Invalid Default Mint URL"));
        }
        Ok(Self {
            default_mint_url: url,
            default_mint_node_id,
            mints: vec![],
        })
    }

    pub fn url_for(&self, node_id: &NodeId) -> Option<&url::Url> {
        if node_id == &self.default_mint_node_id {
            Some(&self.default_mint_url)
        } else {
            self.mints
                .iter()
                .find(|mint| &mint.node_id == node_id)
                .map(|mint| &mint.url)
        }
    }

    pub fn with_mints(mut self, mints: Vec<ConfiguredMint>) -> Result<Self> {
        let mut seen = std::collections::HashSet::new();
        let mut endpoints = std::collections::HashMap::new();
        endpoints.insert(
            self.default_mint_url.origin().ascii_serialization(),
            self.default_mint_node_id.clone(),
        );
        for mint in &mints {
            let origin = mint.url.origin().ascii_serialization();
            if endpoints
                .get(&origin)
                .is_some_and(|node| node != &mint.node_id)
                || mint.url.query().is_some()
                || mint.url.fragment().is_some()
                || mint.name.trim().is_empty()
                || !matches!(mint.url.scheme(), "http" | "https")
                || mint.url.host_str().is_none()
                || !mint.url.username().is_empty()
                || mint.url.password().is_some()
                || !seen.insert(mint.node_id.clone())
                || (mint.node_id == self.default_mint_node_id && mint.url != self.default_mint_url)
            {
                return Err(anyhow!(
                    "Invalid or conflicting configured Mint: {}",
                    mint.node_id
                ));
            }
            endpoints.insert(origin, mint.node_id.clone());
        }
        self.mints = mints;
        Ok(self)
    }
}

/// A container for all persistence related dependencies.
#[derive(Clone)]
pub struct DbContext {
    pub contact_store: Arc<dyn ContactStoreApi>,
    pub bill_store: Arc<dyn BillStoreApi>,
    pub bill_blockchain_store: Arc<dyn BillChainStoreApi>,
    pub identity_store: Arc<dyn IdentityStoreApi>,
    pub identity_chain_store: Arc<dyn IdentityChainStoreApi>,
    pub company_chain_store: Arc<dyn CompanyChainStoreApi>,
    pub company_store: Arc<dyn CompanyStoreApi>,
    pub file_upload_store: Arc<dyn FileUploadStoreApi>,
    pub file_reference_store: Arc<dyn FileReferenceStoreApi>,
    pub nostr_event_offset_store: Arc<dyn NostrEventOffsetStoreApi>,
    pub notification_store: Arc<dyn NotificationStoreApi>,
    pub email_notification_store: Arc<dyn EmailNotificationStoreApi>,
    pub queued_message_store: Arc<dyn NostrQueuedMessageStoreApi>,
    pub nostr_contact_store: Arc<dyn NostrContactStoreApi>,
    pub mint_store: Arc<dyn MintStoreApi>,
    pub nostr_chain_event_store: Arc<dyn NostrChainEventStoreApi>,
    pub transaction_mgr: Arc<dyn TransactionManagerApi>,
}

/// Creates a new instance of the DbContext with the given configuration
pub async fn get_db_context(
    conf: Arc<Config>,
    encryption_keys: &BcrKeys,
) -> bcr_ebill_persistence::Result<DbContext> {
    let encryption_context = Arc::new(EncryptionContext::new(encryption_keys.to_owned()));

    #[cfg(feature = "sqlite")]
    let database = bcr_ebill_persistence::get_sqlite_db(&conf.db_conf).await?;

    #[cfg(all(not(feature = "sqlite"), feature = "postgres"))]
    let database = bcr_ebill_persistence::get_postgres_db(&conf.db_conf).await?;

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let transaction_mgr: Arc<dyn TransactionManagerApi> =
        { Arc::new(database.transaction_mgr(encryption_context.clone())) };

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let company_store: Arc<dyn CompanyStoreApi> =
        { Arc::new(database.company_store(encryption_context.clone())) };

    let file_upload_store = Arc::new(bcr_ebill_persistence::file_upload::FileUploadStore::new(
        conf.db_conf.temp_files_path.clone(),
    ));

    if let Err(e) = file_upload_store.cleanup_temp_uploads().await {
        error!("Error cleaning up temp uploads: {e}");
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let contact_store: Arc<dyn ContactStoreApi> = { Arc::new(database.contact_store()) };

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let bill_store: Arc<dyn BillStoreApi> =
        Arc::new(database.bill_store(encryption_context.clone()));

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let bill_blockchain_store: Arc<dyn BillChainStoreApi> = Arc::new(database.bill_chain_store());

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let identity_store: Arc<dyn IdentityStoreApi> =
        Arc::new(database.identity_store(encryption_context.clone()));

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let identity_chain_store: Arc<dyn IdentityChainStoreApi> =
        Arc::new(database.identity_chain_store());

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let company_chain_store: Arc<dyn CompanyChainStoreApi> =
        Arc::new(database.company_chain_store());

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let nostr_event_offset_store: Arc<dyn NostrEventOffsetStoreApi> =
        Arc::new(database.nostr_event_offset_store());

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let notification_store: Arc<dyn NotificationStoreApi> = Arc::new(database.notification_store());

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let email_notification_store: Arc<dyn EmailNotificationStoreApi> =
        { Arc::new(database.email_notification_store()) };

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let mint_store: Arc<dyn MintStoreApi> =
        Arc::new(database.mint_store(encryption_context.clone()));

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let queued_message_store: Arc<dyn NostrQueuedMessageStoreApi> =
        Arc::new(database.nostr_event_queue_store(encryption_context.clone()));

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let nostr_contact_store: Arc<dyn NostrContactStoreApi> =
        Arc::new(database.nostr_contact_store(encryption_context.clone()));

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let nostr_chain_event_store: Arc<dyn NostrChainEventStoreApi> =
        Arc::new(database.nostr_chain_event_store());

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let file_reference_store: Arc<dyn FileReferenceStoreApi> =
        Arc::new(database.file_reference_store());

    Ok(DbContext {
        contact_store,
        bill_store,
        bill_blockchain_store,
        identity_store,
        identity_chain_store,
        company_chain_store,
        company_store,
        file_upload_store,
        file_reference_store,
        nostr_event_offset_store,
        notification_store,
        email_notification_store,
        queued_message_store,
        nostr_contact_store,
        mint_store,
        nostr_chain_event_store,
        transaction_mgr,
    })
}

#[cfg(test)]
mod mint_config_tests {
    use super::{ConfiguredMint, MintConfig};
    use bcr_common::core::NodeId;
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use bitcoin::Network;

    #[test]
    fn keeps_service_default_and_routes_only_explicit_mints() {
        let a = NodeId::new(BcrKeys::new().pub_key(), Network::Testnet);
        let b = NodeId::new(BcrKeys::new().pub_key(), Network::Testnet);
        let unknown = NodeId::new(BcrKeys::new().pub_key(), Network::Testnet);
        let config = MintConfig::new("http://localhost:5343".into(), a.clone()).unwrap();
        assert!(config.url_for(&b).is_none());
        let config = config
            .with_mints(vec![ConfiguredMint {
                name: "Mint B".into(),
                node_id: b.clone(),
                url: "http://localhost:6343".parse().unwrap(),
            }])
            .unwrap();
        assert_eq!(config.url_for(&a).unwrap().port(), Some(5343));
        assert_eq!(config.url_for(&b).unwrap().port(), Some(6343));
        assert!(config.url_for(&unknown).is_none());
        assert_eq!(config.default_mint_node_id, a);
    }

    #[test]
    fn rejects_conflicting_or_duplicate_registry_entries() {
        let a = NodeId::new(BcrKeys::new().pub_key(), Network::Testnet);
        let config = MintConfig::new("http://localhost:5343".into(), a.clone()).unwrap();
        let mint = ConfiguredMint {
            name: "A".into(),
            node_id: a,
            url: "http://localhost:6343".parse().unwrap(),
        };
        assert!(config.clone().with_mints(vec![mint.clone()]).is_err());
        assert!(config.with_mints(vec![mint.clone(), mint]).is_err());
    }
    #[test]
    fn rejects_distinct_mints_at_one_effective_endpoint_even_with_path_aliases() {
        let a = NodeId::new(BcrKeys::new().pub_key(), Network::Testnet);
        let b = NodeId::new(BcrKeys::new().pub_key(), Network::Testnet);
        for url in [
            "http://localhost:5343",
            "http://localhost:5343/",
            "http://localhost:5343/other-prefix",
        ] {
            let config = MintConfig::new("http://localhost:5343".into(), a.clone()).unwrap();
            assert!(
                config
                    .with_mints(vec![ConfiguredMint {
                        name: "B".into(),
                        node_id: b.clone(),
                        url: url.parse().unwrap()
                    }])
                    .is_err()
            );
        }
        let c = NodeId::new(BcrKeys::new().pub_key(), Network::Testnet);
        assert!(
            MintConfig::new("http://localhost:5343".into(), a)
                .unwrap()
                .with_mints(vec![
                    ConfiguredMint {
                        name: "B".into(),
                        node_id: b,
                        url: "http://localhost:6343".parse().unwrap()
                    },
                    ConfiguredMint {
                        name: "C".into(),
                        node_id: c,
                        url: "http://localhost:6343/prefix".parse().unwrap()
                    },
                ])
                .is_err()
        );
    }
}
