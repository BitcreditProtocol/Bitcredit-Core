#![recursion_limit = "256"]
use anyhow::{Result, anyhow};
use bcr_common::core::NodeId;
use bcr_ebill_persistence::db::surreal::SurrealWrapper;
use bcr_ebill_persistence::{
    ContactStoreApi, FileReferenceStoreApi, NostrChainEventStoreApi, NostrContactStoreApi,
    NostrEventOffsetStoreApi, NotificationStoreApi, SurrealDbConfig, SurrealNostrChainEventStore,
    SurrealNostrContactStore, SurrealNotificationStore,
    traits::bill::{BillChainStoreApi, BillStoreApi},
    traits::company::{CompanyChainStoreApi, CompanyStoreApi},
    traits::file_upload::FileUploadStoreApi,
    traits::identity::{IdentityChainStoreApi, IdentityStoreApi},
    traits::mint::MintStoreApi,
    traits::nostr::NostrQueuedMessageStoreApi,
    traits::notification::EmailNotificationStoreApi,
};
use bcr_ebill_persistence::{DbConfig, get_surreal_db};
use bitcoin::Network;
use log::error;
use std::sync::{Arc, RwLock};

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
    /// The old surreal db config
    pub db_config: SurrealDbConfig,
    /// The new database config
    pub db_conf: DbConfig,
    pub nostr_config: NostrConfig,
    pub mint_config: MintConfig,
    pub payment_config: PaymentConfig,
    pub dev_mode_config: DevModeConfig,
    pub court_config: CourtConfig,
}

static CONFIG: RwLock<Option<Arc<Config>>> = RwLock::new(None);

impl Config {
    pub fn bitcoin_network(&self) -> Network {
        match self.bitcoin_network.as_str() {
            "mainnet" => Network::Bitcoin,
            "bitcoin" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "testnet4" => Network::Testnet4,
            "regtest" => Network::Regtest,
            _ => {
                log::warn!(
                    "Triggered fallback for config bitcoin network, network is set to {}, but defaulted to Testnet",
                    self.bitcoin_network
                );
                Network::Testnet
            }
        }
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
}

impl MintConfig {
    pub fn new(default_mint_url: String, default_mint_node_id: NodeId) -> Result<Self> {
        let url = url::Url::parse(&default_mint_url)
            .map_err(|e| anyhow!("Invalid Default Mint URL: {e}"))?;
        Ok(Self {
            default_mint_url: url,
            default_mint_node_id,
        })
    }
}

pub fn init(conf: Config) -> Result<()> {
    if conf.esplora_base_urls.is_empty() {
        return Err(anyhow!("esplora_base_urls must contain at least one URL"));
    }

    let mut cfg_lock = CONFIG.write().expect("can get write lock on config");
    *cfg_lock = Some(Arc::new(conf));
    Ok(())
}

pub fn get_config() -> Arc<Config> {
    let config = CONFIG.read().expect("Can get E-Bill config lock");
    config.clone().expect("E-Bill API is not initialized")
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
}

/// Creates a new instance of the DbContext with the given SurrealDB configuration.
pub async fn get_db_context(conf: &Config) -> bcr_ebill_persistence::Result<DbContext> {
    let db = get_surreal_db(&conf.db_config).await?;
    let surreal_wrapper = SurrealWrapper {
        db: db.clone(),
        files: false,
    };

    #[cfg(feature = "sqlite")]
    let database = bcr_ebill_persistence::get_sqlite_db(&conf.db_conf).await?;

    #[cfg(all(not(feature = "sqlite"), feature = "postgres"))]
    let database = bcr_ebill_persistence::get_postgres_db(&conf.db_conf).await?;

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let company_store: Arc<dyn CompanyStoreApi> = { Arc::new(database.company_store()) };

    #[cfg(all(not(feature = "sqlite"), not(feature = "postgres")))]
    let company_store = Arc::new(
        bcr_ebill_persistence::db::company::SurrealCompanyStore::new(surreal_wrapper.clone()),
    );

    let file_upload_store = Arc::new(bcr_ebill_persistence::file_upload::FileUploadStore::new(
        conf.db_conf.temp_files_path.clone(),
    ));

    if let Err(e) = file_upload_store.cleanup_temp_uploads().await {
        error!("Error cleaning up temp uploads: {e}");
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let contact_store: Arc<dyn ContactStoreApi> = { Arc::new(database.contact_store()) };

    #[cfg(all(not(feature = "sqlite"), not(feature = "postgres")))]
    let contact_store: Arc<dyn ContactStoreApi> = Arc::new(
        bcr_ebill_persistence::SurrealContactStore::new(surreal_wrapper.clone()),
    );

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let bill_store: Arc<dyn BillStoreApi> = Arc::new(database.bill_store());

    #[cfg(not(any(feature = "sqlite", feature = "postgres")))]
    let bill_store = Arc::new(bcr_ebill_persistence::db::bill::SurrealBillStore::new(
        surreal_wrapper.clone(),
    ));

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let bill_blockchain_store: Arc<dyn BillChainStoreApi> = Arc::new(database.bill_chain_store());

    #[cfg(not(any(feature = "sqlite", feature = "postgres")))]
    let bill_blockchain_store = Arc::new(
        bcr_ebill_persistence::db::bill_chain::SurrealBillChainStore::new(surreal_wrapper.clone()),
    );

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let identity_store: Arc<dyn IdentityStoreApi> = Arc::new(database.identity_store());

    #[cfg(not(any(feature = "sqlite", feature = "postgres")))]
    let identity_store = Arc::new(
        bcr_ebill_persistence::db::identity::SurrealIdentityStore::new(surreal_wrapper.clone()),
    );

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let identity_chain_store: Arc<dyn IdentityChainStoreApi> =
        Arc::new(database.identity_chain_store());

    #[cfg(not(any(feature = "sqlite", feature = "postgres")))]
    let identity_chain_store = Arc::new(
        bcr_ebill_persistence::db::identity_chain::SurrealIdentityChainStore::new(
            surreal_wrapper.clone(),
        ),
    );

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let company_chain_store: Arc<dyn CompanyChainStoreApi> =
        Arc::new(database.company_chain_store());

    #[cfg(not(any(feature = "sqlite", feature = "postgres")))]
    let company_chain_store = Arc::new(
        bcr_ebill_persistence::db::company_chain::SurrealCompanyChainStore::new(
            surreal_wrapper.clone(),
        ),
    );

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let nostr_event_offset_store: Arc<dyn NostrEventOffsetStoreApi> =
        Arc::new(database.nostr_event_offset_store());

    #[cfg(not(any(feature = "sqlite", feature = "postgres")))]
    let nostr_event_offset_store = Arc::new(
        bcr_ebill_persistence::db::nostr_event_offset::SurrealNostrEventOffsetStore::new(
            surreal_wrapper.clone(),
        ),
    );

    let notification_store = Arc::new(SurrealNotificationStore::new(surreal_wrapper.clone()));

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let email_notification_store: Arc<dyn EmailNotificationStoreApi> =
        { Arc::new(database.email_notification_store()) };

    #[cfg(all(not(feature = "sqlite"), not(feature = "postgres")))]
    let email_notification_store = Arc::new(
        bcr_ebill_persistence::db::email_notification::SurrealEmailNotificationStore::new(
            surreal_wrapper.clone(),
        ),
    );

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let mint_store: Arc<dyn MintStoreApi> = Arc::new(database.mint_store());

    #[cfg(not(any(feature = "sqlite", feature = "postgres")))]
    let mint_store: Arc<dyn MintStoreApi> = Arc::new(
        bcr_ebill_persistence::db::mint::SurrealMintStore::new(surreal_wrapper.clone()),
    );

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let queued_message_store: Arc<dyn NostrQueuedMessageStoreApi> =
        Arc::new(database.nostr_event_queue_store());

    #[cfg(not(any(feature = "sqlite", feature = "postgres")))]
    let queued_message_store = Arc::new(
        bcr_ebill_persistence::db::nostr_send_queue::SurrealNostrEventQueueStore::new(
            surreal_wrapper.clone(),
        ),
    );

    let nostr_contact_store = Arc::new(SurrealNostrContactStore::new(surreal_wrapper.clone()));
    let nostr_chain_event_store =
        Arc::new(SurrealNostrChainEventStore::new(surreal_wrapper.clone()));

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    let file_reference_store: Arc<dyn FileReferenceStoreApi> =
        Arc::new(database.file_reference_store());

    #[cfg(not(any(feature = "sqlite", feature = "postgres")))]
    let file_reference_store = Arc::new(
        bcr_ebill_persistence::db::file_reference::SurrealFileReferenceStore::new(
            surreal_wrapper.clone(),
        ),
    );

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
    })
}
