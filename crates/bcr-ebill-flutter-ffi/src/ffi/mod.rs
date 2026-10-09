use crate::ffi::{
    api::general,
    context::Context,
    error::{EbillFfiError, err_init},
};
use ::nostr::nips::nip19::ToBech32;
use anyhow::anyhow;
use bcr_common::core::NodeId;
use bcr_ebill_api::{
    Config as ApiConfig, CourtConfig, DevModeConfig, MintConfig, NostrConfig, PaymentConfig,
    get_db_context, util::validate_node_id_network,
};
use bcr_ebill_core::protocol::crypto::BcrKeys;
use bcr_ebill_persistence::DbConfig;
use flutter_rust_bridge::{JoinHandle, frb};
use log::{debug, error, info};
use once_cell::sync::Lazy;
use std::{
    panic,
    path::PathBuf,
    str::FromStr,
    sync::{
        Arc, Once,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio_util::sync::CancellationToken;

pub mod api;
/// flutter_rust_bridge:ignore
pub mod context;
pub mod data;
pub mod error;
/// flutter_rust_bridge:ignore
pub mod job;
/// flutter_rust_bridge:ignore
pub mod nostr;

// This needs to happen
#[flutter_rust_bridge::frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
}

static PROCESS_INIT: Once = Once::new();
fn initialize_process_globals(log_level: &str) {
    PROCESS_INIT.call_once(|| {
        init_crypto_provider();
        init_logging(log_level);
        init_panic_hook();
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[frb]
pub enum InstanceId {
    Mainnet,
    Testnet,
}

use std::collections::HashMap;
use tokio::sync::RwLock;

struct InstanceManager {
    instances: HashMap<InstanceId, Arc<EbillRuntime>>,
    active: Option<InstanceId>,
}

impl InstanceManager {
    fn new() -> Self {
        Self {
            instances: HashMap::new(),
            active: None,
        }
    }
}

static INSTANCE_MANAGER: Lazy<RwLock<InstanceManager>> =
    Lazy::new(|| RwLock::new(InstanceManager::new()));

async fn get_active_ctx() -> Result<Arc<Context>, EbillFfiError> {
    let manager = INSTANCE_MANAGER.read().await;
    let active = manager
        .active
        .ok_or_else(|| err_init("No active E-Bill instance"))?;
    let runtime = manager
        .instances
        .get(&active)
        .ok_or_else(|| err_init("Active E-Bill instance is not initialized"))?;
    Ok(runtime.ctx.clone())
}

/// Sets the active instance (e.g. testnet, or mainnet)
#[frb]
pub async fn set_active_instance(instance_id: InstanceId) -> Result<(), EbillFfiError> {
    let mut manager = INSTANCE_MANAGER.write().await;
    if !manager.instances.contains_key(&instance_id) {
        return Err(err_init("E-Bill instance is not initialized"));
    }
    manager.active = Some(instance_id);
    Ok(())
}

/// Returns the active instance (e.g. testnet, or mainnet)
#[frb]
pub async fn get_active_instance() -> Option<InstanceId> {
    INSTANCE_MANAGER.read().await.active
}

#[frb]
pub async fn init_ebill_instance(
    instance_id: InstanceId,
    conf: EbillConfig,
) -> Result<(), EbillFfiError> {
    let log_level = match conf.log_level {
        Some(ref log_level) => match log_level.as_str() {
            "info" => log::LevelFilter::Info,
            "debug" => log::LevelFilter::Debug,
            "error" => log::LevelFilter::Error,
            "trace" => log::LevelFilter::Trace,
            _ => log::LevelFilter::Info,
        },
        None => log::LevelFilter::Info,
    };
    initialize_process_globals(&log_level.to_string());
    validate_instance_network(instance_id, &conf)?;

    // check if the instance has been initialized already before init to avoid races
    {
        let manager = INSTANCE_MANAGER.read().await;

        if manager.instances.contains_key(&instance_id) {
            return Err(err_init("Instance is already initialized"));
        }
    }

    let runtime = Arc::new(create_runtime(conf).await?);
    let mut manager = INSTANCE_MANAGER.write().await;
    if manager.instances.contains_key(&instance_id) {
        return Err(err_init("Instance is already initialized"));
    }
    manager.instances.insert(instance_id, runtime);
    if manager.active.is_none() {
        manager.active = Some(instance_id);
    }
    Ok(())
}

#[frb]
pub async fn reset_ebill_instance(instance_id: InstanceId) -> Result<(), EbillFfiError> {
    info!("Resetting Rust E-Bill FFI instance {instance_id:?}");
    let runtime = {
        let mut manager = INSTANCE_MANAGER.write().await;
        let runtime = manager
            .instances
            .remove(&instance_id)
            .ok_or_else(|| err_init("Instance not initialized"))?;
        if manager.active == Some(instance_id) {
            manager.active = manager.instances.keys().next().copied();
        }
        runtime
    };
    shutdown_runtime(runtime).await;
    info!("Rust E-Bill FFI Runtime Reset of {instance_id:?} Done");
    Ok(())
}

struct EbillRuntime {
    ctx: Arc<Context>,
    state: Arc<InstanceRuntimeState>,
    jobs_cancel: CancellationToken,
    jobs_handle: JoinHandle<()>,
    nostr_subscription_cancel: CancellationToken,
    nostr_subscription_handle: JoinHandle<()>,
}

async fn create_runtime(conf: EbillConfig) -> Result<EbillRuntime, EbillFfiError> {
    init_crypto_provider();
    info!("Initializing Rust Ebill FFI");

    let api_config = Arc::new(build_api_config(&conf)?);

    // parse mnemonic to keys
    let parsed_mnemonic_keys = BcrKeys::from_seedphrase(&conf.mnemonic)?;

    // make sure the configured default mint node id is valid for the configured network
    validate_node_id_network(
        &api_config.mint_config.default_mint_node_id,
        api_config.bitcoin_network(),
    )?;

    // init db
    let db = get_db_context(api_config.clone(), &parsed_mnemonic_keys).await?;

    // set the network and check if the configured network matches the persisted network and fail, if not
    db.identity_store
        .set_or_check_network(api_config.bitcoin_network())
        .await?;
    let keys = db
        .identity_store
        .get_or_create_key_pair(&parsed_mnemonic_keys, &conf.mnemonic)
        .await?;

    let node_id = NodeId::new(keys.pub_key(), api_config.bitcoin_network());
    info!("Initialized Flutter API {}", general::VERSION);
    info!("Local node id: {node_id}");
    info!(
        "Local npub: {}",
        node_id.npub().to_bech32().unwrap_or_default()
    );
    info!("Local npub as hex: {}", node_id.npub().to_hex());

    // init context
    let ctx = Arc::new(Context::new(api_config.clone(), db).await?);
    let cancel = CancellationToken::new();
    let handle = job::start_jobs(
        ctx.clone(),
        conf.job_runner_check_interval_seconds,
        conf.job_runner_initial_delay_seconds,
        cancel.clone(),
    );

    let state = Arc::new(InstanceRuntimeState::new());

    let default_mint_node_id = api_config.mint_config.default_mint_node_id.clone();
    let nostr_cancel = CancellationToken::new();
    let nostr_handle = nostr::start_subscription(
        ctx.clone(),
        state.clone(),
        default_mint_node_id,
        conf.job_runner_check_interval_seconds,
        conf.transport_initial_subscription_delay_seconds,
        nostr_cancel.clone(),
    );

    info!("Initialized Rust Ebill FFI");
    Ok(EbillRuntime {
        ctx,
        state,
        jobs_cancel: cancel,
        jobs_handle: handle,
        nostr_subscription_cancel: nostr_cancel,
        nostr_subscription_handle: nostr_handle,
    })
}

struct InstanceRuntimeState {
    transport_connected: AtomicBool,
    last_contact_publish_check: AtomicU64,
}

impl InstanceRuntimeState {
    fn new() -> Self {
        Self {
            transport_connected: AtomicBool::new(false),
            last_contact_publish_check: AtomicU64::new(0),
        }
    }

    fn set_transport_connected(&self, connected: bool) {
        self.transport_connected.store(connected, Ordering::Relaxed);
    }

    fn is_transport_connected(&self) -> bool {
        self.transport_connected.load(Ordering::Relaxed)
    }

    fn set_last_contact_publish_check(&self, last: u64) {
        self.last_contact_publish_check
            .store(last, Ordering::Relaxed);
    }

    fn get_last_contact_publish_check(&self) -> u64 {
        self.last_contact_publish_check.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone)]
pub struct EbillConfig {
    pub sqlite_db_path: String,
    pub temp_files_path: String,
    pub log_level: Option<String>,
    pub bitcoin_network: String,
    pub esplora_base_urls: Vec<String>,
    pub nostr_relays: Vec<String>,
    pub blossom_servers: Option<Vec<String>>,
    pub nostr_only_known_contacts: Option<bool>,
    pub nostr_max_relays: Option<usize>,
    pub nostr_relay_ack_threshold: Option<usize>,
    pub job_runner_initial_delay_seconds: u64,
    pub job_runner_check_interval_seconds: u64,
    pub transport_initial_subscription_delay_seconds: Option<u32>,
    pub default_mint_url: String,
    pub default_mint_node_id: String,
    pub num_confirmations_for_payment: usize,
    pub dev_mode: bool,
    pub mandatory_email_confirmations: bool,
    pub default_court_url: String,
    // The mnemonic for the main identity, used for persistence encryption
    pub mnemonic: String,
}

fn build_api_config(conf: &EbillConfig) -> Result<ApiConfig, EbillFfiError> {
    let _parsed_sqlite_path = PathBuf::from_str(&conf.sqlite_db_path.clone()).map_err(err_init)?;
    let temp_files_path = PathBuf::from_str(&conf.temp_files_path.clone()).map_err(err_init)?;
    let nostr_relays: Vec<url::Url> = conf
        .nostr_relays
        .iter()
        .map(|nr| url::Url::parse(nr).map_err(err_init))
        .collect::<Result<_, EbillFfiError>>()?;
    let blossom_servers: Vec<url::Url> = conf
        .blossom_servers
        .clone()
        .unwrap_or_default()
        .iter()
        .map(|server| url::Url::parse(server).map_err(err_init))
        .collect::<Result<_, EbillFfiError>>()?;
    let db_conf = DbConfig {
        connection_string: conf.sqlite_db_path.to_owned(),
        temp_files_path,
    };
    let mint_node_id = NodeId::from_str(&conf.default_mint_node_id)
        .map_err(|e| err_init(format!("is a valid mint id: {e}")))?;
    let api_config = ApiConfig {
        bitcoin_network: conf.bitcoin_network.to_owned(),
        esplora_base_urls: conf
            .esplora_base_urls
            .iter()
            .map(|u| url::Url::parse(u).map_err(err_init))
            .collect::<Result<_, EbillFfiError>>()?,
        db_conf,
        nostr_config: NostrConfig {
            relays: nostr_relays,
            blossom_servers,
            only_known_contacts: conf.nostr_only_known_contacts.unwrap_or(false),
            max_relays: conf.nostr_max_relays.or(Some(50)),
            relay_ack_threshold: conf.nostr_relay_ack_threshold.unwrap_or(1),
        },
        mint_config: MintConfig::new(conf.default_mint_url.to_owned(), mint_node_id)?,
        payment_config: PaymentConfig {
            num_confirmations_for_payment: conf.num_confirmations_for_payment,
        },
        dev_mode_config: DevModeConfig {
            on: conf.dev_mode,
            mandatory_email_confirmations: conf.mandatory_email_confirmations,
        },
        court_config: CourtConfig {
            default_url: url::Url::parse(&conf.default_court_url).map_err(err_init)?,
        },
    };
    if api_config.esplora_base_urls.is_empty() {
        return Err(EbillFfiError::from(anyhow!(
            "esplora_base_urls must contain at least one URL"
        )));
    }
    debug!("Config: {api_config:?}");
    Ok(api_config)
}

fn init_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

fn init_logging(log_level: &str) {
    info!("Initializing Rust logging");
    let level = log::LevelFilter::from_str(log_level).expect("invalid log level");

    #[cfg(target_os = "android")]
    {
        use android_logger::{Config, FilterBuilder};
        let mut filter = FilterBuilder::new();

        filter.filter(None, log::LevelFilter::Off);
        filter.filter(Some("bcr_ebill_flutter_ffi"), level);
        filter.filter(Some("bcr_common"), level);
        filter.filter(Some("bcr_ebill_api"), level);
        filter.filter(Some("bcr_ebill_core"), level);
        filter.filter(Some("bcr_ebill_persistence"), level);
        filter.filter(Some("bcr_ebill_transport"), level);

        android_logger::init_once(
            Config::default()
                .with_tag("EbillFfi")
                .with_max_level(level)
                .with_filter(filter.build()),
        );
    }

    #[cfg(not(target_os = "android"))]
    {
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Off)
            .filter_module("bcr_common", level)
            .filter_module("bcr_ebill_flutter_ffi", level)
            .filter_module("bcr_ebill_api", level)
            .filter_module("bcr_ebill_core", level)
            .filter_module("bcr_ebill_persistence", level)
            .filter_module("bcr_ebill_transport", level)
            .init();
    }

    info!("Rust logging initialized");
}

fn init_panic_hook() {
    info!("Initializing Rust panic hook");
    panic::set_hook(Box::new(|info| {
        error!("Rust panic: {info}");
    }));
    info!("Rust panic hook initialized");
}

fn validate_instance_network(id: InstanceId, conf: &EbillConfig) -> Result<(), EbillFfiError> {
    let valid = match id {
        InstanceId::Mainnet => {
            conf.bitcoin_network == "mainnet" || conf.bitcoin_network == "bitcoin"
        }
        InstanceId::Testnet => conf.bitcoin_network == "testnet",
    };
    if !valid {
        return Err(err_init(
            "Instance ID does not match configured Bitcoin network",
        ));
    }
    Ok(())
}

async fn shutdown_runtime(runtime: Arc<EbillRuntime>) {
    runtime.jobs_cancel.cancel();
    runtime.nostr_subscription_cancel.cancel();
    runtime.jobs_handle.abort();
    runtime.nostr_subscription_handle.abort();
}

struct InstanceSnapshot {
    ctx: Arc<Context>,
    state: Arc<InstanceRuntimeState>,
}

async fn get_active_instance_snapshot() -> Result<InstanceSnapshot, EbillFfiError> {
    let manager = INSTANCE_MANAGER.read().await;
    let active = manager
        .active
        .ok_or_else(|| err_init("No active E-Bill instance"))?;
    let runtime = manager
        .instances
        .get(&active)
        .ok_or_else(|| err_init("Active instance not initialized"))?;
    Ok(InstanceSnapshot {
        ctx: runtime.ctx.clone(),
        state: runtime.state.clone(),
    })
}
