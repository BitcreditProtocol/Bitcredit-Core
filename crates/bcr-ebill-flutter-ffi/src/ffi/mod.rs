use bcr_common::core::NodeId;
use bcr_ebill_api::{
    Config as ApiConfig, CourtConfig, DevModeConfig, MintConfig, NostrConfig, PaymentConfig,
    get_db_context, util::validate_node_id_network,
};
use bcr_ebill_persistence::SurrealDbConfig;
use flutter_rust_bridge::{JoinHandle, frb};
use log::{debug, error, info};
use nostr_sdk::ToBech32;
use once_cell::sync::Lazy;
use std::{
    panic,
    path::PathBuf,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::ffi::{api::general, context::Context, error::EbillFfiError};

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

/// Minimum time between contact data publish checks to avoid excessive network calls
/// in flaky network conditions. Set to 5 minutes.
const CONTACT_PUBLISH_CHECK_INTERVAL_SEC: u64 = 3600;

static EBILL_RUNTIME: Lazy<Mutex<EbillRuntime>> = Lazy::new(|| Mutex::new(EbillRuntime::new()));

struct EbillRuntime {
    ctx: Option<Arc<Context>>,
    jobs_cancel: Option<CancellationToken>,
    jobs_handle: Option<JoinHandle<()>>,
    nostr_subscription_cancel: Option<CancellationToken>,
    nostr_subscription_handle: Option<JoinHandle<()>>,
    logging_initialized: bool,
    panic_hook_initialized: bool,
    transport_connected: AtomicBool,
    last_contact_publish_check: AtomicU64,
}

impl EbillRuntime {
    fn new() -> Self {
        Self {
            ctx: None,
            jobs_cancel: None,
            jobs_handle: None,
            nostr_subscription_cancel: None,
            nostr_subscription_handle: None,
            logging_initialized: false,
            panic_hook_initialized: false,
            transport_connected: AtomicBool::new(false),
            last_contact_publish_check: AtomicU64::new(0),
        }
    }

    #[frb(ignore)]
    pub fn set_transport_connected(&self, connected: bool) {
        self.transport_connected.store(connected, Ordering::Relaxed);
    }

    #[frb(ignore)]
    pub fn is_transport_connected(&self) -> bool {
        self.transport_connected.load(Ordering::Relaxed)
    }

    #[frb(ignore)]
    pub fn set_last_contact_publish_check(&self, last: u64) {
        self.last_contact_publish_check
            .store(last, Ordering::Relaxed);
    }

    #[frb(ignore)]
    pub fn get_last_contact_publish_check(&self) -> u64 {
        self.last_contact_publish_check.load(Ordering::Relaxed)
    }
}

async fn reset_runtime(rt: &mut EbillRuntime) {
    info!("Resetting Rust E-Bill FFI Runtime");
    if let Some(ref token) = rt.jobs_cancel {
        token.cancel();
    }

    if let Some(ref handle) = rt.jobs_handle {
        handle.abort();
    }

    if let Some(ref token) = rt.nostr_subscription_cancel {
        token.cancel();
    }

    if let Some(ref handle) = rt.nostr_subscription_handle {
        handle.abort();
    }

    rt.set_transport_connected(false);
    rt.set_last_contact_publish_check(0);

    info!("Rust E-Bill FFI Runtime Reset Done");
}

#[derive(Debug, Clone)]
pub struct EbillConfig {
    pub db_folder_path: String,
    pub db_folder_path_files: String,
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
}

#[frb]
pub async fn init_ebill_ffi(conf: EbillConfig) -> Result<(), EbillFfiError> {
    info!("Initializing Rust Wallet FFI");
    let _parsed_path = PathBuf::from_str(&conf.db_folder_path.clone())
        .expect("Not a valid file path for the database");
    let _parsed_path_files = PathBuf::from_str(&conf.db_folder_path_files.clone())
        .expect("Not a valid file path for the database");

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

    let mut rt = EBILL_RUNTIME.lock().await;

    // reset on initialization
    reset_runtime(&mut rt).await;

    // only initialize logging once
    if !rt.logging_initialized {
        init_logging(&log_level.to_string());
        rt.logging_initialized = true;
    }

    // only initialize panic hook once
    if !rt.panic_hook_initialized {
        init_panic_hook();
        rt.panic_hook_initialized = true;
    }

    let nostr_relays: Vec<url::Url> = conf
        .nostr_relays
        .iter()
        .map(|nr| url::Url::parse(nr).expect("nostr relay is not a valid URL"))
        .collect();
    let blossom_servers: Vec<url::Url> = conf
        .blossom_servers
        .unwrap_or_default()
        .iter()
        .map(|server| url::Url::parse(server).expect("blossom server is not a valid URL"))
        .collect();
    let db_path = format!("surrealkv://{}", conf.db_folder_path);
    let db_path_files = format!("surrealkv://{}", conf.db_folder_path_files);
    let db_config = SurrealDbConfig {
        connection_string: db_path,
        namespace: "test".to_owned(),
        database: "ebill".to_owned(),
    };
    let db_config_files = SurrealDbConfig {
        connection_string: db_path_files,
        namespace: "test".to_owned(),
        database: "ebill".to_owned(),
    };
    let mint_node_id = NodeId::from_str(&conf.default_mint_node_id).expect("is a valid mint id");
    let api_config = ApiConfig {
        bitcoin_network: conf.bitcoin_network,
        esplora_base_urls: conf
            .esplora_base_urls
            .iter()
            .map(|u| url::Url::parse(u).expect("esplora base url is not a valid URL"))
            .collect(),
        db_config: db_config,
        files_db_config: db_config_files,
        nostr_config: NostrConfig {
            relays: nostr_relays,
            blossom_servers,
            only_known_contacts: conf.nostr_only_known_contacts.unwrap_or(false),
            max_relays: conf.nostr_max_relays.or(Some(50)),
            relay_ack_threshold: conf.nostr_relay_ack_threshold.unwrap_or(1),
        },
        mint_config: MintConfig::new(conf.default_mint_url, mint_node_id)?,
        payment_config: PaymentConfig {
            num_confirmations_for_payment: conf.num_confirmations_for_payment,
        },
        dev_mode_config: DevModeConfig {
            on: conf.dev_mode,
            mandatory_email_confirmations: conf.mandatory_email_confirmations,
        },
        court_config: CourtConfig {
            default_url: url::Url::parse(&conf.default_court_url)
                .expect("court url is not a valid URL"),
        },
    };
    debug!("Config: {api_config:?}");
    bcr_ebill_api::init(api_config.clone())?;
    // make sure the configured default mint node id is valid for the configured network
    validate_node_id_network(&api_config.mint_config.default_mint_node_id)?;

    // init db
    let db = get_db_context(&api_config).await?;

    // set the network and check if the configured network matches the persisted network and fail, if not
    db.identity_store
        .set_or_check_network(api_config.bitcoin_network())
        .await?;
    let keys = db.identity_store.get_or_create_key_pair().await?;

    let node_id = NodeId::new(keys.pub_key(), api_config.bitcoin_network());
    info!("Initialized WASM API {}", general::VERSION);
    info!("Local node id: {node_id}");
    info!(
        "Local npub: {}",
        node_id
            .npub()
            .to_bech32()
            .expect("invalid npub from node id")
    );
    info!("Local npub as hex: {}", node_id.npub().to_hex());

    // init context
    let ctx = Context::new(api_config.clone(), db).await?;

    rt.ctx = Some(Arc::new(ctx));

    let cancel = CancellationToken::new();
    let handle = job::start_jobs(
        conf.job_runner_check_interval_seconds,
        conf.job_runner_initial_delay_seconds,
        cancel.clone(),
    );

    rt.jobs_cancel = Some(cancel);
    rt.jobs_handle = Some(handle);

    let default_mint_node_id = api_config.mint_config.default_mint_node_id.clone();
    let nostr_cancel = CancellationToken::new();
    let nostr_handle = nostr::start_subscription(
        default_mint_node_id,
        conf.job_runner_check_interval_seconds,
        conf.transport_initial_subscription_delay_seconds,
        nostr_cancel.clone(),
    );

    rt.nostr_subscription_cancel = Some(nostr_cancel);
    rt.nostr_subscription_handle = Some(nostr_handle);

    info!("Initialized Rust Ebill FFI");
    Ok(())
}

fn init_logging(log_level: &str) {
    info!("Initializing Rust logging");
    let level = log::LevelFilter::from_str(log_level).expect("invalid log level");

    #[cfg(target_os = "android")]
    {
        use android_logger::{Config, FilterBuilder};
        let mut filter = FilterBuilder::new();
        filter
            .filter_level(log::LevelFilter::Off)
            .filter_module("bcr_common", level)
            .filter_module("bcr_ebill_api", level)
            .filter_module("bcr_ebill_flutter_ffi", level)
            .filter_module("bcr_ebill_core", level)
            .filter_module("bcr_ebill_persistence", level)
            .filter_module("bcr_ebill_api", level)
            .filter_module("bcr_ebill_transport", level);

        android_logger::init_once(
            Config::default()
                .with_tag("WalletFfi")
                .with_max_level(level)
                .with_filter(filter.build()),
        );
    }

    #[cfg(not(target_os = "android"))]
    {
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Off)
            .filter_module("bcr_ebill_api", level)
            .filter_module("bcr_ebill_flutter_ffi", level)
            .filter_module("bcr_ebill_core", level)
            .filter_module("bcr_ebill_persistence", level)
            .filter_module("bcr_common", level)
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
