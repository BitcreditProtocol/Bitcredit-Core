#![allow(clippy::arc_with_non_send_sync)]
use api::general::VERSION;
use bcr_ebill_api::data::validate_node_id_network;
use bcr_ebill_api::{
    Config as ApiConfig, MintConfig, NostrConfig, SurrealDbConfig, data::NodeId, get_db_context,
    init,
};
use bcr_ebill_api::{CourtConfig, DevModeConfig, PaymentConfig};
use context::{Context, get_ctx};
use job::run_jobs;
use log::info;
use serde::Deserialize;
use std::thread_local;
use std::time::Duration;
use std::{cell::RefCell, str::FromStr};
use tokio::spawn;
use tokio_with_wasm::alias as tokio;
use tsify::Tsify;
use wasm_bindgen::prelude::*;

pub mod api;
mod context;
mod data;
mod error;
mod job;

#[derive(Tsify, Debug, Clone, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct Config {
    pub log_level: Option<String>,
    pub app_url: String,
    pub bitcoin_network: String,
    pub esplora_base_url: String,
    pub nostr_relays: Vec<String>,
    pub nostr_only_known_contacts: Option<bool>,
    pub job_runner_initial_delay_seconds: u32,
    pub job_runner_check_interval_seconds: u32,
    pub default_mint_url: String,
    pub default_mint_node_id: String,
    pub num_confirmations_for_payment: usize,
    pub dev_mode: bool,
    pub default_court_url: String,
}

pub type Result<T> = std::result::Result<T, error::WasmError>;

thread_local! {
    static CONTEXT: RefCell<Option<&'static Context>> = const { RefCell::new(None) } ;
}

#[wasm_bindgen]
pub async fn initialize_api(
    #[wasm_bindgen(unchecked_param_type = "Config")] cfg: JsValue,
) -> Result<()> {
    // init config and API
    let config: Config = serde_wasm_bindgen::from_value(cfg)?;

    // init logging
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));
    let log_level = match config.log_level {
        Some(ref log_level) => match log_level.as_str() {
            "info" => log::LevelFilter::Info,
            "debug" => log::LevelFilter::Debug,
            "error" => log::LevelFilter::Error,
            "trace" => log::LevelFilter::Trace,
            _ => log::LevelFilter::Info,
        },
        None => log::LevelFilter::Info,
    };
    // only log from our own crates
    fern::Dispatch::new()
        .level(log::LevelFilter::Off)
        .level_for("bcr_ebill_wasm", log_level)
        .level_for("bcr_ebill_api", log_level)
        .level_for("bcr_ebill_persistence", log_level)
        .level_for("bcr_ebill_transport", log_level)
        .level_for("bcr_ebill_core", log_level)
        .chain(fern::Output::call(console_log::log))
        .apply()
        .expect("can initialize logging");
    let mint_node_id = NodeId::from_str(&config.default_mint_node_id)?;
    let api_config = ApiConfig {
        app_url: url::Url::parse(&config.app_url).expect("app url is not a valid URL"),
        bitcoin_network: config.bitcoin_network,
        esplora_base_url: config.esplora_base_url,
        db_config: SurrealDbConfig::default(),
        data_dir: "./".to_owned(), // unused in wasm
        nostr_config: NostrConfig {
            relays: config.nostr_relays.to_owned(),
            only_known_contacts: config.nostr_only_known_contacts.unwrap_or(false),
        },
        mint_config: MintConfig::new(config.default_mint_url, mint_node_id)?,
        payment_config: PaymentConfig {
            num_confirmations_for_payment: config.num_confirmations_for_payment,
        },
        dev_mode_config: DevModeConfig {
            on: config.dev_mode,
        },
        court_config: CourtConfig {
            default_url: url::Url::parse(&config.default_court_url)
                .expect("court url is not a valid URL"),
        },
    };
    init(api_config.clone())?;
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
    info!("Initialized WASM API {VERSION}");
    info!("Local node id: {node_id}");
    info!("Local npub: {:?}", node_id.npub());
    info!("Local npub as hex: {}", node_id.npub().to_hex());
    info!("Config: {api_config:?}");

    // init context as static reference
    let ctx = Context::new(api_config.clone(), db).await?;
    CONTEXT.with(|context| {
        let mut context_ref = context.borrow_mut();
        if context_ref.is_none() {
            let leaked: &'static Context = Box::leak(Box::new(ctx)); // leak to get a static ref
            *context_ref = Some(leaked);
        }
    });

    // start jobs
    wasm_bindgen_futures::spawn_local(async move {
        tokio::time::sleep(Duration::from_secs(
            config.job_runner_initial_delay_seconds as u64,
        ))
        .await;
        run_jobs(); // initial run
        let mut interval = tokio::time::interval(Duration::from_secs(
            config.job_runner_check_interval_seconds as u64,
        ));
        loop {
            interval.tick().await;
            run_jobs(); // regular run
        }
    });

    // start nostr subscription
    spawn(async {
        get_ctx()
            .nostr_consumer
            .start()
            .await
            .expect("nostr consumer failed");
    });
    Ok(())
}
