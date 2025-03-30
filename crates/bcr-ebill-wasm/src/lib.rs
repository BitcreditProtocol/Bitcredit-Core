#![allow(clippy::arc_with_non_send_sync)]
use bcr_ebill_api::{Config as ApiConfig, get_db_context, init};
use constants::SURREAL_DB_CON_INDXDB_DATA;
use context::{Context, get_ctx};
use futures::{StreamExt, future::ready};
use gloo_timers::future::{IntervalStream, TimeoutFuture};
use job::run_jobs;
use log::info;
use serde::Deserialize;
use std::cell::RefCell;
use std::thread_local;
use tokio::spawn;
use tokio_with_wasm::alias as tokio;
use tsify::Tsify;
use wasm_bindgen::prelude::*;

pub mod api;
mod constants;
mod context;
mod data;
mod error;
mod job;

#[derive(Tsify, Debug, Clone, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct Config {
    pub log_level: Option<log::Level>,
    pub bitcoin_network: String,
    pub nostr_relay: String,
    pub job_runner_initial_delay_seconds: u32,
    pub job_runner_check_interval_seconds: u32,
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
    console_log::init_with_level(config.log_level.unwrap_or(log::Level::Info))
        .expect("can initialize logging");
    let api_config = ApiConfig {
        bitcoin_network: config.bitcoin_network,
        nostr_relay: config.nostr_relay,
        surreal_db_connection: SURREAL_DB_CON_INDXDB_DATA.to_owned(),
        data_dir: "./".to_owned(), // unused in wasm
    };
    init(api_config.clone())?;

    // init db
    let db = get_db_context(&api_config).await?;
    let keys = db.identity_store.get_or_create_key_pair().await?;

    info!("Local node id: {:?}", keys.get_public_key());
    info!("Local npub: {:?}", keys.get_nostr_npub());
    info!("Local npub as hex: {:?}", keys.get_nostr_npub_as_hex());
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
        TimeoutFuture::new(config.job_runner_initial_delay_seconds * 1000).await;
        IntervalStream::new(config.job_runner_check_interval_seconds * 1000)
            .for_each(|_| {
                run_jobs();
                ready(())
            })
            .await;
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
