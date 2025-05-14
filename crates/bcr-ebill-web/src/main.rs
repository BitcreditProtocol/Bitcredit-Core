use crate::service_context::create_service_context;
use anyhow::Result;
use bcr_ebill_api::{NostrConfig, get_db_context};
use clap::Parser;
use config::Config;
use constants::SHUTDOWN_GRACE_PERIOD_MS;
use log::{error, info};
use tokio::{spawn, sync::broadcast};

mod api_docs;
mod config;
mod constants;
mod data;
mod error;
mod handlers;
mod job;
mod router;
mod service_context;

// MAIN
#[macro_use]
extern crate lazy_static;
lazy_static! {
    pub static ref CONFIG: Config = Config::parse();
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let conf = CONFIG.clone();
    // Initialize the API
    let api_config = bcr_ebill_api::Config {
        bitcoin_network: conf.bitcoin_network.clone(),
        esplora_base_url: conf.esplora_base_url.clone(),
        surreal_db_connection: conf.surreal_db_connection.clone(),
        data_dir: conf.data_dir.clone(),
        nostr_config: NostrConfig {
            relays: vec![conf.nostr_relay.clone()],
            ..Default::default()
        },
    };
    info!("Chosen Network: {:?}", api_config.bitcoin_network());
    bcr_ebill_api::init(api_config.clone())?;

    loop {
        let (reboot_sender, mut reboot_receiver) = tokio::sync::watch::channel(false);
        if let Err(e) = start(api_config.clone(), reboot_sender).await {
            error!("Error starting the application: {e}");
            break;
        }

        let reboot = *reboot_receiver.borrow_and_update();
        if reboot {
            // we need to give the os time to finish its disk operations
            tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
            info!("Restarting application...");
        } else {
            break;
        }
    }

    Ok(())
}

async fn start(
    api_config: bcr_ebill_api::Config,
    reboot_sender: tokio::sync::watch::Sender<bool>,
) -> Result<()> {
    // Initialize the database context
    let db = get_db_context(&api_config).await?;
    let (shutdown_sender, _) = broadcast::channel::<bool>(100);

    let ctrl_c_sender = shutdown_sender.clone();
    spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("can't register ctrl-c handler");
        info!("Received SIGINT. Shutting down...");

        if let Err(e) = ctrl_c_sender.send(true) {
            error!("Error triggering shutdown signal: {e}");
        }
    });

    let keys = db.identity_store.get_or_create_key_pair().await?;
    let local_node_id = db.identity_store.get_key_pair().await?.get_public_key();
    info!("Local node id: {local_node_id:?}");
    info!("Local npub: {:?}", keys.get_nostr_npub());
    info!("Local npriv: {:?}", keys.get_nostr_npriv());
    info!("Local npub as hex: {:?}", keys.get_nostr_npub_as_hex());

    if db.identity_store.exists().await {
        // TODO NOSTR: subscribe to updates on all local bills
        // TODO NOSTR: subscribe to updates on all local companies
        // TODO NOSTR: handle new incoming messages (new companies/bills)
        // TODO NOSTR: check and update propagated data on nostr based on local state
        // TODO NOSTR: react to incoming events and blocks
        //      * Company and Bill blocks - validate and reconcile with local chain
        //      * Company
        //          * AddSignatory - add signatory locally - if it's me - fetch company data, keys and files
        //          etc. and create company locally
        //          * RemoveSignatory - remove signatory locally, if it's me - remove company etc.
        //      * Bill
        //          * When added to a bill - fetch bill, keys and files and create bill locally
    }

    let job_shutdown_receiver = shutdown_sender.clone().subscribe();
    let web_server_error_shutdown_sender = shutdown_sender.clone();
    let service_context_shutdown_sender = shutdown_sender.clone();
    let service_context = create_service_context(
        &local_node_id,
        api_config.clone(),
        service_context_shutdown_sender,
        db,
        reboot_sender,
    )
    .await?;

    let service_context_clone = service_context.clone();
    spawn(async move { job::run(service_context_clone, job_shutdown_receiver).await });

    let service_context_nostr_clone = service_context.clone();
    // run subscription in a tokio task
    let nostr_handle = tokio::spawn(async move {
        // TODO: if it fails - restart? or shutdown?
        service_context_nostr_clone
            .nostr_consumer
            .start()
            .await
            .expect("nostr consumer failed");
    });

    if let Err(e) = router::rocket_main(CONFIG.clone(), service_context)
        .launch()
        .await
    {
        error!("Web server stopped with error: {e}, shutting down the rest of the application...");
        if let Err(e) = web_server_error_shutdown_sender.send(true) {
            error!("Error triggering shutdown signal: {e}");
        }
    }

    info!("Stopping nostr consumer...");
    nostr_handle.abort();

    info!("Waiting for application to exit...");
    // If the web server exits fast, we wait for a grace period so i/o can finish
    tokio::time::sleep(std::time::Duration::from_millis(SHUTDOWN_GRACE_PERIOD_MS)).await;

    Ok(())
}
