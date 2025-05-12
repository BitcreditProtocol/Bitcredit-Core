use std::collections::HashMap;
use std::sync::Arc;

use crate::Config;
use crate::persistence::identity::IdentityStoreApi;
use crate::persistence::nostr::NostrEventOffsetStoreApi;
use crate::persistence::notification::NotificationStoreApi;
use bcr_ebill_persistence::bill::{BillChainStoreApi, BillStoreApi};
use bcr_ebill_persistence::company::CompanyStoreApi;
use bcr_ebill_persistence::nostr::{NostrContactStoreApi, NostrQueuedMessageStoreApi};
use bcr_ebill_transport::handler::{
    BillChainEventHandler, LoggingEventHandler, NotificationHandlerApi,
};
use bcr_ebill_transport::{Error, EventType, Result};
use bcr_ebill_transport::{NotificationServiceApi, PushApi};
use default_service::DefaultNotificationService;
#[cfg(test)]
pub mod test_utils;

pub mod default_service;
mod nostr;

pub use bcr_ebill_transport::NotificationJsonTransportApi;
use log::{debug, error};
pub use nostr::{NostrClient, NostrConfig, NostrConsumer};

use super::contact_service::ContactServiceApi;

/// Creates a new nostr client configured with the current identity user.
pub async fn create_nostr_clients(
    config: &Config,
    identity_store: Arc<dyn IdentityStoreApi>,
    company_store: Arc<dyn CompanyStoreApi>,
) -> Result<Vec<Arc<NostrClient>>> {
    // primary identity is required to launch
    let keys = identity_store.get_or_create_key_pair().await.map_err(|e| {
        error!(
            "Failed to get or create nostr key pair for nostr client: {}",
            e
        );
        Error::Crypto("Failed to get or create nostr key pair".to_string())
    })?;
    let nostr_name = match identity_store.get().await {
        Ok(identity) => identity.get_nostr_name(),
        _ => "New user".to_owned(),
    };
    let mut configs: Vec<NostrConfig> = vec![NostrConfig::new(
        keys,
        config.nostr_config.relays.clone(),
        nostr_name,
    )];

    // optionally collect all company accounts
    let companies = match company_store.get_all().await {
        Ok(companies) => companies,
        Err(e) => {
            error!("Failed to get companies for nostr client: {}", e);
            HashMap::new()
        }
    };

    for (_, (company, keys)) in companies.iter() {
        if let Ok(keys) = keys.clone().try_into() {
            configs.push(NostrConfig::new(
                keys,
                config.nostr_config.relays.clone(),
                company.name.clone(),
            ));
        }
    }

    // init all the clients
    let mut clients = vec![];
    for config in configs {
        debug!("initializing nostr client for {}", &config.get_npub());
        if let Ok(client) = NostrClient::new(&config).await {
            debug!("initialized nostr client for {}", &config.get_npub());
            clients.push(Arc::new(client));
        }
    }

    Ok(clients)
}

/// Creates a new notification service that will send events via the given Nostr json transport.
pub async fn create_notification_service(
    clients: Vec<Arc<NostrClient>>,
    notification_store: Arc<dyn NotificationStoreApi>,
    contact_service: Arc<dyn ContactServiceApi>,
    queued_message_store: Arc<dyn NostrQueuedMessageStoreApi>,
    nostr_relay: &str,
) -> Result<Arc<dyn NotificationServiceApi>> {
    #[allow(clippy::arc_with_non_send_sync)]
    Ok(Arc::new(DefaultNotificationService::new(
        clients
            .iter()
            .map(|c| c.clone() as Arc<dyn NotificationJsonTransportApi>)
            .collect(),
        notification_store,
        contact_service,
        queued_message_store,
        nostr_relay,
    )))
}

/// Creates a new nostr consumer that will listen for incoming events and handle them
/// with the given handlers. The consumer is just set up here and needs to be started
/// via the run method later.
pub async fn create_nostr_consumer(
    clients: Vec<Arc<NostrClient>>,
    contact_service: Arc<dyn ContactServiceApi>,
    nostr_event_offset_store: Arc<dyn NostrEventOffsetStoreApi>,
    notification_store: Arc<dyn NotificationStoreApi>,
    push_service: Arc<dyn PushApi>,
    bill_blockchain_store: Arc<dyn BillChainStoreApi>,
    bill_store: Arc<dyn BillStoreApi>,
    nostr_contact_store: Arc<dyn NostrContactStoreApi>,
) -> Result<NostrConsumer> {
    // we need one nostr client for nostr interactions
    let transport = match clients.first() {
        Some(client) => client.clone(),
        None => panic!("Cant create Nostr consumer as there is no nostr client available"),
    };
    // register the logging event handler for all events for now. Later we will probably
    // setup the handlers outside and pass them to the consumer via this functions arguments.
    let handlers: Vec<Box<dyn NotificationHandlerApi>> = vec![
        Box::new(LoggingEventHandler {
            event_types: EventType::all(),
        }),
        Box::new(BillChainEventHandler::new(
            notification_store,
            push_service,
            bill_blockchain_store,
            bill_store,
            transport,
            nostr_contact_store,
        )),
    ];
    debug!("initializing nostr consumer for {} clients", clients.len());
    let consumer = NostrConsumer::new(clients, contact_service, handlers, nostr_event_offset_store);
    Ok(consumer)
}
