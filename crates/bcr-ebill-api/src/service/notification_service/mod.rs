use std::collections::HashMap;
use std::sync::Arc;

use crate::persistence::identity::IdentityStoreApi;
use crate::persistence::notification::NotificationStoreApi;
use crate::{Config, DbContext, get_config};
use bcr_ebill_core::NodeId;
use bcr_ebill_core::util::BcrKeys;
use bcr_ebill_persistence::company::CompanyStoreApi;
use bcr_ebill_persistence::nostr::{NostrChainEventStoreApi, NostrQueuedMessageStoreApi};
use bcr_ebill_transport::chain_keys::ChainKeyServiceApi;
use bcr_ebill_transport::handler::{
    BillActionEventHandler, BillChainEventHandler, BillChainEventProcessor, BillInviteEventHandler,
    CompanyChainEventHandler, CompanyChainEventProcessor, CompanyInviteEventHandler,
    LoggingEventHandler, NostrContactProcessor, NostrContactProcessorApi, NotificationHandlerApi,
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
        error!("Failed to get or create nostr key pair for nostr client: {e}");
        Error::Crypto("Failed to get or create nostr key pair".to_string())
    })?;
    let nostr_name = match identity_store.get().await {
        Ok(identity) => identity.get_nostr_name(),
        _ => "New user".to_owned(),
    };
    let mut configs: Vec<NostrConfig> = vec![NostrConfig::new(
        keys.clone(),
        config.nostr_config.relays.clone(),
        nostr_name,
        true,
        NodeId::new(keys.pub_key(), get_config().bitcoin_network()),
    )];

    // optionally collect all company accounts
    let companies = match company_store.get_all().await {
        Ok(companies) => companies,
        Err(e) => {
            error!("Failed to get companies for nostr client: {e}");
            HashMap::new()
        }
    };

    for (_, (company, keys)) in companies.iter() {
        if let Ok(k) = BcrKeys::try_from(keys) {
            configs.push(NostrConfig::new(
                k.clone(),
                config.nostr_config.relays.clone(),
                company.name.clone(),
                false,
                NodeId::new(k.pub_key(), get_config().bitcoin_network()),
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
    chain_event_store: Arc<dyn NostrChainEventStoreApi>,
    nostr_relays: Vec<String>,
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
        chain_event_store,
        nostr_relays,
    )))
}

/// Creates a new nostr consumer that will listen for incoming events and handle them
/// with the given handlers. The consumer is just set up here and needs to be started
/// via the run method later.
pub async fn create_nostr_consumer(
    clients: Vec<Arc<NostrClient>>,
    contact_service: Arc<dyn ContactServiceApi>,
    push_service: Arc<dyn PushApi>,
    chain_key_service: Arc<dyn ChainKeyServiceApi>,
    db_context: DbContext,
) -> Result<NostrConsumer> {
    // we need one nostr client for nostr interactions
    let transport = match clients.iter().find(|c| c.is_primary()) {
        Some(client) => client.clone(),
        None => panic!("Cant create Nostr consumer as there is no nostr client available"),
    };

    let nostr_contact_processor = Arc::new(NostrContactProcessor::new(
        transport.clone(),
        db_context.nostr_contact_store.clone(),
        get_config().bitcoin_network(),
    ));

    let bill_processor = Arc::new(BillChainEventProcessor::new(
        db_context.bill_blockchain_store.clone(),
        db_context.bill_store.clone(),
        nostr_contact_processor.clone(),
        get_config().bitcoin_network(),
    ));

    let company_processor = Arc::new(CompanyChainEventProcessor::new(
        db_context.company_chain_store.clone(),
        db_context.company_store.clone(),
        nostr_contact_processor.clone(),
        get_config().bitcoin_network(),
    ));

    // on startup, we make sure the configured default mint exists
    nostr_contact_processor
        .ensure_nostr_contact(&get_config().mint_config.default_mint_node_id)
        .await;

    // register the logging event handler for all events for now. Later we will probably
    // setup the handlers outside and pass them to the consumer via this functions arguments.
    let handlers: Vec<Box<dyn NotificationHandlerApi>> = vec![
        Box::new(LoggingEventHandler {
            event_types: EventType::all(),
        }),
        Box::new(BillActionEventHandler::new(
            db_context.notification_store.clone(),
            push_service,
            bill_processor.clone(),
        )),
        Box::new(BillInviteEventHandler::new(
            transport.clone(),
            bill_processor.clone(),
            db_context.nostr_chain_event_store.clone(),
        )),
        Box::new(BillChainEventHandler::new(
            bill_processor.clone(),
            db_context.bill_store.clone(),
            db_context.nostr_chain_event_store.clone(),
        )),
        Box::new(CompanyInviteEventHandler::new(
            transport.clone(),
            company_processor.clone(),
            db_context.nostr_chain_event_store.clone(),
        )),
        Box::new(CompanyChainEventHandler::new(
            db_context.company_store.clone(),
            company_processor.clone(),
            db_context.nostr_chain_event_store.clone(),
        )),
    ];
    debug!("initializing nostr consumer for {} clients", clients.len());
    let consumer = NostrConsumer::new(
        clients,
        contact_service,
        handlers,
        db_context.nostr_event_offset_store.clone(),
        chain_key_service,
    );
    Ok(consumer)
}
