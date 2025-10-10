use std::{collections::HashMap, sync::Arc};

use bcr_ebill_api::{
    Config, DbContext,
    external::email::EmailClientApi,
    get_config, get_db_context,
    service::{
        contact_service::ContactServiceApi,
        notification_service::{
            NostrConfig, NotificationServiceApi, event::EventType,
            transport::NotificationJsonTransportApi,
        },
    },
    util::BcrKeys,
};
use bcr_ebill_core::NodeId;
use bcr_ebill_persistence::{company::CompanyStoreApi, identity::IdentityStoreApi};
use chain_keys::ChainKeyServiceApi;
use handler::{
    BillActionEventHandler, BillChainEventHandler, BillChainEventProcessor, BillInviteEventHandler,
    CompanyChainEventHandler, CompanyChainEventProcessor, CompanyInviteEventHandler,
    IdentityChainEventHandler, IdentityChainEventProcessor, LoggingEventHandler,
    NostrContactProcessor, NostrContactProcessorApi, NotificationHandlerApi,
};
use log::{debug, error};

pub mod chain_keys;
pub mod handler;
mod nostr;
pub mod notification_service;
pub mod push_notification;
#[cfg(test)]
pub mod test_utils;
pub mod transport;

pub use async_broadcast::Receiver;
pub use bcr_ebill_api::service::notification_service::{Error, Result};
pub use handler::RestoreAccountService;
pub use nostr::{NostrClient, NostrConsumer};
use notification_service::NotificationService;
pub use push_notification::{PushApi, PushService};
pub use transport::bcr_nostr_tag;

use crate::handler::{ContactShareEventHandler, DirectMessageEventProcessor};

/// Creates new nostr clients configured with the current identity user and all local companies.
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
    let mut configs: Vec<NostrConfig> = vec![NostrConfig::new(
        keys.clone(),
        config.nostr_config.relays.clone(),
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

    for (_, (_company, keys)) in companies.iter() {
        if let Ok(k) = BcrKeys::try_from(keys) {
            configs.push(NostrConfig::new(
                k.clone(),
                config.nostr_config.relays.clone(),
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
    db_context: DbContext,
    email_client: Arc<dyn EmailClientApi>,
    nostr_relays: Vec<url::Url>,
) -> Result<Arc<dyn NotificationServiceApi>> {
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
        transport.clone(),
        get_config().bitcoin_network(),
    ));
    let bill_invite_handler = Arc::new(BillInviteEventHandler::new(
        bill_processor.clone(),
        db_context.nostr_chain_event_store.clone(),
    ));
    let company_processor = Arc::new(CompanyChainEventProcessor::new(
        db_context.company_chain_store.clone(),
        db_context.company_store.clone(),
        db_context.identity_store.clone(),
        db_context.identity_proof_store.clone(),
        nostr_contact_processor.clone(),
        bill_invite_handler.clone(),
        transport.clone(),
        get_config().bitcoin_network(),
    ));
    let company_invite_handler = CompanyInviteEventHandler::new(
        transport.clone(),
        company_processor.clone(),
        db_context.nostr_chain_event_store.clone(),
    );
    let identity_processor = Arc::new(IdentityChainEventProcessor::new(
        db_context.identity_chain_store.clone(),
        db_context.identity_store.clone(),
        db_context.identity_proof_store.clone(),
        Arc::new(company_invite_handler.clone()),
        bill_invite_handler.clone(),
        nostr_contact_processor.clone(),
        transport.clone(),
        get_config().bitcoin_network(),
    ));

    #[allow(clippy::arc_with_non_send_sync)]
    Ok(Arc::new(NotificationService::new(
        clients
            .iter()
            .map(|c| c.clone() as Arc<dyn NotificationJsonTransportApi>)
            .collect(),
        db_context.notification_store.clone(),
        db_context.email_notification_store.clone(),
        db_context.contact_store,
        db_context.nostr_contact_store,
        db_context.queued_message_store.clone(),
        db_context.nostr_chain_event_store.clone(),
        email_client,
        bill_processor,
        company_processor,
        identity_processor,
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
        transport.clone(),
        get_config().bitcoin_network(),
    ));

    let bill_invite_handler = Arc::new(BillInviteEventHandler::new(
        bill_processor.clone(),
        db_context.nostr_chain_event_store.clone(),
    ));

    let company_processor = Arc::new(CompanyChainEventProcessor::new(
        db_context.company_chain_store.clone(),
        db_context.company_store.clone(),
        db_context.identity_store.clone(),
        db_context.identity_proof_store.clone(),
        nostr_contact_processor.clone(),
        bill_invite_handler.clone(),
        transport.clone(),
        get_config().bitcoin_network(),
    ));

    let company_invite_handler = CompanyInviteEventHandler::new(
        transport.clone(),
        company_processor.clone(),
        db_context.nostr_chain_event_store.clone(),
    );

    let identity_processor = Arc::new(IdentityChainEventProcessor::new(
        db_context.identity_chain_store.clone(),
        db_context.identity_store.clone(),
        db_context.identity_proof_store.clone(),
        Arc::new(company_invite_handler.clone()),
        bill_invite_handler.clone(),
        nostr_contact_processor.clone(),
        transport.clone(),
        get_config().bitcoin_network(),
    ));

    // on startup, we make sure the configured default mint exists
    nostr_contact_processor
        .ensure_nostr_contact(&get_config().mint_config.default_mint_node_id)
        .await;

    // register the logging event handler for all events for now. Later we will probably
    // setup the handlers outside and pass them to the consumer via this functions arguments.
    let handlers: Vec<Arc<dyn NotificationHandlerApi>> = vec![
        Arc::new(LoggingEventHandler {
            event_types: EventType::all(),
        }),
        Arc::new(BillActionEventHandler::new(
            db_context.notification_store.clone(),
            push_service,
            bill_processor.clone(),
        )),
        bill_invite_handler,
        Arc::new(BillChainEventHandler::new(
            bill_processor.clone(),
            db_context.bill_store.clone(),
            db_context.nostr_chain_event_store.clone(),
        )),
        Arc::new(company_invite_handler),
        Arc::new(CompanyChainEventHandler::new(
            db_context.company_store.clone(),
            company_processor.clone(),
            db_context.nostr_chain_event_store.clone(),
        )),
        Arc::new(IdentityChainEventHandler::new(
            db_context.identity_store.clone(),
            identity_processor.clone(),
            db_context.nostr_chain_event_store.clone(),
        )),
        Arc::new(ContactShareEventHandler::new(
            transport.clone(),
            db_context.contact_store.clone(),
            db_context.nostr_contact_store.clone(),
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

pub async fn create_restore_account_service(
    config: &Config,
    keys: &BcrKeys,
    chain_key_service: Arc<dyn ChainKeyServiceApi>,
    contact_service: Arc<dyn ContactServiceApi>,
) -> Result<RestoreAccountService> {
    let db_context = get_db_context(config)
        .await
        .expect("could not create db context");

    let node_id = NodeId::new(keys.pub_key(), config.bitcoin_network());
    let nostr_config = NostrConfig::new(
        keys.clone(),
        config.nostr_config.relays.clone(),
        true,
        node_id,
    );

    let nostr_client = Arc::new(NostrClient::default(&nostr_config).await?);
    let nostr_contact_processor = Arc::new(NostrContactProcessor::new(
        nostr_client.clone(),
        db_context.nostr_contact_store.clone(),
        config.bitcoin_network(),
    ));

    let bill_processor = Arc::new(BillChainEventProcessor::new(
        db_context.bill_blockchain_store.clone(),
        db_context.bill_store.clone(),
        nostr_contact_processor.clone(),
        nostr_client.clone(),
        get_config().bitcoin_network(),
    ));

    let bill_invite_handler = Arc::new(BillInviteEventHandler::new(
        bill_processor.clone(),
        db_context.nostr_chain_event_store.clone(),
    ));

    let company_processor = Arc::new(CompanyChainEventProcessor::new(
        db_context.company_chain_store.clone(),
        db_context.company_store.clone(),
        db_context.identity_store.clone(),
        db_context.identity_proof_store.clone(),
        nostr_contact_processor.clone(),
        bill_invite_handler.clone(),
        nostr_client.clone(),
        config.bitcoin_network(),
    ));

    let company_invite_handler = Arc::new(CompanyInviteEventHandler::new(
        nostr_client.clone(),
        company_processor.clone(),
        db_context.nostr_chain_event_store.clone(),
    ));

    let processor = Arc::new(IdentityChainEventProcessor::new(
        db_context.identity_chain_store.clone(),
        db_context.identity_store.clone(),
        db_context.identity_proof_store.clone(),
        company_invite_handler.clone(),
        bill_invite_handler.clone(),
        nostr_contact_processor,
        nostr_client.clone(),
        config.bitcoin_network(),
    ));

    let dm_processor = Arc::new(
        DirectMessageEventProcessor::new(
            nostr_client.clone(),
            contact_service.clone(),
            db_context.nostr_event_offset_store.clone(),
            chain_key_service.clone(),
            vec![company_invite_handler, bill_invite_handler],
        )
        .await,
    );

    Ok(RestoreAccountService::new(nostr_client, processor, dm_processor, keys.clone()).await)
}
