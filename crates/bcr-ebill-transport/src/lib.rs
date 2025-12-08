use std::{collections::HashMap, sync::Arc};

use bcr_common::core::NodeId;
use bcr_ebill_api::service::transport_service::{Error, Result, TransportServiceApi};
use bcr_ebill_api::{
    Config, DbContext,
    external::email::EmailClientApi,
    get_config, get_db_context,
    service::{
        contact_service::ContactServiceApi,
        transport_service::{NostrConfig, transport_client::TransportClientApi},
    },
};
use bcr_ebill_core::protocol::crypto::BcrKeys;
use bcr_ebill_core::protocol::event::EventType;
use bcr_ebill_persistence::{company::CompanyStoreApi, identity::IdentityStoreApi};
use chain_keys::ChainKeyServiceApi;
use handler::{
    BillActionEventHandler, BillChainEventHandler, BillChainEventProcessor, BillInviteEventHandler,
    CompanyChainEventHandler, CompanyChainEventProcessor, CompanyInviteEventHandler,
    IdentityChainEventHandler, IdentityChainEventProcessor, LoggingEventHandler,
    NostrContactProcessor, NotificationHandlerApi,
};
use log::{debug, error, warn};
pub use nostr_transport::NostrTransportService;

mod block_transport;
pub mod chain_keys;
mod contact_transport;
pub mod handler;
mod nostr;
mod nostr_transport;
mod notification_transport;
pub mod push_notification;
#[cfg(test)]
pub mod test_utils;
mod transport;
pub mod transport_service;

pub use async_broadcast::Receiver;
pub use handler::RestoreAccountService;
pub use nostr::{NostrClient, NostrConsumer};
pub use push_notification::{PushApi, PushService};
pub use transport::bcr_nostr_tag;

use crate::block_transport::BlockTransportService;
use crate::contact_transport::ContactTransportService;
use crate::handler::{ContactShareEventHandler, DirectMessageEventProcessor};
use crate::notification_transport::NotificationTransportService;
use crate::transport_service::TransportService;

/// Creates a single multi-identity nostr client configured with the current identity user and all local companies.
pub async fn create_nostr_clients(
    config: &Config,
    identity_store: Arc<dyn IdentityStoreApi>,
    company_store: Arc<dyn CompanyStoreApi>,
    nostr_contact_store: Arc<dyn bcr_ebill_persistence::nostr::NostrContactStoreApi>,
) -> Result<Arc<NostrClient>> {
    // primary identity is required to launch
    let keys = identity_store.get_or_create_key_pair().await.map_err(|e| {
        error!("Failed to get or create nostr key pair for nostr client: {e}");
        Error::Crypto("Failed to get or create nostr key pair".to_string())
    })?;

    let primary_node_id = NodeId::new(keys.pub_key(), get_config().bitcoin_network());
    let mut identities = vec![(primary_node_id.clone(), keys.clone())];

    debug!("Adding primary identity: {}", primary_node_id);

    // optionally collect all company accounts
    let mut companies = match company_store.get_all().await {
        Ok(companies) => companies,
        Err(e) => {
            error!("Failed to get companies for nostr client: {e}");
            HashMap::new()
        }
    };

    // we collect companies we were invited to as well, so we can accept/reject the invite
    let invite_companies = match company_store.get_active_company_invites().await {
        Ok(companies) => companies,
        Err(e) => {
            error!("Failed to get invite companies for nostr client: {e}");
            HashMap::new()
        }
    };
    companies.extend(invite_companies);

    // Add all company identities
    for (_, (_company, company_keys)) in companies.iter() {
        let company_node_id = NodeId::new(company_keys.pub_key(), get_config().bitcoin_network());
        debug!("Adding company identity: {}", company_node_id);
        identities.push((company_node_id, company_keys.clone()));
    }

    // Create single multi-identity client with all identities
    debug!(
        "Creating single multi-identity Nostr client with {} identities",
        identities.len()
    );
    let client = NostrClient::new(
        identities,
        config.nostr_config.relays.clone(),
        std::time::Duration::from_secs(20),
        config.nostr_config.max_relays,
        Some(nostr_contact_store),
    )
    .await?;

    // Initial relay refresh to include contact relays
    if let Err(e) = client.refresh_relays().await {
        warn!("Failed initial relay refresh: {}", e);
        // Continue anyway - we have user relays at minimum
    }

    Ok(Arc::new(client))
}

/// Creates a new transport service that will send events via the given Nostr transport.
pub async fn create_transport_service(
    client: Arc<NostrClient>,
    db_context: DbContext,
    email_client: Arc<dyn EmailClientApi>,
    nostr_relays: Vec<url::Url>,
    push_service: Arc<dyn PushApi>,
) -> Result<Arc<dyn TransportServiceApi>> {
    let transport = client.clone();

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
        db_context.notification_store.clone(),
        nostr_contact_processor.clone(),
        bill_invite_handler.clone(),
        push_service,
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
        Arc::new(company_invite_handler.clone()),
        bill_invite_handler.clone(),
        nostr_contact_processor.clone(),
        transport.clone(),
        get_config().bitcoin_network(),
    ));

    let nostr_transport = Arc::new(NostrTransportService::new(
        client,
        db_context.contact_store,
        db_context.nostr_contact_store.clone(),
        db_context.queued_message_store.clone(),
        db_context.nostr_chain_event_store.clone(),
        nostr_relays,
    ));

    let block_transport = Arc::new(BlockTransportService::new(
        nostr_transport.clone(),
        bill_processor.clone(),
        company_processor.clone(),
        identity_processor.clone(),
    ));

    let contact_transport = Arc::new(ContactTransportService::new(
        nostr_transport.clone(),
        db_context.nostr_contact_store.clone(),
        nostr_contact_processor.clone(),
    ));

    let notification_transport = Arc::new(NotificationTransportService::new(
        nostr_transport.clone(),
        db_context.notification_store.clone(),
        db_context.email_notification_store.clone(),
        email_client,
    ));

    #[allow(clippy::arc_with_non_send_sync)]
    Ok(Arc::new(TransportService::new(
        nostr_transport.clone(),
        notification_transport,
        contact_transport,
        block_transport,
    )))
}

/// Creates a new nostr consumer that will listen for incoming events and handle them
/// with the given handlers. The consumer is just set up here and needs to be started
/// via the run method later.
pub async fn create_nostr_consumer(
    client: Arc<NostrClient>,
    contact_service: Arc<dyn ContactServiceApi>,
    push_service: Arc<dyn PushApi>,
    chain_key_service: Arc<dyn ChainKeyServiceApi>,
    db_context: DbContext,
) -> Result<NostrConsumer> {
    // we need one nostr client for nostr interactions
    let transport = client.clone();

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
        db_context.notification_store.clone(),
        nostr_contact_processor.clone(),
        bill_invite_handler.clone(),
        push_service.clone(),
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
        Arc::new(company_invite_handler.clone()),
        bill_invite_handler.clone(),
        nostr_contact_processor.clone(),
        transport.clone(),
        get_config().bitcoin_network(),
    ));

    // register the logging event handler for all events for now. Later we will probably
    // setup the handlers outside and pass them to the consumer via this functions arguments.
    let handlers: Vec<Arc<dyn NotificationHandlerApi>> = vec![
        Arc::new(LoggingEventHandler {
            event_types: EventType::all(),
        }),
        Arc::new(BillActionEventHandler::new(
            db_context.notification_store.clone(),
            push_service.clone(),
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
            db_context.notification_store.clone(),
            push_service.clone(),
        )),
    ];
    debug!("initializing nostr consumer with single multi-identity client");
    let consumer = NostrConsumer::new(
        client,
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
    push_service: Arc<dyn PushApi>,
) -> Result<RestoreAccountService> {
    let db_context = get_db_context(config)
        .await
        .expect("could not create db context");

    let node_id = NodeId::new(keys.pub_key(), config.bitcoin_network());
    let nostr_config = NostrConfig::new(
        keys.clone(),
        config.nostr_config.relays.clone(),
        true,
        node_id.clone(),
    );

    let nostr_client = Arc::new(NostrClient::default(&nostr_config).await?);
    nostr_client.connect().await?;
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
        db_context.notification_store.clone(),
        nostr_contact_processor.clone(),
        bill_invite_handler.clone(),
        push_service,
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

    Ok(
        RestoreAccountService::new(nostr_client, processor, dm_processor, keys.clone(), node_id)
            .await,
    )
}
