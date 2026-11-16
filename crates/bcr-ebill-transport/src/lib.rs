#![recursion_limit = "256"]
use std::sync::Arc;

use bcr_common::core::NodeId;
use bcr_ebill_api::external::mint::MintClientApi;
use bcr_ebill_api::service::transport_service::propagation::{
    BLOCK_PROPAGATION_THRESHOLD, relay_quorum_snapshot,
};
use bcr_ebill_api::service::transport_service::{Error, Result, TransportServiceApi};
use bcr_ebill_api::{
    Config, DbContext,
    external::email::EmailClientApi,
    get_db_context,
    service::{
        contact_service::ContactServiceApi,
        transport_service::{NostrConfig, transport_client::TransportClientApi},
    },
};
use bcr_ebill_core::protocol::crypto::BcrKeys;
use bcr_ebill_core::protocol::event::EventType;
use bcr_ebill_persistence::{traits::company::CompanyStoreApi, traits::identity::IdentityStoreApi};
use chain_keys::ChainKeyServiceApi;
use handler::{
    BillActionEventHandler, BillChainEventProcessor, BillInviteEventHandler,
    CompanyChainEventProcessor, CompanyInviteEventHandler, IdentityChainEventProcessor,
    LoggingEventHandler, NostrContactProcessor, NotificationHandlerApi,
};
use log::{debug, error, warn};
pub use nostr_transport::NostrTransportService;

mod block_transport;
pub mod chain_keys;
mod contact_transport;
pub mod handler;
pub mod incoming_verification;
mod nostr;
mod nostr_transport;
mod notification_transport;
pub mod propagation;
pub mod push_notification;
pub mod relay_sync;
#[cfg(test)]
pub mod test_utils;
mod transport;
pub mod transport_service;

pub use async_broadcast::Receiver;
pub use handler::RestoreAccountService;
pub use nostr::{NostrClient, NostrConsumer};
pub use propagation::NostrPropagationService;
pub use push_notification::{PushApi, PushService};
pub use transport::bcr_nostr_tag;

use crate::block_transport::BlockTransportService;
use crate::contact_transport::ContactTransportService;
use crate::handler::{
    ContactShareEventHandler, DirectMessageEventProcessor, FileMetadataProcessor,
    IncomingChainApplication,
};
use crate::incoming_verification::IncomingPropagationVerifier;
use crate::notification_transport::NotificationTransportService;
use crate::transport_service::TransportService;

/// Creates a single multi-identity nostr client configured with the current identity user and all local companies.
pub async fn create_nostr_clients(
    config: Arc<Config>,
    identity_store: Arc<dyn IdentityStoreApi>,
    company_store: Arc<dyn CompanyStoreApi>,
    nostr_contact_store: Arc<dyn bcr_ebill_persistence::traits::nostr::NostrContactStoreApi>,
) -> Result<Arc<NostrClient>> {
    // primary identity is required to launch
    let keys = identity_store.get_key_pair().await.map_err(|e| {
        error!("Failed to get nostr key pair for nostr client: {e}");
        Error::Crypto("Failed to get nostr key pair".to_string())
    })?;

    let primary_node_id = NodeId::new(keys.pub_key(), config.bitcoin_network());
    let mut identities = vec![(primary_node_id.clone(), keys.clone())];

    debug!("Adding primary identity: {}", primary_node_id);

    // collect company accounts
    // we collect companies we were invited to as well, so we can accept/reject the invite
    let company_ids = match company_store.get_key_ids().await {
        Ok(companies) => companies,
        Err(e) => {
            error!("Failed to get companies for nostr client: {e}");
            vec![]
        }
    };

    for company_id in company_ids {
        let company_keys = match company_store.get_key_pair(&company_id).await {
            Ok(key) => key,
            Err(e) => {
                error!("Failed to get company key for {company_id} for nostr client: {e}");
                continue;
            }
        };
        debug!("Adding company signer: {company_id}");
        identities.push((company_id, company_keys));
    }

    // Create single multi-identity client with all identities
    debug!(
        "Creating single multi-identity Nostr client with {} identities",
        identities.len()
    );
    let client = NostrClient::new(
        identities,
        config.nostr_config.relays.clone(),
        config.nostr_config.blossom_servers.clone(),
        std::time::Duration::from_secs(20),
        config.nostr_config.max_relays,
        config.nostr_config.relay_ack_threshold,
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
    mint_client: Arc<dyn MintClientApi>,
    config: Arc<Config>,
) -> Result<Arc<dyn TransportServiceApi>> {
    let transport = client.clone();

    let propagation_service = Arc::new(NostrPropagationService::new(
        db_context.nostr_propagation_store.clone(),
        transport.clone(),
        config.bitcoin_network(),
    ));

    let nostr_contact_processor = Arc::new(NostrContactProcessor::new(
        transport.clone(),
        db_context.nostr_contact_store.clone(),
        config.bitcoin_network(),
        Some(client.clone()),
    ));
    let bill_processor = Arc::new(BillChainEventProcessor::new(
        db_context.bill_blockchain_store.clone(),
        db_context.bill_store.clone(),
        db_context.file_reference_store.clone(),
        nostr_contact_processor.clone(),
        db_context.nostr_chain_event_store.clone(),
        transport.clone(),
        mint_client,
        db_context.transaction_mgr.clone(),
        config.bitcoin_network(),
        config.clone(),
    ));
    let bill_invite_handler = Arc::new(BillInviteEventHandler::new(
        bill_processor.clone(),
        db_context.incoming_propagation_store.clone(),
    ));
    let company_processor = Arc::new(CompanyChainEventProcessor::new(
        db_context.company_chain_store.clone(),
        db_context.company_store.clone(),
        db_context.file_reference_store.clone(),
        db_context.identity_store.clone(),
        db_context.notification_store.clone(),
        nostr_contact_processor.clone(),
        bill_invite_handler.clone(),
        push_service.clone(),
        db_context.nostr_chain_event_store.clone(),
        transport.clone(),
        db_context.contact_store.clone(),
        db_context.transaction_mgr.clone(),
        config.bitcoin_network(),
        config.clone(),
    ));
    let company_invite_handler = CompanyInviteEventHandler::new(
        transport.clone(),
        company_processor.clone(),
        db_context.incoming_propagation_store.clone(),
    );
    let identity_processor = Arc::new(IdentityChainEventProcessor::new(
        db_context.identity_chain_store.clone(),
        db_context.identity_store.clone(),
        db_context.file_reference_store.clone(),
        Arc::new(company_invite_handler.clone()),
        bill_invite_handler.clone(),
        nostr_contact_processor.clone(),
        db_context.nostr_chain_event_store.clone(),
        transport.clone(),
        db_context.contact_store.clone(),
        db_context.transaction_mgr.clone(),
        config.bitcoin_network(),
        config.clone(),
    ));

    let nostr_transport = Arc::new(NostrTransportService::new(
        client,
        db_context.contact_store,
        db_context.nostr_contact_store.clone(),
        db_context.nostr_chain_event_store.clone(),
        nostr_relays,
        config.clone(),
    ));

    let block_transport = Arc::new(BlockTransportService::new(
        nostr_transport.clone(),
        bill_processor.clone(),
        company_processor.clone(),
        identity_processor.clone(),
        config.clone(),
    ));

    let contact_transport = Arc::new(ContactTransportService::new(
        nostr_transport.clone(),
        db_context.nostr_contact_store.clone(),
        nostr_contact_processor.clone(),
        config.clone(),
    ));

    let notification_transport = Arc::new(NotificationTransportService::new(
        db_context.notification_store.clone(),
        db_context.email_notification_store.clone(),
        email_client,
        push_service.clone(),
        config.clone(),
    ));

    #[allow(clippy::arc_with_non_send_sync)]
    Ok(Arc::new(TransportService::new(
        nostr_transport.clone(),
        notification_transport,
        contact_transport,
        block_transport,
        bill_invite_handler,
        propagation_service,
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
    mint_client: Arc<dyn MintClientApi>,
    config: Arc<Config>,
) -> Result<NostrConsumer> {
    // we need one nostr client for nostr interactions
    let transport = client.clone();

    let nostr_contact_processor = Arc::new(NostrContactProcessor::new(
        transport.clone(),
        db_context.nostr_contact_store.clone(),
        config.bitcoin_network(),
        Some(client.clone()),
    ));

    let bill_processor = Arc::new(BillChainEventProcessor::new(
        db_context.bill_blockchain_store.clone(),
        db_context.bill_store.clone(),
        db_context.file_reference_store.clone(),
        nostr_contact_processor.clone(),
        db_context.nostr_chain_event_store.clone(),
        transport.clone(),
        mint_client,
        db_context.transaction_mgr.clone(),
        config.bitcoin_network(),
        config.clone(),
    ));

    let (catchup_tx, _) = tokio::sync::broadcast::channel::<chain_keys::KnownChain>(64);

    let bill_invite_handler = Arc::new(
        BillInviteEventHandler::new(
            bill_processor.clone(),
            db_context.incoming_propagation_store.clone(),
        )
        .with_catchup_hints(catchup_tx.clone()),
    );

    let company_processor = Arc::new(CompanyChainEventProcessor::new(
        db_context.company_chain_store.clone(),
        db_context.company_store.clone(),
        db_context.file_reference_store.clone(),
        db_context.identity_store.clone(),
        db_context.notification_store.clone(),
        nostr_contact_processor.clone(),
        bill_invite_handler.clone(),
        push_service.clone(),
        db_context.nostr_chain_event_store.clone(),
        transport.clone(),
        db_context.contact_store.clone(),
        db_context.transaction_mgr.clone(),
        config.bitcoin_network(),
        config.clone(),
    ));

    let company_invite_handler = CompanyInviteEventHandler::new(
        transport.clone(),
        company_processor.clone(),
        db_context.incoming_propagation_store.clone(),
    )
    .with_catchup_hints(catchup_tx.clone());

    let identity_processor = Arc::new(IdentityChainEventProcessor::new(
        db_context.identity_chain_store.clone(),
        db_context.identity_store.clone(),
        db_context.file_reference_store.clone(),
        Arc::new(company_invite_handler.clone()),
        bill_invite_handler.clone(),
        nostr_contact_processor.clone(),
        db_context.nostr_chain_event_store.clone(),
        transport.clone(),
        db_context.contact_store.clone(),
        db_context.transaction_mgr.clone(),
        config.bitcoin_network(),
        config.clone(),
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
        Arc::new(company_invite_handler),
        Arc::new(ContactShareEventHandler::new(
            transport.clone(),
            db_context.contact_store.clone(),
            db_context.nostr_contact_store.clone(),
            db_context.file_reference_store.clone(),
            db_context.notification_store.clone(),
            push_service.clone(),
        )),
    ];

    let incoming_application = IncomingChainApplication::new(
        chain_key_service.clone(),
        bill_processor.clone(),
        company_processor.clone(),
        identity_processor.clone(),
        db_context.nostr_chain_event_store.clone(),
    );

    debug!("initializing nostr consumer with single multi-identity client");
    let file_metadata_processor = Arc::new(FileMetadataProcessor::new(
        db_context.file_reference_store.clone(),
    ));
    let relay_snapshot =
        relay_quorum_snapshot(&config.nostr_config.relays, BLOCK_PROPAGATION_THRESHOLD)?;
    let consumer = NostrConsumer::new(
        client,
        contact_service,
        handlers,
        db_context.nostr_event_offset_store.clone(),
        chain_key_service,
        file_metadata_processor,
    )
    .with_incoming_verifier(
        Arc::new(IncomingPropagationVerifier::new(
            db_context.incoming_propagation_store.clone(),
            transport,
            Arc::new(incoming_application),
        )),
        relay_snapshot,
    )
    .with_catchup_hints(catchup_tx);
    Ok(consumer)
}

pub async fn create_restore_account_service(
    config: Arc<Config>,
    keys: &BcrKeys,
    push_service: Arc<dyn PushApi>,
    mint_client: Arc<dyn MintClientApi>,
) -> Result<RestoreAccountService> {
    let db_context = get_db_context(config.clone(), keys)
        .await
        .expect("could not create db context");

    let node_id = NodeId::new(keys.pub_key(), config.bitcoin_network());
    let nostr_config = NostrConfig::new(
        keys.clone(),
        config.nostr_config.relays.clone(),
        config.nostr_config.blossom_servers.clone(),
        true,
        node_id.clone(),
    );

    let nostr_client = Arc::new(NostrClient::default(&nostr_config).await?);
    nostr_client.connect().await?;
    let nostr_contact_processor = Arc::new(NostrContactProcessor::new(
        nostr_client.clone(),
        db_context.nostr_contact_store.clone(),
        config.bitcoin_network(),
        Some(nostr_client.clone()),
    ));

    let bill_processor = Arc::new(BillChainEventProcessor::new(
        db_context.bill_blockchain_store.clone(),
        db_context.bill_store.clone(),
        db_context.file_reference_store.clone(),
        nostr_contact_processor.clone(),
        db_context.nostr_chain_event_store.clone(),
        nostr_client.clone(),
        mint_client,
        db_context.transaction_mgr.clone(),
        config.bitcoin_network(),
        config.clone(),
    ));

    let bill_invite_handler = Arc::new(BillInviteEventHandler::new(
        bill_processor.clone(),
        db_context.incoming_propagation_store.clone(),
    ));

    let company_processor = Arc::new(CompanyChainEventProcessor::new(
        db_context.company_chain_store.clone(),
        db_context.company_store.clone(),
        db_context.file_reference_store.clone(),
        db_context.identity_store.clone(),
        db_context.notification_store.clone(),
        nostr_contact_processor.clone(),
        bill_invite_handler.clone(),
        push_service.clone(),
        db_context.nostr_chain_event_store.clone(),
        nostr_client.clone(),
        db_context.contact_store.clone(),
        db_context.transaction_mgr.clone(),
        config.bitcoin_network(),
        config.clone(),
    ));

    let company_invite_handler = Arc::new(CompanyInviteEventHandler::new(
        nostr_client.clone(),
        company_processor.clone(),
        db_context.incoming_propagation_store.clone(),
    ));

    let contact_share_handler = Arc::new(ContactShareEventHandler::new(
        nostr_client.clone(),
        db_context.contact_store.clone(),
        db_context.nostr_contact_store.clone(),
        db_context.file_reference_store.clone(),
        db_context.notification_store.clone(),
        push_service,
    ));

    let processor = Arc::new(IdentityChainEventProcessor::new(
        db_context.identity_chain_store.clone(),
        db_context.identity_store.clone(),
        db_context.file_reference_store.clone(),
        company_invite_handler.clone(),
        bill_invite_handler.clone(),
        nostr_contact_processor,
        db_context.nostr_chain_event_store.clone(),
        nostr_client.clone(),
        db_context.contact_store.clone(),
        db_context.transaction_mgr.clone(),
        config.bitcoin_network(),
        config.clone(),
    ));

    let chain_key_service = Arc::new(
        chain_keys::ChainKeyService::new(
            db_context.bill_store.clone(),
            db_context.company_store.clone(),
            db_context.identity_store.clone(),
        )
        .with_identity_key_override(node_id.clone(), keys.clone()),
    );

    let incoming_application = Arc::new(IncomingChainApplication::new(
        chain_key_service,
        bill_processor.clone(),
        company_processor.clone(),
        processor.clone(),
        db_context.nostr_chain_event_store.clone(),
    ));

    let verified_ingestion = Arc::new(IncomingPropagationVerifier::new(
        db_context.incoming_propagation_store.clone(),
        nostr_client.clone(),
        incoming_application,
    ));

    let relay_snapshot =
        relay_quorum_snapshot(&config.nostr_config.relays, BLOCK_PROPAGATION_THRESHOLD)?;

    let dm_processor = Arc::new(
        DirectMessageEventProcessor::new(
            nostr_client.clone(),
            db_context.nostr_event_offset_store.clone(),
            vec![
                company_invite_handler,
                bill_invite_handler,
                contact_share_handler,
            ],
        )
        .await,
    );

    Ok(RestoreAccountService::new(
        nostr_client,
        processor,
        dm_processor,
        verified_ingestion,
        relay_snapshot,
        keys.clone(),
        node_id,
    )
    .await)
}
