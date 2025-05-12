use bcr_ebill_api::external::bitcoin::BitcoinClient;
use bcr_ebill_api::service::backup_service::{BackupService, BackupServiceApi};
use bcr_ebill_api::service::bill_service::{BillServiceApi, service::BillService};
use bcr_ebill_api::service::company_service::{CompanyService, CompanyServiceApi};
use bcr_ebill_api::service::contact_service::{ContactService, ContactServiceApi};
use bcr_ebill_api::service::file_upload_service::{FileUploadService, FileUploadServiceApi};
use bcr_ebill_api::service::identity_service::{IdentityService, IdentityServiceApi};
use bcr_ebill_api::service::notification_service::{
    NostrConsumer, create_nostr_clients, create_nostr_consumer, create_notification_service,
};
use bcr_ebill_api::service::search_service::{SearchService, SearchServiceApi};
use bcr_ebill_api::{Config, DbContext, SurrealDbConfig, service::Result};
use bcr_ebill_transport::{
    NotificationServiceApi,
    push_notification::{PushApi, PushService},
};
use log::error;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast, watch};

/// A dependency container for all services that are used by the application
#[derive(Clone)]
pub struct ServiceContext {
    pub contact_service: Arc<dyn ContactServiceApi>,
    pub search_service: Arc<dyn SearchServiceApi>,
    pub bill_service: Arc<dyn BillServiceApi>,
    pub identity_service: Arc<dyn IdentityServiceApi>,
    pub company_service: Arc<dyn CompanyServiceApi>,
    pub file_upload_service: Arc<dyn FileUploadServiceApi>,
    pub nostr_consumer: NostrConsumer,
    pub shutdown_sender: broadcast::Sender<bool>,
    pub reboot_sender: watch::Sender<bool>,
    pub notification_service: Arc<dyn NotificationServiceApi>,
    pub push_service: Arc<dyn PushApi>,
    pub current_identity: Arc<RwLock<SwitchIdentityState>>,
    pub backup_service: Arc<dyn BackupServiceApi>,
}

/// A structure describing the currently selected identity between the personal and multiple
/// possible company identities
#[derive(Clone, Debug)]
pub struct SwitchIdentityState {
    pub personal: String,
    pub company: Option<String>,
}

impl ServiceContext {
    /// sends a shutdown event to all parts of the application
    pub fn shutdown(&self) {
        if let Err(e) = self.shutdown_sender.send(true) {
            error!("Error sending shutdown event: {e}");
        }
    }

    /// sends a reboot event to all parts of the application
    pub fn reboot(&self) {
        if let Err(e) = self.reboot_sender.send(true) {
            error!("Error sending reboot event: {e}");
        }
    }

    pub async fn get_current_identity(&self) -> SwitchIdentityState {
        self.current_identity.read().await.clone()
    }

    pub async fn set_current_personal_identity(&self, node_id: String) {
        let mut current_identity = self.current_identity.write().await;
        current_identity.personal = node_id;
        current_identity.company = None;
    }

    pub async fn set_current_company_identity(&self, node_id: String) {
        let mut current_identity = self.current_identity.write().await;
        current_identity.company = Some(node_id);
    }
}

/// building up the service context dependencies here for now. Later we can modularize this
/// and make it more flexible.
pub async fn create_service_context(
    local_node_id: &str,
    config: Config,
    shutdown_sender: broadcast::Sender<bool>,
    db: DbContext,
    reboot_sender: watch::Sender<bool>,
) -> Result<ServiceContext> {
    let contact_service = Arc::new(ContactService::new(
        db.contact_store.clone(),
        db.file_upload_store.clone(),
        db.identity_store.clone(),
        db.nostr_contact_store.clone(),
    ));
    let bitcoin_client = Arc::new(BitcoinClient::new());

    let nostr_clients =
        create_nostr_clients(&config, db.identity_store.clone(), db.company_store.clone()).await?;
    let notification_service = create_notification_service(
        nostr_clients.clone(),
        db.notification_store.clone(),
        contact_service.clone(),
        db.queued_message_store.clone(),
        &config.nostr_relay,
    )
    .await?;

    let bill_service = Arc::new(BillService::new(
        db.bill_store.clone(),
        db.bill_blockchain_store.clone(),
        db.identity_store.clone(),
        db.file_upload_store.clone(),
        bitcoin_client,
        notification_service.clone(),
        db.identity_chain_store.clone(),
        db.company_chain_store.clone(),
        db.contact_store.clone(),
        db.company_store.clone(),
    ));
    let identity_service = IdentityService::new(
        db.identity_store.clone(),
        db.file_upload_store.clone(),
        db.identity_chain_store.clone(),
    );

    let company_service = CompanyService::new(
        db.company_store,
        db.file_upload_store.clone(),
        db.identity_store.clone(),
        db.contact_store,
        db.identity_chain_store,
        db.company_chain_store,
    );
    let file_upload_service = FileUploadService::new(db.file_upload_store);

    let push_service = Arc::new(PushService::new());

    let nostr_consumer = create_nostr_consumer(
        nostr_clients,
        contact_service.clone(),
        db.nostr_event_offset_store.clone(),
        db.notification_store.clone(),
        push_service.clone(),
        db.bill_blockchain_store.clone(),
        db.bill_store.clone(),
        db.nostr_contact_store.clone(),
    )
    .await?;

    let search_service = SearchService::new(
        bill_service.clone(),
        contact_service.clone(),
        Arc::new(company_service.clone()),
    );

    let backup_service = BackupService::new(
        db.backup_store.clone(),
        db.identity_store.clone(),
        SurrealDbConfig::new(&config.surreal_db_connection),
        reboot_sender.clone(),
    );

    Ok(ServiceContext {
        contact_service,
        search_service: Arc::new(search_service),
        bill_service,
        identity_service: Arc::new(identity_service),
        company_service: Arc::new(company_service),
        file_upload_service: Arc::new(file_upload_service),
        nostr_consumer,
        shutdown_sender,
        reboot_sender,
        notification_service,
        push_service,
        current_identity: Arc::new(RwLock::new(SwitchIdentityState {
            personal: local_node_id.to_owned(),
            company: None,
        })),
        backup_service: Arc::new(backup_service),
    })
}
