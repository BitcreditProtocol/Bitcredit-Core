#![allow(clippy::arc_with_non_send_sync)]
use super::{CONTEXT, Result};
use bcr_ebill_api::{
    Config, DbContext,
    external::{bitcoin::BitcoinClient, mint::MintClient},
    service::{
        bill_service::{BillServiceApi, service::BillService},
        company_service::{CompanyService, CompanyServiceApi},
        contact_service::{ContactService, ContactServiceApi},
        file_upload_service::{FileUploadService, FileUploadServiceApi},
        identity_service::{IdentityService, IdentityServiceApi},
        notification_service::{
            NostrConsumer, create_nostr_clients, create_nostr_consumer, create_notification_service,
        },
        search_service::{SearchService, SearchServiceApi},
    },
};
use bcr_ebill_transport::{
    NotificationServiceApi,
    chain_keys::ChainKeyService,
    push_notification::{PushApi, PushService},
};
use std::sync::Arc;

#[derive(Clone)]
pub struct Context {
    pub contact_service: Arc<dyn ContactServiceApi>,
    pub search_service: Arc<dyn SearchServiceApi>,
    pub bill_service: Arc<dyn BillServiceApi>,
    pub identity_service: Arc<dyn IdentityServiceApi>,
    pub company_service: Arc<dyn CompanyServiceApi>,
    pub file_upload_service: Arc<dyn FileUploadServiceApi>,
    pub nostr_consumer: NostrConsumer,
    pub notification_service: Arc<dyn NotificationServiceApi>,
    pub push_service: Arc<dyn PushApi>,
    pub cfg: Config,
}

impl Context {
    pub async fn new(cfg: Config, db: DbContext) -> Result<Self> {
        let contact_service = Arc::new(ContactService::new(
            db.contact_store.clone(),
            db.file_upload_store.clone(),
            db.identity_store.clone(),
            db.nostr_contact_store.clone(),
            &cfg,
        ));
        let bitcoin_client = Arc::new(BitcoinClient::new());
        let mint_client = Arc::new(MintClient::new());

        let nostr_clients =
            create_nostr_clients(&cfg, db.identity_store.clone(), db.company_store.clone()).await?;
        let notification_service = create_notification_service(
            nostr_clients.clone(),
            db.notification_store.clone(),
            contact_service.clone(),
            db.queued_message_store.clone(),
            db.nostr_chain_event_store.clone(),
            cfg.nostr_config.relays.to_owned(),
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
            db.mint_store.clone(),
            mint_client,
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
        let chain_key_service = Arc::new(ChainKeyService::new(db.bill_store.clone()));

        let nostr_consumer = create_nostr_consumer(
            nostr_clients.clone(),
            contact_service.clone(),
            db.nostr_event_offset_store.clone(),
            db.notification_store.clone(),
            push_service.clone(),
            db.bill_blockchain_store.clone(),
            db.bill_store.clone(),
            db.nostr_contact_store.clone(),
            chain_key_service.clone(),
        )
        .await?;

        let search_service = SearchService::new(
            bill_service.clone(),
            contact_service.clone(),
            Arc::new(company_service.clone()),
        );

        Ok(Self {
            contact_service,
            search_service: Arc::new(search_service),
            bill_service,
            identity_service: Arc::new(identity_service),
            company_service: Arc::new(company_service),
            file_upload_service: Arc::new(file_upload_service),
            nostr_consumer,
            notification_service,
            push_service,
            cfg,
        })
    }
}

pub fn get_ctx() -> &'static Context {
    CONTEXT.with(|c| c.borrow().expect("Context is not initialized"))
}
