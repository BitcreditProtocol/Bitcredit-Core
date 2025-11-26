#![allow(clippy::arc_with_non_send_sync)]
use super::{CONTEXT, Result};
use bcr_ebill_api::{
    Config, DbContext,
    external::{
        bitcoin::BitcoinClient, court::CourtClient, email::EmailClient,
        file_storage::FileStorageClient, mint::MintClient,
    },
    service::{
        bill_service::{BillService, BillServiceApi},
        company_service::{CompanyService, CompanyServiceApi},
        contact_service::{ContactService, ContactServiceApi},
        file_upload_service::{FileUploadService, FileUploadServiceApi},
        identity_service::{IdentityService, IdentityServiceApi},
        search_service::{SearchService, SearchServiceApi},
        transport_service::TransportServiceApi,
    },
};
use bcr_ebill_transport::{
    NostrConsumer,
    chain_keys::{ChainKeyService, ChainKeyServiceApi},
    create_nostr_clients, create_nostr_consumer, create_transport_service,
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
    pub transport_service: Arc<dyn TransportServiceApi>,
    pub push_service: Arc<dyn PushApi>,
    pub chain_key_service: Arc<dyn ChainKeyServiceApi>,
    pub cfg: Config,
}

impl Context {
    pub async fn new(cfg: Config, db: DbContext) -> Result<Self> {
        let db_ctx = db.clone();
        let file_upload_client = Arc::new(FileStorageClient::new());
        let bitcoin_client = Arc::new(BitcoinClient::new());
        let mint_client = Arc::new(MintClient::new());
        let court_client = Arc::new(CourtClient::new());
        let email_client = Arc::new(EmailClient::new());
        let push_service = Arc::new(PushService::new());

        let nostr_clients =
            create_nostr_clients(&cfg, db.identity_store.clone(), db.company_store.clone()).await?;
        let transport_service = create_transport_service(
            nostr_clients.clone(),
            db.clone(),
            email_client.clone(),
            cfg.nostr_config.relays.to_owned(),
            push_service.clone(),
        )
        .await?;

        let contact_service = Arc::new(ContactService::new(
            db.contact_store.clone(),
            db.file_upload_store.clone(),
            file_upload_client.clone(),
            db.identity_store.clone(),
            db.nostr_contact_store.clone(),
            transport_service.clone(),
            &cfg,
        ));

        let bill_service = Arc::new(BillService::new(
            db.bill_store.clone(),
            db.bill_blockchain_store.clone(),
            db.identity_store.clone(),
            db.file_upload_store.clone(),
            file_upload_client.clone(),
            bitcoin_client,
            transport_service.clone(),
            db.identity_chain_store.clone(),
            db.company_chain_store.clone(),
            db.contact_store.clone(),
            db.company_store.clone(),
            db.mint_store.clone(),
            mint_client,
            court_client,
            db.nostr_contact_store.clone(),
        ));

        let identity_service = IdentityService::new(
            db.identity_store.clone(),
            db.file_upload_store.clone(),
            file_upload_client.clone(),
            db.identity_chain_store.clone(),
            transport_service.clone(),
            email_client.clone(),
            db.email_notification_store.clone(),
        );

        let company_service = CompanyService::new(
            db.company_store.clone(),
            db.file_upload_store.clone(),
            file_upload_client.clone(),
            db.identity_store.clone(),
            db.contact_store,
            db.nostr_contact_store.clone(),
            db.identity_chain_store,
            db.company_chain_store,
            transport_service.clone(),
            email_client.clone(),
            db.email_notification_store.clone(),
        );
        let file_upload_service = FileUploadService::new(db.file_upload_store);

        let chain_key_service = Arc::new(ChainKeyService::new(
            db.bill_store.clone(),
            db.company_store.clone(),
            db.identity_store.clone(),
        ));

        let nostr_consumer = create_nostr_consumer(
            nostr_clients.clone(),
            contact_service.clone(),
            push_service.clone(),
            chain_key_service.clone(),
            db_ctx.clone(),
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
            transport_service,
            push_service,
            chain_key_service,
            cfg,
        })
    }
}

pub fn get_ctx() -> &'static Context {
    CONTEXT.with(|c| c.borrow().expect("Context is not initialized"))
}
