use crate::Config;
use bcr_ebill_persistence::{
    BackupStoreApi, ContactStoreApi, NostrEventOffsetStoreApi, NotificationStoreApi,
    SurrealBackupStore, SurrealBillChainStore, SurrealBillStore, SurrealCompanyChainStore,
    SurrealCompanyStore, SurrealContactStore, SurrealDbConfig, SurrealIdentityChainStore,
    SurrealIdentityStore, SurrealNostrEventOffsetStore, SurrealNotificationStore,
    bill::{BillChainStoreApi, BillStoreApi},
    company::{CompanyChainStoreApi, CompanyStoreApi},
    db::{
        nostr_contact_store::SurrealNostrContactStore,
        nostr_send_queue::SurrealNostrEventQueueStore,
    },
    file_upload::FileUploadStoreApi,
    get_surreal_db,
    identity::{IdentityChainStoreApi, IdentityStoreApi},
    nostr::{NostrContactStoreApi, NostrQueuedMessageStoreApi},
};
use log::error;
use std::sync::Arc;

pub use bcr_ebill_persistence::Error;
#[cfg(not(target_arch = "wasm32"))]
pub use bcr_ebill_persistence::backup;
pub use bcr_ebill_persistence::bill;
pub use bcr_ebill_persistence::company;
pub use bcr_ebill_persistence::contact;
pub use bcr_ebill_persistence::db;
pub use bcr_ebill_persistence::file_upload;
pub use bcr_ebill_persistence::identity;
pub use bcr_ebill_persistence::nostr;
pub use bcr_ebill_persistence::notification;

/// A container for all persistence related dependencies.
#[derive(Clone)]
pub struct DbContext {
    pub contact_store: Arc<dyn ContactStoreApi>,
    pub bill_store: Arc<dyn BillStoreApi>,
    pub bill_blockchain_store: Arc<dyn BillChainStoreApi>,
    pub identity_store: Arc<dyn IdentityStoreApi>,
    pub identity_chain_store: Arc<dyn IdentityChainStoreApi>,
    pub company_chain_store: Arc<dyn CompanyChainStoreApi>,
    pub company_store: Arc<dyn CompanyStoreApi>,
    pub file_upload_store: Arc<dyn FileUploadStoreApi>,
    pub nostr_event_offset_store: Arc<dyn NostrEventOffsetStoreApi>,
    pub notification_store: Arc<dyn NotificationStoreApi>,
    pub backup_store: Arc<dyn BackupStoreApi>,
    pub queued_message_store: Arc<dyn NostrQueuedMessageStoreApi>,
    pub nostr_contact_store: Arc<dyn NostrContactStoreApi>,
}

/// Creates a new instance of the DbContext with the given SurrealDB configuration.
pub async fn get_db_context(conf: &Config) -> bcr_ebill_persistence::Result<DbContext> {
    let surreal_db_config = SurrealDbConfig::new(&conf.surreal_db_connection);
    let db = get_surreal_db(&surreal_db_config).await?;

    let company_store = Arc::new(SurrealCompanyStore::new(db.clone()));
    #[cfg(target_arch = "wasm32")]
    let file_upload_store =
        Arc::new(bcr_ebill_persistence::db::file_upload::FileUploadStore::new(db.clone()));

    #[cfg(not(target_arch = "wasm32"))]
    let file_upload_store = Arc::new(
        bcr_ebill_persistence::file_upload::FileUploadStore::new(
            &conf.data_dir,
            "files",
            "temp_upload",
        )
        .await?,
    );

    if let Err(e) = file_upload_store.cleanup_temp_uploads().await {
        error!("Error cleaning up temp uploads: {e}");
    }

    let contact_store = Arc::new(SurrealContactStore::new(db.clone()));

    let bill_store = Arc::new(SurrealBillStore::new(db.clone()));
    let bill_blockchain_store = Arc::new(SurrealBillChainStore::new(db.clone()));

    let identity_store = Arc::new(SurrealIdentityStore::new(db.clone()));
    let identity_chain_store = Arc::new(SurrealIdentityChainStore::new(db.clone()));
    let company_chain_store = Arc::new(SurrealCompanyChainStore::new(db.clone()));

    let nostr_event_offset_store = Arc::new(SurrealNostrEventOffsetStore::new(db.clone()));
    let notification_store = Arc::new(SurrealNotificationStore::new(db.clone()));
    let backup_store = Arc::new(SurrealBackupStore::new(db.clone()));
    let queued_message_store = Arc::new(SurrealNostrEventQueueStore::new(db.clone()));
    let nostr_contact_store = Arc::new(SurrealNostrContactStore::new(db.clone()));

    Ok(DbContext {
        contact_store,
        bill_store,
        bill_blockchain_store,
        identity_store,
        identity_chain_store,
        company_chain_store,
        company_store,
        file_upload_store,
        nostr_event_offset_store,
        notification_store,
        backup_store,
        queued_message_store,
        nostr_contact_store,
    })
}
