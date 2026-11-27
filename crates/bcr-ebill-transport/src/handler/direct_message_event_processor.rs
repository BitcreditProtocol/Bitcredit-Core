use crate::handler::DirectMessageEventProcessorApi;
use crate::{NostrClient, Result, handler::NotificationHandlerApi};
use async_trait::async_trait;
use bcr_ebill_core::application::ServiceTraitBounds;
use bcr_ebill_persistence::NostrEventOffsetStoreApi;
use std::sync::Arc;

#[derive(Clone)]
pub struct DirectMessageEventProcessor {
    client: Arc<NostrClient>,
    offset_store: Arc<dyn NostrEventOffsetStoreApi>,
    handlers: Vec<Arc<dyn NotificationHandlerApi>>,
    processing_lock: Arc<tokio::sync::Mutex<()>>,
}

impl DirectMessageEventProcessor {
    pub async fn new(
        client: Arc<NostrClient>,
        offset_store: Arc<dyn NostrEventOffsetStoreApi>,
        handlers: Vec<Arc<dyn NotificationHandlerApi>>,
    ) -> Self {
        Self {
            client,
            offset_store,
            handlers,
            processing_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }
}

#[async_trait]
impl DirectMessageEventProcessorApi for DirectMessageEventProcessor {
    async fn catch_up_private_events(&self) -> Result<()> {
        crate::nostr::catch_up_private_for_restore(
            self.client.as_ref(),
            &self.offset_store,
            &self.handlers,
            self.processing_lock.as_ref(),
        )
        .await
    }
}

impl ServiceTraitBounds for DirectMessageEventProcessor {}
