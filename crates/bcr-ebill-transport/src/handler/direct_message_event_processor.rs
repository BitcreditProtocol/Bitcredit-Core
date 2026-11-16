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
    async fn process_direct_message(&self, event: Box<nostr::event::Event>) -> Result<()> {
        crate::nostr::process_private_event(
            self.client.as_ref(),
            event.as_ref(),
            &self.offset_store,
            &self.handlers,
            self.processing_lock.as_ref(),
        )
        .await?;
        Ok(())
    }
}

impl ServiceTraitBounds for DirectMessageEventProcessor {}
