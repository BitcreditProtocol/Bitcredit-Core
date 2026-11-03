use std::sync::Arc;

use crate::{
    NostrClient, Result,
    chain_keys::ChainKeyServiceApi,
    handler::{FileMetadataProcessorApi, NotificationHandlerApi},
    nostr::{add_offset, determine_recipient, process_event, should_process},
};
use async_trait::async_trait;
use bcr_ebill_core::application::ServiceTraitBounds;
use bcr_ebill_persistence::NostrEventOffsetStoreApi;

use crate::handler::DirectMessageEventProcessorApi;

#[derive(Clone)]
pub struct DirectMessageEventProcessor {
    client: Arc<NostrClient>,
    offset_store: Arc<dyn NostrEventOffsetStoreApi>,
    chain_key_service: Arc<dyn ChainKeyServiceApi>,
    handlers: Vec<Arc<dyn NotificationHandlerApi>>,
    file_metadata_processor: Arc<dyn FileMetadataProcessorApi>,
}

impl DirectMessageEventProcessor {
    pub async fn new(
        client: Arc<NostrClient>,
        offset_store: Arc<dyn NostrEventOffsetStoreApi>,
        chain_key_service: Arc<dyn ChainKeyServiceApi>,
        handlers: Vec<Arc<dyn NotificationHandlerApi>>,
        file_metadata_processor: Arc<dyn FileMetadataProcessorApi>,
    ) -> Self {
        Self {
            client,
            offset_store,
            chain_key_service,
            handlers,
            file_metadata_processor,
        }
    }
}

#[async_trait]
impl DirectMessageEventProcessorApi for DirectMessageEventProcessor {
    async fn process_direct_message(&self, event: Box<nostr::event::Event>) -> Result<()> {
        // Check if the event should be processed
        if should_process(event.clone(), &self.offset_store, None).await {
            // Determine which identity should receive this event
            match determine_recipient(&event, &self.client).await {
                Ok((recipient_node_id, signer)) => {
                    // Process event with the correct identity's signer
                    let (success, time) = process_event(
                        event.clone(),
                        signer,
                        recipient_node_id.clone(),
                        self.chain_key_service.clone(),
                        &self.handlers,
                        self.file_metadata_processor.clone(),
                    )
                    .await?;

                    // Add event offset for the recipient identity
                    add_offset(
                        &self.offset_store,
                        event.id,
                        time,
                        success,
                        &recipient_node_id,
                    )
                    .await;
                }
                Err(e) => {
                    log::debug!("Could not determine recipient for event {}: {e}", event.id);
                }
            }
        }
        Ok(())
    }
}

impl ServiceTraitBounds for DirectMessageEventProcessor {}
