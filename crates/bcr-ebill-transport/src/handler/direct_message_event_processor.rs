use std::sync::Arc;

use crate::{
    NostrClient, Result,
    chain_keys::ChainKeyServiceApi,
    handler::NotificationHandlerApi,
    nostr::{add_offset, process_event, should_process},
};
use async_trait::async_trait;
use bcr_ebill_api::service::contact_service::ContactServiceApi;
use bcr_ebill_core::application::ServiceTraitBounds;
use bcr_ebill_persistence::NostrEventOffsetStoreApi;
use nostr::signer::NostrSigner;

use crate::handler::DirectMessageEventProcessorApi;

#[derive(Clone)]
pub struct DirectMessageEventProcessor {
    client: Arc<NostrClient>,
    contact_service: Arc<dyn ContactServiceApi>,
    offset_store: Arc<dyn NostrEventOffsetStoreApi>,
    chain_key_service: Arc<dyn ChainKeyServiceApi>,
    handlers: Vec<Arc<dyn NotificationHandlerApi>>,
    signer: Arc<dyn NostrSigner>,
}

impl DirectMessageEventProcessor {
    pub async fn new(
        client: Arc<NostrClient>,
        contact_service: Arc<dyn ContactServiceApi>,
        offset_store: Arc<dyn NostrEventOffsetStoreApi>,
        chain_key_service: Arc<dyn ChainKeyServiceApi>,
        handlers: Vec<Arc<dyn NotificationHandlerApi>>,
    ) -> Self {
        // TODO: This will be refactored in Task 3 to handle multi-identity
        let signer = client.get_default_signer().await;
        Self {
            client,
            contact_service,
            offset_store,
            chain_key_service,
            handlers,
            signer,
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DirectMessageEventProcessorApi for DirectMessageEventProcessor {
    async fn process_direct_message(&self, event: Box<nostr::Event>) -> Result<()> {
        // TODO: This will be refactored in Task 3 to handle multi-identity
        let node_id = self.client.get_node_id();
        
        // check if the event should be processed
        if should_process(
            event.clone(),
            &[node_id.clone()],
            &self.contact_service,
            &self.offset_store,
        )
        .await
        {
            // process event
            let (success, time) = process_event(
                event.clone(),
                self.signer.clone(),
                node_id.clone(),
                self.chain_key_service.clone(),
                &self.handlers,
            )
            .await?;

            // add event offset
            add_offset(
                &self.offset_store,
                event.id,
                time,
                success,
                &node_id,
            )
            .await;
        }
        Ok(())
    }
}

impl ServiceTraitBounds for DirectMessageEventProcessor {}
