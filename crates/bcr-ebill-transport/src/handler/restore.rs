use std::sync::Arc;

use async_trait::async_trait;
use bcr_ebill_api::{
    service::notification_service::{
        Result, restore::RestoreAccountApi, transport::NotificationJsonTransportApi,
    },
    util::BcrKeys,
};
use bcr_ebill_core::{
    NodeId, ServiceTraitBounds,
    blockchain::{BlockchainType, identity::IdentityBlock},
};
use log::{error, info};
use nostr::{filter::Filter, types::Timestamp};

use crate::handler::DirectMessageEventProcessorApi;

use super::{
    IdentityChainEventProcessorApi,
    public_chain_helpers::{BlockData, EventContainer, resolve_event_chains},
};

#[allow(dead_code)]
pub struct RestoreAccountService {
    nostr: Arc<dyn NotificationJsonTransportApi>,
    identity_chain_processor: Arc<dyn IdentityChainEventProcessorApi>,
    dm_processor: Arc<dyn DirectMessageEventProcessorApi>,
    keys: BcrKeys,
    node_id: NodeId,
}

#[allow(dead_code)]
impl RestoreAccountService {
    pub async fn new(
        nostr: Arc<dyn NotificationJsonTransportApi>,
        identity_chain_processor: Arc<dyn IdentityChainEventProcessorApi>,
        dm_processor: Arc<dyn DirectMessageEventProcessorApi>,
        keys: BcrKeys,
    ) -> Self {
        let node_id = nostr.get_sender_node_id();
        Self {
            nostr,
            identity_chain_processor,
            dm_processor,
            keys,
            node_id,
        }
    }

    async fn restore_primary_account(&self) -> Result<()> {
        // restores identity and all our own companies
        self.restore_identity().await?;

        // restore bills and companies primary account was invited to
        self.process_private_events().await?;
        Ok(())
    }

    async fn process_private_events(&self) -> Result<()> {
        let events = self
            .nostr
            .resolve_private_events(Filter::new().since(Timestamp::zero()))
            .await?;
        info!("found private {} dms for primary account", events.len());
        for event in events {
            if let Err(e) = self
                .dm_processor
                .process_direct_message(Box::new(event))
                .await
            {
                error!("Failed to process direct message with: {e}");
            }
        }
        Ok(())
    }

    async fn restore_identity(&self) -> Result<()> {
        info!("restoring identity chain");
        let chains = resolve_event_chains(
            self.nostr.clone(),
            &self.node_id.to_string(),
            BlockchainType::Identity,
            &self.keys,
        )
        .await?;
        info!("found {} chains for primary account", chains.len());
        for chain in chains {
            if self.valid_identity_chain_events(&chain) {
                let blocks: Vec<IdentityBlock> = chain
                    .iter()
                    .filter_map(|d| match d.block.clone() {
                        BlockData::Identity(block) => Some(block),
                        _ => None,
                    })
                    .collect();
                self.identity_chain_processor
                    .process_chain_data(&self.node_id, blocks, Some(self.keys.clone()))
                    .await?;
                info!("restored identity chain from {} events", chain.len());
            }
        }
        Ok(())
    }

    fn valid_identity_chain_events(&self, events: &[EventContainer]) -> bool {
        let mut valid = true;
        for event in events {
            valid = valid
                && self
                    .identity_chain_processor
                    .validate_chain_event_and_sender(&self.node_id, event.event.pubkey);
        }
        valid
    }
}

impl ServiceTraitBounds for RestoreAccountService {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl RestoreAccountApi for RestoreAccountService {
    async fn restore_account(&self) -> Result<()> {
        info!("restoring primary account");
        self.restore_primary_account().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        handler::{MockDirectMessageEventProcessorApi, MockIdentityChainEventProcessorApi},
        test_utils::{MockNotificationJsonTransport, node_id_test},
    };

    use super::*;

    #[tokio::test]
    async fn test_service() {
        let mut nostr = MockNotificationJsonTransport::new();
        let processor = MockIdentityChainEventProcessorApi::new();
        let dm_processor = MockDirectMessageEventProcessorApi::new();
        let keys = BcrKeys::new();

        nostr
            .expect_get_sender_node_id()
            .returning(node_id_test)
            .once();

        nostr
            .expect_resolve_public_chain()
            .returning(|_, _| Ok(vec![]))
            .once();

        nostr
            .expect_resolve_private_events()
            .returning(|_| Ok(vec![]))
            .once();

        let service = RestoreAccountService::new(
            Arc::new(nostr),
            Arc::new(processor),
            Arc::new(dm_processor),
            keys,
        )
        .await;

        service
            .restore_account()
            .await
            .expect("could not restore account");
    }
}
