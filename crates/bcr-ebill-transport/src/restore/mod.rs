use async_trait::async_trait;
use bcr_ebill_api::service::notification_service::{
    Result, restore::RestoreAccountApi, transport::NotificationJsonTransportApi,
};
use bcr_ebill_core::{ServiceTraitBounds, blockchain::BlockchainType};
use log::info;
use nostr::{filter::Filter, types::Timestamp};

#[allow(dead_code)]
pub struct RestoreAccountService {
    nostr: Box<dyn NotificationJsonTransportApi>,
}

#[allow(dead_code)]
impl RestoreAccountService {
    pub async fn new(nostr: Box<dyn NotificationJsonTransportApi>) -> Self {
        Self { nostr }
    }

    async fn restore_primary_account(&self) -> Result<()> {
        let blocks = self
            .nostr
            .resolve_public_chain(
                &self.nostr.get_sender_node_id().to_string(),
                BlockchainType::Identity,
            )
            .await?;
        info!("found identity blocks {blocks :#?} blocks for primary account");

        let dms = self
            .nostr
            .resolve_private_events(Filter::new().since(Timestamp::zero()))
            .await?;
        info!("found private dms {dms :#?} dms for primary account");
        Ok(())
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
    use crate::test_utils::{MockNotificationJsonTransport, node_id_test};

    use super::*;

    #[tokio::test]
    async fn test_service() {
        let mut nostr = MockNotificationJsonTransport::new();

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

        let service = RestoreAccountService::new(Box::new(nostr)).await;

        service
            .restore_account()
            .await
            .expect("could not restore account");
    }
}
