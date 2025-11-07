use super::super::Result;
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::application::ServiceTraitBounds;
use serde::{Deserialize, Serialize};

use crate::{db::surreal::SurrealWrapper, notification::EmailNotificationStoreApi};

#[derive(Clone)]
pub struct SurrealEmailNotificationStore {
    db: SurrealWrapper,
}

impl SurrealEmailNotificationStore {
    const TABLE: &'static str = "email_notifications";

    pub fn new(db: SurrealWrapper) -> Self {
        Self { db }
    }
}

impl ServiceTraitBounds for SurrealEmailNotificationStore {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl EmailNotificationStoreApi for SurrealEmailNotificationStore {
    async fn add_email_preferences_link_for_node_id(
        &self,
        email_preferences_link: &url::Url,
        node_id: &NodeId,
    ) -> Result<()> {
        let db = EmailNotificationPreferencesDb {
            node_id: node_id.to_owned(),
            email_preferences_link: email_preferences_link.to_string(),
        };
        let _: Option<EmailNotificationPreferencesDb> = self
            .db
            .create(Self::TABLE, Some(node_id.to_string()), db)
            .await?;
        Ok(())
    }

    async fn get_email_preferences_link_for_node_id(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<url::Url>> {
        let result: Option<EmailNotificationPreferencesDb> =
            self.db.select_one(Self::TABLE, node_id.to_string()).await?;

        Ok(match result {
            Some(r) => url::Url::parse(&r.email_preferences_link).ok(),
            None => None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EmailNotificationPreferencesDb {
    pub node_id: NodeId,
    pub email_preferences_link: String,
}

#[cfg(test)]
mod tests {
    use crate::{db::get_memory_db, tests::tests::node_id_test};

    use super::*;

    async fn get_store() -> SurrealEmailNotificationStore {
        let db = get_memory_db("test", "email_notification")
            .await
            .expect("could not create memory db");
        SurrealEmailNotificationStore::new(SurrealWrapper { db, files: false })
    }

    #[tokio::test]
    async fn test_email_preferences_link_for_node_id() {
        let store = get_store().await;
        let link_before = store
            .get_email_preferences_link_for_node_id(&node_id_test())
            .await
            .expect("can fetch empty link if it's not set");
        assert!(link_before.is_none());

        store
            .add_email_preferences_link_for_node_id(
                &url::Url::parse("https://www.bit.cr/").unwrap(),
                &node_id_test(),
            )
            .await
            .unwrap();

        let link = store
            .get_email_preferences_link_for_node_id(&node_id_test())
            .await
            .expect("can fetch link after it was set");
        assert_eq!(link, Some(url::Url::parse("https://www.bit.cr/").unwrap()));
    }
}
