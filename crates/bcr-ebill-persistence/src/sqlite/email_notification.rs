use crate::{
    Result,
    sql::email_notification::{SELECT_LINK, UPSERT},
    traits::notification::EmailNotificationStoreApi,
};
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::application::ServiceTraitBounds;
use sqlx::{SqlitePool, types::Text};

#[derive(Clone)]
pub struct SqliteEmailNotificationStore {
    pool: SqlitePool,
}

impl SqliteEmailNotificationStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl ServiceTraitBounds for SqliteEmailNotificationStore {}

#[async_trait]
impl EmailNotificationStoreApi for SqliteEmailNotificationStore {
    async fn add_email_preferences_link_for_node_id(
        &self,
        email_preferences_link: &url::Url,
        node_id: &NodeId,
    ) -> Result<()> {
        sqlx::query(UPSERT)
            .bind(Text(node_id.clone()))
            .bind(Text(email_preferences_link.clone()))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_email_preferences_link_for_node_id(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<url::Url>> {
        let link: Option<Text<url::Url>> = sqlx::query_scalar(SELECT_LINK)
            .bind(Text(node_id.clone()))
            .fetch_optional(&self.pool)
            .await?;
        Ok(link.map(Text::into_inner))
    }
}

#[cfg(test)]
mod tests {
    use super::SqliteEmailNotificationStore;
    use crate::tests::email_notification;
    use sqlx::SqlitePool;

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn email_preferences_link(pool: SqlitePool) {
        let store = SqliteEmailNotificationStore::new(pool);
        email_notification::test_email_preferences_link(&store).await;
    }
}
