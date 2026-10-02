use crate::{
    Result,
    sql::email_notification::{SELECT_LINK, UPSERT},
    traits::notification::EmailNotificationStoreApi,
};
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::application::ServiceTraitBounds;
use sqlx::{PgPool, types::Text};

#[derive(Clone)]
pub struct PostgresEmailNotificationStore {
    pool: PgPool,
}

impl PostgresEmailNotificationStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ServiceTraitBounds for PostgresEmailNotificationStore {}

#[async_trait]
impl EmailNotificationStoreApi for PostgresEmailNotificationStore {
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
    use super::PostgresEmailNotificationStore;
    use crate::tests::email_notification;
    use sqlx::PgPool;

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn email_preferences_link(pool: PgPool) {
        let store = PostgresEmailNotificationStore::new(pool);
        email_notification::test_email_preferences_link(&store).await;
    }
}
