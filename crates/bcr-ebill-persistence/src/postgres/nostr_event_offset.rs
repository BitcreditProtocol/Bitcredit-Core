use crate::{
    NostrEventOffset, NostrEventOffsetStoreApi, Result,
    sql::{
        nostr_event_offset::{
            INSERT_EVENT, NostrEventOffsetRow, SELECT_CURRENT_OFFSET, SELECT_EVENT_ID,
        },
        timestamp_from_db,
    },
};
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::{application::ServiceTraitBounds, protocol::Timestamp};
use sqlx::{PgPool, types::Text};

#[derive(Clone)]
pub struct PostgresNostrEventOffsetStore {
    pool: PgPool,
}

impl PostgresNostrEventOffsetStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ServiceTraitBounds for PostgresNostrEventOffsetStore {}

#[async_trait]
impl NostrEventOffsetStoreApi for PostgresNostrEventOffsetStore {
    async fn current_offset(&self, node_id: &NodeId) -> Result<Timestamp> {
        let time: Option<i64> = sqlx::query_scalar(SELECT_CURRENT_OFFSET)
            .bind(Text(node_id.clone()))
            .fetch_optional(&self.pool)
            .await?;
        match time {
            Some(time) => timestamp_from_db(time),
            None => Ok(Timestamp::new(0).expect("safe")),
        }
    }

    async fn is_processed(&self, event_id: &str) -> Result<bool> {
        let result: Option<String> = sqlx::query_scalar(SELECT_EVENT_ID)
            .bind(event_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(result.is_some())
    }

    async fn add_event(&self, data: NostrEventOffset) -> Result<()> {
        let row = NostrEventOffsetRow::try_from(data)?;
        sqlx::query(INSERT_EVENT)
            .bind(row.event_id)
            .bind(row.time)
            .bind(row.success)
            .bind(row.node_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::PostgresNostrEventOffsetStore;
    use crate::tests::nostr_event_offset;
    use sqlx::PgPool;

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn get_offset_from_empty_table(pool: PgPool) {
        let store = PostgresNostrEventOffsetStore::new(pool);
        nostr_event_offset::test_get_offset_from_empty_table(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn add_event(pool: PgPool) {
        let store = PostgresNostrEventOffsetStore::new(pool);
        nostr_event_offset::test_add_event(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn is_processed(pool: PgPool) {
        let store = PostgresNostrEventOffsetStore::new(pool);
        nostr_event_offset::test_is_processed(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn current_offset_returns_latest_event(pool: PgPool) {
        let store = PostgresNostrEventOffsetStore::new(pool);
        nostr_event_offset::test_current_offset_returns_latest_event(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn current_offset_is_by_node_id(pool: PgPool) {
        let store = PostgresNostrEventOffsetStore::new(pool);
        nostr_event_offset::test_current_offset_is_by_node_id(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn failed_event_is_processed_and_advances_offset(pool: PgPool) {
        let store = PostgresNostrEventOffsetStore::new(pool);
        nostr_event_offset::test_failed_event_is_processed_and_advances_offset(&store).await;
    }
}
