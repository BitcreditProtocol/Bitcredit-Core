use crate::{
    Error, NostrEventOffset, NostrEventOffsetStoreApi, Result,
    sql::{
        nostr_event_offset::{
            DELETE_CATCHUP_UNTIL, IGNORE_PRIVATE_EVENT, INSERT_EVENT, NostrEventOffsetRow,
            SELECT_CATCHUP_UNTIL, SELECT_CURRENT_OFFSET, SELECT_EVENT_ID, UPSERT_CATCHUP_UNTIL,
        },
        timestamp_from_db,
    },
};
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::{application::ServiceTraitBounds, protocol::Timestamp};
use sqlx::{SqlitePool, types::Text};

#[derive(Clone)]
pub struct SqliteNostrEventOffsetStore {
    pool: SqlitePool,
}

impl SqliteNostrEventOffsetStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl ServiceTraitBounds for SqliteNostrEventOffsetStore {}

#[async_trait]
impl NostrEventOffsetStoreApi for SqliteNostrEventOffsetStore {
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

    async fn get_catchup_until(
        &self,
        scope: &str,
        subject_id: &str,
        relay: &url::Url,
    ) -> Result<Option<u64>> {
        let value: Option<i64> = sqlx::query_scalar(SELECT_CATCHUP_UNTIL)
            .bind(scope)
            .bind(subject_id)
            .bind(relay.as_str())
            .fetch_optional(&self.pool)
            .await?;
        value
            .map(|value| {
                u64::try_from(value)
                    .map_err(|_| Error::InvalidData("Invalid catchup cursor".into()))
            })
            .transpose()
    }

    async fn set_catchup_until(
        &self,
        scope: &str,
        subject_id: &str,
        relay: &url::Url,
        until: Option<u64>,
    ) -> Result<()> {
        match until {
            Some(until) => {
                let until = i64::try_from(until)
                    .map_err(|_| Error::InvalidData("Catchup cursor overflow".into()))?;
                sqlx::query(UPSERT_CATCHUP_UNTIL)
                    .bind(scope)
                    .bind(subject_id)
                    .bind(relay.as_str())
                    .bind(until)
                    .execute(&self.pool)
                    .await?;
            }
            None => {
                sqlx::query(DELETE_CATCHUP_UNTIL)
                    .bind(scope)
                    .bind(subject_id)
                    .bind(relay.as_str())
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    async fn ignore_private_event(
        &self,
        event_id: &str,
        time: Timestamp,
        node_id: &NodeId,
        reason: &str,
    ) -> Result<()> {
        sqlx::query(IGNORE_PRIVATE_EVENT)
            .bind(event_id)
            .bind(crate::sql::timestamp_to_db(time)?)
            .bind(Text(node_id.clone()))
            .bind(reason)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SqliteNostrEventOffsetStore;
    use crate::tests::nostr_event_offset;
    use sqlx::SqlitePool;

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn get_offset_from_empty_table(pool: SqlitePool) {
        let store = SqliteNostrEventOffsetStore::new(pool);
        nostr_event_offset::test_get_offset_from_empty_table(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn add_event(pool: SqlitePool) {
        let store = SqliteNostrEventOffsetStore::new(pool);
        nostr_event_offset::test_add_event(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn is_processed(pool: SqlitePool) {
        let store = SqliteNostrEventOffsetStore::new(pool);
        nostr_event_offset::test_is_processed(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn current_offset_returns_latest_event(pool: SqlitePool) {
        let store = SqliteNostrEventOffsetStore::new(pool);
        nostr_event_offset::test_current_offset_returns_latest_event(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn current_offset_is_by_node_id(pool: SqlitePool) {
        let store = SqliteNostrEventOffsetStore::new(pool);
        nostr_event_offset::test_current_offset_is_by_node_id(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn failed_event_is_retryable(pool: SqlitePool) {
        let store = SqliteNostrEventOffsetStore::new(pool);
        nostr_event_offset::test_failed_event_is_retryable(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn test_catchup_cursor_lifecycle(pool: SqlitePool) {
        let store = SqliteNostrEventOffsetStore::new(pool);
        nostr_event_offset::test_catchup_cursor_lifecycle(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn ignored_private_event_does_not_advance_offset(pool: SqlitePool) {
        let store = SqliteNostrEventOffsetStore::new(pool);
        nostr_event_offset::test_ignored_private_event_does_not_advance_offset(&store).await;
    }
}
