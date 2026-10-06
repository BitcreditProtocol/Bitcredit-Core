use crate::{
    Error, Result,
    constants::NOSTR_QUEUE_PROCESSING_TIMEOUT_SECS,
    sql::{
        nostr_send_queue::{
            FAIL_RETRY, INSERT_MESSAGE, NostrQueuedMessageRow, REQUEUE_FAILED_ENTRY,
            SELECT_NON_SUCCEEDED, SELECT_RETRY_MESSAGES, SET_PROCESSING_STARTED_AT, SUCCEED_RETRY,
        },
        timestamp_to_db,
    },
    traits::nostr::{NostrQueuedMessage, NostrQueuedMessageStatus, NostrQueuedMessageStoreApi},
};
use async_trait::async_trait;
use bcr_ebill_core::{application::ServiceTraitBounds, protocol::Timestamp};
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct SqliteNostrEventQueueStore {
    pool: SqlitePool,
}

impl SqliteNostrEventQueueStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl ServiceTraitBounds for SqliteNostrEventQueueStore {}

#[async_trait]
impl NostrQueuedMessageStoreApi for SqliteNostrEventQueueStore {
    async fn add_message(&self, message: NostrQueuedMessage, max_retries: i32) -> Result<()> {
        let row = NostrQueuedMessageRow::new(message, max_retries)?;

        sqlx::query(INSERT_MESSAGE)
            .bind(row.id)
            .bind(row.sender_id)
            .bind(row.recipient)
            .bind(row.payload)
            .bind(row.created)
            .bind(row.last_try)
            .bind(row.num_retries)
            .bind(row.max_retries)
            .bind(row.completed)
            .bind(row.failed)
            .bind(row.processing_started_at)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn get_retry_messages(&self, limit: u64) -> Result<Vec<NostrQueuedMessage>> {
        let limit = i64::try_from(limit)
            .map_err(|_| Error::InvalidData("nostr retry queue limit exceeds i64".to_owned()))?;
        let now = Timestamp::now();
        let retry_before = now
            .inner()
            .saturating_sub(NOSTR_QUEUE_PROCESSING_TIMEOUT_SECS);
        let retry_before = Timestamp::new(retry_before).expect("safe");
        let retry_before = timestamp_to_db(retry_before)?;
        let processing_started_at = timestamp_to_db(now)?;
        let mut tx = self.pool.begin().await?;
        let rows: Vec<NostrQueuedMessageRow> = sqlx::query_as(SELECT_RETRY_MESSAGES)
            .bind(retry_before)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?;

        for row in &rows {
            sqlx::query(SET_PROCESSING_STARTED_AT)
                .bind(&row.id)
                .bind(processing_started_at)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn fail_retry(&self, id: &str) -> Result<()> {
        let now = timestamp_to_db(Timestamp::now())?;
        let zero = timestamp_to_db(Timestamp::zero())?;

        sqlx::query(FAIL_RETRY)
            .bind(id)
            .bind(now)
            .bind(zero)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn succeed_retry(&self, id: &str) -> Result<()> {
        let now = timestamp_to_db(Timestamp::now())?;
        let zero = timestamp_to_db(Timestamp::zero())?;

        sqlx::query(SUCCEED_RETRY)
            .bind(id)
            .bind(now)
            .bind(zero)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn requeue_failed_entry(&self, id: &str) -> Result<()> {
        let zero = timestamp_to_db(Timestamp::zero())?;

        sqlx::query(REQUEUE_FAILED_ENTRY)
            .bind(id)
            .bind(zero)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn get_non_succeeded_retry_messages(
        &self,
    ) -> Result<Vec<(NostrQueuedMessage, NostrQueuedMessageStatus)>> {
        let rows: Vec<NostrQueuedMessageRow> = sqlx::query_as(SELECT_NON_SUCCEEDED)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .into_iter()
            .map(|row| {
                let status = if row.failed {
                    NostrQueuedMessageStatus::Failed
                } else {
                    NostrQueuedMessageStatus::Pending
                };

                (row.into(), status)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::SqliteNostrEventQueueStore;
    use crate::{
        Result,
        sql::{
            nostr_send_queue::{NostrQueuedMessageRow, SET_PROCESSING_STARTED_AT},
            timestamp_from_db, timestamp_to_db,
        },
        tests::nostr_send_queue::{
            self, NostrQueuedMessageStoreTestApi, NostrQueuedMessageTestState, SELECT_MESSAGE,
        },
    };
    use async_trait::async_trait;
    use bcr_ebill_core::protocol::Timestamp;
    use sqlx::SqlitePool;

    #[async_trait]
    impl NostrQueuedMessageStoreTestApi for SqliteNostrEventQueueStore {
        async fn get_state_for_test(
            &self,
            id: &str,
        ) -> Result<Option<NostrQueuedMessageTestState>> {
            let row: Option<NostrQueuedMessageRow> = sqlx::query_as(SELECT_MESSAGE)
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;

            match row {
                Some(row) => Ok(Some(NostrQueuedMessageTestState {
                    num_retries: row.num_retries,
                    completed: row.completed,
                    failed: row.failed,
                    processing_started_at: timestamp_from_db(row.processing_started_at)?,
                })),
                None => Ok(None),
            }
        }

        async fn set_processing_started_at_for_test(
            &self,
            id: &str,
            timestamp: Timestamp,
        ) -> Result<()> {
            sqlx::query(SET_PROCESSING_STARTED_AT)
                .bind(id)
                .bind(timestamp_to_db(timestamp)?)
                .execute(&self.pool)
                .await?;

            Ok(())
        }
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn insert_query_and_mark_succeeded(pool: SqlitePool) {
        let store = SqliteNostrEventQueueStore::new(pool);
        nostr_send_queue::test_insert_query_and_mark_succeeded(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn insert_query_and_mark_failed(pool: SqlitePool) {
        let store = SqliteNostrEventQueueStore::new(pool);
        nostr_send_queue::test_insert_query_and_mark_failed(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn stale_processing_started_at_is_retryable_again(pool: SqlitePool) {
        let store = SqliteNostrEventQueueStore::new(pool);
        nostr_send_queue::test_stale_processing_started_at_is_retryable_again(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn fail_retry_resets_processing_started_at(pool: SqlitePool) {
        let store = SqliteNostrEventQueueStore::new(pool);
        nostr_send_queue::test_fail_retry_resets_processing_started_at(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn fail_retry_with_more_than_max_retries_fails_the_entry(pool: SqlitePool) {
        let store = SqliteNostrEventQueueStore::new(pool);
        nostr_send_queue::test_fail_retry_with_more_than_max_retries_fails_the_entry(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn succeed_retry_resets_processing_started_at(pool: SqlitePool) {
        let store = SqliteNostrEventQueueStore::new(pool);
        nostr_send_queue::test_succeed_retry_resets_processing_started_at(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn succeed_retry_doesnt_set_failed(pool: SqlitePool) {
        let store = SqliteNostrEventQueueStore::new(pool);
        nostr_send_queue::test_succeed_retry_doesnt_set_failed(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn requeue_failed_entry_resets_entry(pool: SqlitePool) {
        let store = SqliteNostrEventQueueStore::new(pool);
        nostr_send_queue::test_requeue_failed_entry_resets_entry(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn get_non_succeeded_retry_messages(pool: SqlitePool) {
        let store = SqliteNostrEventQueueStore::new(pool);
        nostr_send_queue::test_get_non_succeeded_retry_messages(&store).await;
    }
}
