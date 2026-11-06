use crate::{
    EncryptionContext, Error, Result,
    sql::{
        nostr_propagation::{
            MARK_RELAY_ACCEPTED, MARK_RELAY_FAILED, PendingDeliveryRow, PropagationMessageRow,
            PropagationRelayRow, PropagationRow, SELECT_PENDING_DELIVERIES,
            SELECT_PENDING_FOR_PROPAGATION, SELECT_PROPAGATION, SELECT_PROPAGATION_IDS_BY_SUBJECT,
            SELECT_PROPAGATION_MESSAGES, SELECT_PROPAGATION_RELAYS, build_propagation_status,
        },
        timestamp_to_db,
    },
    traits::propagation::{
        NostrPropagationStoreApi, PendingDelivery, PropagationStatus, PropagationSubjectType,
    },
};
use async_trait::async_trait;
use bcr_ebill_core::{application::ServiceTraitBounds, protocol::Timestamp};
use sqlx::SqlitePool;
use std::sync::Arc;

#[derive(Clone)]
pub struct SqliteNostrPropagationStore {
    pool: SqlitePool,
    encryption_ctx: Arc<EncryptionContext>,
}

impl SqliteNostrPropagationStore {
    pub fn new(pool: SqlitePool, encryption_ctx: Arc<EncryptionContext>) -> Self {
        Self {
            pool,
            encryption_ctx,
        }
    }
}

impl ServiceTraitBounds for SqliteNostrPropagationStore {}

#[async_trait]
impl NostrPropagationStoreApi for SqliteNostrPropagationStore {
    async fn get_propagation(&self, propagation_id: &str) -> Result<Option<PropagationStatus>> {
        let row: Option<PropagationRow> = sqlx::query_as(SELECT_PROPAGATION)
            .bind(propagation_id)
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let messages: Vec<PropagationMessageRow> = sqlx::query_as(SELECT_PROPAGATION_MESSAGES)
            .bind(propagation_id)
            .fetch_all(&self.pool)
            .await?;
        let relays: Vec<PropagationRelayRow> = sqlx::query_as(SELECT_PROPAGATION_RELAYS)
            .bind(propagation_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(Some(build_propagation_status(row, messages, relays)?))
    }

    async fn list_propagation_ids(
        &self,
        subject_type: PropagationSubjectType,
        subject_id: &str,
    ) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(SELECT_PROPAGATION_IDS_BY_SUBJECT)
            .bind(subject_type.as_str())
            .bind(subject_id)
            .fetch_all(&self.pool)
            .await?)
    }

    async fn get_pending_deliveries(
        &self,
        now: Timestamp,
        limit: u64,
    ) -> Result<Vec<PendingDelivery>> {
        let limit = i64::try_from(limit)
            .map_err(|_| Error::InvalidData("Propagation retry limit exceeds i64".into()))?;
        let rows: Vec<PendingDeliveryRow> = sqlx::query_as(SELECT_PENDING_DELIVERIES)
            .bind(timestamp_to_db(now)?)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| row.decrypt(self.encryption_ctx.as_ref()))
            .collect()
    }

    async fn get_pending_deliveries_for_propagation(
        &self,
        propagation_id: &str,
        now: Timestamp,
    ) -> Result<Vec<PendingDelivery>> {
        let rows: Vec<PendingDeliveryRow> = sqlx::query_as(SELECT_PENDING_FOR_PROPAGATION)
            .bind(propagation_id)
            .bind(timestamp_to_db(now)?)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| row.decrypt(self.encryption_ctx.as_ref()))
            .collect()
    }

    async fn mark_relay_accepted(
        &self,
        message_id: &str,
        relay: &url::Url,
        accepted_at: Timestamp,
    ) -> Result<()> {
        sqlx::query(MARK_RELAY_ACCEPTED)
            .bind(message_id)
            .bind(relay.as_str())
            .bind(timestamp_to_db(accepted_at)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn mark_relay_failed(
        &self,
        message_id: &str,
        relay: &url::Url,
        next_try_at: Timestamp,
        error: &str,
    ) -> Result<()> {
        sqlx::query(MARK_RELAY_FAILED)
            .bind(message_id)
            .bind(relay.as_str())
            .bind(timestamp_to_db(next_try_at)?)
            .bind(error)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SqliteNostrPropagationStore;
    use crate::sql::nostr_propagation::SELECT_PENDING_FOR_PROPAGATION;
    use crate::{
        EncryptionContext, sqlite::transaction::SqliteTransactionManager, tests::nostr_propagation,
    };
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use sqlx::Row;
    use sqlx::SqlitePool;
    use std::collections::HashSet;
    use std::sync::Arc;

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn propagation_store_roundtrip(pool: SqlitePool) {
        let encryption_ctx = Arc::new(EncryptionContext::new(BcrKeys::new()));
        let manager = SqliteTransactionManager::new(pool.clone(), encryption_ctx.clone());
        let store = SqliteNostrPropagationStore::new(pool, encryption_ctx);
        nostr_propagation::test_propagation_store(&store, &manager).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn child_event_waits_for_parent_ack_on_each_relay(pool: sqlx::SqlitePool) {
        sqlx::query(
            "INSERT INTO nostr_propagations (id, subject_type, subject_id, created_at) VALUES ('p1', 'bill', 'bill1', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        for (message, event) in [("issue-msg", "issue-event"), ("accept-msg", "accept-event")] {
            sqlx::query(
                "INSERT INTO nostr_propagation_messages (id, propagation_id, event_type, nostr_event_id, payload) VALUES ($1, 'p1', 'BillChain', $2, X'00')",
            )
            .bind(message)
            .bind(event)
            .execute(&pool)
            .await
            .unwrap();
            for relay in ["wss://r1.example", "wss://r2.example", "wss://r3.example"] {
                sqlx::query(
                    "INSERT INTO nostr_propagation_relays (message_id, relay_url) VALUES ($1, $2)",
                )
                .bind(message)
                .bind(relay)
                .execute(&pool)
                .await
                .unwrap();
            }
        }

        // Persist the child's Nostr predecessor relationship
        sqlx::query(
            r#"
        INSERT INTO nostr_chain_event (
            event_id, root_id, reply_id,
            author, chain_id, chain_type,
            block_height, block_hash,
            received, time, payload
        )
        VALUES (
            'accept-event', 'issue-event', 'issue-event',
            'author', 'bill1', 'bill',
            2, 'accept-hash',
            1, 1, '{}'
        )
        "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        // Issue succeeds on r1 and r2, but not on r3
        sqlx::query(
            "UPDATE nostr_propagation_relays SET accepted_at = 1 WHERE message_id = 'issue-msg' AND relay_url IN ('wss://r1.example', 'wss://r2.example')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let rows = sqlx::query(SELECT_PENDING_FOR_PROPAGATION)
            .bind("p1")
            .bind(2_i64)
            .fetch_all(&pool)
            .await
            .unwrap();

        let due: HashSet<(String, String)> = rows
            .iter()
            .map(|row| {
                (
                    row.get::<String, _>("message_id"),
                    row.get::<String, _>("relay_url"),
                )
            })
            .collect();

        assert_eq!(
            due,
            HashSet::from([
                ("issue-msg".to_owned(), "wss://r3.example".to_owned(),),
                ("accept-msg".to_owned(), "wss://r1.example".to_owned(),),
                ("accept-msg".to_owned(), "wss://r2.example".to_owned(),),
            ])
        );

        // When Issue is accepted on r3,
        // Accept becomes eligible there as well
        sqlx::query(
            "UPDATE nostr_propagation_relays SET accepted_at = 2 WHERE message_id = 'issue-msg' AND relay_url = 'wss://r3.example'",
        )
        .execute(&pool)
        .await
        .unwrap();

        let rows = sqlx::query(SELECT_PENDING_FOR_PROPAGATION)
            .bind("p1")
            .bind(3_i64)
            .fetch_all(&pool)
            .await
            .unwrap();

        let due_after: HashSet<(String, String)> = rows
            .iter()
            .map(|row| {
                (
                    row.get::<String, _>("message_id"),
                    row.get::<String, _>("relay_url"),
                )
            })
            .collect();

        assert!(due_after.contains(&("accept-msg".to_owned(), "wss://r3.example".to_owned(),)));
        assert!(due_after.iter().all(|(id, _)| { id == "accept-msg" }));
    }
}
