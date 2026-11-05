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
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct PostgresNostrPropagationStore {
    pool: PgPool,
    encryption_ctx: Arc<EncryptionContext>,
}

impl PostgresNostrPropagationStore {
    pub fn new(pool: PgPool, encryption_ctx: Arc<EncryptionContext>) -> Self {
        Self {
            pool,
            encryption_ctx,
        }
    }
}

impl ServiceTraitBounds for PostgresNostrPropagationStore {}

#[async_trait]
impl NostrPropagationStoreApi for PostgresNostrPropagationStore {
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
    use super::PostgresNostrPropagationStore;
    use crate::{
        EncryptionContext, postgres::transaction::PostgresTransactionManager,
        tests::nostr_propagation,
    };
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use sqlx::PgPool;
    use std::sync::Arc;

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn propagation_store_roundtrip(pool: PgPool) {
        let encryption_ctx = Arc::new(EncryptionContext::new(BcrKeys::new()));
        let manager = PostgresTransactionManager::new(pool.clone(), encryption_ctx.clone());
        let store = PostgresNostrPropagationStore::new(pool, encryption_ctx);
        nostr_propagation::test_propagation_store(&store, &manager).await;
    }
}
