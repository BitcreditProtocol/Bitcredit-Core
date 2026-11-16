use crate::{
    EncryptionContext, Error, Result,
    sql::{
        nostr_incoming_propagation::{
            EncodedIncomingCandidate, INSERT_CANDIDATE, IncomingCandidateRow,
            MARK_APPLICATION_DEFERRED, MARK_APPLIED, MARK_PENDING_RETRY, MARK_REJECTED,
            MARK_VERIFIED, SELECT_DUE_CANDIDATES, SELECT_VERIFIED_CANDIDATES,
            WAKE_APPLICATION_FOR_KEYS, WAKE_APPLICATION_FOR_PREDECESSOR,
        },
        timestamp_to_db,
    },
    traits::propagation::{
        ApplicationWaitReason, IncomingChainCandidate, IncomingPropagationStoreApi,
    },
};
use async_trait::async_trait;
use bcr_ebill_core::{application::ServiceTraitBounds, protocol::Timestamp};
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct PostgresIncomingPropagationStore {
    pool: PgPool,
    encryption_ctx: Arc<EncryptionContext>,
}

impl PostgresIncomingPropagationStore {
    pub fn new(pool: PgPool, encryption_ctx: Arc<EncryptionContext>) -> Self {
        Self {
            pool,
            encryption_ctx,
        }
    }
}

impl ServiceTraitBounds for PostgresIncomingPropagationStore {}

#[async_trait]
impl IncomingPropagationStoreApi for PostgresIncomingPropagationStore {
    async fn upsert_candidate(
        &self,
        candidate: &IncomingChainCandidate,
        first_try_at: Timestamp,
    ) -> Result<()> {
        let encoded = EncodedIncomingCandidate::new(candidate, self.encryption_ctx.as_ref())?;
        sqlx::query(INSERT_CANDIDATE)
            .bind(encoded.event_id.as_str())
            .bind(encoded.chain_type.as_str())
            .bind(encoded.chain_id.as_str())
            .bind(encoded.payload.as_slice())
            .bind(encoded.relay_urls_json.as_str())
            .bind(encoded.required_relays)
            .bind(timestamp_to_db(Timestamp::now())?)
            .bind(timestamp_to_db(first_try_at)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_due_candidates(
        &self,
        now: Timestamp,
        limit: u64,
    ) -> Result<Vec<IncomingChainCandidate>> {
        let limit = i64::try_from(limit).map_err(|_| {
            Error::InvalidData("Incoming verification batch limit too large".into())
        })?;
        let rows: Vec<IncomingCandidateRow> = sqlx::query_as(SELECT_DUE_CANDIDATES)
            .bind(timestamp_to_db(now)?)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| row.decrypt(self.encryption_ctx.as_ref()))
            .collect()
    }

    async fn mark_applied(&self, event_id: &str) -> Result<()> {
        sqlx::query(MARK_APPLIED)
            .bind(event_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn mark_pending_retry(
        &self,
        event_id: &str,
        next_try_at: Timestamp,
        reason: &str,
    ) -> Result<()> {
        sqlx::query(MARK_PENDING_RETRY)
            .bind(event_id)
            .bind(timestamp_to_db(next_try_at)?)
            .bind(reason)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn mark_rejected(&self, event_id: &str, reason: &str) -> Result<()> {
        sqlx::query(MARK_REJECTED)
            .bind(event_id)
            .bind(reason)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_verified_candidates(
        &self,
        now: Timestamp,
        limit: u64,
    ) -> Result<Vec<IncomingChainCandidate>> {
        let limit = i64::try_from(limit)
            .map_err(|_| Error::InvalidData("Incoming verified batch limit too large".into()))?;
        let rows: Vec<IncomingCandidateRow> = sqlx::query_as(SELECT_VERIFIED_CANDIDATES)
            .bind(timestamp_to_db(now)?)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| row.decrypt(self.encryption_ctx.as_ref()))
            .collect()
    }

    async fn mark_verified(
        &self,
        event_id: &str,
        verified_at: Timestamp,
        confirmed_relays: &[url::Url],
    ) -> Result<()> {
        let mut relays = confirmed_relays
            .iter()
            .map(|url| url.to_string())
            .collect::<Vec<_>>();
        relays.sort();
        relays.dedup();
        if relays.is_empty() {
            return Err(Error::InvalidData(
                "No confirmed relays for verified event".into(),
            ));
        }
        let confirmed_json = serde_json::to_string(&relays)?;
        sqlx::query(MARK_VERIFIED)
            .bind(event_id)
            .bind(timestamp_to_db(verified_at)?)
            .bind(confirmed_json)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn mark_application_deferred(
        &self,
        event_id: &str,
        next_try_at: Option<Timestamp>,
        reason: ApplicationWaitReason,
        error: &str,
    ) -> Result<()> {
        let next_try_at = next_try_at.map(timestamp_to_db).transpose()?;
        sqlx::query(MARK_APPLICATION_DEFERRED)
            .bind(event_id)
            .bind(next_try_at)
            .bind(reason.as_str())
            .bind(error)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn wake_application_for_keys(&self, chain_type: &str, chain_id: &str) -> Result<()> {
        sqlx::query(WAKE_APPLICATION_FOR_KEYS)
            .bind(chain_type)
            .bind(chain_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn wake_application_for_predecessor(
        &self,
        chain_type: &str,
        chain_id: &str,
    ) -> Result<()> {
        sqlx::query(WAKE_APPLICATION_FOR_PREDECESSOR)
            .bind(chain_type)
            .bind(chain_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::PostgresIncomingPropagationStore;
    use crate::{EncryptionContext, tests::nostr_incoming_propagation};
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use sqlx::PgPool;
    use std::sync::Arc;

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn incoming_candidate_lifecycle(pool: PgPool) {
        let encryption_ctx = Arc::new(EncryptionContext::new(BcrKeys::new()));
        let store = PostgresIncomingPropagationStore::new(pool, encryption_ctx);
        nostr_incoming_propagation::test_incoming_candidate_lifecycle(&store).await;
    }
}
