use crate::{
    Result,
    sql::nostr_chain_event::{
        DELETE_CHAIN_EVENTS, NostrChainEventRow, SELECT_BY_BLOCK_HASH, SELECT_BY_EVENT_ID,
        SELECT_CHAIN_EVENTS, SELECT_LATEST_BLOCK_EVENTS, SELECT_ROOT_EVENT, UPSERT_CHAIN_EVENT,
    },
    traits::nostr::{NostrChainEvent, NostrChainEventStoreApi},
};
use async_trait::async_trait;
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::{Sha256Hash, blockchain::BlockchainType},
};
use sqlx::{SqlitePool, types::Text};

#[derive(Clone)]
pub struct SqliteNostrChainEventStore {
    pool: SqlitePool,
}

impl SqliteNostrChainEventStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl ServiceTraitBounds for SqliteNostrChainEventStore {}

#[async_trait]
impl NostrChainEventStoreApi for SqliteNostrChainEventStore {
    async fn find_chain_events(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> Result<Vec<NostrChainEvent>> {
        let rows: Vec<NostrChainEventRow> = sqlx::query_as(SELECT_CHAIN_EVENTS)
            .bind(chain_id)
            .bind(chain_type.to_string())
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn find_latest_block_events(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> Result<Vec<NostrChainEvent>> {
        let rows: Vec<NostrChainEventRow> = sqlx::query_as(SELECT_LATEST_BLOCK_EVENTS)
            .bind(chain_id)
            .bind(chain_type.to_string())
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn find_by_block_hash(&self, hash: &Sha256Hash) -> Result<Option<NostrChainEvent>> {
        let row: Option<NostrChainEventRow> = sqlx::query_as(SELECT_BY_BLOCK_HASH)
            .bind(Text(hash.clone()))
            .fetch_optional(&self.pool)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn add_chain_event(&self, event: NostrChainEvent) -> Result<()> {
        let row = NostrChainEventRow::try_from(event)?;
        sqlx::query(UPSERT_CHAIN_EVENT)
            .bind(row.event_id)
            .bind(row.root_id)
            .bind(row.reply_id)
            .bind(row.author)
            .bind(row.chain_id)
            .bind(row.chain_type)
            .bind(row.block_height)
            .bind(row.block_hash)
            .bind(row.received)
            .bind(row.time)
            .bind(row.payload)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn by_event_id(&self, event_id: &str) -> Result<Option<NostrChainEvent>> {
        let row: Option<NostrChainEventRow> = sqlx::query_as(SELECT_BY_EVENT_ID)
            .bind(event_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn find_root_event(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> Result<Option<NostrChainEvent>> {
        let row: Option<NostrChainEventRow> = sqlx::query_as(SELECT_ROOT_EVENT)
            .bind(chain_id)
            .bind(chain_type.to_string())
            .fetch_optional(&self.pool)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn remove_chain_events(&self, chain_id: &str, chain_type: BlockchainType) -> Result<()> {
        sqlx::query(DELETE_CHAIN_EVENTS)
            .bind(chain_id)
            .bind(chain_type.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SqliteNostrChainEventStore;
    use crate::tests::nostr_chain_event;
    use sqlx::SqlitePool;

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn add_event(pool: SqlitePool) {
        let store = SqliteNostrChainEventStore::new(pool);
        nostr_chain_event::test_add_event(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn event_by_hash(pool: SqlitePool) {
        let store = SqliteNostrChainEventStore::new(pool);
        nostr_chain_event::test_event_by_hash(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn find_by_block_hash_prefers_latest(pool: SqlitePool) {
        let store = SqliteNostrChainEventStore::new(pool);
        nostr_chain_event::test_find_by_block_hash_prefers_latest(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn find_root_event(pool: SqlitePool) {
        let store = SqliteNostrChainEventStore::new(pool);
        nostr_chain_event::test_find_root_event(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn find_latest_block_events(pool: SqlitePool) {
        let store = SqliteNostrChainEventStore::new(pool);
        nostr_chain_event::test_find_latest_block_events(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn find_all_events(pool: SqlitePool) {
        let store = SqliteNostrChainEventStore::new(pool);
        nostr_chain_event::test_find_all_events(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn upsert_existing_event(pool: SqlitePool) {
        let store = SqliteNostrChainEventStore::new(pool);
        nostr_chain_event::test_upsert_existing_event(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn chain_type_scoping(pool: SqlitePool) {
        let store = SqliteNostrChainEventStore::new(pool);
        nostr_chain_event::test_chain_type_scoping(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn remove_chain_events(pool: SqlitePool) {
        let store = SqliteNostrChainEventStore::new(pool);
        nostr_chain_event::test_remove_chain_events(&store).await;
    }
}
