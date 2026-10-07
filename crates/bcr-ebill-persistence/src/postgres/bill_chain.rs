use crate::{
    Error, Result,
    sql::{
        bill_chain::{
            BillBlockRow, DELETE_FROM_HEIGHT, ENSURE_CHAIN_LOCK, INSERT_BLOCK, SELECT_CHAIN,
            SELECT_LATEST, bind_insert_block, validate_block_append,
        },
        block_id_to_db,
    },
    traits::bill::BillChainStoreApi,
};
use async_trait::async_trait;
use bcr_common::core::BillId;
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::{
        BlockId,
        blockchain::bill::{BillBlock, BillBlockchain},
    },
};
use sqlx::{PgPool, types::Text};

// SQL
// For postgres we use a row-level lock to avoid a race at bill chain creation and adding/removing blocks
pub(crate) const LOCK_CHAIN_POSTGRES: &str = r#"
    SELECT bill_id
    FROM bill_chain_locks
    WHERE bill_id = $1
    FOR UPDATE
"#;
#[derive(Clone)]
pub struct PostgresBillChainStore {
    pool: PgPool,
}

impl PostgresBillChainStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ServiceTraitBounds for PostgresBillChainStore {}

#[async_trait]
impl BillChainStoreApi for PostgresBillChainStore {
    async fn get_latest_block(&self, id: &BillId) -> Result<BillBlock> {
        let row: Option<BillBlockRow> = sqlx::query_as(SELECT_LATEST)
            .bind(Text(id.clone()))
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(row) => row.try_into(),
            None => Err(Error::NoSuchEntity("bill block".to_owned(), id.to_string())),
        }
    }
    async fn add_block(&self, id: &BillId, block: &BillBlock) -> Result<()> {
        let row = BillBlockRow::try_from(block)?;

        let mut tx = self.pool.begin().await?;

        // ensure the lock is there
        sqlx::query(ENSURE_CHAIN_LOCK)
            .bind(Text(id.clone()))
            .execute(&mut *tx)
            .await?;

        // acquire write lock until commit/rollback
        sqlx::query(LOCK_CHAIN_POSTGRES)
            .bind(Text(id.clone()))
            .fetch_one(&mut *tx)
            .await?;

        // get latest block after lock
        let latest_row: Option<BillBlockRow> = sqlx::query_as(SELECT_LATEST)
            .bind(Text(id.clone()))
            .fetch_optional(&mut *tx)
            .await?;
        let latest = latest_row.map(TryInto::try_into).transpose()?;
        validate_block_append(id, block, latest.as_ref())?;
        bind_insert_block!(sqlx::query(INSERT_BLOCK), row)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn get_chain(&self, id: &BillId) -> Result<BillBlockchain> {
        let rows: Vec<BillBlockRow> = sqlx::query_as(SELECT_CHAIN)
            .bind(Text(id.clone()))
            .fetch_all(&self.pool)
            .await?;

        let blocks: Vec<BillBlock> = rows
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_>>()?;

        BillBlockchain::new_from_blocks(blocks).map_err(|e| Error::Protocol(e.into()))
    }

    async fn remove_blocks_from_height(&self, id: &BillId, from_block_id: BlockId) -> Result<()> {
        let block_id = block_id_to_db(from_block_id)?;
        let mut tx = self.pool.begin().await?;

        // ensure the lock is there
        sqlx::query(ENSURE_CHAIN_LOCK)
            .bind(Text(id.clone()))
            .execute(&mut *tx)
            .await?;

        // acquire write lock until commit/rollback
        sqlx::query(LOCK_CHAIN_POSTGRES)
            .bind(Text(id.clone()))
            .fetch_one(&mut *tx)
            .await?;

        // delete blocks after lock
        sqlx::query(DELETE_FROM_HEIGHT)
            .bind(Text(id.clone()))
            .bind(block_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::PostgresBillChainStore;
    use crate::tests::bill_chain::{test_chain, test_concurrent_add, test_concurrent_first_block};
    use sqlx::PgPool;

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn chain(pool: PgPool) {
        let store = PostgresBillChainStore::new(pool);
        test_chain(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn concurrent_first_block(pool: PgPool) {
        let store = PostgresBillChainStore::new(pool);
        test_concurrent_first_block(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn concurrent_add(pool: PgPool) {
        let store = PostgresBillChainStore::new(pool);
        test_concurrent_add(&store).await;
    }
}
