use crate::{
    Error, Result,
    sql::{
        block_id_to_db,
        identity_chain::{
            DELETE_FROM_HEIGHT, INSERT_BLOCK, IdentityBlockRow, SELECT_CHAIN, SELECT_LATEST,
            bind_insert_block, validate_block_append,
        },
    },
    traits::identity::IdentityChainStoreApi,
};
use async_trait::async_trait;
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::{
        BlockId,
        blockchain::identity::{IdentityBlock, IdentityBlockchain},
    },
};
use sqlx::SqlitePool;

// SQL
// sqlite only allows 1 writer, so writing creates the lock for the tx to avoid a race at bill chain creation and adding/removing blocks
pub(crate) const LOCK_CHAIN_SQLITE: &str = r#"
    UPDATE identity_chain_lock
    SET id = id
    WHERE id = 1
"#;

#[derive(Clone)]
pub struct SqliteIdentityChainStore {
    pool: SqlitePool,
}

impl SqliteIdentityChainStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl ServiceTraitBounds for SqliteIdentityChainStore {}

#[async_trait]
impl IdentityChainStoreApi for SqliteIdentityChainStore {
    async fn get_latest_block(&self) -> Result<IdentityBlock> {
        let row: Option<IdentityBlockRow> = sqlx::query_as(SELECT_LATEST)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(row) => row.try_into(),
            None => Err(Error::NoSuchEntity(
                "identity block".to_owned(),
                String::new(),
            )),
        }
    }

    async fn add_block(&self, block: &IdentityBlock) -> Result<()> {
        let row = IdentityBlockRow::try_from(block)?;
        let mut tx = self.pool.begin().await?;
        // acquire write lock until commit/rollback
        sqlx::query(LOCK_CHAIN_SQLITE).execute(&mut *tx).await?;
        // get latest block after lock
        let latest_row: Option<IdentityBlockRow> = sqlx::query_as(SELECT_LATEST)
            .fetch_optional(&mut *tx)
            .await?;
        let latest: Option<IdentityBlock> = latest_row.map(TryInto::try_into).transpose()?;
        validate_block_append(block, latest.as_ref())?;
        bind_insert_block!(sqlx::query(INSERT_BLOCK), row)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn get_chain(&self) -> Result<IdentityBlockchain> {
        let rows: Vec<IdentityBlockRow> =
            sqlx::query_as(SELECT_CHAIN).fetch_all(&self.pool).await?;
        let blocks: Vec<IdentityBlock> = rows
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_>>()?;
        IdentityBlockchain::new_from_blocks(blocks).map_err(|e| Error::Protocol(e.into()))
    }

    async fn remove_blocks_from_height(&self, from_block_id: BlockId) -> Result<()> {
        let block_id = block_id_to_db(from_block_id)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(LOCK_CHAIN_SQLITE).execute(&mut *tx).await?;
        sqlx::query(DELETE_FROM_HEIGHT)
            .bind(block_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SqliteIdentityChainStore;
    use crate::tests::identity_chain::{
        test_concurrent_identity_add, test_concurrent_identity_first_block, test_identity_chain,
    };
    use sqlx::SqlitePool;

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn identity_chain(pool: SqlitePool) {
        let store = SqliteIdentityChainStore::new(pool);
        test_identity_chain(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn concurrent_first_block(pool: SqlitePool) {
        let store = SqliteIdentityChainStore::new(pool);
        test_concurrent_identity_first_block(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn concurrent_add(pool: SqlitePool) {
        let store = SqliteIdentityChainStore::new(pool);
        test_concurrent_identity_add(&store).await;
    }
}
