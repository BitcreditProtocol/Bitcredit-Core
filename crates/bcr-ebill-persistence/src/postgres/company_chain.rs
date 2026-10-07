use crate::traits::company::CompanyChainStoreApi;
use crate::{
    Error, Result,
    sql::{
        block_id_to_db,
        company_chain::{
            CompanyBlockRow, DELETE_CHAIN, DELETE_FROM_HEIGHT, ENSURE_CHAIN_LOCK, INSERT_BLOCK,
            SELECT_CHAIN, SELECT_LATEST, bind_insert_block, validate_block_append,
        },
    },
};
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::{
        BlockId,
        blockchain::company::{CompanyBlock, CompanyBlockchain},
    },
};
use sqlx::{PgPool, types::Text};

// SQL
// For postgres we use a row-level lock to avoid a race at bill chain creation and adding/removing blocks
pub(crate) const LOCK_CHAIN_POSTGRES: &str = r#"
    SELECT company_id
    FROM company_chain_locks
    WHERE company_id = $1
    FOR UPDATE
"#;

#[derive(Clone)]
pub struct PostgresCompanyChainStore {
    pool: PgPool,
}

impl PostgresCompanyChainStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ServiceTraitBounds for PostgresCompanyChainStore {}

#[async_trait]
impl CompanyChainStoreApi for PostgresCompanyChainStore {
    async fn get_latest_block(&self, id: &NodeId) -> Result<CompanyBlock> {
        let row: Option<CompanyBlockRow> = sqlx::query_as(SELECT_LATEST)
            .bind(Text(id.clone()))
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(row) => row.try_into(),
            None => Err(Error::NoSuchEntity(
                "company block".to_owned(),
                id.to_string(),
            )),
        }
    }

    async fn add_block(&self, id: &NodeId, block: &CompanyBlock) -> Result<()> {
        let row = CompanyBlockRow::try_from(block)?;
        let mut tx = self.pool.begin().await?;
        // ensure the lock is there
        sqlx::query(ENSURE_CHAIN_LOCK)
            .bind(Text(id.clone()))
            .execute(&mut *tx)
            .await?;
        // acquire write lock until commit/rollback
        sqlx::query(LOCK_CHAIN_POSTGRES)
            .bind(Text(id.clone()))
            .execute(&mut *tx)
            .await?;
        // get latest block after lock
        let latest_row: Option<CompanyBlockRow> = sqlx::query_as(SELECT_LATEST)
            .bind(Text(id.clone()))
            .fetch_optional(&mut *tx)
            .await?;

        let latest: Option<CompanyBlock> = latest_row.map(TryInto::try_into).transpose()?;
        validate_block_append(id, block, latest.as_ref())?;
        bind_insert_block!(sqlx::query(INSERT_BLOCK), row)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn remove(&self, id: &NodeId) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(ENSURE_CHAIN_LOCK)
            .bind(Text(id.clone()))
            .execute(&mut *tx)
            .await?;
        sqlx::query(LOCK_CHAIN_POSTGRES)
            .bind(Text(id.clone()))
            .execute(&mut *tx)
            .await?;
        sqlx::query(DELETE_CHAIN)
            .bind(Text(id.clone()))
            .execute(&mut *tx)
            .await?;

        // we don't delete company_chain_locks, so we can recreate the company in the future
        tx.commit().await?;
        Ok(())
    }

    async fn get_chain(&self, id: &NodeId) -> Result<CompanyBlockchain> {
        let rows: Vec<CompanyBlockRow> = sqlx::query_as(SELECT_CHAIN)
            .bind(Text(id.clone()))
            .fetch_all(&self.pool)
            .await?;
        let blocks: Vec<CompanyBlock> = rows
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_>>()?;
        CompanyBlockchain::new_from_blocks(blocks).map_err(|e| Error::Protocol(e.into()))
    }

    async fn remove_blocks_from_height(&self, id: &NodeId, from_block_id: BlockId) -> Result<()> {
        let from_block_id = block_id_to_db(from_block_id)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(ENSURE_CHAIN_LOCK)
            .bind(Text(id.clone()))
            .execute(&mut *tx)
            .await?;
        sqlx::query(LOCK_CHAIN_POSTGRES)
            .bind(Text(id.clone()))
            .execute(&mut *tx)
            .await?;
        sqlx::query(DELETE_FROM_HEIGHT)
            .bind(Text(id.clone()))
            .bind(from_block_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::PostgresCompanyChainStore;
    use crate::tests::company_chain::{
        test_company_chain, test_concurrent_company_add, test_concurrent_company_first_block,
    };
    use sqlx::PgPool;

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn company_chain(pool: PgPool) {
        let store = PostgresCompanyChainStore::new(pool);
        test_company_chain(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn concurrent_first_block(pool: PgPool) {
        let store = PostgresCompanyChainStore::new(pool);
        test_concurrent_company_first_block(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn concurrent_add(pool: PgPool) {
        let store = PostgresCompanyChainStore::new(pool);
        test_concurrent_company_add(&store).await;
    }
}
