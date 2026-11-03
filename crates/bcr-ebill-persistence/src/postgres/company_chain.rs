use crate::traits::company::CompanyChainStoreApi;
use crate::{
    Error, Result,
    sql::company_chain::{CompanyBlockRow, DELETE_CHAIN, ENSURE_CHAIN_LOCK, SELECT_CHAIN},
};
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::blockchain::company::{CompanyBlock, CompanyBlockchain},
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
}

#[cfg(test)]
mod tests {
    use super::PostgresCompanyChainStore;
    use crate::{
        EncryptionContext, postgres::transaction::PostgresTransactionManager,
        tests::company_chain::test_company_chain,
    };
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use sqlx::PgPool;
    use std::sync::Arc;

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn company_chain(pool: PgPool) {
        let encryption_ctx = Arc::new(EncryptionContext::new(BcrKeys::new()));
        let store = PostgresCompanyChainStore::new(pool.clone());
        let transaction_mgr = PostgresTransactionManager::new(pool, encryption_ctx);
        test_company_chain(&transaction_mgr, &store).await;
    }
}
