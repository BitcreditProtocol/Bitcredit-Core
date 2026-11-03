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
use sqlx::{SqlitePool, types::Text};

// SQL
// sqlite only allows 1 writer, so writing creates the lock for the tx to avoid a race at bill chain creation and adding/removing blocks
pub(crate) const LOCK_CHAIN_SQLITE: &str = r#"
    UPDATE company_chain_locks
    SET company_id = company_id
    WHERE company_id = $1
"#;

#[derive(Clone)]
pub struct SqliteCompanyChainStore {
    pool: SqlitePool,
}

impl SqliteCompanyChainStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl ServiceTraitBounds for SqliteCompanyChainStore {}

#[async_trait]
impl CompanyChainStoreApi for SqliteCompanyChainStore {
    async fn remove(&self, id: &NodeId) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(ENSURE_CHAIN_LOCK)
            .bind(Text(id.clone()))
            .execute(&mut *tx)
            .await?;
        sqlx::query(LOCK_CHAIN_SQLITE)
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
    use super::SqliteCompanyChainStore;
    use crate::{
        EncryptionContext, sqlite::transaction::SqliteTransactionManager,
        tests::company_chain::test_company_chain,
    };
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use sqlx::SqlitePool;
    use std::sync::Arc;

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn company_chain(pool: SqlitePool) {
        let encryption_ctx = Arc::new(EncryptionContext::new(BcrKeys::new()));
        let store = SqliteCompanyChainStore::new(pool.clone());
        let transaction_mgr = SqliteTransactionManager::new(pool, encryption_ctx);
        test_company_chain(&transaction_mgr, &store).await;
    }
}
