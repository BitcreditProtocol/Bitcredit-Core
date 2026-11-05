use crate::{
    Error, Result,
    sql::bill_chain::{BillBlockRow, SELECT_CHAIN},
    traits::bill::BillChainStoreApi,
};
use async_trait::async_trait;
use bcr_common::core::BillId;
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::blockchain::bill::{BillBlock, BillBlockchain},
};
use sqlx::{SqlitePool, types::Text};

// SQL
// sqlite only allows 1 writer, so writing creates the lock for the tx to avoid a race at bill chain creation and adding/removing blocks
pub(crate) const LOCK_CHAIN_SQLITE: &str = r#"
    UPDATE bill_chain_locks
    SET bill_id = bill_id
    WHERE bill_id = $1
"#;

#[derive(Clone)]
pub struct SqliteBillChainStore {
    pool: SqlitePool,
}

impl SqliteBillChainStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl ServiceTraitBounds for SqliteBillChainStore {}

#[async_trait]
impl BillChainStoreApi for SqliteBillChainStore {
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
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::SqliteBillChainStore;
    use crate::{
        EncryptionContext, sqlite::transaction::SqliteTransactionManager,
        tests::bill_chain::test_chain,
    };
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use sqlx::SqlitePool;

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn chain(pool: SqlitePool) {
        let encryption_ctx = Arc::new(EncryptionContext::new(BcrKeys::new()));
        let store = SqliteBillChainStore::new(pool.clone());
        let transaction_mgr = SqliteTransactionManager::new(pool, encryption_ctx);
        test_chain(&transaction_mgr, &store).await;
    }
}
