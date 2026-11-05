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

    use super::PostgresBillChainStore;
    use crate::{
        EncryptionContext, postgres::transaction::PostgresTransactionManager,
        tests::bill_chain::test_chain,
    };
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use sqlx::PgPool;

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn chain(pool: PgPool) {
        let encryption_ctx = Arc::new(EncryptionContext::new(BcrKeys::new()));
        let store = PostgresBillChainStore::new(pool.clone());
        let transaction_mgr = PostgresTransactionManager::new(pool, encryption_ctx);
        test_chain(&transaction_mgr, &store).await;
    }
}
