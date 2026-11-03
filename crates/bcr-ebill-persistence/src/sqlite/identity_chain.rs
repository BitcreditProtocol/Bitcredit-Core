use crate::{
    Error, Result,
    sql::identity_chain::{IdentityBlockRow, SELECT_CHAIN},
    traits::identity::IdentityChainStoreApi,
};
use async_trait::async_trait;
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::blockchain::identity::{IdentityBlock, IdentityBlockchain},
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
    async fn get_chain(&self) -> Result<IdentityBlockchain> {
        let rows: Vec<IdentityBlockRow> =
            sqlx::query_as(SELECT_CHAIN).fetch_all(&self.pool).await?;
        let blocks: Vec<IdentityBlock> = rows
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_>>()?;
        IdentityBlockchain::new_from_blocks(blocks).map_err(|e| Error::Protocol(e.into()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::SqliteIdentityChainStore;
    use crate::{
        EncryptionContext, sqlite::transaction::SqliteTransactionManager,
        tests::identity_chain::test_identity_chain,
    };
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use sqlx::SqlitePool;

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn identity_chain(pool: SqlitePool) {
        let encryption_ctx = Arc::new(EncryptionContext::new(BcrKeys::new()));
        let store = SqliteIdentityChainStore::new(pool.clone());
        let transaction_mgr = SqliteTransactionManager::new(pool, encryption_ctx);
        test_identity_chain(&transaction_mgr, &store).await;
    }
}
