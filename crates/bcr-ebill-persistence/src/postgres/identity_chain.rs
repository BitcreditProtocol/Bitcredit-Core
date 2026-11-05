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
use sqlx::PgPool;

// SQL
// For postgres we use a row-level lock to avoid a race at bill chain creation and adding/removing blocks
pub(crate) const LOCK_CHAIN_POSTGRES: &str = r#"
    SELECT id
    FROM identity_chain_lock
    WHERE id = 1
    FOR UPDATE
"#;

#[derive(Clone)]
pub struct PostgresIdentityChainStore {
    pool: PgPool,
}

impl PostgresIdentityChainStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ServiceTraitBounds for PostgresIdentityChainStore {}

#[async_trait]
impl IdentityChainStoreApi for PostgresIdentityChainStore {
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
    use super::PostgresIdentityChainStore;
    use crate::{
        EncryptionContext, postgres::transaction::PostgresTransactionManager,
        tests::identity_chain::test_identity_chain,
    };
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use sqlx::PgPool;
    use std::sync::Arc;

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn identity_chain(pool: PgPool) {
        let encryption_ctx = Arc::new(EncryptionContext::new(BcrKeys::new()));
        let store = PostgresIdentityChainStore::new(pool.clone());
        let transaction_mgr = PostgresTransactionManager::new(pool, encryption_ctx);
        test_identity_chain(&transaction_mgr, &store).await;
    }
}
