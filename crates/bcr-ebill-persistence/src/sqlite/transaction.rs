use crate::{
    EncryptionContext, Error, Result,
    sql::{
        block_id_to_db,
        identity::{
            IdentityKeysRow, SELECT_KEYS, UPSERT_EMAIL_CONFIRMATION, UPSERT_IDENTITY,
            bind_identity, email_confirmation_to_row, identity_key_pair_from_row, identity_to_row,
        },
        identity_chain::{
            DELETE_FROM_HEIGHT, INSERT_BLOCK, IdentityBlockRow, SELECT_LATEST, bind_insert_block,
            validate_block_append, validate_expected_identity_tip,
        },
    },
    sqlite::identity_chain::LOCK_CHAIN_SQLITE,
    traits::transaction::{
        IdentityTransactionApi, PersistenceTransactionApi, TransactionManagerApi,
    },
};
use async_trait::async_trait;
use bcr_ebill_core::{
    application::{ServiceTraitBounds, identity::Identity},
    protocol::{
        BlockId, EmailIdentityProofData, SignedIdentityProof, blockchain::identity::IdentityBlock,
    },
};
use sqlx::{Sqlite, SqlitePool, Transaction};
use std::sync::Arc;

#[derive(Clone)]
pub struct SqliteTransactionManager {
    pool: SqlitePool,
    encryption_ctx: Arc<EncryptionContext>,
}

impl SqliteTransactionManager {
    pub fn new(pool: SqlitePool, encryption_ctx: Arc<EncryptionContext>) -> Self {
        Self {
            pool,
            encryption_ctx,
        }
    }
}

impl ServiceTraitBounds for SqliteTransactionManager {}

#[async_trait]
impl TransactionManagerApi for SqliteTransactionManager {
    async fn begin(&self) -> Result<Box<dyn PersistenceTransactionApi>> {
        let tx = self.pool.begin().await?;

        Ok(Box::new(SqlitePersistenceTransaction {
            tx,
            encryption_ctx: self.encryption_ctx.clone(),
            identity_chain_locked: false,
        }))
    }
}

pub struct SqlitePersistenceTransaction {
    tx: Transaction<'static, Sqlite>,
    encryption_ctx: Arc<EncryptionContext>,
    identity_chain_locked: bool,
}

#[async_trait]
impl PersistenceTransactionApi for SqlitePersistenceTransaction {
    async fn commit(self: Box<Self>) -> Result<()> {
        let Self { tx, .. } = *self;
        tx.commit().await?;
        Ok(())
    }
}

impl SqlitePersistenceTransaction {
    async fn lock_identity_chain(&mut self) -> Result<()> {
        if self.identity_chain_locked {
            return Ok(());
        }
        sqlx::query(LOCK_CHAIN_SQLITE)
            .execute(&mut *self.tx)
            .await?;
        self.identity_chain_locked = true;
        Ok(())
    }

    async fn get_latest_identity_block(&mut self) -> Result<Option<IdentityBlock>> {
        let row: Option<IdentityBlockRow> = sqlx::query_as(SELECT_LATEST)
            .fetch_optional(&mut *self.tx)
            .await?;
        row.map(TryInto::try_into).transpose()
    }
}

#[async_trait]
impl IdentityTransactionApi for SqlitePersistenceTransaction {
    async fn append_identity_blocks(
        &mut self,
        expected_latest: Option<&IdentityBlock>,
        blocks: &[IdentityBlock],
    ) -> Result<()> {
        self.lock_identity_chain().await?;
        let mut latest = self.get_latest_identity_block().await?;
        validate_expected_identity_tip(latest.as_ref(), expected_latest)?;
        for block in blocks {
            validate_block_append(block, latest.as_ref())?;
            let row = IdentityBlockRow::try_from(block)?;
            bind_insert_block!(sqlx::query(INSERT_BLOCK), row)
                .execute(&mut *self.tx)
                .await?;
            latest = Some(block.clone());
        }
        Ok(())
    }

    async fn replace_identity_blocks_from_height(
        &mut self,
        expected_latest: &IdentityBlock,
        from_block_id: BlockId,
        replacement_blocks: &[IdentityBlock],
    ) -> Result<()> {
        self.lock_identity_chain().await?;
        let actual_latest = self.get_latest_identity_block().await?;
        validate_expected_identity_tip(actual_latest.as_ref(), Some(expected_latest))?;
        let block_id = block_id_to_db(from_block_id)?;
        sqlx::query(DELETE_FROM_HEIGHT)
            .bind(block_id)
            .execute(&mut *self.tx)
            .await?;

        // validate replacement against the remaining chain after truncation
        let mut latest = self.get_latest_identity_block().await?;
        for block in replacement_blocks {
            validate_block_append(block, latest.as_ref())?;
            let row = IdentityBlockRow::try_from(block)?;
            bind_insert_block!(sqlx::query(INSERT_BLOCK), row)
                .execute(&mut *self.tx)
                .await?;
            latest = Some(block.clone());
        }
        Ok(())
    }

    async fn save_identity(&mut self, identity: &Identity) -> Result<()> {
        let row = identity_to_row(identity)?;
        bind_identity!(sqlx::query(UPSERT_IDENTITY), row)
            .execute(&mut *self.tx)
            .await?;
        Ok(())
    }

    async fn set_identity_email_confirmation(
        &mut self,
        proof: &SignedIdentityProof,
        data: &EmailIdentityProofData,
    ) -> Result<()> {
        let key_row: Option<IdentityKeysRow> = sqlx::query_as(SELECT_KEYS)
            .fetch_optional(&mut *self.tx)
            .await?;
        let key_row = key_row
            .ok_or_else(|| Error::NoSuchEntity("identity key pair".to_owned(), String::new()))?;
        let keys = identity_key_pair_from_row(key_row, &self.encryption_ctx)?;
        if keys.pub_key() != data.node_id.pub_key() {
            return Err(Error::PublicKeyDoesNotMatch);
        }
        let row = email_confirmation_to_row(&(proof.to_owned(), data.to_owned()))?;
        sqlx::query(UPSERT_EMAIL_CONFIRMATION)
            .bind(row.signature)
            .bind(row.witness)
            .bind(row.node_id)
            .bind(row.company_node_id)
            .bind(row.email)
            .bind(row.created_at)
            .execute(&mut *self.tx)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SqliteTransactionManager;
    use crate::{
        EncryptionContext,
        sqlite::{identity::SqliteIdentityStore, identity_chain::SqliteIdentityChainStore},
        tests::identity_transaction::{
            test_identity_transaction_commit, test_identity_transaction_rejects_second_genesis,
            test_identity_transaction_rejects_stale_tip, test_identity_transaction_replace,
            test_identity_transaction_replace_rollback, test_identity_transaction_rollback,
        },
    };
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use sqlx::SqlitePool;
    use std::sync::Arc;

    fn setup(
        pool: SqlitePool,
    ) -> (
        SqliteTransactionManager,
        SqliteIdentityStore,
        SqliteIdentityChainStore,
    ) {
        let encryption_ctx = Arc::new(EncryptionContext::new(BcrKeys::new()));
        (
            SqliteTransactionManager::new(pool.clone(), encryption_ctx.clone()),
            SqliteIdentityStore::new(pool.clone(), encryption_ctx),
            SqliteIdentityChainStore::new(pool),
        )
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn identity_transaction_commit(pool: SqlitePool) {
        let (manager, store, chain) = setup(pool);
        test_identity_transaction_commit(&manager, &store, &chain).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn identity_transaction_rollback(pool: SqlitePool) {
        let (manager, store, chain) = setup(pool);
        test_identity_transaction_rollback(&manager, &store, &chain).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn identity_transaction_rejects_stale_tip(pool: SqlitePool) {
        let (manager, _, chain) = setup(pool);
        test_identity_transaction_rejects_stale_tip(&manager, &chain).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn identity_transaction_replace(pool: SqlitePool) {
        let (manager, _, chain) = setup(pool);
        test_identity_transaction_replace(&manager, &chain).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn identity_transaction_replace_rollback(pool: SqlitePool) {
        let (manager, _, chain) = setup(pool);
        test_identity_transaction_replace_rollback(&manager, &chain).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn identity_transaction_rejects_second_genesis(pool: SqlitePool) {
        let (manager, _, chain) = setup(pool);
        test_identity_transaction_rejects_second_genesis(&manager, &chain).await;
    }
}
