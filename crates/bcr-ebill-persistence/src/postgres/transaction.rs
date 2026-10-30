use crate::{
    EncryptionContext, Error, Result,
    sql::{
        bill::BitcreditBillResultDb,
        bill_chain::{BillBlockRow, validate_expected_bill_tip},
        block_id_to_db,
        company::{
            bind_company, bind_signatory, company_key_pair_from_db, company_signatory_to_row,
            company_to_row,
        },
        company_chain::{CompanyBlockRow, validate_expected_company_tip},
        identity::{
            IdentityKeysRow, bind_identity, email_confirmation_to_row, identity_key_pair_from_row,
            identity_to_row,
        },
        identity_chain::{IdentityBlockRow, validate_expected_identity_tip},
    },
    traits::transaction::{
        BillTransactionApi, CompanyTransactionApi, IdentityTransactionApi,
        PersistenceTransactionApi, TransactionManagerApi,
    },
};
use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::{
    application::{
        ServiceTraitBounds, bill::BitcreditBillResult, company::Company, identity::Identity,
    },
    protocol::{
        BlockId, EmailIdentityProofData, SignedIdentityProof,
        blockchain::{bill::BillBlock, company::CompanyBlock, identity::IdentityBlock},
        crypto::BcrKeys,
    },
};
use bitcoin::base58;
use sqlx::{
    PgPool, Postgres, Transaction,
    types::{Json, Text},
};
use std::{collections::HashSet, sync::Arc};

#[derive(Clone)]
pub struct PostgresTransactionManager {
    pool: PgPool,
    encryption_ctx: Arc<EncryptionContext>,
}

impl PostgresTransactionManager {
    pub fn new(pool: PgPool, encryption_ctx: Arc<EncryptionContext>) -> Self {
        Self {
            pool,
            encryption_ctx,
        }
    }
}

impl ServiceTraitBounds for PostgresTransactionManager {}

#[async_trait]
impl TransactionManagerApi for PostgresTransactionManager {
    async fn begin(&self) -> Result<Box<dyn PersistenceTransactionApi>> {
        Ok(Box::new(PostgresPersistenceTransaction {
            tx: self.pool.begin().await?,
            encryption_ctx: self.encryption_ctx.clone(),
            identity_chain_locked: false,
            company_chains_locked: HashSet::new(),
            bill_chains_locked: HashSet::new(),
        }))
    }
}

pub struct PostgresPersistenceTransaction {
    tx: Transaction<'static, Postgres>,
    encryption_ctx: Arc<EncryptionContext>,
    identity_chain_locked: bool,
    company_chains_locked: HashSet<NodeId>,
    bill_chains_locked: HashSet<BillId>,
}

#[async_trait]
impl PersistenceTransactionApi for PostgresPersistenceTransaction {
    async fn commit(self: Box<Self>) -> Result<()> {
        let Self { tx, .. } = *self;
        tx.commit().await?;
        Ok(())
    }
}

impl PostgresPersistenceTransaction {
    async fn lock_identity_chain(&mut self) -> Result<()> {
        if self.identity_chain_locked {
            return Ok(());
        }

        if !self.company_chains_locked.is_empty() || !self.bill_chains_locked.is_empty() {
            return Err(Error::InvalidData(
                "identity chain lock must be acquired before company and bill chain locks"
                    .to_owned(),
            ));
        }

        sqlx::query(super::identity_chain::LOCK_CHAIN_POSTGRES)
            .execute(&mut *self.tx)
            .await?;
        self.identity_chain_locked = true;
        Ok(())
    }

    async fn lock_company_chain(&mut self, company_id: &NodeId) -> Result<()> {
        if self.company_chains_locked.contains(company_id) {
            return Ok(());
        }

        if !self.bill_chains_locked.is_empty() {
            return Err(Error::InvalidData(
                "company chain lock must be acquired before bill chain locks".to_owned(),
            ));
        }

        sqlx::query(crate::sql::company_chain::ENSURE_CHAIN_LOCK)
            .bind(Text(company_id.clone()))
            .execute(&mut *self.tx)
            .await?;
        sqlx::query(super::company_chain::LOCK_CHAIN_POSTGRES)
            .bind(Text(company_id.clone()))
            .execute(&mut *self.tx)
            .await?;
        self.company_chains_locked.insert(company_id.clone());
        Ok(())
    }

    async fn lock_bill_chain(&mut self, bill_id: &BillId) -> Result<()> {
        if self.bill_chains_locked.contains(bill_id) {
            return Ok(());
        }
        sqlx::query(crate::sql::bill_chain::ENSURE_CHAIN_LOCK)
            .bind(Text(bill_id.clone()))
            .execute(&mut *self.tx)
            .await?;
        sqlx::query(super::bill_chain::LOCK_CHAIN_POSTGRES)
            .bind(Text(bill_id.clone()))
            .fetch_one(&mut *self.tx)
            .await?;
        self.bill_chains_locked.insert(bill_id.clone());
        Ok(())
    }

    async fn get_latest_bill_block(&mut self, bill_id: &BillId) -> Result<Option<BillBlock>> {
        let row: Option<BillBlockRow> = sqlx::query_as(crate::sql::bill_chain::SELECT_LATEST)
            .bind(Text(bill_id.clone()))
            .fetch_optional(&mut *self.tx)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn get_latest_company_block(
        &mut self,
        company_id: &NodeId,
    ) -> Result<Option<CompanyBlock>> {
        let row: Option<CompanyBlockRow> = sqlx::query_as(crate::sql::company_chain::SELECT_LATEST)
            .bind(Text(company_id.clone()))
            .fetch_optional(&mut *self.tx)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn get_latest_identity_block(&mut self) -> Result<Option<IdentityBlock>> {
        let row: Option<IdentityBlockRow> =
            sqlx::query_as(crate::sql::identity_chain::SELECT_LATEST)
                .fetch_optional(&mut *self.tx)
                .await?;
        row.map(TryInto::try_into).transpose()
    }
}

#[async_trait]
impl IdentityTransactionApi for PostgresPersistenceTransaction {
    async fn append_identity_blocks(
        &mut self,
        expected_latest: Option<&IdentityBlock>,
        blocks: &[IdentityBlock],
    ) -> Result<()> {
        self.lock_identity_chain().await?;
        let mut latest = self.get_latest_identity_block().await?;
        validate_expected_identity_tip(latest.as_ref(), expected_latest)?;
        for block in blocks {
            crate::sql::identity_chain::validate_block_append(block, latest.as_ref())?;
            let row = IdentityBlockRow::try_from(block)?;
            crate::sql::identity_chain::bind_insert_block!(
                sqlx::query(crate::sql::identity_chain::INSERT_BLOCK),
                row
            )
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
        sqlx::query(crate::sql::identity_chain::DELETE_FROM_HEIGHT)
            .bind(block_id)
            .execute(&mut *self.tx)
            .await?;

        // validate replacement against the remaining chain after truncation
        let mut latest = self.get_latest_identity_block().await?;
        for block in replacement_blocks {
            crate::sql::identity_chain::validate_block_append(block, latest.as_ref())?;
            let row = IdentityBlockRow::try_from(block)?;
            crate::sql::identity_chain::bind_insert_block!(
                sqlx::query(crate::sql::identity_chain::INSERT_BLOCK),
                row
            )
            .execute(&mut *self.tx)
            .await?;
            latest = Some(block.clone());
        }
        Ok(())
    }

    async fn save_identity(&mut self, identity: &Identity) -> Result<()> {
        let row = identity_to_row(identity)?;
        bind_identity!(sqlx::query(crate::sql::identity::UPSERT_IDENTITY), row)
            .execute(&mut *self.tx)
            .await?;
        Ok(())
    }

    async fn set_identity_email_confirmation(
        &mut self,
        proof: &SignedIdentityProof,
        data: &EmailIdentityProofData,
    ) -> Result<()> {
        let key_row: Option<IdentityKeysRow> = sqlx::query_as(crate::sql::identity::SELECT_KEYS)
            .fetch_optional(&mut *self.tx)
            .await?;
        let key_row = key_row
            .ok_or_else(|| Error::NoSuchEntity("identity key pair".to_owned(), String::new()))?;
        let keys = identity_key_pair_from_row(key_row, &self.encryption_ctx)?;
        if keys.pub_key() != data.node_id.pub_key() {
            return Err(Error::PublicKeyDoesNotMatch);
        }
        let row = email_confirmation_to_row(&(proof.to_owned(), data.to_owned()))?;
        sqlx::query(crate::sql::identity::UPSERT_EMAIL_CONFIRMATION)
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

#[async_trait]
impl CompanyTransactionApi for PostgresPersistenceTransaction {
    async fn append_company_blocks(
        &mut self,
        company_id: &NodeId,
        expected_latest: Option<&CompanyBlock>,
        blocks: &[CompanyBlock],
    ) -> Result<()> {
        self.lock_company_chain(company_id).await?;
        let mut latest = self.get_latest_company_block(company_id).await?;
        validate_expected_company_tip(company_id, latest.as_ref(), expected_latest)?;
        for block in blocks {
            crate::sql::company_chain::validate_block_append(company_id, block, latest.as_ref())?;
            let row = CompanyBlockRow::try_from(block)?;
            crate::sql::company_chain::bind_insert_block!(
                sqlx::query(crate::sql::company_chain::INSERT_BLOCK),
                row
            )
            .execute(&mut *self.tx)
            .await?;
            latest = Some(block.clone());
        }
        Ok(())
    }

    async fn replace_company_blocks_from_height(
        &mut self,
        company_id: &NodeId,
        expected_latest: &CompanyBlock,
        from_block_id: BlockId,
        replacement_blocks: &[CompanyBlock],
    ) -> Result<()> {
        self.lock_company_chain(company_id).await?;
        let actual_latest = self.get_latest_company_block(company_id).await?;
        validate_expected_company_tip(company_id, actual_latest.as_ref(), Some(expected_latest))?;
        sqlx::query(crate::sql::company_chain::DELETE_FROM_HEIGHT)
            .bind(Text(company_id.clone()))
            .bind(block_id_to_db(from_block_id)?)
            .execute(&mut *self.tx)
            .await?;
        let mut latest = self.get_latest_company_block(company_id).await?;
        for block in replacement_blocks {
            crate::sql::company_chain::validate_block_append(company_id, block, latest.as_ref())?;
            let row = CompanyBlockRow::try_from(block)?;
            crate::sql::company_chain::bind_insert_block!(
                sqlx::query(crate::sql::company_chain::INSERT_BLOCK),
                row
            )
            .execute(&mut *self.tx)
            .await?;
            latest = Some(block.clone());
        }
        Ok(())
    }

    async fn insert_company(&mut self, company: &Company) -> Result<()> {
        let row = company_to_row(company)?;
        bind_company!(sqlx::query(crate::sql::company::INSERT_COMPANY), row)
            .execute(&mut *self.tx)
            .await?;
        for (position, signatory) in company.signatories.iter().enumerate() {
            let row = company_signatory_to_row(&company.id, position, signatory)?;
            bind_signatory!(sqlx::query(crate::sql::company::INSERT_SIGNATORY), row)
                .execute(&mut *self.tx)
                .await?;
        }

        Ok(())
    }

    async fn update_company(&mut self, company_id: &NodeId, company: &Company) -> Result<()> {
        if company_id != &company.id {
            return Err(Error::InvalidData("company id mismatch".to_owned()));
        }
        let row = company_to_row(company)?;
        let updated = bind_company!(sqlx::query(crate::sql::company::UPDATE_COMPANY), row)
            .execute(&mut *self.tx)
            .await?;
        if updated.rows_affected() == 0 {
            return Err(Error::NoSuchEntity(
                "company".to_owned(),
                company_id.to_string(),
            ));
        }
        sqlx::query(crate::sql::company::DELETE_SIGNATORIES)
            .bind(Text(company_id.clone()))
            .execute(&mut *self.tx)
            .await?;
        for (position, signatory) in company.signatories.iter().enumerate() {
            let row = company_signatory_to_row(company_id, position, signatory)?;
            bind_signatory!(sqlx::query(crate::sql::company::INSERT_SIGNATORY), row)
                .execute(&mut *self.tx)
                .await?;
        }
        Ok(())
    }

    async fn set_company_email_confirmation(
        &mut self,
        company_id: &NodeId,
        proof: &SignedIdentityProof,
        data: &EmailIdentityProofData,
    ) -> Result<()> {
        let encoded_key: Option<String> = sqlx::query_scalar(crate::sql::company::SELECT_KEY)
            .bind(Text(company_id.clone()))
            .fetch_optional(&mut *self.tx)
            .await?;
        let encoded_key = encoded_key
            .ok_or_else(|| Error::NoSuchEntity("company".to_owned(), company_id.to_string()))?;
        let keys = company_key_pair_from_db(&encoded_key, &self.encryption_ctx)?;
        if Some(keys.pub_key()) != data.company_node_id.as_ref().map(|id| id.pub_key()) {
            return Err(Error::PublicKeyDoesNotMatch);
        }
        let row = email_confirmation_to_row(&(proof.clone(), data.clone()))?;
        sqlx::query(crate::sql::company::UPSERT_EMAIL_CONFIRMATION)
            .bind(Text(company_id.clone()))
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

#[async_trait]
impl BillTransactionApi for PostgresPersistenceTransaction {
    async fn append_bill_blocks(
        &mut self,
        bill_id: &BillId,
        expected_latest: Option<&BillBlock>,
        blocks: &[BillBlock],
    ) -> Result<()> {
        self.lock_bill_chain(bill_id).await?;
        let mut latest = self.get_latest_bill_block(bill_id).await?;
        validate_expected_bill_tip(bill_id, latest.as_ref(), expected_latest)?;
        for block in blocks {
            crate::sql::bill_chain::validate_block_append(bill_id, block, latest.as_ref())?;
            let row = BillBlockRow::try_from(block)?;
            crate::sql::bill_chain::bind_insert_block!(
                sqlx::query(crate::sql::bill_chain::INSERT_BLOCK),
                row
            )
            .execute(&mut *self.tx)
            .await?;
            latest = Some(block.clone());
        }
        Ok(())
    }

    async fn replace_bill_blocks_from_height(
        &mut self,
        bill_id: &BillId,
        expected_latest: &BillBlock,
        from_block_id: BlockId,
        replacement_blocks: &[BillBlock],
    ) -> Result<()> {
        self.lock_bill_chain(bill_id).await?;
        let actual_latest = self.get_latest_bill_block(bill_id).await?;
        validate_expected_bill_tip(bill_id, actual_latest.as_ref(), Some(expected_latest))?;
        sqlx::query(crate::sql::bill_chain::DELETE_FROM_HEIGHT)
            .bind(Text(bill_id.clone()))
            .bind(block_id_to_db(from_block_id)?)
            .execute(&mut *self.tx)
            .await?;
        let mut latest = self.get_latest_bill_block(bill_id).await?;
        for block in replacement_blocks {
            crate::sql::bill_chain::validate_block_append(bill_id, block, latest.as_ref())?;
            let row = BillBlockRow::try_from(block)?;
            crate::sql::bill_chain::bind_insert_block!(
                sqlx::query(crate::sql::bill_chain::INSERT_BLOCK),
                row
            )
            .execute(&mut *self.tx)
            .await?;
            latest = Some(block.clone());
        }

        Ok(())
    }

    async fn save_bill_keys(&mut self, bill_id: &BillId, keys: &BcrKeys) -> Result<()> {
        let plaintext_key = keys.get_private_key_string();
        let encrypted_key = self.encryption_ctx.encrypt(plaintext_key.as_bytes())?;
        let encoded_key = base58::encode(&encrypted_key);
        sqlx::query(crate::sql::bill::INSERT_KEYS)
            .bind(Text(bill_id.clone()))
            .bind(encoded_key)
            .execute(&mut *self.tx)
            .await?;
        Ok(())
    }

    async fn save_bill_to_cache(
        &mut self,
        bill_id: &BillId,
        identity_node_id: &NodeId,
        bill: &BitcreditBillResult,
    ) -> Result<()> {
        if &bill.id != bill_id {
            return Err(Error::InvalidData(format!(
                "bill cache id mismatch: expected {bill_id}, got {}",
                bill.id
            )));
        }
        let payload: BitcreditBillResultDb = (bill, identity_node_id).into();
        sqlx::query(crate::sql::bill::UPSERT_CACHE)
            .bind(Text(bill_id.clone()))
            .bind(Text(identity_node_id.clone()))
            .bind(Json(payload))
            .execute(&mut *self.tx)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::PostgresTransactionManager;
    use crate::{
        EncryptionContext,
        postgres::{
            bill::PostgresBillStore, bill_chain::PostgresBillChainStore,
            company::PostgresCompanyStore, company_chain::PostgresCompanyChainStore,
            identity::PostgresIdentityStore, identity_chain::PostgresIdentityChainStore,
        },
        tests::{
            bill_transaction::{
                test_bill_transaction_commit, test_bill_transaction_rejects_stale_tip,
                test_bill_transaction_replace, test_bill_transaction_rollback,
                test_company_lock_after_bill_lock_is_rejected,
                test_identity_lock_after_bill_lock_is_rejected,
            },
            company_transaction::{
                test_company_transaction_commit, test_company_transaction_rejects_stale_tip,
                test_company_transaction_replace, test_company_transaction_rollback,
                test_company_transaction_update,
                test_cross_chain_rollback_when_company_tip_is_stale,
                test_identity_lock_after_company_lock_is_rejected,
            },
            identity_transaction::{
                test_identity_transaction_commit, test_identity_transaction_rejects_second_genesis,
                test_identity_transaction_rejects_stale_tip, test_identity_transaction_replace,
                test_identity_transaction_replace_rollback, test_identity_transaction_rollback,
            },
        },
    };
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use sqlx::PgPool;
    use std::sync::Arc;

    fn setup(
        pool: PgPool,
    ) -> (
        PostgresTransactionManager,
        PostgresIdentityStore,
        PostgresIdentityChainStore,
        PostgresCompanyChainStore,
        PostgresCompanyStore,
    ) {
        let encryption_ctx = Arc::new(EncryptionContext::new(BcrKeys::new()));
        (
            PostgresTransactionManager::new(pool.clone(), encryption_ctx.clone()),
            PostgresIdentityStore::new(pool.clone(), encryption_ctx.clone()),
            PostgresIdentityChainStore::new(pool.clone()),
            PostgresCompanyChainStore::new(pool.clone()),
            PostgresCompanyStore::new(pool, encryption_ctx),
        )
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn identity_transaction_commit(pool: PgPool) {
        let (manager, store, chain, _, _) = setup(pool);
        test_identity_transaction_commit(&manager, &store, &chain).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn identity_transaction_rollback(pool: PgPool) {
        let (manager, store, chain, _, _) = setup(pool);
        test_identity_transaction_rollback(&manager, &store, &chain).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn identity_transaction_rejects_stale_tip(pool: PgPool) {
        let (manager, _, chain, _, _) = setup(pool);
        test_identity_transaction_rejects_stale_tip(&manager, &chain).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn identity_transaction_replace(pool: PgPool) {
        let (manager, _, chain, _, _) = setup(pool);
        test_identity_transaction_replace(&manager, &chain).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn identity_transaction_replace_rollback(pool: PgPool) {
        let (manager, _, chain, _, _) = setup(pool);
        test_identity_transaction_replace_rollback(&manager, &chain).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn identity_transaction_rejects_second_genesis(pool: PgPool) {
        let (manager, _, chain, _, _) = setup(pool);
        test_identity_transaction_rejects_second_genesis(&manager, &chain).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn company_transaction_commit(pool: PgPool) {
        let (manager, _, identity_chain, company_chain, company_store) = setup(pool);
        test_company_transaction_commit(&manager, &company_store, &company_chain, &identity_chain)
            .await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn company_transaction_rollback(pool: PgPool) {
        let (manager, _, identity_chain, company_chain, company_store) = setup(pool);
        test_company_transaction_rollback(
            &manager,
            &company_store,
            &company_chain,
            &identity_chain,
        )
        .await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn company_transaction_update(pool: PgPool) {
        let (manager, _, _, company_chain, company_store) = setup(pool);
        test_company_transaction_update(&manager, &company_store, &company_chain).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn company_transaction_rejects_stale_tip(pool: PgPool) {
        let (manager, _, _, company_chain, _) = setup(pool);
        test_company_transaction_rejects_stale_tip(&manager, &company_chain).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn company_transaction_replace(pool: PgPool) {
        let (manager, _, _, company_chain, company_store) = setup(pool);
        test_company_transaction_replace(&manager, &company_store, &company_chain).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn cross_chain_rollback_when_company_tip_is_stale(pool: PgPool) {
        let (manager, _, identity_chain, company_chain, company_store) = setup(pool);
        test_cross_chain_rollback_when_company_tip_is_stale(
            &manager,
            &company_store,
            &company_chain,
            &identity_chain,
        )
        .await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn identity_lock_after_company_lock_is_rejected(pool: PgPool) {
        let (manager, _, identity_chain, company_chain, _) = setup(pool);
        test_identity_lock_after_company_lock_is_rejected(
            &manager,
            &company_chain,
            &identity_chain,
        )
        .await;
    }

    fn setup_bill(
        pool: PgPool,
    ) -> (
        PostgresTransactionManager,
        PostgresBillStore,
        PostgresBillChainStore,
    ) {
        let encryption_ctx = Arc::new(EncryptionContext::new(BcrKeys::new()));
        (
            PostgresTransactionManager::new(pool.clone(), encryption_ctx.clone()),
            PostgresBillStore::new(pool.clone(), encryption_ctx),
            PostgresBillChainStore::new(pool),
        )
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn bill_transaction_commit(pool: PgPool) {
        let (manager, store, chain) = setup_bill(pool);
        test_bill_transaction_commit(&manager, &store, &chain).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn bill_transaction_rollback(pool: PgPool) {
        let (manager, store, chain) = setup_bill(pool);
        test_bill_transaction_rollback(&manager, &store, &chain).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn bill_transaction_rejects_stale_tip(pool: PgPool) {
        let (manager, _, chain) = setup_bill(pool);
        test_bill_transaction_rejects_stale_tip(&manager, &chain).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn bill_transaction_replace(pool: PgPool) {
        let (manager, _, chain) = setup_bill(pool);
        test_bill_transaction_replace(&manager, &chain).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn company_lock_after_bill_lock_is_rejected(pool: PgPool) {
        let (manager, _, _) = setup_bill(pool);
        test_company_lock_after_bill_lock_is_rejected(&manager).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn identity_lock_after_bill_lock_is_rejected(pool: PgPool) {
        let (manager, _, _) = setup_bill(pool);
        test_identity_lock_after_bill_lock_is_rejected(&manager).await;
    }
}
