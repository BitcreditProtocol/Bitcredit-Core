use crate::sql::company::{
    CompanyRow, CompanySignatoryRow, DELETE_COMPANY, DELETE_KEY, DELETE_LOCAL_OVERRIDE,
    DELETE_SIGNATORIES, EXISTS, INSERT_COMPANY, INSERT_KEY, INSERT_SIGNATORY,
    LocalSignatoryOverrideRow, SEARCH, SELECT_COMPANIES_WITH_KEYS_BY_STATUS, SELECT_COMPANY,
    SELECT_EMAIL_CONFIRMATIONS, SELECT_KEY, SELECT_LOCAL_OVERRIDES, SELECT_SIGNATORIES,
    UPDATE_COMPANY, UPSERT_EMAIL_CONFIRMATION, UPSERT_LOCAL_OVERRIDE, bind_company, bind_signatory,
    company_from_row, company_signatory_to_row, company_to_row,
};
use crate::sql::identity::{
    EmailConfirmationRow, email_confirmation_from_row, email_confirmation_to_row,
};
use crate::sql::{escape_like, unit_enum_from_db, unit_enum_to_db};
use crate::traits::company::CompanyStoreApi;
use crate::{Error, Result};
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::application::company::{
    CompanyStatus, LocalSignatoryOverride, LocalSignatoryOverrideStatus,
};
use bcr_ebill_core::application::{ServiceTraitBounds, company::Company};
use bcr_ebill_core::protocol::crypto::BcrKeys;
use bcr_ebill_core::protocol::{EmailIdentityProofData, SignedIdentityProof};
use bitcoin::secp256k1::SecretKey;
use sqlx::{SqlitePool, types::Text};
use std::collections::HashMap;

#[derive(Clone)]
pub struct SqliteCompanyStore {
    pool: SqlitePool,
}

impl SqliteCompanyStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl ServiceTraitBounds for SqliteCompanyStore {}

impl SqliteCompanyStore {
    async fn load_company(&self, id: &NodeId) -> Result<Company> {
        let row: Option<CompanyRow> = sqlx::query_as(SELECT_COMPANY)
            .bind(Text(id.clone()))
            .fetch_optional(&self.pool)
            .await?;
        let row = row.ok_or_else(|| Error::NoSuchEntity("company".to_owned(), id.to_string()))?;
        let signatories: Vec<CompanySignatoryRow> = sqlx::query_as(SELECT_SIGNATORIES)
            .bind(Text(id.clone()))
            .fetch_all(&self.pool)
            .await?;
        let signatories = signatories
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>>>()?;
        company_from_row(row, signatories)
    }

    async fn get_all_filter_for_status(
        &self,
        status: CompanyStatus,
    ) -> Result<HashMap<NodeId, (Company, BcrKeys)>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Text<NodeId>,
            private_key: Text<SecretKey>,
        }
        let status = unit_enum_to_db(&status)?;
        let rows: Vec<Row> = sqlx::query_as(SELECT_COMPANIES_WITH_KEYS_BY_STATUS)
            .bind(status)
            .fetch_all(&self.pool)
            .await?;
        let mut result = HashMap::new();
        for row in rows {
            let id = row.id.into_inner();
            let company = self.load_company(&id).await?;
            let private_key = row.private_key.into_inner();
            result.insert(id, (company, BcrKeys::from_private_key(&private_key)));
        }
        Ok(result)
    }
}

#[async_trait]
impl CompanyStoreApi for SqliteCompanyStore {
    async fn search(&self, search_term: &str) -> Result<Vec<Company>> {
        let status = unit_enum_to_db(&CompanyStatus::Active)?;
        let pattern = format!("%{}%", escape_like(search_term));
        let ids: Vec<Text<NodeId>> = sqlx::query_scalar(SEARCH)
            .bind(status)
            .bind(pattern)
            .fetch_all(&self.pool)
            .await?;
        let mut result = Vec::new();
        for id in ids {
            result.push(self.load_company(&id.into_inner()).await?);
        }
        Ok(result)
    }

    async fn exists(&self, id: &NodeId) -> bool {
        let none_status = match unit_enum_to_db(&CompanyStatus::None) {
            Ok(value) => value,
            Err(_) => return false,
        };
        sqlx::query_scalar::<_, bool>(EXISTS)
            .bind(Text(id.clone()))
            .bind(none_status)
            .fetch_one(&self.pool)
            .await
            .unwrap_or(false)
    }

    async fn get(&self, id: &NodeId) -> Result<Company> {
        self.load_company(id).await
    }

    async fn get_all(&self) -> Result<HashMap<NodeId, (Company, BcrKeys)>> {
        self.get_all_filter_for_status(CompanyStatus::Active).await
    }

    async fn insert(&self, data: &Company) -> Result<()> {
        let row = company_to_row(data)?;
        let mut tx = self.pool.begin().await?;
        bind_company!(sqlx::query(INSERT_COMPANY), row)
            .execute(&mut *tx)
            .await?;
        for (position, signatory) in data.signatories.iter().enumerate() {
            let row = company_signatory_to_row(&data.id, position, signatory)?;
            bind_signatory!(sqlx::query(INSERT_SIGNATORY), row)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn update(&self, id: &NodeId, data: &Company) -> Result<()> {
        if id != &data.id {
            return Err(Error::InvalidData("company id mismatch".to_owned()));
        }
        let row = company_to_row(data)?;
        let mut tx = self.pool.begin().await?;
        let updated = bind_company!(sqlx::query(UPDATE_COMPANY), row)
            .execute(&mut *tx)
            .await?;
        if updated.rows_affected() == 0 {
            return Err(Error::NoSuchEntity("company".to_owned(), id.to_string()));
        }
        sqlx::query(DELETE_SIGNATORIES)
            .bind(Text(id.clone()))
            .execute(&mut *tx)
            .await?;
        for (position, signatory) in data.signatories.iter().enumerate() {
            let row = company_signatory_to_row(id, position, signatory)?;
            bind_signatory!(sqlx::query(INSERT_SIGNATORY), row)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn remove(&self, id: &NodeId) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        // company_signatory cascades
        sqlx::query(DELETE_COMPANY)
            .bind(Text(id.clone()))
            .execute(&mut *tx)
            .await?;
        // delete keys
        sqlx::query(DELETE_KEY)
            .bind(Text(id.clone()))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn save_key_pair(&self, id: &NodeId, key_pair: &BcrKeys) -> Result<()> {
        sqlx::query(INSERT_KEY)
            .bind(Text(id.clone()))
            .bind(Text(key_pair.get_private_key_string()))
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn get_key_pair(&self, id: &NodeId) -> Result<BcrKeys> {
        let private_key: Option<Text<SecretKey>> = sqlx::query_scalar(SELECT_KEY)
            .bind(Text(id.clone()))
            .fetch_optional(&self.pool)
            .await?;
        let private_key =
            private_key.ok_or_else(|| Error::NoSuchEntity("company".to_owned(), id.to_string()))?;
        Ok(BcrKeys::from_private_key(&private_key.into_inner()))
    }

    async fn get_email_confirmations(
        &self,
        id: &NodeId,
    ) -> Result<Vec<(SignedIdentityProof, EmailIdentityProofData)>> {
        let rows: Vec<EmailConfirmationRow> = sqlx::query_as(SELECT_EMAIL_CONFIRMATIONS)
            .bind(Text(id.clone()))
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(email_confirmation_from_row).collect()
    }

    async fn set_email_confirmation(
        &self,
        id: &NodeId,
        proof: &SignedIdentityProof,
        data: &EmailIdentityProofData,
    ) -> Result<()> {
        let keys = self.get_key_pair(id).await?;
        if Some(keys.pub_key())
            != data
                .company_node_id
                .as_ref()
                .map(|node_id| node_id.pub_key())
        {
            return Err(Error::PublicKeyDoesNotMatch);
        }
        let row = email_confirmation_to_row(&(proof.clone(), data.clone()))?;
        sqlx::query(UPSERT_EMAIL_CONFIRMATION)
            .bind(Text(id.clone()))
            .bind(row.signature)
            .bind(row.witness)
            .bind(row.node_id)
            .bind(row.company_node_id)
            .bind(row.email)
            .bind(row.created_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_local_signatory_overrides(
        &self,
        id: &NodeId,
    ) -> Result<Vec<LocalSignatoryOverride>> {
        let rows: Vec<LocalSignatoryOverrideRow> = sqlx::query_as(SELECT_LOCAL_OVERRIDES)
            .bind(Text(id.clone()))
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(LocalSignatoryOverride {
                    company_id: row.company_id.into_inner(),
                    node_id: row.node_id.into_inner(),
                    status: unit_enum_from_db(row.status)?,
                })
            })
            .collect()
    }

    async fn set_local_signatory_override(
        &self,
        id: &NodeId,
        signatory: &NodeId,
        status: LocalSignatoryOverrideStatus,
    ) -> Result<()> {
        sqlx::query(UPSERT_LOCAL_OVERRIDE)
            .bind(Text(id.clone()))
            .bind(Text(signatory.clone()))
            .bind(unit_enum_to_db(&status)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_local_signatory_override(&self, id: &NodeId, signatory: &NodeId) -> Result<()> {
        sqlx::query(DELETE_LOCAL_OVERRIDE)
            .bind(Text(id.clone()))
            .bind(Text(signatory.clone()))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_active_company_invites(&self) -> Result<HashMap<NodeId, (Company, BcrKeys)>> {
        self.get_all_filter_for_status(CompanyStatus::Invited).await
    }
}

#[cfg(test)]
mod tests {
    use super::SqliteCompanyStore;
    use crate::tests::company::test_company_store;
    use sqlx::SqlitePool;

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn company_store(pool: SqlitePool) {
        let store = SqliteCompanyStore::new(pool);
        test_company_store(&store).await;
    }
}
