use async_trait::async_trait;
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::{
        Name, Sha256Hash, Timestamp,
        file_reference::{FileReference, FileReferenceContext},
    },
};
use bitcoin::hashes::sha256::Hash as Sha256HexHash;
use sqlx::{PgPool, Postgres, Transaction, types::Text};

use crate::{
    FileReferenceStoreApi, Result,
    sql::file_reference::{
        DELETE_CONTEXTS, DELETE_FILE_REFERENCE, FileReferenceContextRow, FileReferenceRow,
        INSERT_CONTEXT, INSERT_FILE_REFERENCE_IF_ABSENT, SELECT_ALL, SELECT_BY_NOSTR_HASH,
        SELECT_CONTEXTS, SELECT_FILE_REFERENCE, SELECT_IMPORTANT, UPDATE_FILE_REFERENCE,
        add_url_deduped, context_to_row, file_reference_from_row, file_reference_to_row,
    },
};

#[derive(Clone)]
pub struct PostgresFileReferenceStore {
    pool: PgPool,
}

impl PostgresFileReferenceStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn load_contexts(&self, hash: &Sha256Hash) -> Result<Vec<FileReferenceContext>> {
        let rows: Vec<FileReferenceContextRow> = sqlx::query_as(SELECT_CONTEXTS)
            .bind(Text(hash.clone()))
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn reference_from_row(&self, row: FileReferenceRow) -> Result<FileReference> {
        let hash = row.hash.clone().into_inner();
        let contexts = self.load_contexts(&hash).await?;
        file_reference_from_row(row, contexts)
    }

    async fn replace_contexts(
        tx: &mut Transaction<'_, Postgres>,
        hash: &Sha256Hash,
        contexts: &[FileReferenceContext],
    ) -> Result<()> {
        sqlx::query(DELETE_CONTEXTS)
            .bind(Text(hash.clone()))
            .execute(&mut **tx)
            .await?;
        for (position, context) in contexts.iter().enumerate() {
            let row = context_to_row(hash, position, context)?;
            sqlx::query(INSERT_CONTEXT)
                .bind(row.file_reference_hash)
                .bind(row.position)
                .bind(row.context_type)
                .bind(row.context_field)
                .bind(row.context_company_id)
                .bind(row.context_node_id)
                .bind(row.context_bill_id)
                .execute(&mut **tx)
                .await?;
        }

        Ok(())
    }

    async fn persist_full(&self, reference: &FileReference, insert: bool) -> Result<()> {
        let row = file_reference_to_row(reference)?;
        let mut tx = self.pool.begin().await?;
        if insert {
            sqlx::query(INSERT_FILE_REFERENCE_IF_ABSENT)
                .bind(row.hash)
                .bind(row.nostr_hash)
                .bind(row.name)
                .bind(row.server_urls)
                .bind(row.is_important)
                .bind(row.created_at)
                .bind(row.updated_at)
                .execute(&mut *tx)
                .await?;
        } else {
            sqlx::query(UPDATE_FILE_REFERENCE)
                .bind(row.hash)
                .bind(row.nostr_hash)
                .bind(row.name)
                .bind(row.server_urls)
                .bind(row.is_important)
                .bind(row.updated_at)
                .execute(&mut *tx)
                .await?;
        }
        Self::replace_contexts(&mut tx, &reference.hash, &reference.context).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn persist_parent(&self, reference: &FileReference) -> Result<()> {
        let row = file_reference_to_row(reference)?;
        sqlx::query(UPDATE_FILE_REFERENCE)
            .bind(row.hash)
            .bind(row.nostr_hash)
            .bind(row.name)
            .bind(row.server_urls)
            .bind(row.is_important)
            .bind(row.updated_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

impl ServiceTraitBounds for PostgresFileReferenceStore {}

#[async_trait]
impl FileReferenceStoreApi for PostgresFileReferenceStore {
    async fn upsert(
        &self,
        hash: &Sha256Hash,
        nostr_hash: &Sha256HexHash,
        name: Option<Name>,
        server_urls: Vec<url::Url>,
        is_important: Option<bool>,
        context: Vec<FileReferenceContext>,
    ) -> Result<FileReference> {
        let existing = self.get(hash).await?;
        let insert = existing.is_none();
        let now = Timestamp::now();
        let reference = match existing {
            Some(mut existing) => {
                existing.nostr_hash = *nostr_hash;
                if let Some(name) = name {
                    existing.name = Some(name);
                }
                for url in server_urls {
                    add_url_deduped(&mut existing.server_urls, url);
                }
                if let Some(is_important) = is_important {
                    existing.is_important = is_important;
                }
                for context in context {
                    if !existing.context.contains(&context) {
                        existing.context.push(context);
                    }
                }
                existing.updated_at = now;
                existing
            }
            None => {
                let mut deduped_urls = Vec::new();
                for url in server_urls {
                    add_url_deduped(&mut deduped_urls, url);
                }
                FileReference {
                    hash: hash.clone(),
                    nostr_hash: *nostr_hash,
                    name,
                    server_urls: deduped_urls,
                    is_important: is_important.unwrap_or(false),
                    context,
                    created_at: now,
                    updated_at: now,
                }
            }
        };
        self.persist_full(&reference, insert).await?;
        Ok(reference)
    }

    async fn get(&self, hash: &Sha256Hash) -> Result<Option<FileReference>> {
        let row: Option<FileReferenceRow> = sqlx::query_as(SELECT_FILE_REFERENCE)
            .bind(Text(hash.clone()))
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(row) => Ok(Some(self.reference_from_row(row).await?)),
            None => Ok(None),
        }
    }

    async fn find_by_nostr_hash(
        &self,
        nostr_hash: &Sha256HexHash,
    ) -> Result<Option<FileReference>> {
        let row: Option<FileReferenceRow> = sqlx::query_as(SELECT_BY_NOSTR_HASH)
            .bind(Text(*nostr_hash))
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(row) => Ok(Some(self.reference_from_row(row).await?)),
            None => Ok(None),
        }
    }

    async fn delete(&self, hash: &Sha256Hash) -> Result<()> {
        sqlx::query(DELETE_FILE_REFERENCE)
            .bind(Text(hash.clone()))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<FileReference>> {
        let rows: Vec<FileReferenceRow> = sqlx::query_as(SELECT_ALL).fetch_all(&self.pool).await?;
        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            result.push(self.reference_from_row(row).await?);
        }
        Ok(result)
    }

    async fn list_important(&self) -> Result<Vec<FileReference>> {
        let rows: Vec<FileReferenceRow> = sqlx::query_as(SELECT_IMPORTANT)
            .fetch_all(&self.pool)
            .await?;
        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            result.push(self.reference_from_row(row).await?);
        }
        Ok(result)
    }

    async fn add_server_urls(&self, hash: &Sha256Hash, urls: Vec<url::Url>) -> Result<bool> {
        let Some(mut reference) = self.get(hash).await? else {
            return Ok(false);
        };
        let original_len = reference.server_urls.len();
        for url in urls {
            add_url_deduped(&mut reference.server_urls, url);
        }
        if reference.server_urls.len() == original_len {
            return Ok(false);
        }
        reference.updated_at = Timestamp::now();
        self.persist_parent(&reference).await?;
        Ok(true)
    }

    async fn mark_important(&self, hash: &Sha256Hash, important: bool) -> Result<()> {
        let Some(mut reference) = self.get(hash).await? else {
            return Ok(());
        };
        if reference.is_important == important {
            return Ok(());
        }
        reference.is_important = important;
        reference.updated_at = Timestamp::now();
        self.persist_parent(&reference).await
    }

    async fn update_nostr_hash(&self, hash: &Sha256Hash, nostr_hash: &Sha256HexHash) -> Result<()> {
        let Some(mut reference) = self.get(hash).await? else {
            return Ok(());
        };
        if reference.nostr_hash == *nostr_hash {
            return Ok(());
        }
        reference.nostr_hash = *nostr_hash;
        reference.updated_at = Timestamp::now();
        self.persist_parent(&reference).await
    }

    async fn add_context(&self, hash: &Sha256Hash, context: FileReferenceContext) -> Result<bool> {
        let Some(mut reference) = self.get(hash).await? else {
            return Ok(false);
        };
        if reference.context.contains(&context) {
            return Ok(false);
        }
        reference.context.push(context);
        reference.updated_at = Timestamp::now();
        self.persist_full(&reference, false).await?;
        Ok(true)
    }

    async fn remove_context(
        &self,
        hash: &Sha256Hash,
        context: &FileReferenceContext,
    ) -> Result<bool> {
        let Some(mut reference) = self.get(hash).await? else {
            return Ok(false);
        };
        let Some(position) = reference.context.iter().position(|entry| entry == context) else {
            return Ok(false);
        };
        reference.context.remove(position);
        reference.updated_at = Timestamp::now();
        self.persist_full(&reference, false).await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::PostgresFileReferenceStore;
    use crate::tests::file_reference;
    use sqlx::PgPool;

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn upsert_creates_new(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_upsert_creates_new(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn upsert_updates_existing(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_upsert_updates_existing(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn find_by_nostr_hash(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_find_by_nostr_hash(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn find_by_nostr_hash_missing(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_find_by_nostr_hash_missing(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn upsert_deduplicates_server_urls(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_upsert_deduplicates_server_urls(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn get_existing(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_get_existing(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn get_nonexistent(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_get_nonexistent(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn delete(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_delete(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn list(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_list(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn list_important(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_list_important(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn add_server_urls(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_add_server_urls(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn add_server_urls_no_change_for_duplicates(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_add_server_urls_no_change_for_duplicates(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn mark_important(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_mark_important(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn update_nostr_hash(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_update_nostr_hash(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn upsert_preserves_existing_name_when_none_provided(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_upsert_preserves_existing_name_when_none_provided(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn coexistence_with_existing_file_fields(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_coexistence_with_existing_file_fields(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn upsert_with_context(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_upsert_with_context(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn add_and_remove_context(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_add_and_remove_context(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn context_deduplication_on_upsert(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_context_deduplication_on_upsert(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn add_context_to_nonexistent_record(pool: PgPool) {
        let store = PostgresFileReferenceStore::new(pool);
        file_reference::test_add_context_to_nonexistent_record(&store).await;
    }
}
