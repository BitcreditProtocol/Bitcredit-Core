use std::collections::HashMap;

use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::application::{ServiceTraitBounds, contact::Contact};
use sqlx::{SqlitePool, types::Text};

use crate::{
    ContactStoreApi, Result,
    sql::contact::{
        ContactRow, DELETE, INSERT, SEARCH, SELECT_ALL, SELECT_ONE, UPDATE, bind_insert,
        bind_update, ensure_node_id_matches,
    },
};

#[derive(Clone)]
pub struct SqliteContactStore {
    pool: SqlitePool,
}

impl SqliteContactStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl ServiceTraitBounds for SqliteContactStore {}

#[async_trait]
impl ContactStoreApi for SqliteContactStore {
    async fn search(&self, search_term: &str) -> Result<Vec<Contact>> {
        let rows: Vec<ContactRow> = sqlx::query_as(SEARCH)
            .bind(search_term)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn get_map(&self) -> Result<HashMap<NodeId, Contact>> {
        let rows: Vec<ContactRow> = sqlx::query_as(SELECT_ALL).fetch_all(&self.pool).await?;
        let contacts = rows
            .into_iter()
            .map(Contact::try_from)
            .collect::<Result<Vec<_>>>()?;
        Ok(contacts
            .into_iter()
            .map(|contact| (contact.node_id.clone(), contact))
            .collect())
    }

    async fn get(&self, node_id: &NodeId) -> Result<Option<Contact>> {
        let row: Option<ContactRow> = sqlx::query_as(SELECT_ONE)
            .bind(Text(node_id.clone()))
            .fetch_optional(&self.pool)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn insert(&self, node_id: &NodeId, data: Contact) -> Result<()> {
        ensure_node_id_matches(node_id, &data)?;
        let row = ContactRow::try_from(&data)?;
        bind_insert!(sqlx::query(INSERT), row)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete(&self, node_id: &NodeId) -> Result<()> {
        sqlx::query(DELETE)
            .bind(Text(node_id.clone()))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn update(&self, node_id: &NodeId, data: Contact) -> Result<()> {
        ensure_node_id_matches(node_id, &data)?;
        let row = ContactRow::try_from(&data)?;
        bind_update!(sqlx::query(UPDATE), row)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SqliteContactStore;
    use crate::tests::contact;
    use sqlx::SqlitePool;

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn insert(pool: SqlitePool) {
        let store = SqliteContactStore::new(pool);
        contact::test_insert_contact(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn delete(pool: SqlitePool) {
        let store = SqliteContactStore::new(pool);
        contact::test_delete_contact(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn update(pool: SqlitePool) {
        let store = SqliteContactStore::new(pool);
        contact::test_update_contact(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn get_map(pool: SqlitePool) {
        let store = SqliteContactStore::new(pool);
        contact::test_get_map(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn search(pool: SqlitePool) {
        let store = SqliteContactStore::new(pool);
        contact::test_search(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn nostr_relays(pool: SqlitePool) {
        let store = SqliteContactStore::new(pool);
        contact::test_nostr_relays_roundtrip(&store).await;
    }
}
