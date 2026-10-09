use std::sync::Arc;

use crate::{
    EncryptionContext, Error, Result,
    sql::{
        escape_like,
        nostr_chain_event::NostrEventDb,
        nostr_contact_store::{
            CONTACT_SELECT_BASE, DELETE_CONTACT, DELETE_PENDING_SHARE, DELETE_RELAY_RETRY,
            INSERT_RELAY_RETRY, NostrContactRow, PendingContactShareRow, RelaySyncRetryRow,
            RelaySyncStatusRow, SELECT_CONTACT_BY_ID, SELECT_PENDING_RELAY_RETRIES,
            SELECT_PENDING_RELAYS, SELECT_PENDING_SHARE, SELECT_PENDING_SHARE_EXISTS,
            SELECT_PENDING_SHARES_BY_RECEIVER, SELECT_PENDING_SHARES_BY_RECEIVER_DIRECTION,
            SELECT_RELAY_RETRY_COUNT, SELECT_RELAY_SYNC_STATUS, UPDATE_HANDSHAKE_STATUS,
            UPDATE_RELAY_RETRY_FAILED, UPDATE_RELAY_SYNC_PROGRESS, UPDATE_TRUST_LEVEL,
            UPSERT_CONTACT, UPSERT_PENDING_SHARE, UPSERT_RELAY_LAST_SEEN, UPSERT_RELAY_SYNC_STATUS,
            handshake_status_to_db, nostr_contact_to_row, share_direction_to_db, sync_status_to_db,
            trust_level_to_db,
        },
        timestamp_to_db,
    },
    traits::nostr::{
        NostrStoreApi, PendingContactShare, RelaySyncStatus, ShareDirection, SyncStatus,
    },
};
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    application::nostr_contact::{HandshakeStatus, NostrContact, NostrPublicKey, TrustLevel},
    protocol::Timestamp,
};
use bitcoin::base58;
use sqlx::{PgPool, Postgres, QueryBuilder, types::Json};

#[derive(Clone)]
pub struct PostgresNostrStore {
    pool: PgPool,
    encryption_ctx: Arc<EncryptionContext>,
}

impl PostgresNostrStore {
    pub fn new(pool: PgPool, encryption_ctx: Arc<EncryptionContext>) -> Self {
        Self {
            pool,
            encryption_ctx,
        }
    }

    fn encrypt_contact_row(&self, mut row: NostrContactRow) -> Result<NostrContactRow> {
        if let Some(key) = row.contact_private_key.as_mut() {
            let encrypted_key = self.encryption_ctx.encrypt(key.as_bytes())?;
            *key = base58::encode(&encrypted_key);
        }
        Ok(row)
    }

    fn decrypt_contact_row(&self, mut row: NostrContactRow) -> Result<NostrContact> {
        if let Some(key) = row.contact_private_key.as_mut() {
            let decoded_key = base58::decode(key)?;
            let decrypted_key = self.encryption_ctx.decrypt(&decoded_key)?;
            *key = String::from_utf8(decrypted_key)
                .map_err(|e| Error::InvalidData(format!("Invalid contact private key: {e}")))?;
        }
        row.try_into()
    }

    fn encrypt_pending_share_row(
        &self,
        mut row: PendingContactShareRow,
    ) -> Result<PendingContactShareRow> {
        let encrypted_key = self
            .encryption_ctx
            .encrypt(row.contact_private_key.as_bytes())?;
        row.contact_private_key = base58::encode(&encrypted_key);
        Ok(row)
    }

    fn decrypt_pending_share_row(
        &self,
        mut row: PendingContactShareRow,
    ) -> Result<PendingContactShare> {
        let decoded_key = base58::decode(&row.contact_private_key)?;
        let decrypted_key = self.encryption_ctx.decrypt(&decoded_key)?;
        row.contact_private_key = String::from_utf8(decrypted_key)
            .map_err(|e| Error::InvalidData(format!("Invalid contact private key: {e}")))?;
        row.try_into()
    }
}

impl ServiceTraitBounds for PostgresNostrStore {}

#[async_trait]
impl NostrStoreApi for PostgresNostrStore {
    async fn by_node_id(&self, node_id: &NodeId) -> Result<Option<NostrContact>> {
        self.by_npub(&node_id.npub()).await
    }

    async fn by_node_ids(&self, node_ids: Vec<NodeId>) -> Result<Vec<NostrContact>> {
        if node_ids.is_empty() {
            return Ok(vec![]);
        }
        let mut query = QueryBuilder::<Postgres>::new(CONTACT_SELECT_BASE);
        query.push(" WHERE node_id IN (");
        {
            let mut separated = query.separated(", ");
            for node_id in node_ids {
                separated.push_bind(node_id.to_string());
            }
        }
        query.push(")");
        let rows: Vec<NostrContactRow> = query.build_query_as().fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| self.decrypt_contact_row(row))
            .collect()
    }

    async fn get_all(&self) -> Result<Vec<NostrContact>> {
        let rows: Vec<NostrContactRow> = sqlx::query_as(CONTACT_SELECT_BASE)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| self.decrypt_contact_row(row))
            .collect()
    }

    async fn by_npub(&self, npub: &NostrPublicKey) -> Result<Option<NostrContact>> {
        let row: Option<NostrContactRow> = sqlx::query_as(SELECT_CONTACT_BY_ID)
            .bind(npub.to_hex())
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| self.decrypt_contact_row(row)).transpose()
    }

    async fn upsert(&self, data: &NostrContact) -> Result<()> {
        let row = self.encrypt_contact_row(nostr_contact_to_row(data)?)?;
        sqlx::query(UPSERT_CONTACT)
            .bind(row.id)
            .bind(row.node_id)
            .bind(row.name)
            .bind(row.relays)
            .bind(row.blossom_servers)
            .bind(row.trust_level)
            .bind(row.handshake_status)
            .bind(row.contact_private_key)
            .bind(row.mint_url)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete(&self, node_id: &NodeId) -> Result<()> {
        sqlx::query(DELETE_CONTACT)
            .bind(node_id.npub().to_hex())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_handshake_status(&self, node_id: &NodeId, status: HandshakeStatus) -> Result<()> {
        sqlx::query(UPDATE_HANDSHAKE_STATUS)
            .bind(node_id.npub().to_hex())
            .bind(handshake_status_to_db(&status))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_trust_level(&self, node_id: &NodeId, trust_level: TrustLevel) -> Result<()> {
        sqlx::query(UPDATE_TRUST_LEVEL)
            .bind(node_id.npub().to_hex())
            .bind(trust_level_to_db(&trust_level))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_npubs(&self, levels: Vec<TrustLevel>) -> Result<Vec<NostrPublicKey>> {
        if levels.is_empty() {
            return Ok(vec![]);
        }
        let mut query =
            QueryBuilder::<Postgres>::new("SELECT id FROM nostr_contact WHERE trust_level IN (");
        {
            let mut separated = query.separated(", ");
            for level in levels {
                separated.push_bind(trust_level_to_db(&level));
            }
        }
        query.push(")");
        let ids: Vec<String> = query.build_query_scalar().fetch_all(&self.pool).await?;
        ids.into_iter()
            .map(|id| NostrPublicKey::parse(&id).map_err(|_| Error::EncodingError))
            .collect()
    }

    async fn search(
        &self,
        search_term: &str,
        levels: Vec<TrustLevel>,
    ) -> Result<Vec<NostrContact>> {
        if levels.is_empty() {
            return Ok(vec![]);
        }
        let mut query = QueryBuilder::<Postgres>::new(CONTACT_SELECT_BASE);
        query.push(" WHERE trust_level IN (");
        {
            let mut separated = query.separated(", ");
            for level in levels {
                separated.push_bind(trust_level_to_db(&level));
            }
        }
        query.push(") AND LOWER(name) LIKE LOWER(");
        query.push_bind(format!("%{}%", escape_like(search_term)));
        query.push(") ESCAPE '\\'");
        let rows: Vec<NostrContactRow> = query.build_query_as().fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| self.decrypt_contact_row(row))
            .collect()
    }

    // Pending contact shares
    async fn add_pending_share(&self, pending_share: PendingContactShare) -> Result<()> {
        let row =
            self.encrypt_pending_share_row(PendingContactShareRow::try_from(pending_share)?)?;
        sqlx::query(UPSERT_PENDING_SHARE)
            .bind(row.id)
            .bind(row.node_id)
            .bind(row.contact)
            .bind(row.sender_node_id)
            .bind(row.contact_private_key)
            .bind(row.receiver_node_id)
            .bind(row.received_at)
            .bind(row.direction)
            .bind(row.initial_share_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_pending_share(&self, id: &str) -> Result<Option<PendingContactShare>> {
        let row: Option<PendingContactShareRow> = sqlx::query_as(SELECT_PENDING_SHARE)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| self.decrypt_pending_share_row(row))
            .transpose()
    }

    async fn list_pending_shares_by_receiver(
        &self,
        receiver_node_id: &NodeId,
    ) -> Result<Vec<PendingContactShare>> {
        let rows: Vec<PendingContactShareRow> = sqlx::query_as(SELECT_PENDING_SHARES_BY_RECEIVER)
            .bind(receiver_node_id.to_string())
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| self.decrypt_pending_share_row(row))
            .collect()
    }

    async fn list_pending_shares_by_receiver_and_direction(
        &self,
        receiver_node_id: &NodeId,
        direction: ShareDirection,
    ) -> Result<Vec<PendingContactShare>> {
        let rows: Vec<PendingContactShareRow> =
            sqlx::query_as(SELECT_PENDING_SHARES_BY_RECEIVER_DIRECTION)
                .bind(receiver_node_id.to_string())
                .bind(share_direction_to_db(&direction))
                .fetch_all(&self.pool)
                .await?;
        rows.into_iter()
            .map(|row| self.decrypt_pending_share_row(row))
            .collect()
    }

    async fn delete_pending_share(&self, id: &str) -> Result<()> {
        sqlx::query(DELETE_PENDING_SHARE)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn pending_share_exists_for_node_and_receiver(
        &self,
        node_id: &NodeId,
        receiver_node_id: &NodeId,
        direction: ShareDirection,
    ) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(SELECT_PENDING_SHARE_EXISTS)
            .bind(node_id.to_string())
            .bind(receiver_node_id.to_string())
            .bind(share_direction_to_db(&direction))
            .fetch_one(&self.pool)
            .await?;

        Ok(exists)
    }

    async fn get_pending_relays(&self) -> Result<Vec<url::Url>> {
        let urls: Vec<String> = sqlx::query_scalar(SELECT_PENDING_RELAYS)
            .fetch_all(&self.pool)
            .await?;
        Ok(urls
            .into_iter()
            .filter_map(|url| url::Url::parse(&url).ok())
            .collect())
    }

    async fn get_relay_sync_status(&self, relay: &url::Url) -> Result<Option<RelaySyncStatus>> {
        let row: Option<RelaySyncStatusRow> = sqlx::query_as(SELECT_RELAY_SYNC_STATUS)
            .bind(relay.to_string())
            .fetch_optional(&self.pool)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn update_relay_sync_status(&self, relay: &url::Url, status: SyncStatus) -> Result<()> {
        sqlx::query(UPSERT_RELAY_SYNC_STATUS)
            .bind(relay.to_string())
            .bind(timestamp_to_db(Timestamp::now())?)
            .bind(sync_status_to_db(&status))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn update_relay_sync_progress(
        &self,
        relay: &url::Url,
        timestamp: Timestamp,
    ) -> Result<()> {
        let result = sqlx::query(UPDATE_RELAY_SYNC_PROGRESS)
            .bind(relay.to_string())
            .bind(timestamp_to_db(timestamp)?)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(Error::Persistence(format!(
                "Relay sync status not found for {}",
                relay
            )));
        }
        Ok(())
    }

    async fn update_relay_last_seen(&self, relay: &url::Url, timestamp: Timestamp) -> Result<()> {
        sqlx::query(UPSERT_RELAY_LAST_SEEN)
            .bind(relay.to_string())
            .bind(timestamp_to_db(timestamp)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn add_failed_relay_sync(
        &self,
        relay: &url::Url,
        event: nostr::event::Event,
    ) -> Result<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let event_id = event.id.to_hex();
        let persisted = NostrEventDb::try_from(event)?;
        sqlx::query(INSERT_RELAY_RETRY)
            .bind(id)
            .bind(relay.to_string())
            .bind(event_id)
            .bind(Json(persisted))
            .bind(0_i64)
            .bind(timestamp_to_db(Timestamp::now())?)
            .bind(Option::<i64>::None)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_pending_relay_retries(
        &self,
        relay: &url::Url,
        limit: usize,
    ) -> Result<Vec<nostr::event::Event>> {
        let limit = i64::try_from(limit)
            .map_err(|_| Error::InvalidData("relay retry limit exceeds i64".to_owned()))?;
        let rows: Vec<RelaySyncRetryRow> = sqlx::query_as(SELECT_PENDING_RELAY_RETRIES)
            .bind(relay.to_string())
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(RelaySyncRetryRow::into_event)
            .collect()
    }

    async fn mark_relay_retry_success(&self, relay: &url::Url, event_id: &str) -> Result<()> {
        sqlx::query(DELETE_RELAY_RETRY)
            .bind(relay.to_string())
            .bind(event_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn mark_relay_retry_failed(
        &self,
        relay: &url::Url,
        event_id: &str,
        max_retries: usize,
    ) -> Result<()> {
        let max_retries = i64::try_from(max_retries)
            .map_err(|_| Error::InvalidData("relay max retries exceeds i64".to_owned()))?;
        let mut tx = self.pool.begin().await?;
        let retry_count: Option<i64> = sqlx::query_scalar(SELECT_RELAY_RETRY_COUNT)
            .bind(relay.to_string())
            .bind(event_id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(retry_count) = retry_count else {
            tx.commit().await?;
            return Ok(());
        };
        if retry_count >= max_retries {
            sqlx::query(DELETE_RELAY_RETRY)
                .bind(relay.to_string())
                .bind(event_id)
                .execute(&mut *tx)
                .await?;
        } else {
            sqlx::query(UPDATE_RELAY_RETRY_FAILED)
                .bind(relay.to_string())
                .bind(event_id)
                .bind(timestamp_to_db(Timestamp::now())?)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::PostgresNostrStore;
    use crate::EncryptionContext;
    use crate::tests::nostr_contact_store;
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use sqlx::PgPool;
    use std::sync::Arc;

    macro_rules! contract_test {
        ($name:ident, $contract:ident) => {
            #[sqlx::test(migrations = "migrations/postgres")]
            async fn $name(pool: PgPool) {
                let store =
                    PostgresNostrStore::new(pool, Arc::new(EncryptionContext::new(BcrKeys::new())));
                nostr_contact_store::$contract(&store).await;
            }
        };
    }

    contract_test!(
        upsert_and_retrieve_by_node_id,
        test_upsert_and_retrieve_by_node_id
    );
    contract_test!(
        upsert_and_retrieve_by_npub,
        test_upsert_and_retrieve_by_npub
    );
    contract_test!(get_all, test_get_all);
    contract_test!(delete_contact, test_delete_contact);
    contract_test!(set_handshake_status, test_set_handshake_status);
    contract_test!(set_trust_level, test_set_trust_level);
    contract_test!(get_npubs, test_get_npubs);
    contract_test!(search, test_search);
    contract_test!(by_node_ids, test_by_node_ids);

    contract_test!(pending_share_crud, test_pending_share_crud);
    contract_test!(
        pending_share_exists_distinguishes_direction,
        test_pending_share_exists_distinguishes_direction
    );

    contract_test!(
        update_relay_last_seen_creates_new_status,
        test_update_relay_last_seen_creates_new_status
    );
    contract_test!(
        update_relay_last_seen_updates_existing,
        test_update_relay_last_seen_updates_existing
    );
    contract_test!(update_relay_sync_status, test_update_relay_sync_status);
    contract_test!(get_pending_relays, test_get_pending_relays);
    contract_test!(update_relay_sync_progress, test_update_relay_sync_progress);

    contract_test!(
        add_and_get_pending_relay_retries,
        test_add_and_get_pending_relay_retries
    );
    contract_test!(mark_relay_retry_success, test_mark_relay_retry_success);
    contract_test!(
        mark_relay_retry_failed_increments_count,
        test_mark_relay_retry_failed_increments_count
    );
    contract_test!(
        get_pending_relay_retries_filters_by_relay,
        test_get_pending_relay_retries_filters_by_relay
    );
    contract_test!(
        get_pending_relay_retries_respects_limit,
        test_get_pending_relay_retries_respects_limit
    );
}
