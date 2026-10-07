use std::collections::HashSet;
use std::str::FromStr;

use crate::sql::bill::{
    BILL_EXISTS, BILLS_WITH_LATEST_OP_CODE, BillCacheRow, BitcreditBillResultDb, CLEAR_CACHE,
    GET_BILL_IDS, INSERT_KEYS, INVALIDATE_CACHE, IS_PAID, PaymentStateRow, SELECT_CACHE_ONE,
    SELECT_KEYS, SELECT_OFFER_TO_SELL_PAYMENT, SELECT_PAYMENT, SELECT_RECOURSE_PAYMENT,
    UPSERT_CACHE, UPSERT_OFFER_TO_SELL_PAYMENT, UPSERT_PAYMENT, UPSERT_RECOURSE_PAYMENT,
    WAITING_FOR_PAYMENT, payment_state_to_db,
};
use crate::sql::{block_id_to_db, timestamp_to_db};
use crate::{Error, Result};
use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::application::bill::PaymentState;
use bcr_ebill_core::application::{ServiceTraitBounds, bill::BitcreditBillResult};
use bcr_ebill_core::protocol::blockchain::bill::BillOpCode;
use bcr_ebill_core::protocol::crypto::BcrKeys;
use bcr_ebill_core::protocol::{BlockId, Timestamp};
use bitcoin::secp256k1::SecretKey;
use sqlx::types::Json;
use sqlx::{PgPool, types::Text};

use crate::traits::bill::BillStoreApi;

#[derive(Clone)]
pub struct PostgresBillStore {
    pool: PgPool,
}

impl PostgresBillStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ServiceTraitBounds for PostgresBillStore {}

#[async_trait]
impl BillStoreApi for PostgresBillStore {
    async fn save_bill_to_cache(
        &self,
        id: &BillId,
        identity_node_id: &NodeId,
        bill: &BitcreditBillResult,
    ) -> Result<()> {
        if &bill.id != id {
            return Err(Error::InvalidData(format!(
                "bill cache id mismatch: \
                 expected {id}, got {}",
                bill.id
            )));
        }
        let payload: BitcreditBillResultDb = (bill, identity_node_id).into();
        sqlx::query(UPSERT_CACHE)
            .bind(Text(id.clone()))
            .bind(Text(identity_node_id.clone()))
            .bind(Json(payload))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_bill_from_cache(
        &self,
        id: &BillId,
        identity_node_id: &NodeId,
    ) -> Result<Option<BitcreditBillResult>> {
        let row: Option<BillCacheRow> = sqlx::query_as(SELECT_CACHE_ONE)
            .bind(Text(id.clone()))
            .bind(Text(identity_node_id.clone()))
            .fetch_optional(&self.pool)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn get_bills_from_cache(
        &self,
        ids: &[BillId],
        identity_node_id: &NodeId,
    ) -> Result<Vec<BitcreditBillResult>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            r#"
            SELECT bill_id, identity_node_id, payload
            FROM bill_cache
            WHERE identity_node_id =
            "#,
        );
        builder.push_bind(Text(identity_node_id.clone()));
        builder.push(" AND bill_id IN (");
        let mut separated = builder.separated(", ");
        for id in ids {
            separated.push_bind(Text(id.clone()));
        }
        separated.push_unseparated(")");
        let rows: Vec<BillCacheRow> = builder.build_query_as().fetch_all(&self.pool).await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn invalidate_bill_in_cache(&self, id: &BillId) -> Result<()> {
        sqlx::query(INVALIDATE_CACHE)
            .bind(Text(id.clone()))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn clear_bill_cache(&self) -> Result<()> {
        sqlx::query(CLEAR_CACHE).execute(&self.pool).await?;
        Ok(())
    }

    async fn save_keys(&self, id: &BillId, key_pair: &BcrKeys) -> Result<()> {
        let key = key_pair.get_private_key_string();
        sqlx::query(INSERT_KEYS)
            .bind(Text(id.clone()))
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_keys(&self, id: &BillId) -> Result<BcrKeys> {
        let key: Option<String> = sqlx::query_scalar(SELECT_KEYS)
            .bind(Text(id.clone()))
            .fetch_optional(&self.pool)
            .await?;
        let key = key.ok_or_else(|| Error::NoSuchEntity("bill".to_owned(), id.to_string()))?;
        let private_key = SecretKey::from_str(&key).map_err(|_| Error::EncodingError)?;
        Ok(BcrKeys::from_private_key(&private_key))
    }

    async fn set_payment_state(&self, id: &BillId, payment_state: &PaymentState) -> Result<()> {
        let state = payment_state_to_db(payment_state)?;
        sqlx::query(UPSERT_PAYMENT)
            .bind(Text(id.clone()))
            .bind(state.payment_state)
            .bind(state.block_time)
            .bind(state.block_hash)
            .bind(state.confirmations)
            .bind(state.tx_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_payment_state(&self, id: &BillId) -> Result<Option<PaymentState>> {
        let row: Option<PaymentStateRow> = sqlx::query_as(SELECT_PAYMENT)
            .bind(Text(id.clone()))
            .fetch_optional(&self.pool)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn is_paid(&self, id: &BillId) -> Result<bool> {
        Ok(sqlx::query_scalar(IS_PAID)
            .bind(Text(id.clone()))
            .fetch_one(&self.pool)
            .await?)
    }

    async fn set_offer_to_sell_payment_state(
        &self,
        id: &BillId,
        block_id: BlockId,
        payment_state: &PaymentState,
    ) -> Result<()> {
        let state = payment_state_to_db(payment_state)?;
        sqlx::query(UPSERT_OFFER_TO_SELL_PAYMENT)
            .bind(Text(id.clone()))
            .bind(block_id_to_db(block_id)?)
            .bind(state.payment_state)
            .bind(state.block_time)
            .bind(state.block_hash)
            .bind(state.confirmations)
            .bind(state.tx_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_offer_to_sell_payment_state(
        &self,
        id: &BillId,
        block_id: BlockId,
    ) -> Result<Option<PaymentState>> {
        let row: Option<PaymentStateRow> = sqlx::query_as(SELECT_OFFER_TO_SELL_PAYMENT)
            .bind(Text(id.clone()))
            .bind(block_id_to_db(block_id)?)
            .fetch_optional(&self.pool)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn set_recourse_payment_state(
        &self,
        id: &BillId,
        block_id: BlockId,
        payment_state: &PaymentState,
    ) -> Result<()> {
        let state = payment_state_to_db(payment_state)?;
        sqlx::query(UPSERT_RECOURSE_PAYMENT)
            .bind(Text(id.clone()))
            .bind(block_id_to_db(block_id)?)
            .bind(state.payment_state)
            .bind(state.block_time)
            .bind(state.block_hash)
            .bind(state.confirmations)
            .bind(state.tx_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_recourse_payment_state(
        &self,
        id: &BillId,
        block_id: BlockId,
    ) -> Result<Option<PaymentState>> {
        let row: Option<PaymentStateRow> = sqlx::query_as(SELECT_RECOURSE_PAYMENT)
            .bind(Text(id.clone()))
            .bind(block_id_to_db(block_id)?)
            .fetch_optional(&self.pool)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn exists(&self, id: &BillId) -> Result<bool> {
        Ok(sqlx::query_scalar(BILL_EXISTS)
            .bind(Text(id.clone()))
            .fetch_one(&self.pool)
            .await?)
    }

    async fn get_ids(&self) -> Result<Vec<BillId>> {
        let ids: Vec<Text<BillId>> = sqlx::query_scalar(GET_BILL_IDS)
            .fetch_all(&self.pool)
            .await?;
        Ok(ids.into_iter().map(Text::into_inner).collect())
    }

    async fn get_bill_ids_waiting_for_payment(&self) -> Result<Vec<BillId>> {
        let ids: Vec<Text<BillId>> = sqlx::query_scalar(WAITING_FOR_PAYMENT)
            .bind(Text(BillOpCode::RequestToPay))
            .fetch_all(&self.pool)
            .await?;
        Ok(ids.into_iter().map(Text::into_inner).collect())
    }

    async fn get_bill_ids_waiting_for_sell_payment(&self) -> Result<Vec<BillId>> {
        let ids: Vec<Text<BillId>> = sqlx::query_scalar(BILLS_WITH_LATEST_OP_CODE)
            .bind(Text(BillOpCode::OfferToSell))
            .fetch_all(&self.pool)
            .await?;
        Ok(ids.into_iter().map(Text::into_inner).collect())
    }

    async fn get_bill_ids_waiting_for_recourse_payment(&self) -> Result<Vec<BillId>> {
        let ids: Vec<Text<BillId>> = sqlx::query_scalar(BILLS_WITH_LATEST_OP_CODE)
            .bind(Text(BillOpCode::RequestRecourse))
            .fetch_all(&self.pool)
            .await?;
        Ok(ids.into_iter().map(Text::into_inner).collect())
    }

    async fn get_bill_ids_with_op_codes_since(
        &self,
        op_codes: HashSet<BillOpCode>,
        since: Timestamp,
    ) -> Result<Vec<BillId>> {
        if op_codes.is_empty() {
            return Ok(vec![]);
        }
        let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            r#"
            SELECT bill_id
            FROM bill_chain
            WHERE timestamp >=
            "#,
        );
        builder.push_bind(timestamp_to_db(since)?);
        builder.push(" AND op_code IN (");
        let mut separated = builder.separated(", ");
        for op_code in op_codes {
            separated.push_bind(Text(op_code));
        }
        separated.push_unseparated(")");
        builder.push(
            r#"
        GROUP BY bill_id
        ORDER BY MAX(timestamp) DESC
        "#,
        );
        let rows: Vec<Text<BillId>> = builder.build_query_scalar().fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(Text::into_inner).collect())
    }
}

#[cfg(test)]
mod tests {
    use crate::postgres::bill::PostgresBillStore;
    use crate::postgres::bill_chain::PostgresBillChainStore;
    use crate::tests::bill::test_bill_store;
    use sqlx::PgPool;
    #[sqlx::test(migrations = "migrations/postgres")]
    async fn bill_store(pool: PgPool) {
        let store = PostgresBillStore::new(pool.clone());
        let chain_store = PostgresBillChainStore::new(pool);
        test_bill_store(&store, &chain_store).await;
    }
}
