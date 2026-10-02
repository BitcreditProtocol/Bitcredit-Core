use crate::{
    Error, Result,
    sql::{
        mint::{
            ADD_PROOFS, ADD_RECOVERY_DATA, DELETE_REQUESTS_FOR_BILL, EXISTS_FOR_BILL, INSERT_OFFER,
            INSERT_REQUEST, MintOfferRow, MintRequestRow, NewMintOffer, SELECT_ACTIVE_REQUESTS,
            SELECT_OFFER, SELECT_REQUEST, SELECT_REQUESTS, SELECT_REQUESTS_FOR_BILL,
            SET_PROOFS_SPENT, UPDATE_REQUEST, recovery_data_to_json, status_to_db,
        },
        timestamp_to_db,
    },
    traits::mint::MintStoreApi,
};
use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::{
        Sum, Timestamp,
        mint::{MintOffer, MintRequest, MintRequestStatus},
    },
};
use sqlx::{SqlitePool, types::Text};
use uuid::Uuid;

#[derive(Clone)]
pub struct SqliteMintStore {
    pool: SqlitePool,
}

impl SqliteMintStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl ServiceTraitBounds for SqliteMintStore {}

#[async_trait]
impl MintStoreApi for SqliteMintStore {
    async fn exists_for_bill(&self, requester_node_id: &NodeId, bill_id: &BillId) -> Result<bool> {
        match sqlx::query_scalar::<_, bool>(EXISTS_FOR_BILL)
            .bind(Text(requester_node_id.clone()))
            .bind(Text(bill_id.clone()))
            .fetch_one(&self.pool)
            .await
        {
            Ok(exists) => Ok(exists),
            Err(e) => {
                log::error!("Error checking if mint request exists for bill {bill_id}: {e}");
                Ok(false)
            }
        }
    }

    async fn dev_mode_reset_for_bill(&self, bill_id: &BillId) -> Result<()> {
        // mint_offers are removed through ON DELETE CASCADE
        sqlx::query(DELETE_REQUESTS_FOR_BILL)
            .bind(Text(bill_id.clone()))
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn get_all_active_requests(&self) -> Result<Vec<MintRequest>> {
        let rows: Vec<MintRequestRow> = sqlx::query_as(SELECT_ACTIVE_REQUESTS)
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn get_requests(
        &self,
        requester_node_id: &NodeId,
        bill_id: &BillId,
        mint_node_id: &NodeId,
    ) -> Result<Vec<MintRequest>> {
        let rows: Vec<MintRequestRow> = sqlx::query_as(SELECT_REQUESTS)
            .bind(Text(requester_node_id.clone()))
            .bind(Text(bill_id.clone()))
            .bind(Text(mint_node_id.clone()))
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn get_requests_for_bill(
        &self,
        requester_node_id: &NodeId,
        bill_id: &BillId,
    ) -> Result<Vec<MintRequest>> {
        let rows: Vec<MintRequestRow> = sqlx::query_as(SELECT_REQUESTS_FOR_BILL)
            .bind(Text(requester_node_id.clone()))
            .bind(Text(bill_id.clone()))
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn add_request(
        &self,
        requester_node_id: &NodeId,
        bill_id: &BillId,
        mint_node_id: &NodeId,
        mint_request_id: &Uuid,
        timestamp: Timestamp,
    ) -> Result<()> {
        let result = sqlx::query(INSERT_REQUEST)
            .bind(Text(requester_node_id.clone()))
            .bind(Text(bill_id.clone()))
            .bind(Text(mint_node_id.clone()))
            .bind(Text(*mint_request_id))
            .bind(timestamp_to_db(timestamp)?)
            .bind("pending")
            .bind(Option::<i64>::None)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(Error::Conflict("mint request already exists".to_owned()));
        }

        Ok(())
    }

    async fn get_request(&self, mint_request_id: &Uuid) -> Result<Option<MintRequest>> {
        let row: Option<MintRequestRow> = sqlx::query_as(SELECT_REQUEST)
            .bind(Text(*mint_request_id))
            .fetch_optional(&self.pool)
            .await?;

        row.map(TryInto::try_into).transpose()
    }

    async fn update_request(
        &self,
        mint_request_id: &Uuid,
        new_status: &MintRequestStatus,
    ) -> Result<()> {
        let (status, status_timestamp) = status_to_db(new_status)?;

        sqlx::query(UPDATE_REQUEST)
            .bind(status)
            .bind(status_timestamp)
            .bind(Text(*mint_request_id))
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn add_proofs_to_offer(&self, mint_request_id: &Uuid, proofs: &str) -> Result<()> {
        let result = sqlx::query(ADD_PROOFS)
            .bind(proofs)
            .bind(Text(*mint_request_id))
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 1 {
            return Ok(());
        }

        match self.get_offer(mint_request_id).await? {
            None => Err(Error::NoSuchEntity(
                "mint offer".to_owned(),
                mint_request_id.to_string(),
            )),
            Some(offer) if offer.proofs.is_some() => {
                Err(Error::Conflict("mint offer already has proofs".to_owned()))
            }
            Some(_) => Err(Error::Conflict(
                "could not add proofs to mint offer".to_owned(),
            )),
        }
    }

    async fn add_recovery_data_to_offer(
        &self,
        mint_request_id: &Uuid,
        secrets: &[String],
        rs: &[String],
    ) -> Result<()> {
        let recovery_data = recovery_data_to_json(secrets, rs)?;

        let result = sqlx::query(ADD_RECOVERY_DATA)
            .bind(recovery_data)
            .bind(Text(*mint_request_id))
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 1 {
            return Ok(());
        }

        match self.get_offer(mint_request_id).await? {
            None => Err(Error::NoSuchEntity(
                "mint offer".to_owned(),
                mint_request_id.to_string(),
            )),
            Some(offer) if offer.proofs.is_some() => {
                Err(Error::Conflict("mint offer already has proofs".to_owned()))
            }
            Some(offer) if offer.recovery_data.is_some() => Err(Error::Conflict(
                "mint offer already has recovery data".to_owned(),
            )),
            Some(_) => Err(Error::Conflict("could not add recovery data".to_owned())),
        }
    }

    async fn set_proofs_to_spent_for_offer(&self, mint_request_id: &Uuid) -> Result<()> {
        let result = sqlx::query(SET_PROOFS_SPENT)
            .bind(Text(*mint_request_id))
            .execute(&self.pool)
            .await?;

        if result.rows_affected() > 0 {
            return Ok(());
        }

        match self.get_offer(mint_request_id).await? {
            None => Err(Error::NoSuchEntity(
                "mint offer".to_owned(),
                mint_request_id.to_string(),
            )),
            Some(offer) if offer.proofs.is_none() => Err(Error::NoSuchEntity(
                "offer proofs".to_owned(),
                mint_request_id.to_string(),
            )),
            Some(_) => Ok(()),
        }
    }

    async fn add_offer(
        &self,
        mint_request_id: &Uuid,
        keyset_id: &str,
        expiration_timestamp: Timestamp,
        discounted_sum: Sum,
    ) -> Result<()> {
        let row = NewMintOffer::new(
            mint_request_id,
            keyset_id,
            expiration_timestamp,
            &discounted_sum,
        )?;

        let result = sqlx::query(INSERT_OFFER)
            .bind(row.mint_request_id)
            .bind(&row.keyset_id)
            .bind(row.expiration_timestamp)
            .bind(row.discounted_sum_amount)
            .bind(&row.discounted_sum_currency_code)
            .bind(row.discounted_sum_currency_decimals)
            .bind(&row.discounted_sum_reference_exchange_rate)
            .bind(Option::<String>::None)
            .bind(false)
            .bind(Option::<String>::None)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(Error::Conflict("mint offer already exists".to_owned()));
        }

        Ok(())
    }

    async fn get_offer(&self, mint_request_id: &Uuid) -> Result<Option<MintOffer>> {
        let row: Option<MintOfferRow> = sqlx::query_as(SELECT_OFFER)
            .bind(Text(*mint_request_id))
            .fetch_optional(&self.pool)
            .await?;

        row.map(TryInto::try_into).transpose()
    }
}

#[sqlx::test(migrations = "migrations/sqlite")]
async fn mint_store_contract_sqlite(pool: sqlx::SqlitePool) {
    let store = SqliteMintStore::new(pool);
    crate::tests::mint::mint_store_contract(&store).await;
}
