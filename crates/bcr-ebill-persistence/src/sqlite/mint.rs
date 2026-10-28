use crate::{
    EncryptionContext, Error, Result,
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
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct SqliteMintStore {
    pool: SqlitePool,
    encryption_ctx: Arc<EncryptionContext>,
}

impl SqliteMintStore {
    pub fn new(pool: SqlitePool, encryption_ctx: Arc<EncryptionContext>) -> Self {
        Self {
            pool,
            encryption_ctx,
        }
    }

    fn encrypt_mint_offer_value(&self, value: &str) -> Result<Vec<u8>> {
        self.encryption_ctx.encrypt(value.as_bytes())
    }

    fn decrypt_mint_offer_value(&self, value: &[u8]) -> Result<Vec<u8>> {
        self.encryption_ctx.decrypt(value)
    }

    fn decrypt_mint_offer_row(&self, mut row: MintOfferRow) -> Result<MintOffer> {
        if let Some(proofs) = row.proofs.as_mut() {
            *proofs = self.decrypt_mint_offer_value(proofs)?;
        }
        if let Some(recovery_data) = row.recovery_data.as_mut() {
            *recovery_data = self.decrypt_mint_offer_value(recovery_data)?;
        }
        row.try_into()
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

    async fn get_request(
        &self,
        mint_node_id: &NodeId,
        mint_request_id: &Uuid,
    ) -> Result<Option<MintRequest>> {
        let row: Option<MintRequestRow> = sqlx::query_as(SELECT_REQUEST)
            .bind(Text(mint_node_id.clone()))
            .bind(Text(*mint_request_id))
            .fetch_optional(&self.pool)
            .await?;

        row.map(TryInto::try_into).transpose()
    }

    async fn update_request(
        &self,
        mint_node_id: &NodeId,
        mint_request_id: &Uuid,
        new_status: &MintRequestStatus,
    ) -> Result<()> {
        let (status, status_timestamp) = status_to_db(new_status)?;

        sqlx::query(UPDATE_REQUEST)
            .bind(status)
            .bind(status_timestamp)
            .bind(Text(mint_node_id.clone()))
            .bind(Text(*mint_request_id))
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn add_proofs_to_offer(
        &self,
        mint_node_id: &NodeId,
        mint_request_id: &Uuid,
        proofs: &str,
    ) -> Result<()> {
        let encrypted_proofs = self.encrypt_mint_offer_value(proofs)?;
        let result = sqlx::query(ADD_PROOFS)
            .bind(encrypted_proofs)
            .bind(Text(mint_node_id.clone()))
            .bind(Text(*mint_request_id))
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 1 {
            return Ok(());
        }

        match self.get_offer(mint_node_id, mint_request_id).await? {
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
        mint_node_id: &NodeId,
        mint_request_id: &Uuid,
        secrets: &[String],
        rs: &[String],
    ) -> Result<()> {
        let recovery_data = recovery_data_to_json(secrets, rs)?;
        let encrypted_recovery_data = self.encrypt_mint_offer_value(&recovery_data)?;

        let result = sqlx::query(ADD_RECOVERY_DATA)
            .bind(encrypted_recovery_data)
            .bind(Text(mint_node_id.clone()))
            .bind(Text(*mint_request_id))
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 1 {
            return Ok(());
        }

        match self.get_offer(mint_node_id, mint_request_id).await? {
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

    async fn set_proofs_to_spent_for_offer(
        &self,
        mint_node_id: &NodeId,
        mint_request_id: &Uuid,
    ) -> Result<()> {
        let result = sqlx::query(SET_PROOFS_SPENT)
            .bind(Text(mint_node_id.clone()))
            .bind(Text(*mint_request_id))
            .execute(&self.pool)
            .await?;

        if result.rows_affected() > 0 {
            return Ok(());
        }

        match self.get_offer(mint_node_id, mint_request_id).await? {
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
        mint_node_id: &NodeId,
        mint_request_id: &Uuid,
        keyset_id: &str,
        expiration_timestamp: Timestamp,
        discounted_sum: Sum,
    ) -> Result<()> {
        let row = NewMintOffer::new(
            mint_node_id,
            mint_request_id,
            keyset_id,
            expiration_timestamp,
            &discounted_sum,
        )?;

        let result = sqlx::query(INSERT_OFFER)
            .bind(row.mint_node_id)
            .bind(row.mint_request_id)
            .bind(&row.keyset_id)
            .bind(row.expiration_timestamp)
            .bind(row.discounted_sum_amount)
            .bind(&row.discounted_sum_currency_code)
            .bind(row.discounted_sum_currency_decimals)
            .bind(&row.discounted_sum_reference_exchange_rate)
            .bind(Option::<Vec<u8>>::None)
            .bind(false)
            .bind(Option::<Vec<u8>>::None)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(Error::Conflict("mint offer already exists".to_owned()));
        }

        Ok(())
    }

    async fn get_offer(
        &self,
        mint_node_id: &NodeId,
        mint_request_id: &Uuid,
    ) -> Result<Option<MintOffer>> {
        let row: Option<MintOfferRow> = sqlx::query_as(SELECT_OFFER)
            .bind(Text(mint_node_id.clone()))
            .bind(Text(*mint_request_id))
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| self.decrypt_mint_offer_row(row)).transpose()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        EncryptionContext,
        sql::mint::NewMintOffer,
        sqlite::mint::SqliteMintStore,
        tests::tests::{bill_id_test, node_id_test, node_id_test_other, test_ts},
        traits::mint::MintStoreApi,
    };
    use bcr_ebill_core::protocol::{Sum, crypto::BcrKeys, mint::MintRequestStatus};
    use sqlx::types::Text;
    use std::sync::Arc;

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn mint_store_contract_sqlite(pool: sqlx::SqlitePool) {
        let store = SqliteMintStore::new(pool, Arc::new(EncryptionContext::new(BcrKeys::new())));
        crate::tests::mint::mint_store_contract(&store).await;
    }

    #[sqlx::test(migrations = "migrations/sqlite")]
    async fn mint_store_scopes_quotes_by_mint_sqlite(pool: sqlx::SqlitePool) {
        let store = SqliteMintStore::new(pool, Arc::new(EncryptionContext::new(BcrKeys::new())));
        crate::tests::mint::mint_store_scopes_quotes_by_mint(&store).await;
    }

    /// Offers stored before quotes were scoped by Mint move onto their request's Mint with
    /// unchanged ids, status, terms, proofs and recovery data.
    #[sqlx::test(migrations = false)]
    async fn scope_migration_keeps_existing_offer_on_its_request_mint(pool: sqlx::SqlitePool) {
        sqlx::raw_sql(include_str!("../../migrations/sqlite/0001_initial.sql"))
            .execute(&pool)
            .await
            .unwrap();
        let encryption_ctx = Arc::new(EncryptionContext::new(BcrKeys::new()));
        let mint = node_id_test_other();
        let id = uuid::uuid!("00000000-0000-0000-0000-0000000000bb");
        sqlx::query(
            "INSERT INTO mint_requests (requester_node_id, bill_id, mint_node_id, mint_request_id, timestamp, status, status_timestamp) VALUES ($1, $2, $3, $4, $5, 'minting_enabled', NULL)",
        )
        .bind(Text(node_id_test()))
        .bind(Text(bill_id_test()))
        .bind(Text(mint.clone()))
        .bind(Text(id))
        .bind(crate::sql::timestamp_to_db(test_ts()).unwrap())
        .execute(&pool)
        .await
        .unwrap();
        let offer = NewMintOffer::new(
            &mint,
            &id,
            "synthetic-keyset",
            test_ts(),
            &Sum::new_sat(1500).unwrap(),
        )
        .unwrap();
        sqlx::query(
            "INSERT INTO mint_offers (mint_request_id, keyset_id, expiration_timestamp, discounted_sum_amount, discounted_sum_currency_code, discounted_sum_currency_decimals, discounted_sum_reference_exchange_rate, proofs, proofs_spent, recovery_data) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE, $9)",
        )
        .bind(offer.mint_request_id)
        .bind(&offer.keyset_id)
        .bind(offer.expiration_timestamp)
        .bind(offer.discounted_sum_amount)
        .bind(&offer.discounted_sum_currency_code)
        .bind(offer.discounted_sum_currency_decimals)
        .bind(&offer.discounted_sum_reference_exchange_rate)
        .bind(encryption_ctx.encrypt(b"synthetic-proof").unwrap())
        .bind(
            encryption_ctx
                .encrypt(br#"{"secrets":["synthetic-secret"],"rs":["synthetic-r"]}"#)
                .unwrap(),
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::raw_sql(include_str!(
            "../../migrations/sqlite/0002_scope_mint_quotes_by_mint.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();

        let store = SqliteMintStore::new(pool, encryption_ctx);
        assert!(matches!(
            store.get_request(&mint, &id).await.unwrap().unwrap().status,
            MintRequestStatus::MintingEnabled
        ));
        let offer = store.get_offer(&mint, &id).await.unwrap().unwrap();
        assert_eq!(offer.keyset_id, "synthetic-keyset");
        assert_eq!(offer.discounted_sum, Sum::new_sat(1500).unwrap());
        assert_eq!(offer.proofs.as_deref(), Some("synthetic-proof"));
        assert!(offer.proofs_spent);
        assert_eq!(offer.recovery_data.unwrap().rs, ["synthetic-r"]);
        assert!(
            store
                .get_offer(&node_id_test(), &id)
                .await
                .unwrap()
                .is_none()
        );

        // The same quote id from another Mint is now a distinct request and offer.
        store
            .add_request(
                &node_id_test(),
                &bill_id_test(),
                &node_id_test(),
                &id,
                test_ts(),
            )
            .await
            .unwrap();
        store
            .add_offer(
                &node_id_test(),
                &id,
                "mint-b",
                test_ts(),
                Sum::new_sat(2500).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .get_offer(&mint, &id)
                .await
                .unwrap()
                .unwrap()
                .keyset_id,
            "synthetic-keyset"
        );
    }
}
