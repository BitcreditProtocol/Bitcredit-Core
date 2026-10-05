use async_trait::async_trait;
use bcr_ebill_core::{
    application::{
        ServiceTraitBounds,
        identity::{ActiveIdentityState, Identity, IdentityWithAll},
    },
    protocol::{EmailIdentityProofData, SignedIdentityProof},
};
use bitcoin::Network;
use sqlx::{PgPool, types::Text};

use crate::{
    Error, Result,
    protocol::crypto::BcrKeys,
    sql::identity::{
        ActiveIdentityRow, EmailConfirmationRow, INSERT_NETWORK, IdentityKeysRow, IdentityRow,
        SELECT_ACTIVE_IDENTITY, SELECT_EMAIL_CONFIRMATIONS, SELECT_IDENTITY, SELECT_KEYS,
        SELECT_NETWORK, UPSERT_ACTIVE_IDENTITY, UPSERT_EMAIL_CONFIRMATION, UPSERT_IDENTITY,
        UPSERT_KEYS, bind_identity, email_confirmation_from_row, email_confirmation_to_row,
        identity_to_row,
    },
    traits::identity::IdentityStoreApi,
};

#[derive(Clone)]
pub struct PostgresIdentityStore {
    pool: PgPool,
}

impl PostgresIdentityStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn get_db_keys(&self) -> Result<Option<IdentityKeysRow>> {
        Ok(sqlx::query_as(SELECT_KEYS)
            .fetch_optional(&self.pool)
            .await?)
    }

    async fn get_db_network(&self) -> Result<Option<Network>> {
        let result: Option<Text<Network>> = sqlx::query_scalar(SELECT_NETWORK)
            .fetch_optional(&self.pool)
            .await?;

        Ok(result.map(Text::into_inner))
    }
}

impl ServiceTraitBounds for PostgresIdentityStore {}

#[async_trait]
impl IdentityStoreApi for PostgresIdentityStore {
    async fn exists(&self) -> bool {
        self.get().await.is_ok()
    }

    async fn save(&self, identity: &Identity) -> Result<()> {
        let row = identity_to_row(identity)?;
        bind_identity!(sqlx::query(UPSERT_IDENTITY), row)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get(&self) -> Result<Identity> {
        let row: Option<IdentityRow> = sqlx::query_as(SELECT_IDENTITY)
            .fetch_optional(&self.pool)
            .await?;
        row.map(TryInto::try_into)
            .transpose()?
            .ok_or_else(|| Error::NoSuchEntity("identity".to_owned(), String::new()))
    }

    async fn get_full(&self) -> Result<IdentityWithAll> {
        Ok(IdentityWithAll {
            identity: self.get().await?,
            key_pair: self.get_key_pair().await?,
        })
    }

    async fn save_key_pair(&self, key_pair: &BcrKeys, seed: &str) -> Result<()> {
        sqlx::query(UPSERT_KEYS)
            .bind(Text(key_pair.get_private_key_string()))
            .bind(seed)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_key_pair(&self) -> Result<BcrKeys> {
        match self.get_db_keys().await? {
            None => Err(Error::NoSuchEntity(
                "identity key pair".to_owned(),
                String::new(),
            )),
            Some(row) => {
                let private_key = row.key.into_inner();
                Ok(BcrKeys::from_private_key(&private_key))
            }
        }
    }

    async fn set_or_check_network(&self, configured_network: Network) -> Result<()> {
        match self.get_db_network().await? {
            None => {
                sqlx::query(INSERT_NETWORK)
                    .bind(Text(configured_network))
                    .execute(&self.pool)
                    .await?;
                Ok(())
            }
            Some(network) => {
                if configured_network != network {
                    return Err(Error::NetworkDoesNotMatch);
                }
                Ok(())
            }
        }
    }

    async fn get_or_create_key_pair(&self) -> Result<BcrKeys> {
        let keys = match self.get_key_pair().await {
            Ok(keys) => keys,
            _ => {
                let (new_keys, seed) = BcrKeys::new_with_seed_phrase()?;
                self.save_key_pair(&new_keys, &seed).await?;
                new_keys
            }
        };

        Ok(keys)
    }

    async fn get_seedphrase(&self) -> Result<String> {
        match self.get_db_keys().await? {
            Some(row) => Ok(row.seed_phrase),
            None => Err(Error::NoSuchEntity("seedphrase".to_owned(), String::new())),
        }
    }

    async fn get_current_identity(&self) -> Result<ActiveIdentityState> {
        let row: Option<ActiveIdentityRow> = sqlx::query_as(SELECT_ACTIVE_IDENTITY)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(row) => Ok(row.into()),
            None => {
                let identity = self.get().await?;
                Ok(ActiveIdentityState {
                    personal: identity.node_id,

                    company: None,
                })
            }
        }
    }

    async fn set_current_identity(&self, identity_state: &ActiveIdentityState) -> Result<()> {
        sqlx::query(UPSERT_ACTIVE_IDENTITY)
            .bind(Text(identity_state.personal.clone()))
            .bind(identity_state.company.clone().map(Text))
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn get_email_confirmations(
        &self,
    ) -> Result<Vec<(SignedIdentityProof, EmailIdentityProofData)>> {
        let rows: Vec<EmailConfirmationRow> = sqlx::query_as(SELECT_EMAIL_CONFIRMATIONS)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| {
                let db = email_confirmation_from_row(row)?;
                Ok(db)
            })
            .collect()
    }

    async fn set_email_confirmation(
        &self,
        proof: &SignedIdentityProof,
        data: &EmailIdentityProofData,
    ) -> Result<()> {
        let keys = self.get_key_pair().await?;
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
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::PostgresIdentityStore;
    use crate::tests::identity::{test_get_or_create_key_pair, test_identity_store};
    use sqlx::PgPool;

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn identity_store(pool: PgPool) {
        let store = PostgresIdentityStore::new(pool);
        test_identity_store(&store).await;
    }

    #[sqlx::test(migrations = "migrations/postgres")]
    async fn get_or_create_key_pair(pool: PgPool) {
        let store = PostgresIdentityStore::new(pool);
        test_get_or_create_key_pair(&store).await;
    }
}
