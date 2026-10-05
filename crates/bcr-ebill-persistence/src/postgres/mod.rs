use crate::{
    Error, Result,
    postgres::{
        bill::PostgresBillStore, bill_chain::PostgresBillChainStore,
        company_chain::PostgresCompanyChainStore, contact::PostgresContactStore,
        email_notification::PostgresEmailNotificationStore,
        identity_chain::PostgresIdentityChainStore, mint::PostgresMintStore,
    },
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;

pub mod bill;
pub mod bill_chain;
pub mod company_chain;
pub mod contact;
pub mod email_notification;
pub mod identity_chain;
pub mod mint;

#[derive(Clone)]
pub struct PostgresPersistence {
    pool: PgPool,
}

#[derive(Debug, Clone)]
pub struct PostgresConfig {
    pub database_url: String,
    pub max_connections: u32,
    pub acquire_timeout_secs: u64,
}

impl PostgresConfig {
    pub fn new(database_url: String) -> Self {
        Self {
            database_url,
            max_connections: 5,
            acquire_timeout_secs: 10,
        }
    }
}

impl PostgresPersistence {
    pub async fn connect(config: PostgresConfig) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .min_connections(1)
            .max_connections(config.max_connections)
            .acquire_timeout(Duration::from_secs(config.acquire_timeout_secs))
            .connect(&config.database_url)
            .await
            .map_err(|e| Error::Init(format!("Could not initialize postgres pool: {e}")))?;

        run_migrations(&pool).await?;

        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }

    pub fn contact_store(&self) -> PostgresContactStore {
        PostgresContactStore::new(self.pool.clone())
    }

    pub fn email_notification_store(&self) -> PostgresEmailNotificationStore {
        PostgresEmailNotificationStore::new(self.pool.clone())
    }

    pub fn mint_store(&self) -> PostgresMintStore {
        PostgresMintStore::new(self.pool.clone())
    }

    pub fn bill_chain_store(&self) -> PostgresBillChainStore {
        PostgresBillChainStore::new(self.pool.clone())
    }

    pub fn bill_store(&self) -> PostgresBillStore {
        PostgresBillStore::new(self.pool.clone())
    }

    pub fn company_chain_store(&self) -> PostgresCompanyChainStore {
        PostgresCompanyChainStore::new(self.pool.clone())
    }

    pub fn identity_chain_store(&self) -> PostgresIdentityChainStore {
        PostgresIdentityChainStore::new(self.pool.clone())
    }
}

pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("./migrations/postgres").run(pool).await?;
    Ok(())
}
