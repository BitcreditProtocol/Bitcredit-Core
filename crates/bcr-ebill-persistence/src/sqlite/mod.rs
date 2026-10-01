use crate::{
    Error, Result,
    sqlite::{
        contact::SqliteContactStore, email_notification::SqliteEmailNotificationStore,
        mint::SqliteMintStore,
    },
};
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::{path::PathBuf, time::Duration};

pub mod contact;
pub mod email_notification;
pub mod mint;

#[derive(Debug, Clone)]
pub struct SqliteConfig {
    pub path: PathBuf,
    pub max_connections: u32,
    pub busy_timeout_secs: u64,
}

impl SqliteConfig {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            max_connections: 5,
            busy_timeout_secs: 5,
        }
    }
}

#[derive(Clone)]
pub struct SqlitePersistence {
    pool: SqlitePool,
}

impl SqlitePersistence {
    pub async fn open(config: SqliteConfig) -> Result<Self> {
        if let Some(parent) = config.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let options = SqliteConnectOptions::new()
            .filename(&config.path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_secs(config.busy_timeout_secs));

        let pool = SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(config.max_connections)
            .connect_with(options)
            .await
            .map_err(|e| Error::Init(format!("Could not initialize sqlite pool: {e}")))?;

        run_migrations(&pool).await?;

        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }

    pub fn contact_store(&self) -> SqliteContactStore {
        SqliteContactStore::new(self.pool.clone())
    }

    pub fn email_notification_store(&self) -> SqliteEmailNotificationStore {
        SqliteEmailNotificationStore::new(self.pool.clone())
    }

    pub fn mint_store(&self) -> SqliteMintStore {
        SqliteMintStore::new(self.pool.clone())
    }
}

async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    sqlx::migrate!("./migrations/sqlite").run(pool).await?;
    Ok(())
}
