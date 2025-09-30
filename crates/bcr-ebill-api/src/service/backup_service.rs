#![cfg(not(target_arch = "wasm32"))]
use std::{path::Path, sync::Arc};

use crate::{
    persistence::{backup::BackupStoreApi, db::SurrealDbConfig, identity::IdentityStoreApi},
    util,
};

use super::{Error, Result};
use bcr_ebill_core::ValidationError;
#[cfg(test)]
use mockall::automock;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch,
};

/// Allows to backup and restore the database as an encrypted file.
#[cfg_attr(test, automock)]
#[async_trait::async_trait]
pub trait BackupServiceApi: Send + Sync {
    /// Creates an encrypted backup of the database and returns the
    /// data as a byte vector.
    async fn backup(&self) -> Result<Vec<u8>>;

    /// Restores the database from the given encrypted file path.
    async fn restore(&self, file: &Path) -> Result<()>;
}

pub struct BackupService {
    store: Arc<dyn BackupStoreApi>,
    identity_store: Arc<dyn IdentityStoreApi>,
    surreal_db_config: SurrealDbConfig,
    reboot_sender: watch::Sender<bool>,
}

impl BackupService {
    pub fn new(
        store: Arc<dyn BackupStoreApi>,
        identity_store: Arc<dyn IdentityStoreApi>,
        surreal_db_config: SurrealDbConfig,
        reboot_sender: watch::Sender<bool>,
    ) -> Self {
        Self {
            store,
            identity_store,
            surreal_db_config,
            reboot_sender,
        }
    }

    fn validate_surreal_db_connection(&self) -> Result<()> {
        let connection = &self.surreal_db_config.connection_string;
        if connection.starts_with("rocksdb")
            || connection.starts_with("mem")
            || connection.starts_with("http")
        {
            return Ok(());
        }
        Err(Error::Validation(ValidationError::BackupNotSupported))
    }
}

#[async_trait::async_trait]
impl BackupServiceApi for BackupService {
    async fn backup(&self) -> Result<Vec<u8>> {
        self.validate_surreal_db_connection()?;
        let public_key = self.identity_store.get_key_pair().await?.pub_key();
        let bytes = self.store.backup().await?;
        let encrypted_bytes = util::crypto::encrypt_ecies(&bytes, &public_key)?;
        Ok(encrypted_bytes)
    }

    async fn restore(&self, file_path: &Path) -> Result<()> {
        let private_key = self.identity_store.get_key_pair().await?.get_private_key();
        let mut buffer = vec![];
        let mut file = File::open(file_path).await?;
        file.read_to_end(&mut buffer).await?;
        let decrypted_bytes = util::crypto::decrypt_ecies(&buffer, &private_key)?;
        let out_path = file_path.with_file_name("restore.surql");
        let mut out = File::create(out_path.as_path()).await?;
        out.write_all(&decrypted_bytes).await?;
        self.store.drop_db(&self.surreal_db_config.database).await?;
        self.store.restore(out_path.as_path()).await?;
        self.reboot_sender
            .send(true)
            .expect("Can initiate a reboot");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::tests::{MockBackupStoreApiMock, MockIdentityStoreApiMock};

    use super::*;

    #[tokio::test]
    async fn test_backup_with_external_socket_db_should_fail() {
        let mut store = MockBackupStoreApiMock::new();
        let mut identity_store = MockIdentityStoreApiMock::new();
        let surreal_db_config = SurrealDbConfig {
            connection_string: "ws://localhost:8000".to_string(),
            database: "test".to_string(),
            namespace: "test".to_string(),
        };

        identity_store.expect_get_key_pair().never();
        store.expect_backup().never();
        let (tx, _) = watch::channel(false);
        let service = BackupService::new(
            Arc::new(store),
            Arc::new(identity_store),
            surreal_db_config,
            tx,
        );

        let result = service.backup().await;
        assert!(result.is_err());
    }
}
