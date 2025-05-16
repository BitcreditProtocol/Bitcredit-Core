use std::path::Path;

use super::Result;
use async_trait::async_trait;
use bcr_ebill_core::ServiceTraitBounds;

/// Backup and restore the database from/to bytes.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait BackupStoreApi: ServiceTraitBounds {
    /// creates a backup of the currently active database as a byte vector
    /// ready for encryption
    async fn backup(&self) -> Result<Vec<u8>>;

    /// Restores the default database from given surqul file
    async fn restore(&self, file_path: &Path) -> Result<()>;

    /// drops the database with the given name
    async fn drop_db(&self, name: &str) -> Result<()>;
}
