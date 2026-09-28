use super::Result;
use async_trait::async_trait;
use bcr_ebill_core::application::ServiceTraitBounds;

#[allow(dead_code)]
#[async_trait]
pub trait RestoreAccountApi: ServiceTraitBounds {
    /// restores the account and all the associated data
    async fn restore_account(&self) -> Result<()>;
}
