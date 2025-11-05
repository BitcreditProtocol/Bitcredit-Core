use super::Result;
use async_trait::async_trait;
use bcr_ebill_core::application::ServiceTraitBounds;

#[allow(dead_code)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait RestoreAccountApi: ServiceTraitBounds {
    /// restores the account and all the associated data
    async fn restore_account(&self) -> Result<()>;
}
