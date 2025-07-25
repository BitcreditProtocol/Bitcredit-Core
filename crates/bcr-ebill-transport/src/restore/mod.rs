use crate::Result;
use async_trait::async_trait;
use bcr_ebill_core::{ServiceTraitBounds, util::BcrKeys};

#[allow(dead_code)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait RestoreAccountApi: ServiceTraitBounds {
    /// Given a set of keys and relays, restores the account and all the associated data
    fn restore_account(&self, keys: BcrKeys, relays: Vec<String>) -> Result<()>;
}
