use super::Result;
use async_trait::async_trait;

use bcr_ebill_core::{
    ServiceTraitBounds,
    blockchain::identity::IdentityBlock,
    identity::{ActiveIdentityState, Identity, IdentityWithAll},
    util::crypto::BcrKeys,
};

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait IdentityStoreApi: ServiceTraitBounds {
    /// Checks if the identity has been created
    async fn exists(&self) -> bool;
    /// Saves the given identity
    async fn save(&self, identity: &Identity) -> Result<()>;
    /// Gets the local identity
    async fn get(&self) -> Result<Identity>;
    /// Gets the local identity with it's node id and key pair
    async fn get_full(&self) -> Result<IdentityWithAll>;
    /// Saves the given key pair
    async fn save_key_pair(&self, key_pair: &BcrKeys, seed: &str) -> Result<()>;
    /// Gets the local key pair
    async fn get_key_pair(&self) -> Result<BcrKeys>;
    /// Gets the local key pair or creates a new one if it doesn't exist.
    /// The new key pair is saved to the store together with the node id.
    async fn get_or_create_key_pair(&self) -> Result<BcrKeys>;
    /// Returns the seed phrase that generated the private keys.
    async fn get_seedphrase(&self) -> Result<String>;
    /// Returns actively set identity
    async fn get_current_identity(&self) -> Result<ActiveIdentityState>;
    /// Sets the given current active identity state
    async fn set_current_identity(&self, identity_state: &ActiveIdentityState) -> Result<()>;
    /// Sets the network for this identity, or, if it's set, checks if the set network is the same as the configured one
    async fn set_or_check_network(&self, configured_network: bitcoin::Network) -> Result<()>;
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait IdentityChainStoreApi: ServiceTraitBounds {
    /// Gets the latest block of the chain
    async fn get_latest_block(&self) -> Result<IdentityBlock>;
    /// Adds the block to the chain
    async fn add_block(&self, block: &IdentityBlock) -> Result<()>;
}
