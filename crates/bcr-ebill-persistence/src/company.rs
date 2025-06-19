use bcr_ebill_core::blockchain::company::{CompanyBlock, CompanyBlockchain};
use bcr_ebill_core::company::{Company, CompanyKeys};
use bcr_ebill_core::{NodeId, ServiceTraitBounds};
use std::collections::HashMap;

use super::Result;
use async_trait::async_trait;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait CompanyStoreApi: ServiceTraitBounds {
    /// Searches the company for the search term
    async fn search(&self, search_term: &str) -> Result<Vec<Company>>;

    /// Checks if the given company exists
    async fn exists(&self, id: &NodeId) -> bool;

    /// Fetches the given company
    async fn get(&self, id: &NodeId) -> Result<Company>;

    /// Returns all companies
    async fn get_all(&self) -> Result<HashMap<NodeId, (Company, CompanyKeys)>>;

    /// Inserts the company with the given id
    async fn insert(&self, data: &Company) -> Result<()>;

    /// Updates the company with the given id
    async fn update(&self, id: &NodeId, data: &Company) -> Result<()>;

    /// Removes the company with the given id (e.g. if we're removed as signatory)
    async fn remove(&self, id: &NodeId) -> Result<()>;

    /// Saves the key pair for the given company id
    async fn save_key_pair(&self, id: &NodeId, key_pair: &CompanyKeys) -> Result<()>;

    /// Gets the key pair for the given company id
    async fn get_key_pair(&self, id: &NodeId) -> Result<CompanyKeys>;
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait CompanyChainStoreApi: ServiceTraitBounds {
    /// Gets the latest block of the chain
    async fn get_latest_block(&self, id: &NodeId) -> Result<CompanyBlock>;
    /// Adds the block to the chain
    async fn add_block(&self, id: &NodeId, block: &CompanyBlock) -> Result<()>;
    /// Removes the whole blockchain
    async fn remove(&self, id: &NodeId) -> Result<()>;
    /// Get the whole blockchain
    async fn get_chain(&self, id: &NodeId) -> Result<CompanyBlockchain>;
}
