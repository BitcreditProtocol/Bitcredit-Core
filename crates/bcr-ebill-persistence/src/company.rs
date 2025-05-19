use bcr_ebill_core::ServiceTraitBounds;
use bcr_ebill_core::blockchain::company::{CompanyBlock, CompanyBlockchain};
use bcr_ebill_core::company::{Company, CompanyKeys};
use std::collections::HashMap;

use super::Result;
use async_trait::async_trait;

use borsh::{from_slice, to_vec};

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait CompanyStoreApi: ServiceTraitBounds {
    /// Searches the company for the search term
    async fn search(&self, search_term: &str) -> Result<Vec<Company>>;

    /// Checks if the given company exists
    async fn exists(&self, id: &str) -> bool;

    /// Fetches the given company
    async fn get(&self, id: &str) -> Result<Company>;

    /// Returns all companies
    async fn get_all(&self) -> Result<HashMap<String, (Company, CompanyKeys)>>;

    /// Inserts the company with the given id
    async fn insert(&self, data: &Company) -> Result<()>;

    /// Updates the company with the given id
    async fn update(&self, id: &str, data: &Company) -> Result<()>;

    /// Removes the company with the given id (e.g. if we're removed as signatory)
    async fn remove(&self, id: &str) -> Result<()>;

    /// Saves the key pair for the given company id
    async fn save_key_pair(&self, id: &str, key_pair: &CompanyKeys) -> Result<()>;

    /// Gets the key pair for the given company id
    async fn get_key_pair(&self, id: &str) -> Result<CompanyKeys>;
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait CompanyChainStoreApi: ServiceTraitBounds {
    /// Gets the latest block of the chain
    async fn get_latest_block(&self, id: &str) -> Result<CompanyBlock>;
    /// Adds the block to the chain
    async fn add_block(&self, id: &str, block: &CompanyBlock) -> Result<()>;
    /// Removes the whole blockchain
    async fn remove(&self, id: &str) -> Result<()>;
    /// Get the whole blockchain
    async fn get_chain(&self, id: &str) -> Result<CompanyBlockchain>;
}

pub fn company_from_bytes(bytes: &[u8]) -> Result<Company> {
    let company: Company = from_slice(bytes)?;
    Ok(company)
}

pub fn company_to_bytes(company: &Company) -> Result<Vec<u8>> {
    let bytes = to_vec(&company)?;
    Ok(bytes)
}

pub fn company_keys_from_bytes(bytes: &[u8]) -> Result<CompanyKeys> {
    let company_keys: CompanyKeys = from_slice(bytes)?;
    Ok(company_keys)
}

pub fn company_keys_to_bytes(company_keys: &CompanyKeys) -> Result<Vec<u8>> {
    let bytes = to_vec(&company_keys)?;
    Ok(bytes)
}

pub fn company_chain_from_bytes(bytes: &[u8]) -> Result<CompanyBlockchain> {
    let company_chain: CompanyBlockchain = from_slice(bytes)?;
    Ok(company_chain)
}

pub fn company_chain_to_bytes(company_chain: &CompanyBlockchain) -> Result<Vec<u8>> {
    let bytes = to_vec(&company_chain)?;
    Ok(bytes)
}
