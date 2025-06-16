use std::collections::HashSet;

use super::Result;
use async_trait::async_trait;
use bcr_ebill_core::{
    ServiceTraitBounds,
    bill::{BillKeys, BitcreditBillResult},
    blockchain::bill::{BillBlock, BillBlockchain, BillOpCode},
};

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait BillStoreApi: ServiceTraitBounds {
    /// Gets the bills from cache
    async fn get_bills_from_cache(
        &self,
        ids: &[String],
        identity_node_id: &str,
    ) -> Result<Vec<BitcreditBillResult>>;
    /// Gets the bill from cache
    async fn get_bill_from_cache(
        &self,
        id: &str,
        identity_node_id: &str,
    ) -> Result<Option<BitcreditBillResult>>;
    /// Saves the bill to cache
    async fn save_bill_to_cache(
        &self,
        id: &str,
        identity_node_id: &str,
        bill: &BitcreditBillResult,
    ) -> Result<()>;
    /// Invalidates the cached bill
    async fn invalidate_bill_in_cache(&self, id: &str) -> Result<()>;
    /// clear the bill cache
    async fn clear_bill_cache(&self) -> Result<()>;
    /// Checks if the given bill exists
    async fn exists(&self, id: &str) -> Result<bool>;
    /// Gets all bill ids
    async fn get_ids(&self) -> Result<Vec<String>>;
    /// Saves the keys
    async fn save_keys(&self, id: &str, keys: &BillKeys) -> Result<()>;
    /// Get bill keys
    async fn get_keys(&self, id: &str) -> Result<BillKeys>;
    /// Check if the given bill was paid
    async fn is_paid(&self, id: &str) -> Result<bool>;
    /// Set the given bill to paid on the given payment address
    async fn set_to_paid(&self, id: &str, payment_address: &str) -> Result<()>;
    /// Gets all bills with a RequestToPay block, which are not paid already
    async fn get_bill_ids_waiting_for_payment(&self) -> Result<Vec<String>>;
    /// Gets all bills where the latest block is OfferToSell, which are still waiting for payment
    async fn get_bill_ids_waiting_for_sell_payment(&self) -> Result<Vec<String>>;
    /// Gets all bills where the latest block is RequestRecourse, which are still waiting for payment
    async fn get_bill_ids_waiting_for_recourse_payment(&self) -> Result<Vec<String>>;
    /// Returns all bill ids that are currently within the given op codes and block not
    /// older than the given timestamp.
    async fn get_bill_ids_with_op_codes_since(
        &self,
        op_code: HashSet<BillOpCode>,
        since: u64,
    ) -> Result<Vec<String>>;
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait BillChainStoreApi: ServiceTraitBounds {
    /// Gets the latest block of the chain
    async fn get_latest_block(&self, id: &str) -> Result<BillBlock>;
    /// Adds the block to the chain
    async fn add_block(&self, id: &str, block: &BillBlock) -> Result<()>;
    /// Get the whole blockchain
    async fn get_chain(&self, id: &str) -> Result<BillBlockchain>;
}
