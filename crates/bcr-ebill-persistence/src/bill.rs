use std::collections::HashSet;

use super::Result;
use async_trait::async_trait;
use bcr_ebill_core::{
    NodeId, ServiceTraitBounds,
    bill::{BillId, BillKeys, BitcreditBillResult, PaymentState},
    blockchain::bill::{BillBlock, BillBlockchain, BillOpCode},
};

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait BillStoreApi: ServiceTraitBounds {
    /// Gets the bills from cache
    async fn get_bills_from_cache(
        &self,
        ids: &[BillId],
        identity_node_id: &NodeId,
    ) -> Result<Vec<BitcreditBillResult>>;
    /// Gets the bill from cache
    async fn get_bill_from_cache(
        &self,
        id: &BillId,
        identity_node_id: &NodeId,
    ) -> Result<Option<BitcreditBillResult>>;
    /// Saves the bill to cache
    async fn save_bill_to_cache(
        &self,
        id: &BillId,
        identity_node_id: &NodeId,
        bill: &BitcreditBillResult,
    ) -> Result<()>;
    /// Invalidates the cached bill
    async fn invalidate_bill_in_cache(&self, id: &BillId) -> Result<()>;
    /// clear the bill cache
    async fn clear_bill_cache(&self) -> Result<()>;
    /// Checks if the given bill exists
    async fn exists(&self, id: &BillId) -> Result<bool>;
    /// Gets all bill ids
    async fn get_ids(&self) -> Result<Vec<BillId>>;
    /// Saves the keys
    async fn save_keys(&self, id: &BillId, keys: &BillKeys) -> Result<()>;
    /// Get bill keys
    async fn get_keys(&self, id: &BillId) -> Result<BillKeys>;
    /// Check if the given bill was paid
    async fn is_paid(&self, id: &BillId) -> Result<bool>;
    /// Set payment state for given bill
    async fn set_payment_state(&self, id: &BillId, payment_state: &PaymentState) -> Result<()>;
    /// Get payment state for given bill
    async fn get_payment_state(&self, id: &BillId) -> Result<Option<PaymentState>>;
    /// Set offer to sell payment state for given bill
    async fn set_offer_to_sell_payment_state(
        &self,
        id: &BillId,
        block_id: u64,
        payment_state: &PaymentState,
    ) -> Result<()>;
    /// Get offer to sell payment state for given bill
    async fn get_offer_to_sell_payment_state(
        &self,
        id: &BillId,
        block_id: u64,
    ) -> Result<Option<PaymentState>>;
    /// Set recourse payment state for given bill
    async fn set_recourse_payment_state(
        &self,
        id: &BillId,
        block_id: u64,
        payment_state: &PaymentState,
    ) -> Result<()>;
    /// Get recourse payment state for given bill
    async fn get_recourse_payment_state(
        &self,
        id: &BillId,
        block_id: u64,
    ) -> Result<Option<PaymentState>>;
    /// Gets all bills with a RequestToPay block, which are not paid already
    async fn get_bill_ids_waiting_for_payment(&self) -> Result<Vec<BillId>>;
    /// Gets all bills where the latest block is OfferToSell, which might still be waiting for payment
    async fn get_bill_ids_waiting_for_sell_payment(&self) -> Result<Vec<BillId>>;
    /// Gets all bills where the latest block is RequestRecourse, which might still be waiting for payment
    async fn get_bill_ids_waiting_for_recourse_payment(&self) -> Result<Vec<BillId>>;
    /// Returns all bill ids that are currently within the given op codes and block not
    /// older than the given timestamp.
    async fn get_bill_ids_with_op_codes_since(
        &self,
        op_code: HashSet<BillOpCode>,
        since: u64,
    ) -> Result<Vec<BillId>>;
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait BillChainStoreApi: ServiceTraitBounds {
    /// Gets the latest block of the chain
    async fn get_latest_block(&self, id: &BillId) -> Result<BillBlock>;
    /// Adds the block to the chain
    async fn add_block(&self, id: &BillId, block: &BillBlock) -> Result<()>;
    /// Get the whole blockchain
    async fn get_chain(&self, id: &BillId) -> Result<BillBlockchain>;
}
