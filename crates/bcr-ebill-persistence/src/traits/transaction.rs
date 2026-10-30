use crate::Result;
use crate::traits::nostr::NostrChainEvent;
use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::protocol::blockchain::BlockchainType;
use bcr_ebill_core::{
    application::{
        ServiceTraitBounds, bill::BitcreditBillResult, company::Company, identity::Identity,
    },
    protocol::{
        BlockId, EmailIdentityProofData, SignedIdentityProof,
        blockchain::{bill::BillBlock, company::CompanyBlock, identity::IdentityBlock},
        crypto::BcrKeys,
    },
};

/// Atomic persistence transactions spanning multiple stores
///
/// Chain lock ordering
/// Transactions that mutate multiple chains must acquire chain locks
/// in the following global order:
///
/// 1. Identity chain
/// 2. Company chains, ordered by `NodeId`
/// 3. Bill chains, ordered by `BillId`
///
/// Callers and transaction implementations must preserve this ordering
/// This avoids deadlocks on backends such as PostgreSQL when multiple
/// transactions touch the same chains in different combinations
#[async_trait]
pub trait TransactionManagerApi: ServiceTraitBounds {
    async fn begin(&self) -> Result<Box<dyn PersistenceTransactionApi>>;
}

/// A persistence transaction spanning multiple logical stores
/// When multiple chain locks are acquired, callers must follow the
/// lock ordering mentioned above
#[async_trait]
pub trait PersistenceTransactionApi:
    IdentityTransactionApi
    + CompanyTransactionApi
    + BillTransactionApi
    + NostrChainEventTransactionApi
    + Send
{
    async fn commit(self: Box<Self>) -> Result<()>;
}

#[async_trait]
pub trait IdentityTransactionApi: Send {
    /// append one or more blocks atomically after expected_latest
    /// if the tip is not expected_latest, this operation fails
    /// `blocks` may be empty when the caller only needs to lock and recheck the tip
    async fn append_identity_blocks(
        &mut self,
        expected_latest: Option<&IdentityBlock>,
        blocks: &[IdentityBlock],
    ) -> Result<()>;
    /// truncate blocks from from_block_id, replace with replacement_blocks
    async fn replace_identity_blocks_from_height(
        &mut self,
        expected_latest: &IdentityBlock,
        from_block_id: BlockId,
        replacement_blocks: &[IdentityBlock],
    ) -> Result<()>;
    async fn save_identity(&mut self, identity: &Identity) -> Result<()>;
    async fn set_identity_email_confirmation(
        &mut self,
        proof: &SignedIdentityProof,
        data: &EmailIdentityProofData,
    ) -> Result<()>;
}

#[async_trait]
pub trait CompanyTransactionApi: Send {
    /// append one or more blocks atomically after expected_latest
    /// if the tip is not expected_latest, this operation fails
    /// `blocks` may be empty when the caller only needs to lock and recheck the tip
    async fn append_company_blocks(
        &mut self,
        company_id: &NodeId,
        expected_latest: Option<&CompanyBlock>,
        blocks: &[CompanyBlock],
    ) -> Result<()>;
    /// truncate blocks from from_block_id, replace with replacement_blocks
    async fn replace_company_blocks_from_height(
        &mut self,
        company_id: &NodeId,
        expected_latest: &CompanyBlock,
        from_block_id: BlockId,
        replacement_blocks: &[CompanyBlock],
    ) -> Result<()>;
    async fn insert_company(&mut self, company: &Company) -> Result<()>;
    async fn update_company(&mut self, company_id: &NodeId, company: &Company) -> Result<()>;
    async fn set_company_email_confirmation(
        &mut self,
        company_id: &NodeId,
        proof: &SignedIdentityProof,
        data: &EmailIdentityProofData,
    ) -> Result<()>;
    async fn save_company_key_pair(&mut self, company_id: &NodeId, keys: &BcrKeys) -> Result<()>;
}

#[async_trait]
pub trait BillTransactionApi: Send {
    /// append one or more blocks atomically after expected_latest
    /// if the tip is not expected_latest, this operation fails
    /// `blocks` may be empty when the caller only needs to lock and recheck the tip
    async fn append_bill_blocks(
        &mut self,
        bill_id: &BillId,
        expected_latest: Option<&BillBlock>,
        blocks: &[BillBlock],
    ) -> Result<()>;
    /// truncate blocks from from_block_id, replace with replacement_blocks
    async fn replace_bill_blocks_from_height(
        &mut self,
        bill_id: &BillId,
        expected_latest: &BillBlock,
        from_block_id: BlockId,
        replacement_blocks: &[BillBlock],
    ) -> Result<()>;
    async fn save_bill_keys(&mut self, bill_id: &BillId, keys: &BcrKeys) -> Result<()>;
    async fn save_bill_to_cache(
        &mut self,
        bill_id: &BillId,
        identity_node_id: &NodeId,
        bill: &BitcreditBillResult,
    ) -> Result<()>;
}

#[async_trait]
pub trait NostrChainEventTransactionApi: Send {
    async fn add_chain_event(&mut self, event: &NostrChainEvent) -> Result<()>;
    async fn remove_chain_events(
        &mut self,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> Result<()>;
}
