use super::Result;
use crate::service::transport_service::ResyncMode;
use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::{
    application::{ServiceTraitBounds, nostr::ResendQueueEntry},
    protocol::{
        blockchain::bill::BillBlock,
        event::{BillChainEvent, CompanyChainEvent, IdentityChainEvent},
    },
};

#[cfg(test)]
use mockall::automock;

/// Methods required for all block propagations and chain re-syncs
#[allow(dead_code)]
#[cfg_attr(test, automock)]
#[async_trait]
pub trait BlockTransportServiceApi: ServiceTraitBounds {
    /// Sent when an identity chain is created or updated
    async fn send_identity_chain_events(&self, events: IdentityChainEvent) -> Result<()>;
    /// Sent when a company chain is created or updated
    async fn send_company_chain_events(&self, events: CompanyChainEvent) -> Result<()>;
    /// Sent when: A bill chain is created or updated
    async fn send_bill_chain_events(&self, events: BillChainEvent) -> Result<()>;
    /// Resync bill chain. If `from_nostr` is true, fetches missing blocks from Nostr first.
    /// If false, only invalidates the local cache.
    async fn resync_bill_chain(
        &self,
        bill_id: &BillId,
        from_nostr: bool,
        mode: ResyncMode,
    ) -> Result<()>;
    /// Resync company chain
    async fn resync_company_chain(&self, company_id: &NodeId, mode: ResyncMode) -> Result<()>;
    /// Resync identity chain
    async fn resync_identity_chain(&self, mode: ResyncMode) -> Result<()>;
    /// Validates that the given list of blocks exist in the resolved chain from Nostr
    async fn validate_bill_blocks_exist_on_nostr_chain(
        &self,
        bill_id: &BillId,
        blocks: &[BillBlock],
    ) -> Result<bool>;
    /// Fetch failed and pending resend queue entries
    async fn fetch_resend_queue_entries(&self) -> Result<Vec<ResendQueueEntry>>;
    /// Requeue a failed resend queue entry by ID
    async fn requeue_resend_queue_entry(&self, id: &str) -> Result<()>;
}

#[cfg(test)]
impl ServiceTraitBounds for MockBlockTransportServiceApi {}
