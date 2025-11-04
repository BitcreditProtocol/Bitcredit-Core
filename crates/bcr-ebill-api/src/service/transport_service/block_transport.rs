use super::Result;
use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::protocol::{BillChainEvent, CompanyChainEvent, IdentityChainEvent};

#[cfg(test)]
use bcr_ebill_core::ServiceTraitBounds;
#[cfg(test)]
use mockall::automock;

/// Methods required for all block propagations and chain re-syncs
#[allow(dead_code)]
#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait BlockPropagationServiceApi {
    /// Sent when an identity chain is created or updated
    async fn send_identity_chain_events(&self, events: IdentityChainEvent) -> Result<()>;
    /// Sent when a company chain is created or updated
    async fn send_company_chain_events(&self, events: CompanyChainEvent) -> Result<()>;
    /// Sent when: A bill chain is created or updated
    async fn send_bill_chain_events(&self, events: BillChainEvent) -> Result<()>;
    /// Resync bill chain
    async fn resync_bill_chain(&self, bill_id: &BillId) -> Result<()>;
    /// Resync company chain
    async fn resync_company_chain(&self, company_id: &NodeId) -> Result<()>;
    /// Resync identity chain
    async fn resync_identity_chain(&self) -> Result<()>;
}

#[cfg(test)]
impl ServiceTraitBounds for MockBlockPropagationServiceApi {}
