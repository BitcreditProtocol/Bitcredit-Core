use super::Result;
use crate::service::transport_service::ResyncMode;
use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::{
        blockchain::bill::BillBlock,
        event::{BillChainEvent, CompanyChainEvent, IdentityChainEvent},
    },
};
use bcr_ebill_persistence::traits::{
    nostr::NostrChainEvent, propagation::PreparedPropagationMessage,
};

#[cfg(test)]
use mockall::automock;

/// Methods required for all block propagations and chain re-syncs
#[allow(dead_code)]
#[cfg_attr(test, automock)]
#[async_trait]
pub trait BlockTransportServiceApi: ServiceTraitBounds {
    /// batch-prepare identity chain events if we're propagating multiple at the same time
    /// e.g. when creating an identity and adding an identity proof
    async fn prepare_identity_chain_events(
        &self,
        events: &[IdentityChainEvent],
    ) -> Result<Vec<NostrChainEvent>>;
    /// batch-prepare company chain events if we're propagating multiple at the same time
    /// e.g. when creating a company and adding an identity proof
    async fn prepare_company_chain_events(
        &self,
        events: &[CompanyChainEvent],
    ) -> Result<Vec<NostrChainEvent>>;
    /// batch-prepare bill chain events if we're propagating multiple at the same time
    /// e.g. when issuing a bill and accepting it immediately
    async fn prepare_bill_chain_events(
        &self,
        events: &[BillChainEvent],
    ) -> Result<Vec<NostrChainEvent>>;
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
    /// validates and prepares nostr event - does not publish, or persist
    async fn prepare_identity_chain_event(
        &self,
        events: &IdentityChainEvent,
    ) -> Result<Option<NostrChainEvent>>;
    /// validates and prepares nostr event - does not publish, or persist
    async fn prepare_company_chain_event(
        &self,
        events: &CompanyChainEvent,
    ) -> Result<Option<NostrChainEvent>>;
    /// validates and prepares nostr event - does not publish, or persist
    async fn prepare_bill_chain_event(
        &self,
        events: &BillChainEvent,
    ) -> Result<Option<NostrChainEvent>>;
    /// creates signed NIP-17 bill chain invites - does not publish, or persist
    async fn prepare_bill_chain_invites(
        &self,
        events: &BillChainEvent,
    ) -> Result<Vec<PreparedPropagationMessage>>;
    /// creates signed NIP-17 company chain invites - does not publish, or persist
    async fn prepare_company_chain_invites(
        &self,
        events: &CompanyChainEvent,
    ) -> Result<Vec<PreparedPropagationMessage>>;
}

#[cfg(test)]
impl ServiceTraitBounds for MockBlockTransportServiceApi {}
