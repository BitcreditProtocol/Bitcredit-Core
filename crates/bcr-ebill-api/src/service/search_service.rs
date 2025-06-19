use super::Result;
use super::{
    bill_service::BillServiceApi, company_service::CompanyServiceApi,
    contact_service::ContactServiceApi,
};
use crate::data::GeneralSearchResult;
use crate::data::{GeneralSearchFilterItemType, bill::BillsFilterRole};
use async_trait::async_trait;
use log::debug;
use std::sync::Arc;

use bcr_ebill_core::{NodeId, ServiceTraitBounds};

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait SearchServiceApi: ServiceTraitBounds {
    /// General Search
    async fn search(
        &self,
        search_term: &str,
        currency: &str,
        item_types: &[GeneralSearchFilterItemType],
        current_identity_node_id: &NodeId,
    ) -> Result<GeneralSearchResult>;
}

/// The serach service is responsible for implementing cross-domain search
#[derive(Clone)]
pub struct SearchService {
    bill_service: Arc<dyn BillServiceApi>,
    contact_service: Arc<dyn ContactServiceApi>,
    company_service: Arc<dyn CompanyServiceApi>,
}

impl SearchService {
    pub fn new(
        bill_service: Arc<dyn BillServiceApi>,
        contact_service: Arc<dyn ContactServiceApi>,
        company_service: Arc<dyn CompanyServiceApi>,
    ) -> Self {
        Self {
            bill_service,
            contact_service,
            company_service,
        }
    }
}

impl ServiceTraitBounds for SearchService {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl SearchServiceApi for SearchService {
    async fn search(
        &self,
        search_term: &str,
        currency: &str,
        item_types: &[GeneralSearchFilterItemType],
        current_identity_node_id: &NodeId,
    ) -> Result<GeneralSearchResult> {
        debug!("search for {search_term}, with {currency} and {item_types:?}");
        let search_term_lc = search_term.to_lowercase();
        let bills = if item_types.contains(&GeneralSearchFilterItemType::Bill) {
            self.bill_service
                .search_bills(
                    currency,
                    &Some(search_term_lc.clone()),
                    None,
                    None,
                    &BillsFilterRole::All,
                    current_identity_node_id,
                )
                .await?
        } else {
            vec![]
        };

        let contacts = if item_types.contains(&GeneralSearchFilterItemType::Contact) {
            self.contact_service.search(&search_term_lc).await?
        } else {
            vec![]
        };

        let companies = if item_types.contains(&GeneralSearchFilterItemType::Company) {
            self.company_service.search(&search_term_lc).await?
        } else {
            vec![]
        };

        Ok(GeneralSearchResult {
            bills,
            contacts,
            companies,
        })
    }
}
