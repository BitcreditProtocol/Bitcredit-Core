use bcr_ebill_core::{NodeId, ServiceTraitBounds, contact::Contact};
use std::collections::HashMap;

use super::Result;
use async_trait::async_trait;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ContactStoreApi: ServiceTraitBounds {
    async fn search(&self, search_term: &str) -> Result<Vec<Contact>>;
    async fn get_map(&self) -> Result<HashMap<NodeId, Contact>>;
    async fn get(&self, node_id: &NodeId) -> Result<Option<Contact>>;
    async fn insert(&self, node_id: &NodeId, data: Contact) -> Result<()>;
    async fn delete(&self, node_id: &NodeId) -> Result<()>;
    async fn update(&self, node_id: &NodeId, data: Contact) -> Result<()>;
}
