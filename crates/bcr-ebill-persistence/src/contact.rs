use bcr_common::core::NodeId;
use bcr_ebill_core::{application::ServiceTraitBounds, application::contact::Contact};
use std::collections::HashMap;

use super::Result;
use async_trait::async_trait;

#[async_trait]
pub trait ContactStoreApi: ServiceTraitBounds {
    async fn search(&self, search_term: &str) -> Result<Vec<Contact>>;
    async fn get_map(&self) -> Result<HashMap<NodeId, Contact>>;
    async fn get(&self, node_id: &NodeId) -> Result<Option<Contact>>;
    async fn insert(&self, node_id: &NodeId, data: Contact) -> Result<()>;
    async fn delete(&self, node_id: &NodeId) -> Result<()>;
    async fn update(&self, node_id: &NodeId, data: Contact) -> Result<()>;
}
