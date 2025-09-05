use async_trait::async_trait;
use bcr_ebill_core::{NodeId, ServiceTraitBounds, util::BcrKeys};
use thiserror::Error;
use url::Url;

#[cfg(test)]
use mockall::automock;

/// Generic result type
pub type Result<T> = std::result::Result<T, super::Error>;

/// Generic error type
#[derive(Debug, Error)]
pub enum Error {
    /// all errors originating from interacting with the web
    #[error("External Identity Proof Web error: {0}")]
    Api(#[from] reqwest::Error),
}

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait IdentityProofApi: ServiceTraitBounds {
    /// Sign the given node_id using the given keys and return the resulting signature
    /// This is the string users are supposed to post on their social media
    fn get_string_to_post(&self, node_id: &NodeId, keys: &BcrKeys) -> Result<String>;
    /// Checks if the given string to_find is somewhere in the (successful) response of calling the given URL
    async fn check_url(&self, to_find: &str, url: &Url) -> Result<IdentityProofResult>;
}

#[derive(Debug, Clone, Default)]
pub struct IdentityProofClient {
    cl: reqwest::Client,
}

impl IdentityProofClient {
    pub fn new() -> Self {
        Self {
            cl: reqwest::Client::new(),
        }
    }
}

impl ServiceTraitBounds for IdentityProofClient {}

#[cfg(test)]
impl ServiceTraitBounds for MockIdentityProofApi {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl IdentityProofApi for IdentityProofClient {
    fn get_string_to_post(&self, node_id: &NodeId, keys: &BcrKeys) -> Result<String> {
        Ok("".to_string())
    }

    async fn check_url(&self, to_find: &str, url: &Url) -> Result<IdentityProofResult> {
        Ok(IdentityProofResult::Success)
    }
}

#[derive(Debug, Clone)]
pub enum IdentityProofResult {
    /// The request succeeded and we found the signature we were looking for in the response
    Success,
    /// The request succeeded, but we didn't found the signature we were looking for in the response
    NotFound,
    /// The request failed with a client error (4xx)
    FailureClient,
    /// The request failed with a server error (5xx)
    FailureServer,
}
