use std::fmt;
use std::str::FromStr;

use async_trait::async_trait;
use bcr_ebill_core::{NodeId, ServiceTraitBounds};
use secp256k1::{SecretKey, schnorr::Signature};
use thiserror::Error;
use url::Url;

#[cfg(test)]
use mockall::automock;

/// Generic result type
pub type Result<T> = std::result::Result<T, super::Error>;

/// Generic error type
#[derive(Debug, Error)]
pub enum Error {
    /// all errors originating from secp256k1
    #[error("External Identity Proof Secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
    /// all errors originating from interacting with the web
    #[error("External Identity Proof Web error: {0}")]
    Api(#[from] reqwest::Error),
}

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait IdentityProofApi: ServiceTraitBounds {
    /// Sign the base58 sha256 hash of the given node_id using the given keys and returns the resulting signature
    /// This is the string users are supposed to post on their social media
    fn create_identity_proof(
        &self,
        node_id: &NodeId,
        private_key: &SecretKey,
    ) -> Result<IdentityProof>;
    /// Verifies that the given node_id corresponds to the given identity proof
    fn verify_identity_proof(
        &self,
        node_id: &NodeId,
        identity_proof: &IdentityProof,
    ) -> Result<bool>;
    /// Checks if the given string to_find is somewhere in the (successful) response of calling the given URL
    async fn check_url(
        &self,
        identity_proof: &IdentityProof,
        url: &Url,
    ) -> Result<CheckIdentityProofResult>;
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

// #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
// #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
// impl IdentityProofApi for IdentityProofClient {}

#[derive(Debug, Clone)]
pub struct IdentityProof {
    inner: Signature,
}

impl fmt::Display for IdentityProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl FromStr for IdentityProof {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self {
            inner: Signature::from_str(s)?,
        })
    }
}

#[derive(Debug, Clone)]
pub enum CheckIdentityProofResult {
    /// The request succeeded and we found the signature we were looking for in the response
    Success,
    /// The request succeeded, but we didn't found the signature we were looking for in the response
    NotFound,
    /// The request failed with a client error (4xx)
    FailureClient,
    /// The request failed with a server error (5xx)
    FailureServer,
}
