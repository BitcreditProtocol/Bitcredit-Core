use std::fmt;
use std::str::FromStr;

use async_trait::async_trait;
use bcr_ebill_core::{NodeId, ServiceTraitBounds};
use log::error;
use secp256k1::{SecretKey, schnorr::Signature};
use thiserror::Error;
use url::Url;

#[cfg(test)]
use mockall::automock;

use crate::util;

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
    /// all errors originating from interacting with cryptography
    #[error("External Identity Proof Crypto error: {0}")]
    Crypto(#[from] util::crypto::Error),
    /// all errors originating from interacting with base58
    #[error("External Identity Proof Base58 error: {0}")]
    Base58(#[from] util::Error),
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
    /// Checks if the given identity proof somewhere in the (successful) response of calling the given URL
    async fn check_url(
        &self,
        identity_proof: &IdentityProof,
        url: &Url,
    ) -> CheckIdentityProofResult;
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
    fn create_identity_proof(
        &self,
        node_id: &NodeId,
        private_key: &SecretKey,
    ) -> Result<IdentityProof> {
        let hash = util::sha256_hash(node_id.to_string().as_bytes());
        let signature = util::crypto::signature(&hash, private_key).map_err(Error::Crypto)?;
        Ok(IdentityProof::from_str(&signature)?)
    }

    fn verify_identity_proof(
        &self,
        node_id: &NodeId,
        identity_proof: &IdentityProof,
    ) -> Result<bool> {
        let hash = util::sha256_hash(node_id.to_string().as_bytes());
        let verified = util::crypto::verify(&hash, &identity_proof.to_string(), &node_id.pub_key())
            .map_err(Error::Crypto)?;
        Ok(verified)
    }

    async fn check_url(
        &self,
        identity_proof: &IdentityProof,
        url: &Url,
    ) -> CheckIdentityProofResult {
        // Make an unauthenticated request to the given URL and retrieve its body
        match self.cl.get(url.to_owned()).send().await {
            Ok(res) => {
                match res.error_for_status() {
                    Ok(resp) => {
                        match resp.text().await {
                            Ok(body) => {
                                // Check if the identity proof is contained in the response
                                if identity_proof.is_contained_in(&body) {
                                    CheckIdentityProofResult::Success
                                } else {
                                    CheckIdentityProofResult::NotFound
                                }
                            }
                            Err(body_err) => {
                                error!("Error checking url: {url} for identity proof: {body_err}");
                                CheckIdentityProofResult::FailureClient
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error checking url: {url} for identity proof: {e}");
                        if let Some(status) = e.status() {
                            if status.is_client_error() {
                                CheckIdentityProofResult::FailureClient
                            } else if status.is_server_error() {
                                CheckIdentityProofResult::FailureServer
                            } else {
                                CheckIdentityProofResult::FailureConnect
                            }
                        } else {
                            CheckIdentityProofResult::FailureConnect
                        }
                    }
                }
            }
            Err(req_err) => {
                error!("Error checking url: {url} for identity proof: {req_err}");
                CheckIdentityProofResult::FailureConnect
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct IdentityProof {
    inner: Signature,
}

impl IdentityProof {
    /// Checks if the identity proof signature string is within the given body of text
    pub fn is_contained_in(&self, body: &str) -> bool {
        let self_str = self.to_string();
        body.contains(&self_str)
    }
}

impl fmt::Display for IdentityProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", util::base58_encode(&self.inner.serialize()))
    }
}

impl From<Signature> for IdentityProof {
    fn from(value: Signature) -> Self {
        Self { inner: value }
    }
}

impl FromStr for IdentityProof {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self {
            inner: Signature::from_slice(&util::base58_decode(s)?)?,
        })
    }
}

#[derive(Debug, Clone)]
pub enum CheckIdentityProofResult {
    /// The request succeeded and we found the signature we were looking for in the response
    Success,
    /// The request succeeded, but we didn't find the signature we were looking for in the response
    NotFound,
    /// The request failed with a connection error
    FailureConnect,
    /// The request failed with a client error (4xx)
    FailureClient,
    /// The request failed with a server error (5xx)
    FailureServer,
}

#[cfg(test)]
pub mod tests {
    use crate::tests::tests::{node_id_test, private_key_test};

    use super::*;

    #[test]
    fn test_create_and_verify() {
        let node_id = node_id_test();
        let private_key = private_key_test();

        let identity_proof_client = IdentityProofClient::new();

        let identity_proof = identity_proof_client
            .create_identity_proof(&node_id, &private_key)
            .expect("can create identity proof");
        assert!(
            identity_proof_client
                .verify_identity_proof(&node_id, &identity_proof)
                .expect("can verify identity proof")
        );
    }

    #[tokio::test]
    #[ignore]
    // Ignored by default, since it makes an HTTP request - useful for testing how different social
    // networks interact with the check_url() call.
    async fn test_check_url() {
        let node_id = node_id_test();

        let identity_proof_client = IdentityProofClient::new();

        // is a valid identity proof
        let identity_proof = IdentityProof::from_str("2DmtcWtNk2hvXaBCUAng63Gn1VDBZEojMwoZWr2VqDL5LZNgszj26YT4Pj4MUSf5o4HSmdiAEENyuNQ5UEK7zG1p").expect("is valid");
        assert!(
            identity_proof_client
                .verify_identity_proof(&node_id, &identity_proof)
                .expect("can verify identity proof")
        );

        let valid_url = Url::parse("https://primal.net/e/nevent1qqs24kk3m0rc8e7a6f8k8daddqes0a2n74jszdszppu84e6y5q8ss3cy2rxs4").unwrap();
        let check_url_res = identity_proof_client
            .check_url(&identity_proof, &valid_url)
            .await;
        assert!(matches!(check_url_res, CheckIdentityProofResult::Success));

        let not_found_url = Url::parse("https://primal.net/e/nevent1qqsv64erdk323pkpuzqspyk3e842egaeuu8v6js970tvnyjlkjakzqc0whefs").unwrap();
        let check_url_res = identity_proof_client
            .check_url(&identity_proof, &not_found_url)
            .await;
        assert!(matches!(check_url_res, CheckIdentityProofResult::NotFound));

        let invalid_url = Url::parse("https://www.bit.cr/does-not-exist-ever").unwrap();
        let check_url_res = identity_proof_client
            .check_url(&identity_proof, &invalid_url)
            .await;
        assert!(matches!(
            check_url_res,
            CheckIdentityProofResult::FailureClient
        ));
    }
}
