use async_trait::async_trait;
use bcr_ebill_core::{
    ServiceTraitBounds,
    identity_proof::{IdentityProofStamp, IdentityProofStatus},
};
use log::error;
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
    #[error("External Identity Proof Validation error: {0}")]
    Validation(#[from] util::ValidationError),
}

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait IdentityProofApi: ServiceTraitBounds {
    /// Checks if the given identity proof somewhere in the (successful) response of calling the given URL
    async fn check_url(
        &self,
        identity_proof_stamp: &IdentityProofStamp,
        url: &Url,
    ) -> IdentityProofStatus;
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
    async fn check_url(
        &self,
        identity_proof: &IdentityProofStamp,
        url: &Url,
    ) -> IdentityProofStatus {
        // Make an unauthenticated request to the given URL and retrieve its body
        match self.cl.get(url.to_owned()).send().await {
            Ok(res) => {
                match res.error_for_status() {
                    Ok(resp) => {
                        match resp.text().await {
                            Ok(body) => {
                                // Check if the identity proof is contained in the response
                                if identity_proof.is_contained_in(&body) {
                                    IdentityProofStatus::Success
                                } else {
                                    IdentityProofStatus::NotFound
                                }
                            }
                            Err(body_err) => {
                                error!("Error checking url: {url} for identity proof: {body_err}");
                                IdentityProofStatus::FailureClient
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error checking url: {url} for identity proof: {e}");
                        if let Some(status) = e.status() {
                            if status.is_client_error() {
                                IdentityProofStatus::FailureClient
                            } else if status.is_server_error() {
                                IdentityProofStatus::FailureServer
                            } else {
                                IdentityProofStatus::FailureConnect
                            }
                        } else {
                            IdentityProofStatus::FailureConnect
                        }
                    }
                }
            }
            Err(req_err) => {
                error!("Error checking url: {url} for identity proof: {req_err}");
                IdentityProofStatus::FailureConnect
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::str::FromStr;

    use crate::tests::tests::node_id_test;

    use super::*;

    #[tokio::test]
    #[ignore]
    // Ignored by default, since it makes an HTTP request - useful for testing how different social
    // networks interact with the check_url() call.
    async fn test_check_url() {
        let node_id = node_id_test();

        let identity_proof_client = IdentityProofClient::new();

        // is a valid identity proof
        let identity_proof = IdentityProofStamp::from_str("2DmtcWtNk2hvXaBCUAng63Gn1VDBZEojMwoZWr2VqDL5LZNgszj26YT4Pj4MUSf5o4HSmdiAEENyuNQ5UEK7zG1p").expect("is valid");
        assert!(identity_proof.verify_against_node_id(&node_id));

        let valid_url = Url::parse("https://primal.net/e/nevent1qqs24kk3m0rc8e7a6f8k8daddqes0a2n74jszdszppu84e6y5q8ss3cy2rxs4").unwrap();
        let check_url_res = identity_proof_client
            .check_url(&identity_proof, &valid_url)
            .await;
        assert!(matches!(check_url_res, IdentityProofStatus::Success));

        let not_found_url = Url::parse("https://primal.net/e/nevent1qqsv64erdk323pkpuzqspyk3e842egaeuu8v6js970tvnyjlkjakzqc0whefs").unwrap();
        let check_url_res = identity_proof_client
            .check_url(&identity_proof, &not_found_url)
            .await;
        assert!(matches!(check_url_res, IdentityProofStatus::NotFound));

        let invalid_url = Url::parse("https://www.bit.cr/does-not-exist-ever").unwrap();
        let check_url_res = identity_proof_client
            .check_url(&identity_proof, &invalid_url)
            .await;
        assert!(matches!(check_url_res, IdentityProofStatus::FailureClient));
    }
}
