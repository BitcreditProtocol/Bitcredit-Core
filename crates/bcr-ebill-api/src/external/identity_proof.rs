use async_trait::async_trait;
use bcr_ebill_core::{
    ServiceTraitBounds,
    identity_proof::{IdentityProofStamp, IdentityProofStatus},
};
use borsh_derive::BorshSerialize;
use log::error;
use nostr::hashes::Hash;
use nostr::{hashes::sha256, nips::nip19::ToBech32};
use secp256k1::{Keypair, Message, SECP256K1};
use serde::Serialize;
use thiserror::Error;
use url::Url;

#[cfg(test)]
use mockall::automock;

use crate::{external::file_storage::to_url, util};

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
    /// all nostr key  errors
    #[error("External Identity Proof Nostr Key Error")]
    NostrKey,
    /// all borsh errors
    #[error("External Identity Proof Borsh Error")]
    Borsh(#[from] borsh::io::Error),
}

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait IdentityProofApi: ServiceTraitBounds {
    /// Checks if the given identity proof somewhere in the (successful) response of calling the given URL
    /// The request is proxied through the given relay and signed by the caller's private key
    async fn check_url(
        &self,
        relay_url: &url::Url,
        identity_proof_stamp: &IdentityProofStamp,
        private_key: &nostr::SecretKey,
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

#[derive(Debug, Clone, Serialize)]
pub struct ProxyReq {
    pub payload: ProxyReqPayload,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, BorshSerialize)]
pub struct ProxyReqPayload {
    pub npub: String,
    pub url: String,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl IdentityProofApi for IdentityProofClient {
    async fn check_url(
        &self,
        relay_url: &url::Url,
        identity_proof: &IdentityProofStamp,
        private_key: &nostr::SecretKey,
        url: &Url,
    ) -> IdentityProofStatus {
        let (proxy_url, proxy_req) = match create_proxy_req(relay_url, private_key, url) {
            Ok(r) => r,
            Err(e) => {
                error!("Error creating proxy request for {url}: {e}");
                return IdentityProofStatus::FailureClient;
            }
        };
        // Call the Nostr relay's proxy function with a signed payload
        match self.cl.post(proxy_url).json(&proxy_req).send().await {
            Ok(res) => {
                let status = res.status();
                match res.text().await {
                    Ok(body) => {
                        if status.is_client_error() {
                            error!(
                                "Error checking url: {url} for identity proof: {status}, {body}"
                            );
                            return IdentityProofStatus::FailureClient;
                        } else if status.is_server_error() {
                            error!(
                                "Error checking url: {url} for identity proof: {status}, {body}"
                            );
                            return IdentityProofStatus::FailureServer;
                        }

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
            Err(req_err) => {
                error!("Error checking url: {url} for identity proof: {req_err}");
                IdentityProofStatus::FailureConnect
            }
        }
    }
}

// Returns the relay URL to call and the request
fn create_proxy_req(
    relay_url: &url::Url,
    private_key: &nostr::SecretKey,
    url: &Url,
) -> Result<(Url, ProxyReq)> {
    let npub = nostr::Keys::new(private_key.clone())
        .public_key()
        .to_bech32()
        .map_err(|_| Error::NostrKey)?;

    let payload = ProxyReqPayload {
        npub,
        url: url.to_string(),
    };
    let key_pair = Keypair::from_secret_key(SECP256K1, private_key);
    let serialized = borsh::to_vec(&payload).map_err(Error::Borsh)?;
    let hash: sha256::Hash = sha256::Hash::hash(&serialized);
    let msg = Message::from_digest(*hash.as_ref());

    let signature = SECP256K1.sign_schnorr(&msg, &key_pair).to_string();
    Ok((
        to_url(relay_url, "proxy/v1/req")?,
        ProxyReq { signature, payload },
    ))
}

#[cfg(test)]
pub mod tests {
    use std::str::FromStr;

    use bcr_ebill_core::util::BcrKeys;
    use bitcoin::XOnlyPublicKey;
    use nostr::key::SecretKey;
    use secp256k1::schnorr::Signature;

    use crate::tests::tests::{node_id_test, private_key_test};

    use super::*;
    pub fn verify_request<Req>(req: &Req, signature: &str, key: &XOnlyPublicKey) -> bool
    where
        Req: borsh::BorshSerialize,
    {
        let serialized = borsh::to_vec(&req).unwrap();
        let hash = sha256::Hash::hash(&serialized);
        let msg = Message::from_digest(*hash.as_ref());
        let decoded_signature = Signature::from_str(signature).unwrap();

        SECP256K1
            .verify_schnorr(&decoded_signature, &msg, key)
            .is_ok()
    }

    #[test]
    fn sig_req_proxy_test() {
        let relay_url = url::Url::parse("wss://bcr-relay-dev.minibill.tech").unwrap();
        let secret_key =
            SecretKey::from_str("8863c82829480536893fc49c4b30e244f97261e989433373d73c648c1a656a79")
                .unwrap();
        let x_only_pub = secret_key.public_key(SECP256K1).x_only_public_key().0;
        let (proxy_url, proxy_req) = create_proxy_req(&relay_url, &secret_key, &Url::parse("https://primal.net/e/nevent1qqs24kk3m0rc8e7a6f8k8daddqes0a2n74jszdszppu84e6y5q8ss3cy2rxs4").unwrap()).expect("creating proxy req works");

        assert_eq!(
            proxy_url,
            Url::parse("https://bcr-relay-dev.minibill.tech/proxy/v1/req").unwrap()
        );
        assert!(verify_request(
            &proxy_req.payload,
            &proxy_req.signature,
            &x_only_pub
        ));
    }

    #[tokio::test]
    #[ignore]
    // Ignored by default, since it makes an HTTP request - useful for testing how different social
    // networks interact with the check_url() call.
    async fn test_check_url() {
        let node_id = node_id_test();
        let relay_url = url::Url::parse("wss://bcr-relay-dev.minibill.tech").unwrap();
        let private_key = BcrKeys::from_private_key(&private_key_test())
            .unwrap()
            .get_nostr_keys()
            .secret_key()
            .to_owned();

        let identity_proof_client = IdentityProofClient::new();

        // is a valid identity proof
        let identity_proof = IdentityProofStamp::from_str("2DmtcWtNk2hvXaBCUAng63Gn1VDBZEojMwoZWr2VqDL5LZNgszj26YT4Pj4MUSf5o4HSmdiAEENyuNQ5UEK7zG1p").expect("is valid");
        assert!(identity_proof.verify_against_node_id(&node_id));

        let valid_url = Url::parse("https://primal.net/e/nevent1qqs24kk3m0rc8e7a6f8k8daddqes0a2n74jszdszppu84e6y5q8ss3cy2rxs4").unwrap();
        let check_url_res = identity_proof_client
            .check_url(&relay_url, &identity_proof, &private_key, &valid_url)
            .await;
        assert!(matches!(check_url_res, IdentityProofStatus::Success));

        let not_found_url = Url::parse("https://primal.net/e/nevent1qqsv64erdk323pkpuzqspyk3e842egaeuu8v6js970tvnyjlkjakzqc0whefs").unwrap();
        let check_url_res = identity_proof_client
            .check_url(&relay_url, &identity_proof, &private_key, &not_found_url)
            .await;
        assert!(matches!(check_url_res, IdentityProofStatus::NotFound));

        let invalid_url = Url::parse("https://www.bit.cr/does-not-exist-ever").unwrap();
        let check_url_res = identity_proof_client
            .check_url(&relay_url, &identity_proof, &private_key, &invalid_url)
            .await;
        assert!(matches!(check_url_res, IdentityProofStatus::FailureClient));
    }
}
