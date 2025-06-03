use std::io::Write;

use async_trait::async_trait;
use bcr_ebill_core::ServiceTraitBounds;
use nostr::hashes::{
    Hash,
    sha256::{self, Hash as Sha256Hash},
};
use serde::Deserialize;
use thiserror::Error;

/// Generic result type
pub type Result<T> = std::result::Result<T, super::Error>;

/// Generic error type
#[derive(Debug, Error)]
pub enum Error {
    /// all errors originating from interacting with the web api
    #[error("External File Storage Web API error: {0}")]
    Api(#[from] reqwest::Error),
    /// all errors originating from invalid urls
    #[error("External File Storage Invalid Relay Url Error")]
    InvalidRelayUrl,
    /// all errors originating from invalid hashes
    #[error("External File Storage Invalid Hash")]
    InvalidHash,
    /// all errors originating from hashing
    #[error("External File Storage Hash Error")]
    Hash,
}

#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait FileStorageClientApi: ServiceTraitBounds {
    /// Upload the given bytes, checking and returning the nostr_hash
    async fn upload(&self, relay_url: &str, bytes: Vec<u8>) -> Result<Sha256Hash>;
    /// Download the bytes with the given nostr_hash and compare if the hash matches the file
    async fn download(&self, relay_url: &str, nostr_hash: &str) -> Result<Vec<u8>>;
}

#[derive(Debug, Clone, Default)]
pub struct FileStorageClient {
    cl: reqwest::Client,
}

impl ServiceTraitBounds for FileStorageClient {}

#[cfg(test)]
impl ServiceTraitBounds for MockFileStorageClientApi {}

impl FileStorageClient {
    pub fn new() -> Self {
        Self {
            cl: reqwest::Client::new(),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl FileStorageClientApi for FileStorageClient {
    async fn upload(&self, relay_url: &str, bytes: Vec<u8>) -> Result<Sha256Hash> {
        // Calculate hash to compare with the hash we get back
        let mut hash_engine = sha256::HashEngine::default();
        if hash_engine.write_all(&bytes).is_err() {
            return Err(Error::Hash.into());
        }
        let hash = sha256::Hash::from_engine(hash_engine);

        // PUT {relay_url}/upload
        let url = reqwest::Url::parse(relay_url)
            .and_then(|url| url.join("upload"))
            .map_err(|_| Error::InvalidRelayUrl)?;
        // Make upload request
        let resp: BlobDescriptorReply = self.cl.put(url).body(bytes).send().await?.json().await?;
        let nostr_hash = resp.sha256;

        // Check hash
        if hash != nostr_hash {
            return Err(Error::InvalidHash.into());
        }

        Ok(nostr_hash)
    }

    async fn download(&self, relay_url: &str, nostr_hash: &str) -> Result<Vec<u8>> {
        // GET {relay_url}/{hash}
        let url = reqwest::Url::parse(relay_url)
            .and_then(|url| url.join(nostr_hash))
            .map_err(|_| Error::InvalidRelayUrl)?;
        // Make download request
        let resp: Vec<u8> = self.cl.get(url).send().await?.bytes().await?.into();

        // Calculate hash to compare with the hash we sent
        let mut hash_engine = sha256::HashEngine::default();
        if hash_engine.write_all(&resp).is_err() {
            return Err(Error::Hash.into());
        }

        // Check hash
        let hash = sha256::Hash::from_engine(hash_engine);
        if hash.to_string() != nostr_hash {
            return Err(Error::InvalidHash.into());
        }

        Ok(resp)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlobDescriptorReply {
    sha256: Sha256Hash,
}
