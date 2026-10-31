//! Authenticate the configured wallet endpoint with the configured eBill node key.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use bcr_common::{
    core::NodeId,
    wire::mint_identity::{MINT_IDENTITY_PATH, MintIdentity},
};

use super::mint::{Error, Result};

const IDENTITY_CACHE_SECONDS: i64 = 600;
const MAX_CACHE_ENTRIES: usize = 128;
const MAX_IDENTITY_BYTES: usize = 4096;
const IDENTITY_TIMEOUT_SECONDS: u64 = 15;

#[derive(Debug, Clone, Default)]
pub(super) struct IdentityCache(Arc<Mutex<HashMap<(NodeId, url::Url), i64>>>);

impl IdentityCache {
    pub(super) async fn verify(&self, url: &url::Url, node: &NodeId) -> Result<()> {
        let key = (node.clone(), url.clone());
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        {
            let mut entries = self.0.lock().map_err(|_| Error::QuoteClient)?;
            // Clock rollback invalidates cached verifications as well.
            entries.retain(|_, verified| (0..IDENTITY_CACHE_SECONDS).contains(&(now - *verified)));
            if entries.contains_key(&key) {
                return Ok(());
            }
        }
        let challenge = hex::encode(rand::random::<[u8; 32]>());
        let mut endpoint = url
            .join(MINT_IDENTITY_PATH)
            .map_err(|_| Error::InvalidMintUrl)?;
        endpoint
            .query_pairs_mut()
            .append_pair("challenge", &challenge);
        let body = fetch_identity(endpoint).await?;
        let proof: MintIdentity =
            serde_json::from_slice(&body).map_err(|_| Error::MintIdentityMismatch)?;
        let verified = time::OffsetDateTime::now_utc().unix_timestamp();
        if !proof.verify(node, &challenge, verified) {
            return Err(Error::MintIdentityMismatch.into());
        }
        let mut entries = self.0.lock().map_err(|_| Error::QuoteClient)?;
        if entries.len() >= MAX_CACHE_ENTRIES {
            entries.clear();
        }
        entries.insert(key, verified);
        Ok(())
    }
}

async fn fetch_identity(url: url::Url) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(IDENTITY_TIMEOUT_SECONDS))
        .build()
        .map_err(|_| Error::QuoteClient)?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| Error::QuoteClient)?;
    if !response.status().is_success() {
        return Err(Error::QuoteClient.into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::QuoteClient)? {
        if chunk.len() > MAX_IDENTITY_BYTES.saturating_sub(body.len()) {
            return Err(Error::QuoteClient.into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external::mint::{MintClient, MintClientApi};
    use bcr_ebill_core::protocol::crypto::BcrKeys;
    use bitcoin::{Network, hashes::Hash};
    use mockito::{Matcher, Server};

    fn proof_for(request: &mockito::Request, keys: &BcrKeys, node: &NodeId) -> MintIdentity {
        let url =
            url::Url::parse(&format!("http://mint.test{}", request.path_and_query())).unwrap();
        let challenge = url
            .query_pairs()
            .find(|(k, _)| k == "challenge")
            .unwrap()
            .1
            .into_owned();
        MintIdentity::sign(
            node.clone(),
            challenge,
            time::OffsetDateTime::now_utc().unix_timestamp(),
            &keys.get_key_pair(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn mint_identity_rejects_invalid_proofs_and_never_caches_failure() {
        for fault in [
            "wrong-key",
            "wrong-network",
            "wrong-node",
            "replayed-challenge",
            "stale",
            "future",
            "schema",
            "signature",
            "unavailable",
            "malformed",
            "oversized",
        ] {
            let mut server = Server::new_async().await;
            let keys = BcrKeys::new();
            let expected = NodeId::new(keys.pub_key(), Network::Regtest);
            let node = expected.clone();
            let endpoint = server
                .mock("GET", MINT_IDENTITY_PATH)
                .match_query(Matcher::Regex("^challenge=[0-9a-f]{64}$".to_owned()))
                .with_status(if fault == "unavailable" { 404 } else { 200 })
                .with_body_from_request(move |request| {
                    let mut proof = proof_for(request, &keys, &node);
                    match fault {
                        "wrong-key" => {
                            let other = BcrKeys::new();
                            let hash = bitcoin::hashes::sha256::Hash::hash(
                                proof.canonical_text().as_bytes(),
                            );
                            proof.signature = bitcoin::secp256k1::SECP256K1
                                .sign_schnorr_no_aux_rand(
                                    &bitcoin::secp256k1::Message::from_digest(hash.to_byte_array()),
                                    &other.get_key_pair(),
                                )
                                .to_string();
                        }
                        "wrong-network" => proof.network = "testnet".to_owned(),
                        "wrong-node" => {
                            proof.node_id = NodeId::new(BcrKeys::new().pub_key(), Network::Regtest)
                        }
                        "replayed-challenge" => proof.challenge = "ab".repeat(32),
                        "stale" => proof.issued_at -= 301,
                        "future" => proof.issued_at += 601,
                        "schema" => proof.schema = "other-purpose-v1".to_owned(),
                        "signature" => proof.signature = "00".repeat(64),
                        "malformed" => return b"{}".to_vec(),
                        "oversized" => return vec![b'x'; MAX_IDENTITY_BYTES + 1],
                        _ => {}
                    }
                    if !matches!(fault, "wrong-key" | "signature") {
                        let hash =
                            bitcoin::hashes::sha256::Hash::hash(proof.canonical_text().as_bytes());
                        proof.signature = bitcoin::secp256k1::SECP256K1
                            .sign_schnorr_no_aux_rand(
                                &bitcoin::secp256k1::Message::from_digest(hash.to_byte_array()),
                                &keys.get_key_pair(),
                            )
                            .to_string();
                    }
                    serde_json::to_vec(&proof).unwrap()
                })
                .expect(2)
                .create_async()
                .await;
            let client = MintClient::new(std::sync::Arc::new(crate::tests::tests::test_cfg()));
            let url = server.url().parse().unwrap();
            for _ in 0..2 {
                assert!(
                    client.verify_mint_identity(&url, &expected).await.is_err(),
                    "{fault}"
                );
            }
            endpoint.assert_async().await;
        }
    }

    #[tokio::test]
    async fn mint_identity_cache_is_scoped_expires_and_rechallenges() {
        let mut server = Server::new_async().await;
        let keys = BcrKeys::new();
        let expected = NodeId::new(keys.pub_key(), Network::Regtest);
        let node = expected.clone();
        let challenges = Arc::new(Mutex::new(Vec::new()));
        let seen = challenges.clone();
        let endpoint = server
            .mock("GET", MINT_IDENTITY_PATH)
            .match_query(Matcher::Any)
            .with_body_from_request(move |request| {
                let proof = proof_for(request, &keys, &node);
                seen.lock().unwrap().push(proof.challenge.clone());
                serde_json::to_vec(&proof).unwrap()
            })
            .expect(4)
            .create_async()
            .await;
        let client = MintClient::new(std::sync::Arc::new(crate::tests::tests::test_cfg()));
        let url: url::Url = server.url().parse().unwrap();
        client.verify_mint_identity(&url, &expected).await.unwrap();
        client
            .clone()
            .verify_mint_identity(&url, &expected)
            .await
            .unwrap();
        let wrong = NodeId::new(BcrKeys::new().pub_key(), Network::Regtest);
        assert!(client.verify_mint_identity(&url, &wrong).await.is_err());
        client.identity_cache.0.lock().unwrap().insert(
            (expected.clone(), url.clone()),
            time::OffsetDateTime::now_utc().unix_timestamp() - IDENTITY_CACHE_SECONDS,
        );
        client.verify_mint_identity(&url, &expected).await.unwrap();
        client.identity_cache.0.lock().unwrap().insert(
            (expected.clone(), url.clone()),
            time::OffsetDateTime::now_utc().unix_timestamp() + 60,
        );
        client.verify_mint_identity(&url, &expected).await.unwrap();
        endpoint.assert_async().await;
        {
            let seen = challenges.lock().unwrap();
            assert_eq!(seen.len(), 4);
            let unique: std::collections::HashSet<_> = seen.iter().collect();
            assert_eq!(unique.len(), seen.len());
        }
        let other_url = "http://127.0.0.1:1".parse().unwrap();
        assert!(
            client
                .verify_mint_identity(&other_url, &expected)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn mint_identity_rejects_redirects() {
        let mut server = Server::new_async().await;
        let redirected = server
            .mock("GET", "/redirect-target")
            .expect(0)
            .create_async()
            .await;
        let endpoint = server
            .mock("GET", MINT_IDENTITY_PATH)
            .match_query(Matcher::Any)
            .with_status(302)
            .with_header("location", &format!("{}/redirect-target", server.url()))
            .expect(1)
            .create_async()
            .await;
        let node = NodeId::new(BcrKeys::new().pub_key(), Network::Regtest);
        assert!(
            MintClient::new(std::sync::Arc::new(crate::tests::tests::test_cfg()))
                .verify_mint_identity(&server.url().parse().unwrap(), &node)
                .await
                .is_err()
        );
        endpoint.assert_async().await;
        redirected.assert_async().await;
    }
}
