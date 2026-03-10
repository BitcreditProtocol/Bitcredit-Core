use crate::NostrConfig;
use crate::external::file_storage::FileStorageClientApi;
use crate::service::{Error, Result};
use log::warn;
use nostr::hashes::sha256::Hash as Sha256HexHash;

fn push_unique(urls: &mut Vec<url::Url>, url: url::Url) {
    if !urls.iter().any(|existing| existing == &url) {
        urls.push(url);
    }
}

/// Converts a relay URL into its Blossom HTTP endpoint form.
pub fn blossom_server_from_relay(relay_url: &url::Url) -> Result<url::Url> {
    let mut blossom_url = relay_url.clone();
    match blossom_url.scheme() {
        "ws" => blossom_url
            .set_scheme("http")
            .map_err(|_| Error::NotFound)?,
        "wss" => blossom_url
            .set_scheme("https")
            .map_err(|_| Error::NotFound)?,
        _ => {}
    }
    Ok(blossom_url)
}

/// Returns the configured Blossom servers, or derives a single fallback server from the first relay.
pub fn configured_blossom_servers(config: &NostrConfig) -> Vec<url::Url> {
    if !config.blossom_servers.is_empty() {
        return config.blossom_servers.clone();
    }

    config
        .relays
        .first()
        .and_then(|relay| blossom_server_from_relay(relay).ok())
        .into_iter()
        .collect()
}

/// Chooses explicit Blossom servers when available, otherwise derives them from relay fallbacks.
pub fn resolve_blossom_servers(
    blossom_servers: &[url::Url],
    fallback_relays: &[url::Url],
) -> Vec<url::Url> {
    if !blossom_servers.is_empty() {
        return blossom_servers.to_vec();
    }

    fallback_relays
        .first()
        .and_then(|relay| blossom_server_from_relay(relay).ok())
        .into_iter()
        .collect()
}

/// Merges multiple Blossom server lists while preserving order and removing duplicates.
pub fn merge_blossom_servers(server_sets: &[&[url::Url]]) -> Vec<url::Url> {
    let mut merged = Vec::new();
    for servers in server_sets {
        for server in *servers {
            push_unique(&mut merged, server.clone());
        }
    }
    merged
}

/// Uploads to each Blossom server and succeeds once at least one upload completes.
pub async fn upload_to_blossom_servers(
    client: &dyn FileStorageClientApi,
    servers: &[url::Url],
    bytes: Vec<u8>,
) -> Result<Sha256HexHash> {
    if servers.is_empty() {
        return Err(Error::NotFound);
    }

    let mut first_success = None;
    let mut last_error = None;

    for server in servers {
        match client.upload(server, bytes.clone()).await {
            Ok(hash) => {
                if first_success.is_none() {
                    first_success = Some(hash);
                }
            }
            Err(err) => {
                warn!("Failed Blossom upload to {server}: {err}");
                last_error = Some(err);
            }
        }
    }

    if let Some(hash) = first_success {
        return Ok(hash);
    }

    match last_error {
        Some(err) => Err(err.into()),
        None => Err(Error::NotFound),
    }
}

/// Downloads from the first Blossom server that returns the requested blob.
pub async fn download_from_blossom_servers(
    client: &dyn FileStorageClientApi,
    servers: &[url::Url],
    nostr_hash: &Sha256HexHash,
) -> Result<Vec<u8>> {
    if servers.is_empty() {
        return Err(Error::NotFound);
    }

    let mut last_error = None;
    for server in servers {
        match client.download(server, nostr_hash).await {
            Ok(bytes) => return Ok(bytes),
            Err(err) => {
                warn!("Failed Blossom download from {server}: {err}");
                last_error = Some(err);
            }
        }
    }

    match last_error {
        Some(err) => Err(err.into()),
        None => Err(Error::NotFound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external::file_storage::{Error as FileStorageError, MockFileStorageClientApi};
    use mockall::predicate::eq;
    use std::str::FromStr;

    fn test_config() -> NostrConfig {
        NostrConfig {
            only_known_contacts: false,
            relays: vec![url::Url::parse("wss://relay.example.com").unwrap()],
            blossom_servers: vec![],
            max_relays: Some(50),
        }
    }

    #[test]
    fn blossom_server_from_relay_converts_websocket_schemes() {
        assert_eq!(
            blossom_server_from_relay(&url::Url::parse("ws://relay.example.com").unwrap())
                .unwrap()
                .as_str(),
            "http://relay.example.com/"
        );
        assert_eq!(
            blossom_server_from_relay(&url::Url::parse("wss://relay.example.com").unwrap())
                .unwrap()
                .as_str(),
            "https://relay.example.com/"
        );
    }

    #[test]
    fn configured_and_resolved_blossom_servers_prefer_explicit_values() {
        let explicit = url::Url::parse("https://blossom.example.com").unwrap();
        let mut config = test_config();
        config.blossom_servers = vec![explicit.clone()];

        assert_eq!(configured_blossom_servers(&config), vec![explicit.clone()]);
        assert_eq!(
            resolve_blossom_servers(std::slice::from_ref(&explicit), &config.relays),
            vec![explicit]
        );
    }

    #[test]
    fn configured_and_resolved_blossom_servers_fallback_to_first_relay() {
        let config = test_config();
        let expected = url::Url::parse("https://relay.example.com/").unwrap();

        assert_eq!(configured_blossom_servers(&config), vec![expected.clone()]);
        assert_eq!(resolve_blossom_servers(&[], &config.relays), vec![expected]);
    }

    #[test]
    fn merge_blossom_servers_preserves_order_and_deduplicates() {
        let merged = merge_blossom_servers(&[
            &[
                url::Url::parse("https://one.example.com").unwrap(),
                url::Url::parse("https://two.example.com").unwrap(),
            ],
            &[
                url::Url::parse("https://two.example.com").unwrap(),
                url::Url::parse("https://three.example.com").unwrap(),
            ],
        ]);

        assert_eq!(
            merged,
            vec![
                url::Url::parse("https://one.example.com").unwrap(),
                url::Url::parse("https://two.example.com").unwrap(),
                url::Url::parse("https://three.example.com").unwrap(),
            ]
        );
    }

    #[tokio::test]
    async fn upload_to_blossom_servers_succeeds_when_any_server_accepts_upload() {
        let mut client = MockFileStorageClientApi::new();
        let first = url::Url::parse("https://one.example.com").unwrap();
        let second = url::Url::parse("https://two.example.com").unwrap();
        let bytes = b"hello".to_vec();
        let expected = Sha256HexHash::from_str(
            "d277fe40da2609ca08215cdfbeac44835d4371a72f1416a63c87efd67ee24bfa",
        )
        .unwrap();

        client
            .expect_upload()
            .with(eq(first.clone()), eq(bytes.clone()))
            .returning(|_, _| Err(FileStorageError::InvalidRelayUrl.into()))
            .once();
        client
            .expect_upload()
            .with(eq(second.clone()), eq(bytes.clone()))
            .returning(move |_, _| Ok(expected))
            .once();

        let result = upload_to_blossom_servers(&client, &[first, second], bytes)
            .await
            .unwrap();

        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn download_from_blossom_servers_falls_back_until_one_server_returns_data() {
        let mut client = MockFileStorageClientApi::new();
        let first = url::Url::parse("https://one.example.com").unwrap();
        let second = url::Url::parse("https://two.example.com").unwrap();
        let nostr_hash = Sha256HexHash::from_str(
            "d277fe40da2609ca08215cdfbeac44835d4371a72f1416a63c87efd67ee24bfa",
        )
        .unwrap();
        let expected = b"hello".to_vec();

        client
            .expect_download()
            .with(eq(first.clone()), eq(nostr_hash))
            .returning(|_, _| Err(FileStorageError::InvalidRelayUrl.into()))
            .once();
        let expected_clone = expected.clone();
        client
            .expect_download()
            .with(eq(second.clone()), eq(nostr_hash))
            .returning(move |_, _| Ok(expected_clone.clone()))
            .once();

        let result = download_from_blossom_servers(&client, &[first, second], &nostr_hash)
            .await
            .unwrap();

        assert_eq!(result, expected);
    }
}
