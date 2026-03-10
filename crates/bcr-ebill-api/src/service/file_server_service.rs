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
