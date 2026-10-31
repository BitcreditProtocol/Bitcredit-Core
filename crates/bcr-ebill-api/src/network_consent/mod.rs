//! Narrow test-network signing. Signatures authenticate optional public claims/consent only.
mod data;
pub mod signer;
pub use data::*;

use bcr_common::core::NodeId;
use bcr_ebill_core::protocol::{Country, ProtocolValidationError, Timestamp, crypto::BcrKeys};
use bitcoin::{
    Network,
    hashes::{Hash, sha256},
    secp256k1::{Message, SECP256K1, XOnlyPublicKey},
};
use serde_json::json;
use std::str::FromStr;
use uuid::Uuid;

type Result<T> = std::result::Result<T, ProtocolValidationError>;
const MAX_EVENT_BYTES: usize = 16 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidHash
}

fn check_signer(signer: &NodeId, keys: &BcrKeys, now: Timestamp) -> Result<()> {
    if keys.pub_key() != signer.pub_key() {
        return Err(ProtocolValidationError::CallerMustBeSignatory);
    }
    if signer.network() == Network::Bitcoin {
        return Err(ProtocolValidationError::InvalidNodeId);
    }
    if now.inner() == 0 || now.inner() > MAX_SAFE_INTEGER {
        return Err(ProtocolValidationError::InvalidTimestamp);
    }
    Ok(())
}

fn hex32(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    Ok(())
}

fn audience(grant_id: &Uuid, requesting: &str, answering: &str) -> Result<()> {
    if grant_id.get_variant() != uuid::Variant::RFC4122
        || !(1..=8).contains(&grant_id.get_version_num())
    {
        return Err(ProtocolValidationError::FieldInvalid(
            bcr_ebill_core::protocol::Field::Id,
        ));
    }
    for key in [requesting, answering] {
        hex32(key)?;
        XOnlyPublicKey::from_str(key).map_err(|_| invalid())?;
    }
    if requesting == answering {
        return Err(invalid());
    }
    Ok(())
}

pub fn fresh_nonce() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| invalid())?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Exact field order, decimal seconds and a terminal LF are the wire contract.
fn grant_text(grant: &CrossMintGrant) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\nbill_status\n{}\n{}\n{}\n{}\n{}\n",
        grant.schema,
        grant.grant_id,
        grant.network,
        grant.subject_node_id,
        grant.requesting_mint_pubkey,
        grant.answering_mint_pubkey,
        grant.bill_id,
        grant.case_binding,
        grant.issued_at,
        grant.expires_at,
        grant.nonce,
    )
}

fn revoke_text(revoke: &CrossMintRevoke) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        revoke.schema,
        revoke.grant_id,
        revoke.network,
        revoke.subject_node_id,
        revoke.requesting_mint_pubkey,
        revoke.answering_mint_pubkey,
        revoke.nonce,
        revoke.issued_at,
    )
}

fn message(text: &str) -> Message {
    Message::from_digest(sha256::Hash::hash(text.as_bytes()).to_byte_array())
}

pub fn sign_grant(
    payload: &CrossMintGrantPayload,
    signer: &NodeId,
    keys: &BcrKeys,
    now: Timestamp,
    nonce: String,
) -> Result<SignedCrossMintGrant> {
    check_signer(signer, keys, now)?;
    audience(
        &payload.grant_id,
        &payload.requesting_mint_pubkey,
        &payload.answering_mint_pubkey,
    )?;
    hex32(&nonce)?;
    hex32(&payload.case_binding)?;
    if payload.bill_id.network() != signer.network() {
        return Err(ProtocolValidationError::InvalidNodeId);
    }
    let lifetime = payload.lifetime_seconds.unwrap_or(300);
    if !(1..=300).contains(&lifetime) {
        return Err(ProtocolValidationError::InvalidTimestamp);
    }
    let expires_at = now
        .inner()
        .checked_add(lifetime)
        .filter(|v| *v <= MAX_SAFE_INTEGER)
        .ok_or(ProtocolValidationError::InvalidTimestamp)?;
    let grant = CrossMintGrant {
        schema: "cross-mint-grant-v1".into(),
        grant_id: payload.grant_id.to_string(),
        network: signer.network().to_string(),
        subject_node_id: signer.to_string(),
        requesting_mint_pubkey: payload.requesting_mint_pubkey.clone(),
        answering_mint_pubkey: payload.answering_mint_pubkey.clone(),
        operation: payload.operation.clone(),
        bill_id: payload.bill_id.to_string(),
        case_binding: payload.case_binding.clone(),
        issued_at: now.inner(),
        expires_at,
        nonce,
    };
    let signature = SECP256K1
        .sign_schnorr(&message(&grant_text(&grant)), &keys.get_key_pair())
        .to_string();
    Ok(SignedCrossMintGrant { grant, signature })
}

pub fn sign_revoke(
    payload: &CrossMintRevokePayload,
    signer: &NodeId,
    keys: &BcrKeys,
    now: Timestamp,
    nonce: String,
) -> Result<SignedCrossMintRevoke> {
    check_signer(signer, keys, now)?;
    audience(
        &payload.grant_id,
        &payload.requesting_mint_pubkey,
        &payload.answering_mint_pubkey,
    )?;
    hex32(&nonce)?;
    let revoke = CrossMintRevoke {
        schema: "cross-mint-revoke-v1".into(),
        grant_id: payload.grant_id.to_string(),
        network: signer.network().to_string(),
        subject_node_id: signer.to_string(),
        requesting_mint_pubkey: payload.requesting_mint_pubkey.clone(),
        answering_mint_pubkey: payload.answering_mint_pubkey.clone(),
        nonce,
        issued_at: now.inner(),
    };
    let signature = SECP256K1
        .sign_schnorr(&message(&revoke_text(&revoke)), &keys.get_key_pair())
        .to_string();
    Ok(SignedCrossMintRevoke { revoke, signature })
}

fn text_bound(text: &str, max: usize) -> Result<()> {
    if text.trim().is_empty()
        || text.encode_utf16().count() > max
        || text.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    Ok(())
}

fn country_code(country: &str) -> Result<()> {
    if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(ProtocolValidationError::InvalidCountry);
    }
    Country::parse(country)?;
    Ok(())
}

fn validate_listing(payload: &DirectoryListingPayload, now: Timestamp) -> Result<()> {
    text_bound(&payload.name, 200)?;
    text_bound(&payload.notice_version, 100)?;
    if payload.trading_names.len() > 20 {
        return Err(invalid());
    }
    for name in &payload.trading_names {
        text_bound(name, 200)?;
    }
    if let Some(region) = &payload.region {
        text_bound(region, 200)?;
    }
    if payload.subject_type == DirectorySubjectType::SoleTrader
        && (payload.registration.is_some()
            || payload.business_address.is_some()
            || payload.business_contact.is_some())
    {
        return Err(invalid());
    }
    if let Some(address) = &payload.business_address {
        country_code(&address.country)?;
        text_bound(&address.city, 200)?;
        if let Some(zip) = &address.zip {
            text_bound(zip, 40)?;
        }
        text_bound(&address.address, 400)?;
    }
    if let Some(contact) = &payload.business_contact {
        if let Some(email) = &contact.email {
            text_bound(email, 320)?;
            bcr_ebill_core::protocol::Email::new(email)?;
        }
        if let Some(phone) = &contact.phone {
            text_bound(phone, 40)?;
        }
        if let Some(website) = &contact.website {
            text_bound(website, 500)?;
            let url = url::Url::parse(website).map_err(|_| invalid())?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err(invalid());
            }
        }
    }
    if let Some(description) = &payload.description {
        text_bound(description, 2000)?;
    }
    if let Some(country) = &payload.country {
        country_code(country)?;
    }
    if let Some(registration) = &payload.registration {
        country_code(&registration.country)?;
        if payload
            .country
            .as_ref()
            .is_some_and(|country| country != &registration.country)
        {
            return Err(invalid());
        }
        text_bound(&registration.registry, 100)?;
        if !registration.registry.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || (i > 0 && matches!(b, b'.' | b'_' | b'-'))
        }) {
            return Err(invalid());
        }
        text_bound(&registration.number, 100)?;
        if !registration.number.chars().any(char::is_alphanumeric) {
            return Err(invalid());
        }
    }
    if payload.products.len() > 20
        || payload.acting_persons.len() > 10
        || payload.contact_relays.len() > 4
    {
        return Err(invalid());
    }
    for product in &payload.products {
        text_bound(&product.label, 200)?;
        if let Some(code) = &product.code {
            text_bound(code, 100)?;
        }
    }
    for person in &payload.acting_persons {
        text_bound(&person.public_name, 200)?;
        text_bound(&person.public_role, 200)?;
    }
    for relay in &payload.contact_relays {
        text_bound(relay, 500)?;
        let url = url::Url::parse(relay).map_err(|_| invalid())?;
        if !matches!(url.scheme(), "ws" | "wss")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid());
        }
    }
    if payload.valid_until <= now.inner()
        || payload.valid_until.saturating_sub(now.inner()) > 30 * 86400
    {
        return Err(ProtocolValidationError::InvalidTimestamp);
    }
    Ok(())
}

fn listing_tags(signer: &NodeId) -> Vec<Vec<String>> {
    vec![
        vec!["d".into(), format!("yellow-book:v1:{}", signer.network())],
        vec!["t".into(), "bitcredit-yellow-book-v1".into()],
    ]
}

/// NIP-01 serialization, not sorted-object JSON or the consent text format.
fn event_text(event: &SignedDirectoryEvent) -> String {
    json!([
        0,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags,
        event.content
    ])
    .to_string()
}

fn sign_event(
    signer: &NodeId,
    keys: &BcrKeys,
    now: Timestamp,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
) -> Result<SignedDirectoryEvent> {
    check_signer(signer, keys, now)?;
    let mut event = SignedDirectoryEvent {
        id: String::new(),
        pubkey: signer.npub().to_string(),
        created_at: now.inner(),
        kind,
        tags,
        content,
        sig: String::new(),
    };
    let msg = message(&event_text(&event));
    event.id = sha256::Hash::from_byte_array(*msg.as_ref()).to_string();
    event.sig = SECP256K1
        .sign_schnorr(&msg, &keys.get_key_pair())
        .to_string();
    if serde_json::to_vec(&event).map_err(|_| invalid())?.len() > MAX_EVENT_BYTES {
        return Err(invalid());
    }
    Ok(event)
}

pub fn sign_listing(
    payload: &DirectoryListingPayload,
    signer: &NodeId,
    keys: &BcrKeys,
    subject_type: DirectorySubjectType,
    now: Timestamp,
) -> Result<SignedDirectoryEvent> {
    check_signer(signer, keys, now)?;
    if payload.subject_type != subject_type {
        return Err(ProtocolValidationError::CallerMustBeSignatory);
    }
    validate_listing(payload, now)?;
    let mut content = serde_json::to_value(payload).map_err(|_| invalid())?;
    content["schema"] = json!("yellow-book-v1");
    content["network"] = json!(signer.network().to_string());
    content["subjectNodeId"] = json!(signer.to_string());
    content["status"] = json!("listed");
    sign_event(
        signer,
        keys,
        now,
        38900,
        listing_tags(signer),
        content.to_string(),
    )
}

pub fn sign_withdrawal(
    payload: &DirectoryWithdrawalPayload,
    signer: &NodeId,
    keys: &BcrKeys,
    now: Timestamp,
) -> Result<SignedDirectoryWithdrawal> {
    check_signer(signer, keys, now)?;
    if payload.prior_events.is_empty() || payload.prior_events.len() > 31 {
        return Err(invalid());
    }
    let coordinate = format!(
        "38900:{}:yellow-book:v1:{}",
        signer.npub(),
        signer.network()
    );
    let mut tags = vec![
        vec!["k".into(), "38900".into()],
        vec!["a".into(), coordinate],
    ];
    for event in &payload.prior_events {
        hex32(&event.id)?;
        if event.kind != 38900
            || event.pubkey != signer.npub().to_string()
            || event.created_at > now.inner()
            || serde_json::to_vec(event).map_err(|_| invalid())?.len() > MAX_EVENT_BYTES
        {
            return Err(invalid());
        }
        let d_tags: Vec<_> = event
            .tags
            .iter()
            .filter(|tag| tag.first().is_some_and(|name| name == "d"))
            .collect();
        if d_tags.len() != 1 || d_tags[0] != &listing_tags(signer)[0] {
            return Err(invalid());
        }
        let parsed: nostr::event::Event =
            serde_json::from_value(serde_json::to_value(event).map_err(|_| invalid())?)
                .map_err(|_| invalid())?;
        parsed.verify().map_err(|_| invalid())?;
        tags.push(vec!["e".into(), event.id.clone()]);
    }
    let content = json!({"schema":"yellow-book-v1", "network":signer.network().to_string(),
        "subjectNodeId":signer.to_string(), "status":"withdrawn"})
    .to_string();
    let withdrawal = sign_event(signer, keys, now, 38900, listing_tags(signer), content)?;
    if payload
        .prior_events
        .iter()
        .any(|event| event.id == withdrawal.id)
    {
        return Err(invalid());
    }
    let deletion = sign_event(signer, keys, now, 5, tags, String::new())?;
    Ok(SignedDirectoryWithdrawal {
        withdrawal,
        deletion,
    })
}

/// Fixed order and terminal LF; BIP340 over SHA256 of these UTF-8 bytes.
fn service_voice_text(admission: &ServiceVoiceAdmission) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        admission.schema,
        admission.network,
        admission.subject_node_id,
        admission.service_mint_node_id,
        admission.issued_at,
        admission.expires_at,
        admission.nonce
    )
}

pub fn sign_service_voice_admission(
    payload: &ServiceVoiceAdmissionPayload,
    signer: &NodeId,
    keys: &BcrKeys,
    default_mint: &NodeId,
    now: Timestamp,
    nonce: String,
) -> Result<SignedServiceVoiceAdmission> {
    check_signer(signer, keys, now)?;
    hex32(&nonce)?;
    if &payload.service_mint_node_id != default_mint || default_mint.network() != signer.network() {
        return Err(ProtocolValidationError::InvalidNodeId);
    }
    let lifetime = payload.lifetime_seconds.unwrap_or(300);
    if !(1..=300).contains(&lifetime) {
        return Err(ProtocolValidationError::InvalidTimestamp);
    }
    let expires_at = now
        .inner()
        .checked_add(lifetime)
        .filter(|v| *v <= MAX_SAFE_INTEGER)
        .ok_or(ProtocolValidationError::InvalidTimestamp)?;
    let admission = ServiceVoiceAdmission {
        schema: "service-voice-admission-v1".into(),
        network: signer.network().to_string(),
        subject_node_id: signer.to_string(),
        service_mint_node_id: default_mint.to_string(),
        issued_at: now.inner(),
        expires_at,
        nonce,
    };
    let signature = SECP256K1
        .sign_schnorr(
            &message(&service_voice_text(&admission)),
            &keys.get_key_pair(),
        )
        .to_string();
    Ok(SignedServiceVoiceAdmission {
        admission,
        signature,
    })
}

#[cfg(test)]
mod tests;
