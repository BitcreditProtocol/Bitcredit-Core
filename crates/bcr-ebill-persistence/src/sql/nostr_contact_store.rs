use std::str::FromStr;

use crate::{
    Error, Result,
    sql::{timestamp_from_db, timestamp_to_db},
    traits::nostr::{PendingContactShare, RelaySyncStatus, ShareDirection, SyncStatus},
};
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    application::nostr_contact::{HandshakeStatus, NostrContact, NostrPublicKey, TrustLevel},
    protocol::{Name, SecretKey},
};
use sqlx::types::Text;

// SQL
pub(crate) const CONTACT_SELECT_BASE: &str = r#"
    SELECT
        id,
        node_id,
        name,
        relays,
        blossom_servers,
        trust_level,
        handshake_status,
        contact_private_key,
        mint_url
    FROM nostr_contact
"#;

pub(crate) const SELECT_CONTACT_BY_ID: &str = r#"
    SELECT
        id,
        node_id,
        name,
        relays,
        blossom_servers,
        trust_level,
        handshake_status,
        contact_private_key,
        mint_url
    FROM nostr_contact
    WHERE id = $1
"#;

pub(crate) const UPSERT_CONTACT: &str = r#"
    INSERT INTO nostr_contact (
        id,
        node_id,
        name,
        relays,
        blossom_servers,
        trust_level,
        handshake_status,
        contact_private_key,
        mint_url
    )
    VALUES (
        $1, $2, $3, $4, $5,
        $6, $7, $8, $9
    )
    ON CONFLICT (id)
    DO UPDATE SET
        node_id = excluded.node_id,
        name = excluded.name,
        relays = excluded.relays,
        blossom_servers = excluded.blossom_servers,
        trust_level = excluded.trust_level,
        handshake_status = excluded.handshake_status,
        contact_private_key = excluded.contact_private_key,
        mint_url = excluded.mint_url
"#;

pub(crate) const DELETE_CONTACT: &str = r#"
    DELETE FROM nostr_contact
    WHERE id = $1
"#;

pub(crate) const UPDATE_HANDSHAKE_STATUS: &str = r#"
    UPDATE nostr_contact
    SET handshake_status = $2
    WHERE id = $1
"#;

pub(crate) const UPDATE_TRUST_LEVEL: &str = r#"
    UPDATE nostr_contact
    SET trust_level = $2
    WHERE id = $1
"#;

// Pending contact share queries
pub(crate) const UPSERT_PENDING_SHARE: &str = r#"
    INSERT INTO pending_contact_share (
        id,
        node_id,
        contact,
        sender_node_id,
        contact_private_key,
        receiver_node_id,
        received_at,
        direction,
        initial_share_id
    )
    VALUES (
        $1, $2, $3, $4, $5,
        $6, $7, $8, $9
    )
    ON CONFLICT (id)
    DO UPDATE SET
        node_id = excluded.node_id,
        contact = excluded.contact,
        sender_node_id = excluded.sender_node_id,
        contact_private_key = excluded.contact_private_key,
        receiver_node_id = excluded.receiver_node_id,
        received_at = excluded.received_at,
        direction = excluded.direction,
        initial_share_id = excluded.initial_share_id
"#;

pub(crate) const SELECT_PENDING_SHARE: &str = r#"
    SELECT
        id,
        node_id,
        contact,
        sender_node_id,
        contact_private_key,
        receiver_node_id,
        received_at,
        direction,
        initial_share_id
    FROM pending_contact_share
    WHERE id = $1
"#;

pub(crate) const SELECT_PENDING_SHARES_BY_RECEIVER: &str = r#"
    SELECT
        id,
        node_id,
        contact,
        sender_node_id,
        contact_private_key,
        receiver_node_id,
        received_at,
        direction,
        initial_share_id
    FROM pending_contact_share
    WHERE receiver_node_id = $1
    ORDER BY received_at DESC
"#;

pub(crate) const SELECT_PENDING_SHARES_BY_RECEIVER_DIRECTION: &str = r#"
    SELECT
        id,
        node_id,
        contact,
        sender_node_id,
        contact_private_key,
        receiver_node_id,
        received_at,
        direction,
        initial_share_id
    FROM pending_contact_share
    WHERE receiver_node_id = $1
      AND direction = $2
    ORDER BY received_at DESC
"#;

pub(crate) const DELETE_PENDING_SHARE: &str = r#"
    DELETE FROM pending_contact_share
    WHERE id = $1
"#;

pub(crate) const SELECT_PENDING_SHARE_EXISTS: &str = r#"
    SELECT EXISTS (
        SELECT 1
        FROM pending_contact_share
        WHERE node_id = $1
          AND receiver_node_id = $2
          AND direction = $3
    )
"#;

// Relay sync status queries
pub(crate) const SELECT_PENDING_RELAYS: &str = r#"
    SELECT relay_url
    FROM relay_sync_status
    WHERE sync_status IN (
        'pending',
        'in_progress',
        'failed'
    )
"#;

pub(crate) const SELECT_RELAY_SYNC_STATUS: &str = r#"
    SELECT
        id,
        relay_url,
        last_seen_in_config,
        sync_status,
        events_synced,
        last_synced_timestamp,
        last_error
    FROM relay_sync_status
    WHERE relay_url = $1
    LIMIT 1
"#;

pub(crate) const UPSERT_RELAY_SYNC_STATUS: &str = r#"
    INSERT INTO relay_sync_status (
        id,
        relay_url,
        last_seen_in_config,
        sync_status,
        events_synced,
        last_synced_timestamp,
        last_error
    )
    VALUES (
        $1, $1, $2, $3,
        0, NULL, NULL
    )
    ON CONFLICT (id)
    DO UPDATE SET
        sync_status = excluded.sync_status,
        last_error = CASE
            WHEN excluded.sync_status = 'completed'
                THEN NULL
            ELSE relay_sync_status.last_error
        END
"#;

pub(crate) const UPDATE_RELAY_SYNC_PROGRESS: &str = r#"
    UPDATE relay_sync_status
    SET
        events_synced = events_synced + 1,
        last_synced_timestamp = $2
    WHERE relay_url = $1
"#;

pub(crate) const UPSERT_RELAY_LAST_SEEN: &str = r#"
    INSERT INTO relay_sync_status (
        id,
        relay_url,
        last_seen_in_config,
        sync_status,
        events_synced,
        last_synced_timestamp,
        last_error
    )
    VALUES (
        $1, $1, $2,
        'pending',
        0,
        NULL,
        NULL
    )
    ON CONFLICT (id)
    DO UPDATE SET
        last_seen_in_config = excluded.last_seen_in_config
"#;

// Relay retry queries
pub(crate) const INSERT_RELAY_RETRY: &str = r#"
    INSERT INTO relay_sync_retry (
        id,
        relay_url,
        event_id,
        event,
        retry_count,
        created_at,
        last_retry_at
    )
    VALUES (
        $1, $2, $3, $4,
        $5, $6, $7
    )
"#;

pub(crate) const SELECT_PENDING_RELAY_RETRIES: &str = r#"
    SELECT
        id,
        relay_url,
        event_id,
        event,
        retry_count,
        created_at,
        last_retry_at
    FROM relay_sync_retry
    WHERE relay_url = $1
    LIMIT $2
"#;

pub(crate) const DELETE_RELAY_RETRY: &str = r#"
    DELETE FROM relay_sync_retry
    WHERE relay_url = $1
      AND event_id = $2
"#;

pub(crate) const SELECT_RELAY_RETRY_COUNT: &str = r#"
    SELECT retry_count
    FROM relay_sync_retry
    WHERE relay_url = $1
      AND event_id = $2
    LIMIT 1
"#;

pub(crate) const UPDATE_RELAY_RETRY_FAILED: &str = r#"
    UPDATE relay_sync_retry
    SET
        retry_count = retry_count + 1,
        last_retry_at = $3
    WHERE relay_url = $1
      AND event_id = $2
"#;

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct NostrContactRow {
    pub id: String,
    pub node_id: Text<NodeId>,
    pub name: Option<Text<Name>>,
    pub relays: String,
    pub blossom_servers: String,
    pub trust_level: String,
    pub handshake_status: String,
    pub contact_private_key: Option<String>,
    pub mint_url: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct PendingContactShareRow {
    pub id: String,
    pub node_id: Text<NodeId>,
    pub contact: String,
    pub sender_node_id: Text<NodeId>,
    pub contact_private_key: String,
    pub receiver_node_id: Text<NodeId>,
    pub received_at: i64,
    pub direction: String,
    pub initial_share_id: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(unused)]
pub(crate) struct RelaySyncRetryRow {
    pub id: String,
    pub relay_url: String,
    pub event_id: String,
    pub event: String,
    pub retry_count: i64,
    pub created_at: i64,
    pub last_retry_at: Option<i64>,
}

impl RelaySyncRetryRow {
    pub(crate) fn into_event(self) -> Result<nostr::event::Event> {
        crate::sql::nostr_chain_event::deserialize_payload(&self.event)
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct RelaySyncStatusRow {
    #[allow(unused)]
    pub id: String,
    pub relay_url: String,
    pub last_seen_in_config: i64,
    pub sync_status: String,
    pub events_synced: i64,
    pub last_synced_timestamp: Option<i64>,
    pub last_error: Option<String>,
}

pub(crate) fn nostr_contact_to_row(contact: &NostrContact) -> Result<NostrContactRow> {
    let relays = serde_json::to_string(&contact.relays).map_err(|e| {
        Error::InvalidData(format!("could not serialize nostr contact relays: {e}"))
    })?;
    let blossom_servers = serde_json::to_string(&contact.blossom_servers)
        .map_err(|e| Error::InvalidData(format!("could not serialize blossom servers: {e}")))?;
    Ok(NostrContactRow {
        id: contact.npub.to_hex(),
        node_id: Text(contact.node_id.clone()),
        name: contact.name.clone().map(Text),
        relays,
        blossom_servers,
        trust_level: trust_level_to_db(&contact.trust_level).to_owned(),
        handshake_status: handshake_status_to_db(&contact.handshake_status).to_owned(),
        contact_private_key: contact
            .contact_private_key
            .map(|v| v.display_secret().to_string()),
        mint_url: contact.mint_url.as_ref().map(url::Url::to_string),
    })
}

impl TryFrom<NostrContactRow> for NostrContact {
    type Error = Error;

    fn try_from(row: NostrContactRow) -> Result<Self> {
        let relays = serde_json::from_str(&row.relays).map_err(|e| {
            Error::InvalidData(format!("invalid persisted nostr contact relays: {e}"))
        })?;
        let blossom_servers = serde_json::from_str(&row.blossom_servers).map_err(|e| {
            Error::InvalidData(format!(
                "invalid persisted nostr contact blossom_servers: {e}"
            ))
        })?;
        Ok(Self {
            npub: NostrPublicKey::parse(&row.id).map_err(|_| Error::EncodingError)?,
            node_id: row.node_id.into_inner(),
            name: row.name.map(Text::into_inner),
            relays,
            blossom_servers,
            trust_level: trust_level_from_db(&row.trust_level)?,
            handshake_status: handshake_status_from_db(&row.handshake_status)?,
            contact_private_key: row
                .contact_private_key
                .map(|v| SecretKey::from_str(&v))
                .transpose()
                .map_err(|e| Error::InvalidData(format!("invalid contact private key: {e}")))?,
            mint_url: row
                .mint_url
                .map(|value| {
                    url::Url::parse(&value).map_err(|_| {
                        Error::InvalidData(format!("invalid persisted mint URL: {value}"))
                    })
                })
                .transpose()?,
        })
    }
}

impl TryFrom<PendingContactShare> for PendingContactShareRow {
    type Error = Error;

    fn try_from(share: PendingContactShare) -> Result<Self> {
        let contact = serde_json::to_string(&share.contact).map_err(|e| {
            Error::InvalidData(format!("could not serialize pending contact share: {e}"))
        })?;
        Ok(Self {
            id: share.id,
            node_id: Text(share.node_id),
            contact,
            sender_node_id: Text(share.sender_node_id),
            contact_private_key: share.contact_private_key.display_secret().to_string(),
            receiver_node_id: Text(share.receiver_node_id),
            received_at: timestamp_to_db(share.received_at)?,
            direction: share_direction_to_db(&share.direction).to_owned(),
            initial_share_id: share.initial_share_id,
        })
    }
}

impl TryFrom<PendingContactShareRow> for PendingContactShare {
    type Error = Error;

    fn try_from(row: PendingContactShareRow) -> Result<Self> {
        let contact = serde_json::from_str(&row.contact)
            .map_err(|e| Error::InvalidData(format!("invalid persisted nostr contact: {e}")))?;
        Ok(Self {
            id: row.id,
            node_id: row.node_id.into_inner(),
            contact,
            sender_node_id: row.sender_node_id.into_inner(),
            contact_private_key: SecretKey::from_str(&row.contact_private_key)
                .map_err(|e| Error::InvalidData(format!("invalid contact private key: {e}")))?,
            receiver_node_id: row.receiver_node_id.into_inner(),
            received_at: timestamp_from_db(row.received_at)?,
            direction: share_direction_from_db(&row.direction)?,
            initial_share_id: row.initial_share_id,
        })
    }
}

impl TryFrom<RelaySyncStatusRow> for RelaySyncStatus {
    type Error = Error;

    fn try_from(row: RelaySyncStatusRow) -> Result<Self> {
        let events_synced = usize::try_from(row.events_synced).map_err(|_| {
            Error::InvalidData(format!(
                "invalid persisted relay events_synced: {}",
                row.events_synced
            ))
        })?;

        Ok(Self {
            relay_url: url::Url::parse(&row.relay_url).map_err(|_| {
                Error::InvalidData(format!("invalid persisted relay URL: {}", row.relay_url))
            })?,
            last_seen_in_config: timestamp_from_db(row.last_seen_in_config)?,
            sync_status: sync_status_from_db(&row.sync_status)?,
            events_synced,
            last_synced_timestamp: row
                .last_synced_timestamp
                .map(timestamp_from_db)
                .transpose()?,
            last_error: row.last_error,
        })
    }
}

pub(crate) fn trust_level_to_db(value: &TrustLevel) -> &'static str {
    match value {
        TrustLevel::None => "none",
        TrustLevel::Participant => "participant",
        TrustLevel::Trusted => "trusted",
        TrustLevel::Banned => "banned",
    }
}

fn trust_level_from_db(value: &str) -> Result<TrustLevel> {
    match value {
        "none" => Ok(TrustLevel::None),
        "participant" => Ok(TrustLevel::Participant),
        "trusted" => Ok(TrustLevel::Trusted),
        "banned" => Ok(TrustLevel::Banned),
        other => Err(Error::InvalidData(format!(
            "invalid persisted trust level: {other}"
        ))),
    }
}

pub(crate) fn handshake_status_to_db(value: &HandshakeStatus) -> &'static str {
    match value {
        HandshakeStatus::None => "none",
        HandshakeStatus::InProgress => "in_progress",
        HandshakeStatus::Added => "added",
    }
}

fn handshake_status_from_db(value: &str) -> Result<HandshakeStatus> {
    match value {
        "none" => Ok(HandshakeStatus::None),
        "in_progress" => Ok(HandshakeStatus::InProgress),
        "added" => Ok(HandshakeStatus::Added),
        other => Err(Error::InvalidData(format!(
            "invalid persisted handshake status: {other}"
        ))),
    }
}

pub(crate) fn share_direction_to_db(value: &ShareDirection) -> &'static str {
    match value {
        ShareDirection::Incoming => "incoming",
        ShareDirection::Outgoing => "outgoing",
    }
}

fn share_direction_from_db(value: &str) -> Result<ShareDirection> {
    match value {
        "incoming" => Ok(ShareDirection::Incoming),
        "outgoing" => Ok(ShareDirection::Outgoing),
        other => Err(Error::InvalidData(format!(
            "invalid persisted contact share direction: {other}"
        ))),
    }
}

pub(crate) fn sync_status_to_db(value: &SyncStatus) -> &'static str {
    match value {
        SyncStatus::Pending => "pending",
        SyncStatus::InProgress => "in_progress",
        SyncStatus::Completed => "completed",
        SyncStatus::Failed => "failed",
    }
}

fn sync_status_from_db(value: &str) -> Result<SyncStatus> {
    match value {
        "pending" => Ok(SyncStatus::Pending),
        "in_progress" => Ok(SyncStatus::InProgress),
        "completed" => Ok(SyncStatus::Completed),
        "failed" => Ok(SyncStatus::Failed),
        other => Err(Error::InvalidData(format!(
            "invalid persisted relay sync status: {other}"
        ))),
    }
}
