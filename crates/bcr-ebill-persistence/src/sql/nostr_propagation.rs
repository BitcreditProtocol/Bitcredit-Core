use std::collections::HashMap;

use crate::{
    EncryptionContext, Error, Result,
    sql::{timestamp_from_db, unit_enum_from_db},
    traits::propagation::{
        PendingDelivery, PropagationMessageStatus, PropagationStatus, PropagationSubjectType,
        RelayPropagationStatus,
    },
};
use bcr_common::core::NodeId;
use bcr_ebill_core::protocol::Sha256Hash;
use sqlx::types::Text;

// SQL

pub(crate) const INSERT_PROPAGATION: &str = r#"
    INSERT INTO nostr_propagations (
        id,
        subject_type,
        subject_id,
        created_at
    )
    VALUES ($1, $2, $3, $4)
"#;

pub(crate) const INSERT_MESSAGE: &str = r#"
    INSERT INTO nostr_propagation_messages (
        id,
        propagation_id,
        event_type,
        recipient_id,
        chain_id,
        block_hash,
        nostr_event_id,
        payload
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
"#;

pub(crate) const INSERT_RELAY: &str = r#"
    INSERT INTO nostr_propagation_relays (
        message_id,
        relay_url
    )
    VALUES ($1, $2)
"#;

pub(crate) const SELECT_PROPAGATION: &str = r#"
    SELECT id, subject_type, subject_id, created_at
    FROM nostr_propagations
    WHERE id = $1
"#;

pub(crate) const SELECT_PROPAGATION_IDS_BY_SUBJECT: &str = r#"
    SELECT id
    FROM nostr_propagations
    WHERE subject_type = $1 AND subject_id = $2
    ORDER BY created_at DESC, id DESC
"#;

pub(crate) const SELECT_PROPAGATION_MESSAGES: &str = r#"
    SELECT
        id, event_type, recipient_id,
        chain_id, block_hash, nostr_event_id
    FROM nostr_propagation_messages
    WHERE propagation_id = $1
    ORDER BY id
"#;

pub(crate) const SELECT_PROPAGATION_RELAYS: &str = r#"
    SELECT
        r.message_id, r.relay_url, r.accepted_at,
        r.attempts, r.next_try_at, r.last_error
    FROM nostr_propagation_relays r
    JOIN nostr_propagation_messages m
        ON m.id = r.message_id
    WHERE m.propagation_id = $1
    ORDER BY r.message_id, r.relay_url
"#;

// select pending deliveries, but make sure we propagate in order if there are multiple unpropagated blocks
// for the same subject
pub(crate) const SELECT_PENDING_DELIVERIES: &str = r#"
    SELECT
        m.id AS message_id,
        m.propagation_id,
        m.nostr_event_id,
        m.payload,
        r.relay_url,
        r.attempts
    FROM nostr_propagation_relays r
    JOIN nostr_propagation_messages m
        ON m.id = r.message_id
    WHERE r.accepted_at IS NULL
      AND r.next_try_at <= $1
      AND NOT EXISTS (
          SELECT 1
          FROM nostr_chain_event child
          JOIN nostr_propagation_messages parent_message
              ON parent_message.nostr_event_id = child.reply_id
          JOIN nostr_propagation_relays parent_relay
              ON parent_relay.message_id = parent_message.id
             AND parent_relay.relay_url = r.relay_url
          WHERE child.event_id = m.nostr_event_id
            AND parent_relay.accepted_at IS NULL
      )
    ORDER BY r.next_try_at, m.id, r.relay_url
    LIMIT $2
"#;

// select pending to propagate, but make sure we propagate in order if there are multiple unpropagated blocks
// for the same subject
pub(crate) const SELECT_PENDING_FOR_PROPAGATION: &str = r#"
    SELECT
        m.id AS message_id,
        m.propagation_id,
        m.nostr_event_id,
        m.payload,
        r.relay_url,
        r.attempts
    FROM nostr_propagation_messages m
    JOIN nostr_propagation_relays r
        ON r.message_id = m.id
    WHERE m.propagation_id = $1
      AND r.accepted_at IS NULL
      AND r.next_try_at <= $2
      AND NOT EXISTS (
          SELECT 1
          FROM nostr_chain_event child
          JOIN nostr_propagation_messages parent_message
              ON parent_message.nostr_event_id = child.reply_id
          JOIN nostr_propagation_relays parent_relay
              ON parent_relay.message_id = parent_message.id
             AND parent_relay.relay_url = r.relay_url
          WHERE child.event_id = m.nostr_event_id
            AND parent_relay.accepted_at IS NULL
      )
    ORDER BY r.next_try_at, m.id, r.relay_url
"#;

// we never overwrite accepted propagations
pub(crate) const MARK_RELAY_ACCEPTED: &str = r#"
    UPDATE nostr_propagation_relays
    SET
        accepted_at = $3,
        attempts = attempts + 1,
        next_try_at = 0,
        last_error = NULL
    WHERE message_id = $1
      AND relay_url = $2
      AND accepted_at IS NULL
"#;

// we never overwrite accepted propagations
pub(crate) const MARK_RELAY_FAILED: &str = r#"
    UPDATE nostr_propagation_relays
    SET
        attempts = attempts + 1,
        next_try_at = $3,
        last_error = $4
    WHERE message_id = $1
      AND relay_url = $2
      AND accepted_at IS NULL
"#;

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct PropagationRow {
    pub id: String,
    pub subject_type: String,
    pub subject_id: String,
    pub created_at: i64,
}

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct PropagationMessageRow {
    pub id: String,
    pub event_type: String,
    pub recipient_id: Option<Text<NodeId>>,
    pub chain_id: Option<String>,
    pub block_hash: Option<Text<Sha256Hash>>,
    pub nostr_event_id: String,
}

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct PropagationRelayRow {
    pub message_id: String,
    pub relay_url: String,
    pub accepted_at: Option<i64>,
    pub attempts: i32,
    pub next_try_at: i64,
    pub last_error: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct PendingDeliveryRow {
    pub message_id: String,
    pub propagation_id: String,
    pub nostr_event_id: String,
    pub payload: Vec<u8>,
    pub relay_url: String,
    pub attempts: i32,
}

fn subject_type_from_db(value: &str) -> Result<PropagationSubjectType> {
    match value {
        "bill" => Ok(PropagationSubjectType::Bill),
        "identity" => Ok(PropagationSubjectType::Identity),
        "company" => Ok(PropagationSubjectType::Company),
        "contact" => Ok(PropagationSubjectType::Contact),
        other => Err(Error::InvalidData(format!(
            "Unknown propagation subject type: {other}"
        ))),
    }
}

pub(crate) fn build_propagation_status(
    propagation: PropagationRow,
    message_rows: Vec<PropagationMessageRow>,
    relay_rows: Vec<PropagationRelayRow>,
) -> Result<PropagationStatus> {
    let mut messages = Vec::with_capacity(message_rows.len());
    let mut message_indices = HashMap::new();
    for row in message_rows {
        message_indices.insert(row.id.clone(), messages.len());
        messages.push(PropagationMessageStatus {
            id: row.id,
            event_type: unit_enum_from_db(row.event_type)?,
            recipient_id: row.recipient_id.map(Text::into_inner),
            chain_id: row.chain_id,
            block_hash: row.block_hash.map(Text::into_inner),
            nostr_event_id: row.nostr_event_id,
            relays: Vec::new(),
        });
    }

    for row in relay_rows {
        let index = message_indices.get(&row.message_id).ok_or_else(|| {
            Error::InvalidData(format!(
                "Relay references unknown message: {}",
                row.message_id
            ))
        })?;
        let relay_url = url::Url::parse(&row.relay_url)
            .map_err(|e| Error::InvalidData(format!("Invalid persisted relay URL: {e}")))?;
        let attempts = u32::try_from(row.attempts)
            .map_err(|_| Error::InvalidData("Negative relay attempt count".into()))?;
        messages[*index].relays.push(RelayPropagationStatus {
            relay_url,
            accepted_at: row.accepted_at.map(timestamp_from_db).transpose()?,
            attempts,
            next_try_at: timestamp_from_db(row.next_try_at)?,
            last_error: row.last_error,
        });
    }

    Ok(PropagationStatus {
        id: propagation.id,
        subject_type: subject_type_from_db(&propagation.subject_type)?,
        subject_id: propagation.subject_id,
        created_at: timestamp_from_db(propagation.created_at)?,
        messages,
    })
}

impl PendingDeliveryRow {
    pub(crate) fn decrypt(self, encryption_ctx: &EncryptionContext) -> Result<PendingDelivery> {
        let plaintext = encryption_ctx.decrypt(&self.payload)?;
        let event: nostr::event::Event = serde_json::from_slice(&plaintext)?;
        // verify the decrypted event matches the message metadata
        if event.id.to_string() != self.nostr_event_id {
            return Err(Error::InvalidData(format!(
                "Nostr event ID mismatch for message {}",
                self.message_id
            )));
        }
        let relay_url = url::Url::parse(&self.relay_url)
            .map_err(|e| Error::InvalidData(format!("Invalid persisted relay URL: {e}")))?;
        let attempts = u32::try_from(self.attempts)
            .map_err(|_| Error::InvalidData("Negative relay attempt count".into()))?;
        Ok(PendingDelivery {
            message_id: self.message_id,
            propagation_id: self.propagation_id,
            relay_url,
            event,
            attempts,
        })
    }
}
