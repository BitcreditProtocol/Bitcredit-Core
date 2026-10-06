use crate::{
    Error, Result,
    sql::{timestamp_from_db, timestamp_to_db},
    traits::nostr::NostrChainEvent,
};
use bcr_ebill_core::protocol::{Sha256Hash, blockchain::BlockchainType};
use nostr::event::Event;
use serde::{Deserialize, Serialize};
use sqlx::types::Text;

// SQL
pub(crate) const SELECT_CHAIN_EVENTS: &str = r#"
    SELECT
        event_id,
        root_id,
        reply_id,
        author,
        chain_id,
        chain_type,
        block_height,
        block_hash,
        received,
        time,
        payload
    FROM nostr_chain_event
    WHERE chain_id = $1
      AND chain_type = $2
    ORDER BY block_height DESC
"#;

pub(crate) const SELECT_LATEST_BLOCK_EVENTS: &str = r#"
    SELECT
        event_id,
        root_id,
        reply_id,
        author,
        chain_id,
        chain_type,
        block_height,
        block_hash,
        received,
        time,
        payload
    FROM nostr_chain_event
    WHERE chain_id = $1
      AND chain_type = $2
      AND block_height = (
          SELECT MAX(block_height)
          FROM nostr_chain_event
          WHERE chain_id = $1
            AND chain_type = $2
      )
"#;

pub(crate) const SELECT_BY_BLOCK_HASH: &str = r#"
    SELECT
        event_id,
        root_id,
        reply_id,
        author,
        chain_id,
        chain_type,
        block_height,
        block_hash,
        received,
        time,
        payload
    FROM nostr_chain_event
    WHERE block_hash = $1
    ORDER BY
        block_height DESC,
        received DESC
    LIMIT 1
"#;

pub(crate) const SELECT_BY_EVENT_ID: &str = r#"
    SELECT
        event_id,
        root_id,
        reply_id,
        author,
        chain_id,
        chain_type,
        block_height,
        block_hash,
        received,
        time,
        payload
    FROM nostr_chain_event
    WHERE event_id = $1
"#;

pub(crate) const SELECT_ROOT_EVENT: &str = r#"
    SELECT
        event_id,
        root_id,
        reply_id,
        author,
        chain_id,
        chain_type,
        block_height,
        block_hash,
        received,
        time,
        payload
    FROM nostr_chain_event
    WHERE chain_id = $1
      AND chain_type = $2
      AND event_id = root_id
    LIMIT 1
"#;

pub(crate) const UPSERT_CHAIN_EVENT: &str = r#"
    INSERT INTO nostr_chain_event (
        event_id,
        root_id,
        reply_id,
        author,
        chain_id,
        chain_type,
        block_height,
        block_hash,
        received,
        time,
        payload
    )
    VALUES (
        $1, $2, $3, $4, $5, $6,
        $7, $8, $9, $10, $11
    )
    ON CONFLICT (event_id)
    DO UPDATE SET
        root_id = excluded.root_id,
        reply_id = excluded.reply_id,
        author = excluded.author,
        chain_id = excluded.chain_id,
        chain_type = excluded.chain_type,
        block_height = excluded.block_height,
        block_hash = excluded.block_hash,
        received = excluded.received,
        time = excluded.time,
        payload = excluded.payload
"#;

pub(crate) const DELETE_CHAIN_EVENTS: &str = r#"
    DELETE FROM nostr_chain_event
    WHERE chain_id = $1
      AND chain_type = $2
"#;

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct NostrChainEventRow {
    pub event_id: String,
    pub root_id: String,
    pub reply_id: Option<String>,
    pub author: String,
    pub chain_id: String,
    pub chain_type: String,
    pub block_height: i64,
    pub block_hash: Text<Sha256Hash>,
    pub received: i64,
    pub time: i64,
    pub payload: String,
}

impl TryFrom<NostrChainEvent> for NostrChainEventRow {
    type Error = Error;

    fn try_from(event: NostrChainEvent) -> Result<Self> {
        let block_height = i64::try_from(event.block_height).map_err(|_| {
            Error::InvalidData("nostr chain event block height exceeds i64".to_owned())
        })?;
        Ok(Self {
            event_id: event.event_id,
            root_id: event.root_id,
            reply_id: event.reply_id,
            author: event.author,
            chain_id: event.chain_id,
            chain_type: event.chain_type.to_string(),
            block_height,
            block_hash: Text(event.block_hash),
            received: timestamp_to_db(event.received)?,
            time: timestamp_to_db(event.time)?,
            payload: serialize_payload(event.payload)?,
        })
    }
}

impl TryFrom<NostrChainEventRow> for NostrChainEvent {
    type Error = Error;

    fn try_from(row: NostrChainEventRow) -> Result<Self> {
        let chain_type = BlockchainType::try_from(row.chain_type.as_str()).map_err(|e| {
            Error::InvalidData(format!(
                "invalid persisted blockchain type '{}': {e}",
                row.chain_type
            ))
        })?;
        let block_height = usize::try_from(row.block_height).map_err(|_| {
            Error::InvalidData(format!(
                "invalid persisted nostr chain block height: {}",
                row.block_height
            ))
        })?;
        Ok(Self {
            event_id: row.event_id,
            root_id: row.root_id,
            reply_id: row.reply_id,
            author: row.author,
            chain_id: row.chain_id,
            chain_type,
            block_height,
            block_hash: row.block_hash.into_inner(),
            received: timestamp_from_db(row.received)?,
            time: timestamp_from_db(row.time)?,
            payload: deserialize_payload(&row.payload)?,
        })
    }
}

pub(crate) fn serialize_payload(event: Event) -> Result<String> {
    let event = NostrEventDb::try_from(event)?;
    serde_json::to_string(&event).map_err(|e| {
        Error::InvalidData(format!(
            "could not serialize nostr chain event payload: {e}"
        ))
    })
}

pub(crate) fn deserialize_payload(payload: &str) -> Result<Event> {
    let event: NostrEventDb = serde_json::from_str(payload).map_err(|e| {
        Error::InvalidData(format!("invalid persisted nostr chain event payload: {e}"))
    })?;
    event.try_into()
}

/// Nostr event persistence representation.
///
/// Keep this representation rather than serializing `nostr::Event`
/// directly. In particular, the schnorr signature representation
/// preserves compatibility with events persisted before nostr 0.45.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrEventDb {
    id: nostr::event::EventId,
    pubkey: nostr::key::PublicKey,
    created_at: nostr::types::Timestamp,
    kind: nostr::event::Kind,
    tags: nostr::event::Tags,
    content: String,
    // Use the pre-nostr-0.45 representation as bytes for backwards compat.
    sig: bitcoin::secp256k1::schnorr::Signature,
}

impl TryFrom<Event> for NostrEventDb {
    type Error = Error;

    fn try_from(event: Event) -> Result<Self> {
        Ok(Self {
            id: event.id,
            pubkey: event.pubkey,
            created_at: event.created_at,
            kind: event.kind,
            tags: event.tags,
            content: event.content,
            sig: bitcoin::secp256k1::schnorr::Signature::from_slice(event.sig.as_bytes()).map_err(
                |e| {
                    Error::Persistence(format!(
                        "could not create schnorr signature from nostr signature: {e}"
                    ))
                },
            )?,
        })
    }
}

impl TryFrom<NostrEventDb> for Event {
    type Error = Error;
    fn try_from(value: NostrEventDb) -> Result<Self> {
        let sig = nostr::event::Signature::from_slice(&value.sig.serialize()).map_err(|e| {
            Error::Persistence(format!(
                "could not create nostr signature from persisted signature: {e}"
            ))
        })?;
        Ok(Event::new(
            value.id,
            value.pubkey,
            value.created_at,
            value.kind,
            value.tags,
            value.content,
            sig,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::deserialize_payload;

    #[test]
    fn reads_payload_persisted_with_nostr_0_43() {
        let keys = nostr_043::key::Keys::generate();
        let legacy_event =
            nostr_043::event::EventBuilder::new(nostr_043::event::Kind::TextNote, "legacy content")
                .sign_with_keys(&keys)
                .expect("could not create legacy event");
        let payload =
            serde_json::to_string(&legacy_event).expect("could not serialize legacy event");
        let loaded = deserialize_payload(&payload).expect("could not decode legacy nostr payload");
        assert_eq!(loaded.content, "legacy content");
    }
}
