use crate::{
    NostrEventOffset, Result,
    sql::{timestamp_from_db, timestamp_to_db},
};
use bcr_common::core::NodeId;
use sqlx::types::Text;

// SQL
pub(crate) const SELECT_CURRENT_OFFSET: &str = r#"
    SELECT time
    FROM nostr_event_offset
    WHERE node_id = $1
      AND success = TRUE
      AND ignored = FALSE
    ORDER BY time DESC
    LIMIT 1
"#;

pub(crate) const SELECT_EVENT_ID: &str = r#"
    SELECT event_id
    FROM nostr_event_offset
    WHERE event_id = $1
      AND success = TRUE
    LIMIT 1
"#;

pub(crate) const INSERT_EVENT: &str = r#"
    INSERT INTO nostr_event_offset (
        event_id,
        time,
        success,
        node_id
    )
    VALUES ($1, $2, $3, $4)
    ON CONFLICT(event_id) DO UPDATE SET
        success = TRUE,
        time = EXCLUDED.time,
        node_id = EXCLUDED.node_id
    WHERE EXCLUDED.success = TRUE
      AND nostr_event_offset.success = FALSE
"#;

pub(crate) const SELECT_CATCHUP_UNTIL: &str = r#"
    SELECT until_seconds
    FROM nostr_catchup_cursor
    WHERE scope = $1
      AND subject_id = $2
      AND relay_url = $3
"#;

pub(crate) const UPSERT_CATCHUP_UNTIL: &str = r#"
    INSERT INTO nostr_catchup_cursor (
        scope, subject_id, relay_url, until_seconds
    )
    VALUES ($1, $2, $3, $4)
    ON CONFLICT(scope, subject_id, relay_url)
    DO UPDATE SET until_seconds = EXCLUDED.until_seconds
"#;

pub(crate) const DELETE_CATCHUP_UNTIL: &str = r#"
    DELETE FROM nostr_catchup_cursor
    WHERE scope = $1
      AND subject_id = $2
      AND relay_url = $3
"#;

pub(crate) const IGNORE_PRIVATE_EVENT: &str = r#"
    INSERT INTO nostr_event_offset (
        event_id, time, success, node_id,
        ignored, ignore_reason
    )
    VALUES ($1, $2, TRUE, $3, TRUE, $4)
    ON CONFLICT(event_id) DO UPDATE SET
        success = TRUE,
        ignored = TRUE,
        ignore_reason = EXCLUDED.ignore_reason,
        time = EXCLUDED.time,
        node_id = EXCLUDED.node_id
    WHERE nostr_event_offset.success = FALSE
"#;

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct NostrEventOffsetRow {
    pub event_id: String,
    pub time: i64,
    pub success: bool,
    pub node_id: Text<NodeId>,
}

impl TryFrom<NostrEventOffset> for NostrEventOffsetRow {
    type Error = crate::Error;

    fn try_from(offset: NostrEventOffset) -> Result<Self> {
        Ok(Self {
            event_id: offset.event_id,
            time: timestamp_to_db(offset.time)?,
            success: offset.success,
            node_id: Text(offset.node_id),
        })
    }
}

impl TryFrom<NostrEventOffsetRow> for NostrEventOffset {
    type Error = crate::Error;

    fn try_from(row: NostrEventOffsetRow) -> Result<Self> {
        Ok(Self {
            event_id: row.event_id,
            time: timestamp_from_db(row.time)?,
            success: row.success,
            node_id: row.node_id.into_inner(),
        })
    }
}
