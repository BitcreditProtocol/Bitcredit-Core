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
    ORDER BY time DESC
    LIMIT 1
"#;

pub(crate) const SELECT_EVENT_ID: &str = r#"
    SELECT event_id
    FROM nostr_event_offset
    WHERE event_id = $1
    LIMIT 1
"#;

pub(crate) const INSERT_EVENT: &str = r#"
    INSERT INTO nostr_event_offset (
        event_id,
        time,
        success,
        node_id
    )
    VALUES (
        $1, $2, $3, $4
    )
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
