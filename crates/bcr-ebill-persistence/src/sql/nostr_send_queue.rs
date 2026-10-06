use bcr_common::core::NodeId;
use bcr_ebill_core::protocol::Timestamp;
use sqlx::types::Text;

use crate::{Result, sql::timestamp_to_db, traits::nostr::NostrQueuedMessage};

pub(crate) const INSERT_MESSAGE: &str = r#"
    INSERT INTO nostr_send_queue (
        id,
        sender_id,
        recipient,
        payload,
        created,
        last_try,
        num_retries,
        max_retries,
        completed,
        failed,
        processing_started_at
    )
    VALUES (
        $1, $2, $3, $4, $5,
        $6, $7, $8, $9, $10, $11
    )
"#;

pub(crate) const SELECT_RETRY_MESSAGES: &str = r#"
    SELECT
        id,
        sender_id,
        recipient,
        payload,
        created,
        last_try,
        num_retries,
        max_retries,
        completed,
        failed,
        processing_started_at
    FROM nostr_send_queue
    WHERE completed = false
      AND processing_started_at < $1
    ORDER BY last_try ASC
    LIMIT $2
"#;

pub(crate) const SET_PROCESSING_STARTED_AT: &str = r#"
    UPDATE nostr_send_queue
    SET processing_started_at = $2
    WHERE id = $1
"#;

pub(crate) const FAIL_RETRY: &str = r#"
    UPDATE nostr_send_queue
    SET
        num_retries = num_retries + 1,
        last_try = $2,
        completed = CASE
            WHEN num_retries + 1 >= max_retries THEN true
            ELSE false
        END,
        failed = CASE
            WHEN num_retries + 1 >= max_retries THEN true
            ELSE failed
        END,
        processing_started_at = $3
    WHERE id = $1
"#;

pub(crate) const SUCCEED_RETRY: &str = r#"
    UPDATE nostr_send_queue
    SET
        completed = true,
        last_try = $2,
        processing_started_at = $3
    WHERE id = $1
"#;

pub(crate) const REQUEUE_FAILED_ENTRY: &str = r#"
    UPDATE nostr_send_queue
    SET
        completed = false,
        failed = false,
        num_retries = 0,
        processing_started_at = $2
    WHERE id = $1
      AND completed = true
      AND failed = true
"#;

pub(crate) const SELECT_NON_SUCCEEDED: &str = r#"
    SELECT
        id,
        sender_id,
        recipient,
        payload,
        created,
        last_try,
        num_retries,
        max_retries,
        completed,
        failed,
        processing_started_at
    FROM nostr_send_queue
    WHERE completed = false
       OR failed = true
    ORDER BY created ASC
"#;

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct NostrQueuedMessageRow {
    pub id: String,
    pub sender_id: Text<NodeId>,
    pub recipient: Option<Text<NodeId>>,
    pub payload: String,
    pub created: i64,
    pub last_try: i64,
    pub num_retries: i32,
    pub max_retries: i32,
    pub completed: bool,
    pub failed: bool,
    pub processing_started_at: i64,
}

impl NostrQueuedMessageRow {
    pub(crate) fn new(message: NostrQueuedMessage, max_retries: i32) -> Result<Self> {
        Ok(Self {
            id: message.id,
            sender_id: Text(message.sender_id),
            recipient: message.recipient.map(Text),
            payload: message.payload,
            created: timestamp_to_db(Timestamp::now())?,
            last_try: timestamp_to_db(Timestamp::zero())?,
            num_retries: 0,
            max_retries,
            completed: false,
            failed: false,
            processing_started_at: timestamp_to_db(Timestamp::zero())?,
        })
    }
}

impl From<NostrQueuedMessageRow> for NostrQueuedMessage {
    fn from(row: NostrQueuedMessageRow) -> Self {
        Self {
            id: row.id,
            sender_id: row.sender_id.into_inner(),
            recipient: row.recipient.map(Text::into_inner),
            payload: row.payload,
        }
    }
}
