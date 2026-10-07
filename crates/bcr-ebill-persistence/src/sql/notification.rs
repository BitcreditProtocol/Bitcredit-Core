use crate::{
    Error, Result,
    sql::{timestamp_from_db, timestamp_to_db},
};
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    application::notification::{Notification, NotificationLevel, NotificationType},
    protocol::{Timestamp, event::bill_events::ActionType},
};
use serde_json::Value;
use sqlx::types::Text;

// SQL
pub(crate) const SELECT_NOTIFICATION_BASE: &str = r#"
    SELECT
        id,
        node_id,
        notification_type,
        reference_id,
        description,
        datetime,
        active,
        level,
        payload,
        event_id
    FROM notifications
"#;

pub(crate) const INSERT_NOTIFICATION: &str = r#"
    INSERT INTO notifications (
        id,
        node_id,
        notification_type,
        reference_id,
        description,
        datetime,
        active,
        level,
        payload,
        event_id
    )
    VALUES (
        $1, $2, $3, $4, $5,
        $6, $7, $8, $9, $10
    )
"#;

pub(crate) const MARK_NOTIFICATION_DONE: &str = r#"
    UPDATE notifications
    SET active = false
    WHERE id = $1
"#;

pub(crate) const DELETE_NOTIFICATION: &str = r#"
    DELETE FROM notifications
    WHERE id = $1
"#;

pub(crate) const INSERT_SENT_NOTIFICATION: &str = r#"
    INSERT INTO sent_notifications (
        notification_type,
        reference_id,
        block_height,
        action_type,
        datetime
    )
    VALUES (
        $1, $2, $3, $4, $5
    )
    ON CONFLICT (
        notification_type,
        reference_id,
        block_height,
        action_type
    )
    DO NOTHING
"#;

pub(crate) const SELECT_SENT_NOTIFICATION_EXISTS: &str = r#"
    SELECT EXISTS (
        SELECT 1
        FROM sent_notifications
        WHERE notification_type = $1
          AND reference_id = $2
          AND block_height = $3
          AND action_type = $4
    )
"#;

pub(crate) const SELECT_NOTIFICATION_EVENT_EXISTS: &str = r#"
    SELECT EXISTS (
        SELECT 1
        FROM notifications
        WHERE event_id = $1
          AND node_id = $2
    )
"#;

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct NotificationRow {
    pub id: String,
    pub node_id: Option<Text<NodeId>>,
    pub notification_type: String,
    pub reference_id: Option<String>,
    pub description: String,
    pub datetime: i64,
    pub active: bool,
    pub level: String,
    pub payload: Option<String>,
    pub event_id: Option<String>,
}

pub(crate) fn notification_to_row(value: Notification) -> Result<NotificationRow> {
    let payload = value
        .payload
        .map(|payload| {
            serde_json::to_string(&payload).map_err(|e| {
                Error::InvalidData(format!("could not serialize notification payload: {e}"))
            })
        })
        .transpose()?;
    Ok(NotificationRow {
        id: value.id,
        node_id: value.node_id.map(Text),
        notification_type: notification_type_to_db(&value.notification_type).to_owned(),
        reference_id: value.reference_id,
        description: value.description,
        datetime: timestamp_to_db(Timestamp::from(value.datetime))?,
        active: value.active,
        level: notification_level_to_db(&value.level).to_owned(),
        payload,
        event_id: value.event_id,
    })
}

impl TryFrom<NotificationRow> for Notification {
    type Error = Error;

    fn try_from(row: NotificationRow) -> Result<Self> {
        let payload: Option<Value> = row
            .payload
            .map(|payload| {
                serde_json::from_str(&payload).map_err(|e| {
                    Error::InvalidData(format!("invalid persisted notification payload: {e}"))
                })
            })
            .transpose()?;
        Ok(Self {
            id: row.id,
            node_id: row.node_id.map(Text::into_inner),
            notification_type: notification_type_from_db(&row.notification_type)?,
            reference_id: row.reference_id,
            description: row.description,
            datetime: timestamp_from_db(row.datetime)?.to_datetime(),
            active: row.active,
            level: notification_level_from_db(&row.level)?,
            payload,
            event_id: row.event_id,
        })
    }
}

pub(crate) fn notification_type_to_db(value: &NotificationType) -> &'static str {
    match value {
        NotificationType::General => "General",
        NotificationType::Company => "Company",
        NotificationType::Bill => "Bill",
        NotificationType::Contact => "Contact",
    }
}

fn notification_type_from_db(value: &str) -> Result<NotificationType> {
    match value {
        "General" => Ok(NotificationType::General),
        "Company" => Ok(NotificationType::Company),
        "Bill" => Ok(NotificationType::Bill),
        "Contact" => Ok(NotificationType::Contact),
        other => Err(Error::InvalidData(format!(
            "invalid persisted notification type: {other}"
        ))),
    }
}

pub(crate) fn notification_level_to_db(value: &NotificationLevel) -> &'static str {
    match value {
        NotificationLevel::Informational => "Informational",
        NotificationLevel::ActionRequired => "ActionRequired",
    }
}

fn notification_level_from_db(value: &str) -> Result<NotificationLevel> {
    match value {
        "Informational" => Ok(NotificationLevel::Informational),
        "ActionRequired" => Ok(NotificationLevel::ActionRequired),
        other => Err(Error::InvalidData(format!(
            "invalid persisted notification level: {other}"
        ))),
    }
}

pub(crate) fn action_type_to_db(value: &ActionType) -> &'static str {
    match value {
        ActionType::BuyBill => "BuyBill",
        ActionType::RecourseBill => "RecourseBill",
        ActionType::AcceptBill => "AcceptBill",
        ActionType::CheckBill => "CheckBill",
        ActionType::PayBill => "PayBill",
        ActionType::CheckQuote => "CheckQuote",
    }
}
