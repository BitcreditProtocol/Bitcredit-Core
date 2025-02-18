use crate::util::date::{now, DateTimeUtc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Display;
use uuid::Uuid;

/// A notification as it will be delivered to the UI.
///
/// A generic notification. Payload is unstructured json. The timestamp refers to the
/// time when the client received the notification. The type determines the payload
/// type and the reference_id is used to identify and optional other entity like a
/// Bill or Company.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    /// The unique id of the notification
    pub id: String,
    /// Id of the identity that the notification is for
    pub node_id: Option<String>,
    /// The type/topic of the notification
    pub notification_type: NotificationType,
    /// An optional reference to some other entity
    pub reference_id: Option<String>,
    /// A description to quickly show to a user in the ui (probably a translation key)
    pub description: String,
    /// The datetime when the notification was created
    pub datetime: DateTimeUtc,
    /// Whether the notification is active or not. If active the user shold still perform
    /// some action to dismiss the notification.
    pub active: bool,
    /// Additional data to be used for notification specific logic
    pub payload: Option<Value>,
}

impl Notification {
    pub fn new_bill_notification(
        bill_id: &str,
        node_id: &str,
        description: &str,
        payload: Option<Value>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            node_id: Some(node_id.to_string()),
            notification_type: NotificationType::Bill,
            reference_id: Some(bill_id.to_string()),
            description: description.to_string(),
            datetime: now(),
            active: true,
            payload,
        }
    }
}

/// The type/topic of a notification we show to the user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationType {
    General,
    Bill,
}

impl Display for NotificationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("{:?}", self).as_str())
    }
}
