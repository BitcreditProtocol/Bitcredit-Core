use bcr_ebill_core::application::notification::{
    Notification, NotificationLevel, NotificationType,
};

#[derive(Debug, Clone)]
pub struct NotificationStatusFfi {
    pub node_id: String,
    pub active: bool,
}

#[derive(Debug, Clone)]
pub struct NotificationFfi {
    pub id: String,
    pub node_id: Option<String>,
    pub notification_type: NotificationTypeFfi,
    pub reference_id: Option<String>,
    pub description: String,
    pub datetime: String,
    pub active: bool,
    pub level: NotificationLevelFfi,
    pub payload: Option<String>,
}

impl From<Notification> for NotificationFfi {
    fn from(val: Notification) -> Self {
        NotificationFfi {
            id: val.id,
            node_id: val.node_id.map(|id| id.to_string()),
            notification_type: val.notification_type.into(),
            reference_id: val.reference_id,
            description: val.description,
            datetime: val
                .datetime
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            active: val.active,
            level: val.level.into(),
            payload: val.payload.map(|v| v.to_string()),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum NotificationTypeFfi {
    General,
    Company,
    Bill,
    Contact,
}

impl From<NotificationType> for NotificationTypeFfi {
    fn from(val: NotificationType) -> Self {
        match val {
            NotificationType::Bill => NotificationTypeFfi::Bill,
            NotificationType::Company => NotificationTypeFfi::Company,
            NotificationType::General => NotificationTypeFfi::General,
            NotificationType::Contact => NotificationTypeFfi::Contact,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum NotificationLevelFfi {
    Informational,
    ActionRequired,
}

impl From<NotificationLevel> for NotificationLevelFfi {
    fn from(val: NotificationLevel) -> Self {
        match val {
            NotificationLevel::Informational => NotificationLevelFfi::Informational,
            NotificationLevel::ActionRequired => NotificationLevelFfi::ActionRequired,
        }
    }
}
