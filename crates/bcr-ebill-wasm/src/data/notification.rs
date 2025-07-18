use bcr_ebill_api::data::{
    NodeId,
    notification::{Notification, NotificationType},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Debug, Clone, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct NotificationStatusWeb {
    #[tsify(type = "string")]
    pub node_id: NodeId,
    pub active: bool,
}

#[derive(Tsify, Debug, Clone, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct NotificationWeb {
    pub id: String,
    #[tsify(type = "string")]
    pub node_id: Option<NodeId>,
    pub notification_type: NotificationTypeWeb,
    pub reference_id: Option<String>,
    pub description: String,
    pub datetime: String,
    pub active: bool,
    #[tsify(type = "any | undefined")]
    pub payload: Option<Value>,
}

impl From<Notification> for NotificationWeb {
    fn from(val: Notification) -> Self {
        NotificationWeb {
            id: val.id,
            node_id: val.node_id,
            notification_type: val.notification_type.into(),
            reference_id: val.reference_id,
            description: val.description,
            datetime: val
                .datetime
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            active: val.active,
            payload: val.payload,
        }
    }
}

#[derive(Tsify, Debug, Copy, Clone, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum NotificationTypeWeb {
    General,
    Bill,
}

impl From<NotificationType> for NotificationTypeWeb {
    fn from(val: NotificationType) -> Self {
        match val {
            NotificationType::Bill => NotificationTypeWeb::Bill,
            NotificationType::General => NotificationTypeWeb::General,
        }
    }
}
