use crate::{
    NodeId,
    bill::BillId,
    util::date::{DateTimeUtc, now},
};
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
    pub node_id: Option<NodeId>,
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
        bill_id: &BillId,
        node_id: &NodeId,
        description: &str,
        payload: Option<Value>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            node_id: Some(node_id.to_owned()),
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NotificationType {
    General,
    Bill,
}

impl Display for NotificationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("{self:?}").as_str())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[allow(clippy::enum_variant_names, dead_code)]
pub enum ActionType {
    BuyBill,
    RecourseBill,
    AcceptBill,
    CheckBill,
    PayBill,
    CheckQuote,
}

/// The different types of events that can be sent via this service.
/// For now we only have Bill events and this needs some clippy
/// exceptions here. As soon as we have other event topics, we can
/// add new types here and remove the clippy exceptions.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[allow(clippy::enum_variant_names, dead_code)]
pub enum BillEventType {
    BillSigned,
    BillAccepted,
    BillAcceptanceRequested,
    BillAcceptanceRejected,
    BillAcceptanceTimeout,
    BillAcceptanceRecourse,
    BillPaymentRequested,
    BillPaymentRejected,
    BillPaymentRecourse,
    BillRecourseRejected,
    BillRecourseTimeout,
    BillPaymentTimeout,
    BillSellOffered,
    BillBuyingRejected,
    BillPaid,
    BillRecoursePaid,
    BillEndorsed,
    BillSold,
    BillMintingRequested,
    BillNewQuote,
    BillQuoteApproved,
    #[default]
    BillBlock,
}

impl BillEventType {
    pub fn all() -> Vec<Self> {
        vec![
            Self::BillSigned,
            Self::BillAccepted,
            Self::BillAcceptanceRequested,
            Self::BillAcceptanceRejected,
            Self::BillAcceptanceTimeout,
            Self::BillAcceptanceRecourse,
            Self::BillPaymentRequested,
            Self::BillPaymentRejected,
            Self::BillPaymentTimeout,
            Self::BillPaymentRecourse,
            Self::BillRecourseTimeout,
            Self::BillRecourseRejected,
            Self::BillSellOffered,
            Self::BillBuyingRejected,
            Self::BillPaid,
            Self::BillRecoursePaid,
            Self::BillEndorsed,
            Self::BillSold,
            Self::BillMintingRequested,
            Self::BillNewQuote,
            Self::BillQuoteApproved,
            Self::BillBlock,
        ]
    }

    pub fn is_action_event(&self) -> bool {
        !matches!(self, Self::BillBlock)
    }
}

impl ActionType {
    /// Return a corresponding rejected event type for the action type
    /// if the action has a rejected event type. If not, return None.
    pub fn get_rejected_event_type(&self) -> Option<BillEventType> {
        match self {
            Self::AcceptBill => Some(BillEventType::BillAcceptanceRejected),
            Self::PayBill => Some(BillEventType::BillPaymentRejected),
            Self::BuyBill => Some(BillEventType::BillBuyingRejected),
            Self::RecourseBill => Some(BillEventType::BillRecourseRejected),
            _ => None,
        }
    }

    /// Return a corresponding timeout event type for the action type
    /// if the action has a timeout event type. If not, return None.
    pub fn get_timeout_event_type(&self) -> Option<BillEventType> {
        match self {
            Self::AcceptBill => Some(BillEventType::BillAcceptanceTimeout),
            Self::PayBill => Some(BillEventType::BillPaymentTimeout),
            Self::RecourseBill => Some(BillEventType::BillRecourseTimeout),
            _ => None,
        }
    }

    // Return a corresponding recourse event type for the action type
    // if the action has a recourse event type. If not, return None.
    pub fn get_recourse_event_type(&self) -> Option<BillEventType> {
        match self {
            Self::AcceptBill => Some(BillEventType::BillAcceptanceRecourse),
            Self::PayBill => Some(BillEventType::BillPaymentRecourse),
            _ => None,
        }
    }
}
