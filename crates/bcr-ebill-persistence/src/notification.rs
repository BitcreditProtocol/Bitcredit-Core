use std::collections::HashMap;

use async_trait::async_trait;

use super::Result;
use bcr_ebill_core::{
    NodeId, ServiceTraitBounds,
    bill::BillId,
    notification::{ActionType, Notification, NotificationType},
};

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait NotificationStoreApi: ServiceTraitBounds {
    /// Stores a new notification into the database
    async fn add(&self, notification: Notification) -> Result<Notification>;
    /// Returns all currently active notifications from the database
    async fn list(&self, filter: NotificationFilter) -> Result<Vec<Notification>>;
    /// Returns the latest active notifications for the given reference and notification type
    async fn get_latest_by_references(
        &self,
        reference: &[String],
        notification_type: NotificationType,
    ) -> Result<HashMap<String, Notification>>;
    /// Returns the latest active notification for the given reference and notification type
    async fn get_latest_by_reference(
        &self,
        reference: &str,
        notification_type: NotificationType,
    ) -> Result<Option<Notification>>;
    /// Returns all notifications for the given reference and notification type that are active
    #[allow(unused)]
    async fn list_by_type(&self, notification_type: NotificationType) -> Result<Vec<Notification>>;
    /// Marks an active notification as done
    async fn mark_as_done(&self, notification_id: &str) -> Result<()>;
    /// deletes a notification from the database
    #[allow(unused)]
    async fn delete(&self, notification_id: &str) -> Result<()>;
    /// marks a notification with specific type as sent for the current block of given bill
    async fn set_bill_notification_sent(
        &self,
        bill_id: &BillId,
        block_height: i32,
        action_type: ActionType,
    ) -> Result<()>;
    /// lookup whether a notification has been sent for the given bill and block height
    async fn bill_notification_sent(
        &self,
        bill_id: &BillId,
        block_height: i32,
        action_type: ActionType,
    ) -> Result<bool>;
}

#[derive(Default, Clone, PartialEq, Debug)]
pub struct NotificationFilter {
    pub active: Option<bool>,
    pub reference_id: Option<String>,
    pub notification_type: Option<String>,
    pub node_ids: Vec<NodeId>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl NotificationFilter {
    pub fn filters(&self) -> String {
        let mut parts = vec![];
        if self.active.is_some() {
            parts.push("active = $active");
        }
        if self.reference_id.is_some() {
            parts.push("reference_id = $reference_id");
        }
        if self.notification_type.is_some() {
            parts.push("notification_type = $notification_type");
        }

        if !self.node_ids.is_empty() {
            parts.push("node_id IN $node_ids");
        }

        let filters = parts.join(" AND ");
        if filters.is_empty() {
            filters
        } else {
            format!("WHERE {filters}")
        }
    }

    pub fn get_limit(&self) -> i64 {
        self.limit.unwrap_or(200)
    }

    pub fn get_offset(&self) -> i64 {
        self.offset.unwrap_or(0)
    }

    pub fn get_active(&self) -> Option<(String, bool)> {
        self.active.map(|active| ("active".to_string(), active))
    }

    pub fn get_reference_id(&self) -> Option<(String, String)> {
        self.reference_id
            .as_ref()
            .map(|reference_id| ("reference_id".to_string(), reference_id.to_string()))
    }

    pub fn get_notification_type(&self) -> Option<(String, String)> {
        self.notification_type.as_ref().map(|notification_type| {
            (
                "notification_type".to_string(),
                notification_type.to_string(),
            )
        })
    }

    pub fn get_node_ids(&self) -> Option<(String, Vec<NodeId>)> {
        if !self.node_ids.is_empty() {
            Some(("node_ids".to_string(), self.node_ids.clone()))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::tests::{node_id_test, node_id_test_other};

    #[test]
    fn test_query_filters() {
        let empty = super::NotificationFilter::default();
        assert_eq!(empty.filters(), "");

        let active = super::NotificationFilter {
            active: Some(true),
            ..Default::default()
        };
        assert_eq!(active.filters(), "WHERE active = $active");

        let node_ids = super::NotificationFilter {
            node_ids: vec![node_id_test(), node_id_test_other()],
            ..Default::default()
        };

        assert_eq!(node_ids.filters(), "WHERE node_id IN $node_ids");

        assert_eq!(
            node_ids.get_node_ids(),
            Some((
                "node_ids".to_string(),
                vec![node_id_test(), node_id_test_other()]
            ))
        );

        let all = super::NotificationFilter {
            active: Some(true),
            reference_id: Some("123".to_string()),
            notification_type: Some("Bill".to_string()),
            node_ids: vec![node_id_test()],
            ..Default::default()
        };

        assert_eq!(
            all.filters(),
            "WHERE active = $active AND reference_id = $reference_id AND notification_type = $notification_type AND node_id IN $node_ids"
        );
    }
}
