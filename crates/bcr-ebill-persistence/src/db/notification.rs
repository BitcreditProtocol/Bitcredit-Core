#[cfg(target_arch = "wasm32")]
use super::get_new_surreal_db;
use std::collections::{HashMap, hash_map::Entry};

use super::super::{Error, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use surrealdb::{Surreal, engine::any::Any, sql::Thing};

use crate::{
    constants::{DB_ACTIVE, DB_IDS, DB_NOTIFICATION_TYPE, DB_TABLE},
    notification::{NotificationFilter, NotificationStoreApi},
    util::date::{DateTimeUtc, now},
};
use bcr_ebill_core::notification::ActionType;
use bcr_ebill_core::notification::{Notification, NotificationType};

#[derive(Clone)]
pub struct SurrealNotificationStore {
    #[allow(dead_code)]
    db: Surreal<Any>,
}

impl SurrealNotificationStore {
    const TABLE: &'static str = "notifications";
    const SENT_TABLE: &'static str = "sent_notifications";

    pub fn new(db: Surreal<Any>) -> Self {
        Self { db }
    }

    #[cfg(target_arch = "wasm32")]
    async fn db(&self) -> Result<Surreal<Any>> {
        get_new_surreal_db().await
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn db(&self) -> Result<Surreal<Any>> {
        Ok(self.db.clone())
    }
}

#[async_trait]
impl NotificationStoreApi for SurrealNotificationStore {
    /// Stores a new notification into the database
    async fn add(&self, notification: Notification) -> Result<Notification> {
        let id = notification.id.to_owned();
        let entity: NotificationDb = notification.into();
        let result: Option<NotificationDb> = self
            .db()
            .await?
            .insert((Self::TABLE, id.to_string()))
            .content(entity)
            .await?;

        match result {
            Some(n) => Ok(n.into()),
            None => Err(Error::InsertFailed(format!(
                "{} with id {}",
                Self::TABLE,
                id
            ))),
        }
    }
    /// Returns all currently active notifications from the database
    async fn list(&self, filter: NotificationFilter) -> Result<Vec<Notification>> {
        let filters = filter.filters();
        let db = self.db().await?;
        let mut query = db.query(format!(
                "SELECT * FROM type::table($table) {} ORDER BY datetime DESC LIMIT $limit START $offset",
                filters
            ))
            .bind(("table", Self::TABLE))
            .bind(("limit", filter.get_limit()))
            .bind(("offset", filter.get_offset()));

        if let Some(active) = filter.get_active() {
            query = query.bind(active.to_owned());
        }
        if let Some(reference_id) = filter.get_reference_id() {
            query = query.bind(reference_id.to_owned());
        }
        if let Some(notification_type) = filter.get_notification_type() {
            query = query.bind(notification_type.to_owned());
        }
        if let Some(node_ids) = filter.get_node_ids() {
            query = query.bind(node_ids.to_owned());
        }
        let result: Vec<NotificationDb> = query.await?.take(0)?;
        Ok(result.into_iter().map(|n| n.into()).collect())
    }
    /// Returns the latest active notifications for the given reference and notification type
    async fn get_latest_by_references(
        &self,
        references: &[String],
        notification_type: NotificationType,
    ) -> Result<HashMap<String, Notification>> {
        let result: Vec<NotificationDb> = self
            .db().await?
            .query(
                "SELECT * FROM type::table($table) WHERE active = $active AND notification_type = $notification_type AND reference_id IN $ids",
            )
            .bind((DB_TABLE, Self::TABLE))
            .bind((DB_ACTIVE, true))
            .bind((DB_NOTIFICATION_TYPE, notification_type.to_owned()))
            .bind((DB_IDS, references.to_owned()))
            .await?
            .take(0)?;
        let mut latest_map: HashMap<String, Notification> = HashMap::new();

        for notification in result {
            if let Some(ref_id) = &notification.reference_id {
                let entry = latest_map.entry(ref_id.clone());

                match entry {
                    Entry::Vacant(e) => {
                        e.insert(notification.into());
                    }
                    Entry::Occupied(mut e) => {
                        // only keep the latest one
                        if notification.datetime > e.get().datetime {
                            e.insert(notification.into());
                        }
                    }
                }
            }
        }

        Ok(latest_map)
    }
    /// Returns the latest active notification for the given reference and notification type
    async fn get_latest_by_reference(
        &self,
        reference: &str,
        notification_type: NotificationType,
    ) -> Result<Option<Notification>> {
        let result = self
            .list(NotificationFilter {
                active: Some(true),
                reference_id: Some(reference.to_owned()),
                notification_type: Some(notification_type.to_string()),
                limit: Some(1),
                ..Default::default()
            })
            .await?;
        Ok(result.first().cloned())
    }
    /// Returns all notifications for the given reference and notification type that are active
    async fn list_by_type(&self, notification_type: NotificationType) -> Result<Vec<Notification>> {
        let result = self
            .list(NotificationFilter {
                active: Some(true),
                notification_type: Some(notification_type.to_string()),
                ..Default::default()
            })
            .await?;
        Ok(result)
    }
    /// Marks an active notification as done
    async fn mark_as_done(&self, notification_id: &str) -> Result<()> {
        let thing: Thing = (Self::TABLE, notification_id).into();
        self.db()
            .await?
            .query("UPDATE $id SET active = false")
            .bind(("id", thing))
            .await?;
        Ok(())
    }
    /// deletes a notification from the database
    async fn delete(&self, notification_id: &str) -> Result<()> {
        let _: Option<NotificationDb> = self
            .db()
            .await?
            .delete((Self::TABLE, notification_id))
            .await?;
        Ok(())
    }

    async fn set_bill_notification_sent(
        &self,
        bill_id: &str,
        block_height: i32,
        action_type: ActionType,
    ) -> Result<()> {
        let db = SentBlockNotificationDb {
            notification_type: NotificationType::Bill,
            reference_id: bill_id.to_owned(),
            block_height,
            action_type,
            datetime: now(),
        };
        let _: Vec<SentBlockNotificationDb> = self
            .db()
            .await?
            .insert(Self::SENT_TABLE)
            .content(db)
            .await?;
        Ok(())
    }

    async fn bill_notification_sent(
        &self,
        bill_id: &str,
        block_height: i32,
        action_type: ActionType,
    ) -> Result<bool> {
        let res: Option<SentBlockNotificationDb> = self.db().await?
            .query("SELECT * FROM type::table($table) WHERE notification_type = $notification_type AND reference_id = $reference_id AND block_height = $block_height AND action_type = $action_type limit 1")
            .bind(("table", Self::SENT_TABLE))
            .bind(("notification_type", NotificationType::Bill))
            .bind(("reference_id", bill_id.to_owned()))
            .bind(("block_height", block_height))
            .bind(("action_type", action_type))
            .await?
            .take(0)?;
        Ok(res.is_some())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NotificationDb {
    pub id: Thing,
    pub node_id: Option<String>,
    pub notification_type: NotificationType,
    pub reference_id: Option<String>,
    pub description: String,
    pub datetime: DateTimeUtc,
    pub active: bool,
    pub payload: Option<Value>,
}

impl From<NotificationDb> for Notification {
    fn from(value: NotificationDb) -> Self {
        Self {
            id: value.id.id.to_raw(),
            node_id: value.node_id,
            notification_type: value.notification_type,
            reference_id: value.reference_id,
            description: value.description,
            datetime: value.datetime,
            active: value.active,
            payload: value.payload,
        }
    }
}

impl From<Notification> for NotificationDb {
    fn from(value: Notification) -> Self {
        Self {
            id: (
                SurrealNotificationStore::TABLE.to_owned(),
                value.id.to_owned(),
            )
                .into(),
            node_id: value.node_id,
            notification_type: value.notification_type,
            reference_id: value.reference_id,
            description: value.description,
            datetime: value.datetime,
            active: value.active,
            payload: value.payload,
        }
    }
}

/// Tracks sending of notifications for a blockchain based resource.
/// The block height is used to track the block in which the notification was sent.
/// The same notification can be sent multiple times, but only if the underlying
/// resource has added new blocks to the chain.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct SentBlockNotificationDb {
    pub notification_type: NotificationType,
    pub reference_id: String,
    pub block_height: i32,
    pub action_type: ActionType,
    pub datetime: DateTimeUtc,
}

#[cfg(test)]
mod tests {

    use serde_json::json;
    use uuid::Uuid;

    use super::*;
    use crate::{db::get_memory_db, util::date::now};

    async fn get_store() -> SurrealNotificationStore {
        let db = get_memory_db("test", "notification")
            .await
            .expect("could not create memory db");
        SurrealNotificationStore::new(db)
    }

    #[tokio::test]
    async fn test_notification_sent_returns_false_for_non_existing() {
        let store = get_store().await;
        let sent = store
            .bill_notification_sent("bill_id", 1, ActionType::AcceptBill)
            .await
            .expect("could not check if notification was sent");
        assert!(!sent);
    }

    #[tokio::test]
    async fn test_notification_sent_returns_true_for_existing() {
        let store = get_store().await;
        store
            .set_bill_notification_sent("bill_id", 1, ActionType::AcceptBill)
            .await
            .expect("could not set notification as sent");
        let sent = store
            .bill_notification_sent("bill_id", 1, ActionType::AcceptBill)
            .await
            .expect("could not check if notification was sent");
        assert!(sent);
    }

    #[tokio::test]
    async fn test_notification_sent_returns_false_for_different_notification_type() {
        let store = get_store().await;
        store
            .set_bill_notification_sent("bill_id", 1, ActionType::AcceptBill)
            .await
            .expect("could not set notification as sent");
        let sent = store
            .bill_notification_sent("bill_id", 1, ActionType::PayBill)
            .await
            .expect("could not check if notification was sent");
        assert!(!sent);
    }

    #[tokio::test]
    async fn test_inserts_and_queries_notification() {
        let store = get_store().await;
        let notification = test_notification("bill_id", Some(test_payload()));
        let r = store
            .add(notification.clone())
            .await
            .expect("could not create notification");

        let all = store
            .list(NotificationFilter::default())
            .await
            .expect("could not list notifications");
        assert!(!all.is_empty());
        assert_eq!(notification.id, r.id);
    }

    #[tokio::test]
    async fn test_deletes_existing_notification() {
        let store = get_store().await;
        let notification = test_notification("bill_id", Some(test_payload()));
        let r = store
            .add(notification.clone())
            .await
            .expect("could not create notification");

        let all = store
            .list(NotificationFilter::default())
            .await
            .expect("could not list notifications");
        assert!(!all.is_empty());

        store
            .delete(&r.id)
            .await
            .expect("could not delete notification");
        let all = store
            .list(NotificationFilter::default())
            .await
            .expect("could not list notifications");
        assert!(all.is_empty());
    }

    #[tokio::test]
    async fn test_marks_done_and_no_longer_returns_in_list() {
        let store = get_store().await;
        let notification = test_notification("bill_id", Some(test_payload()));
        let r = store
            .add(notification.clone())
            .await
            .expect("could not create notification");

        let filter = NotificationFilter {
            active: Some(true),
            ..Default::default()
        };
        let all = store
            .list(filter.clone())
            .await
            .expect("could not list notifications");
        assert!(!all.is_empty());

        store
            .mark_as_done(&r.id)
            .await
            .expect("could not mark notification as done");

        let all = store
            .list(filter)
            .await
            .expect("could not list notifications");
        assert!(all.is_empty());
    }

    #[tokio::test]
    async fn test_marks_done_and_no_longer_returns_by_references() {
        let store = get_store().await;
        let notification = test_notification("bill_id", Some(test_payload()));
        let notification2 = test_notification("bill_id2", Some(test_payload()));
        let r = store
            .add(notification.clone())
            .await
            .expect("could not create notification");
        store
            .add(notification2.clone())
            .await
            .expect("could not create notification");

        let references = store
            .get_latest_by_references(
                &["bill_id".to_string(), "bill_id2".to_string()],
                NotificationType::Bill,
            )
            .await
            .expect("could not list notifications");
        assert_eq!(references.len(), 2);
        assert_eq!(
            references
                .get("bill_id")
                .unwrap()
                .reference_id
                .as_ref()
                .unwrap(),
            &"bill_id".to_string()
        );
        assert_eq!(
            references
                .get("bill_id2")
                .unwrap()
                .reference_id
                .as_ref()
                .unwrap(),
            &"bill_id2".to_string()
        );

        store
            .mark_as_done(&r.id)
            .await
            .expect("could not mark notification as done");

        let references = store
            .get_latest_by_references(
                &["bill_id".to_string(), "bill_id2".to_string()],
                NotificationType::Bill,
            )
            .await
            .expect("could not list notifications");
        assert_eq!(references.len(), 1);
        assert_eq!(
            references
                .get("bill_id2")
                .unwrap()
                .reference_id
                .as_ref()
                .unwrap(),
            &"bill_id2".to_string()
        );
    }

    #[tokio::test]
    async fn test_marks_done_and_no_longer_returns_by_reference() {
        let store = get_store().await;
        let notification = test_notification("bill_id", Some(test_payload()));
        let r = store
            .add(notification.clone())
            .await
            .expect("could not create notification");

        let latest = store
            .get_latest_by_reference(
                &notification.clone().reference_id.unwrap(),
                NotificationType::Bill,
            )
            .await
            .expect("could not list notifications");
        assert!(latest.is_some());

        store
            .mark_as_done(&r.id)
            .await
            .expect("could not mark notification as done");

        let latest = store
            .get_latest_by_reference(
                &notification.clone().reference_id.unwrap(),
                NotificationType::Bill,
            )
            .await
            .expect("could not list notifications");

        assert!(latest.is_none());
    }

    #[tokio::test]
    async fn test_returns_all_active_by_type() {
        let store = get_store().await;
        let notification1 = test_notification("bill_id1", Some(test_payload()));
        let notification2 = test_notification("bill_id2", Some(test_payload()));
        let notification3 = test_general_notification();
        let _ = store
            .add(notification1.clone())
            .await
            .expect("notification created");
        let _ = store
            .add(notification2.clone())
            .await
            .expect("notification created");
        let _ = store
            .add(notification3.clone())
            .await
            .expect("notification created");
        store
            .mark_as_done(&notification2.clone().id)
            .await
            .expect("notification marked done");
        let by_type = store
            .list_by_type(NotificationType::Bill)
            .await
            .expect("returned list by type");

        assert_eq!(by_type.len(), 1, "should only have one bill type in list");
        by_type.iter().for_each(|n| {
            assert!(n.active);
            assert_ne!(
                n.id, notification2.id,
                "notfication 2 should be done already"
            );
        });
    }

    fn test_notification(bill_id: &str, payload: Option<Value>) -> Notification {
        Notification::new_bill_notification(bill_id, "node_id", "test_notification", payload)
    }

    fn test_payload() -> Value {
        json!({ "Some": "value", "for": 66, "testing": true })
    }

    fn test_general_notification() -> Notification {
        Notification {
            id: Uuid::new_v4().to_string(),
            node_id: Some("node_id".to_string()),
            notification_type: NotificationType::General,
            reference_id: Some("general".to_string()),
            description: "general desc".to_string(),
            datetime: now(),
            active: true,
            payload: None,
        }
    }
}
