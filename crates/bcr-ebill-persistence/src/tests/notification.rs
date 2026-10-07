use crate::{
    tests::tests::{bill_id_test, bill_id_test_other, node_id_test, node_id_test_other},
    traits::notification::{NotificationFilter, NotificationStoreApi},
};
use bcr_common::core::BillId;
use bcr_ebill_core::{
    application::notification::{Notification, NotificationLevel, NotificationType},
    protocol::{Timestamp, event::bill_events::ActionType},
};
use serde_json::{Value, json};
use uuid::Uuid;

fn test_payload() -> Value {
    json!({
        "Some": "value",
        "for": 66,
        "testing": true
    })
}

fn test_notification(bill_id: &BillId, payload: Option<Value>) -> Notification {
    Notification::new_bill_notification(
        bill_id,
        &node_id_test(),
        "test_notification",
        payload,
        NotificationLevel::Informational,
    )
}

fn test_general_notification() -> Notification {
    Notification {
        id: Uuid::new_v4().to_string(),
        node_id: Some(node_id_test()),
        notification_type: NotificationType::General,
        reference_id: Some("general".to_string()),
        description: "general desc".to_string(),
        datetime: Timestamp::now().to_datetime(),
        active: true,
        level: NotificationLevel::Informational,
        payload: None,
        event_id: None,
    }
}

pub async fn test_notification_sent_returns_false_for_non_existing<S>(store: &S)
where
    S: NotificationStoreApi + ?Sized,
{
    let sent = store
        .bill_notification_sent(&bill_id_test(), 1, ActionType::AcceptBill)
        .await
        .unwrap();
    assert!(!sent);
}

pub async fn test_notification_sent_returns_true_for_existing<S>(store: &S)
where
    S: NotificationStoreApi + ?Sized,
{
    store
        .set_bill_notification_sent(&bill_id_test(), 1, ActionType::AcceptBill)
        .await
        .unwrap();
    assert!(
        store
            .bill_notification_sent(&bill_id_test(), 1, ActionType::AcceptBill,)
            .await
            .unwrap()
    );
}

pub async fn test_notification_sent_returns_false_for_different_action<S>(store: &S)
where
    S: NotificationStoreApi + ?Sized,
{
    store
        .set_bill_notification_sent(&bill_id_test(), 1, ActionType::AcceptBill)
        .await
        .unwrap();
    assert!(
        !store
            .bill_notification_sent(&bill_id_test(), 1, ActionType::PayBill,)
            .await
            .unwrap()
    );
}

pub async fn test_inserts_and_queries_notification<S>(store: &S)
where
    S: NotificationStoreApi + ?Sized,
{
    let notification = test_notification(&bill_id_test(), Some(test_payload()));
    let created = store.add(notification.clone()).await.unwrap();
    assert_eq!(created.id, notification.id);
    assert_eq!(created.payload, notification.payload);
    let all = store.list(NotificationFilter::default()).await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].payload, notification.payload);
}

pub async fn test_deletes_existing_notification<S>(store: &S)
where
    S: NotificationStoreApi + ?Sized,
{
    let notification = test_notification(&bill_id_test(), Some(test_payload()));
    store.add(notification.clone()).await.unwrap();
    store.delete(&notification.id).await.unwrap();
    let all = store.list(NotificationFilter::default()).await.unwrap();
    assert!(all.is_empty());
}

pub async fn test_marks_done_and_no_longer_returns_in_list<S>(store: &S)
where
    S: NotificationStoreApi + ?Sized,
{
    let notification = test_notification(&bill_id_test(), Some(test_payload()));
    store.add(notification.clone()).await.unwrap();
    let filter = NotificationFilter {
        active: Some(true),
        ..Default::default()
    };
    assert_eq!(store.list(filter.clone()).await.unwrap().len(), 1);
    store.mark_as_done(&notification.id).await.unwrap();
    assert!(store.list(filter).await.unwrap().is_empty());
}

pub async fn test_marks_done_and_no_longer_returns_by_references<S>(store: &S)
where
    S: NotificationStoreApi + ?Sized,
{
    let first = test_notification(&bill_id_test(), Some(test_payload()));
    let second = test_notification(&bill_id_test_other(), Some(test_payload()));
    store.add(first.clone()).await.unwrap();
    store.add(second.clone()).await.unwrap();
    let references = store
        .get_latest_by_references(
            &[bill_id_test().to_string(), bill_id_test_other().to_string()],
            NotificationType::Bill,
        )
        .await
        .unwrap();
    assert_eq!(references.len(), 2);
    store.mark_as_done(&first.id).await.unwrap();
    let references = store
        .get_latest_by_references(
            &[bill_id_test().to_string(), bill_id_test_other().to_string()],
            NotificationType::Bill,
        )
        .await
        .unwrap();
    assert_eq!(references.len(), 1);
    assert!(references.contains_key(&bill_id_test_other().to_string()));
}

pub async fn test_latest_by_reference_really_returns_latest<S>(store: &S)
where
    S: NotificationStoreApi + ?Sized,
{
    let mut older = test_notification(&bill_id_test(), None);
    older.id = Uuid::new_v4().to_string();
    older.datetime = Timestamp::new(1000).unwrap().to_datetime();
    let mut newer = test_notification(&bill_id_test(), None);
    newer.id = Uuid::new_v4().to_string();
    newer.datetime = Timestamp::new(2000).unwrap().to_datetime();
    store.add(older).await.unwrap();
    store.add(newer.clone()).await.unwrap();
    let latest = store
        .get_latest_by_reference(&bill_id_test().to_string(), NotificationType::Bill)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(latest.id, newer.id);
}

pub async fn test_latest_by_reference_and_node_id<S>(store: &S)
where
    S: NotificationStoreApi + ?Sized,
{
    let reference = bill_id_test().to_string();
    let mut node1 = test_notification(&bill_id_test(), None);
    node1.id = Uuid::new_v4().to_string();
    node1.node_id = Some(node_id_test());
    node1.datetime = Timestamp::new(1000).unwrap().to_datetime();
    let mut node2 = test_notification(&bill_id_test(), None);
    node2.id = Uuid::new_v4().to_string();
    node2.node_id = Some(node_id_test_other());
    node2.datetime = Timestamp::new(2000).unwrap().to_datetime();
    store.add(node1.clone()).await.unwrap();
    store.add(node2).await.unwrap();
    let result = store
        .get_latest_by_reference_and_node_id(&reference, NotificationType::Bill, &node_id_test())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.id, node1.id);
}

pub async fn test_returns_all_active_by_type<S>(store: &S)
where
    S: NotificationStoreApi + ?Sized,
{
    let first = test_notification(&bill_id_test(), Some(test_payload()));
    let second = test_notification(&bill_id_test_other(), Some(test_payload()));
    let general = test_general_notification();
    store.add(first.clone()).await.unwrap();
    store.add(second.clone()).await.unwrap();
    store.add(general).await.unwrap();
    store.mark_as_done(&second.id).await.unwrap();
    let by_type = store.list_by_type(NotificationType::Bill).await.unwrap();
    assert_eq!(by_type.len(), 1);
    assert_eq!(by_type[0].id, first.id);
}

pub async fn test_returns_active_status_for_node_ids<S>(store: &S)
where
    S: NotificationStoreApi + ?Sized,
{
    let notification1 = test_notification(&bill_id_test(), Some(test_payload()));
    let mut notification2 = test_notification(&bill_id_test_other(), Some(test_payload()));
    notification2.node_id = Some(node_id_test_other());
    let notification3 = test_general_notification();
    store.add(notification1).await.unwrap();
    store.add(notification2.clone()).await.unwrap();
    store.add(notification3).await.unwrap();
    let status = store.get_active_status_for_node_ids(&[]).await.unwrap();
    assert_eq!(status.len(), 2);
    assert!(*status.get(&node_id_test()).unwrap());
    assert!(*status.get(&node_id_test_other()).unwrap());
    store.mark_as_done(&notification2.id).await.unwrap();
    let status = store
        .get_active_status_for_node_ids(&[node_id_test(), node_id_test_other()])
        .await
        .unwrap();
    assert!(*status.get(&node_id_test()).unwrap());
    assert!(!*status.get(&node_id_test_other()).unwrap());
}

pub async fn test_notification_exists_for_event_id<S>(store: &S)
where
    S: NotificationStoreApi + ?Sized,
{
    let mut notification = test_notification(&bill_id_test(), None);
    notification.event_id = Some("nostr-event-id".to_owned());
    store.add(notification).await.unwrap();
    assert!(
        store
            .notification_exists_for_event_id("nostr-event-id", &node_id_test(),)
            .await
            .unwrap()
    );
    assert!(
        !store
            .notification_exists_for_event_id("nostr-event-id", &node_id_test_other(),)
            .await
            .unwrap()
    );
}
