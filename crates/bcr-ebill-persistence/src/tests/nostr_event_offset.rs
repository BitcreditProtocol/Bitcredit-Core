use crate::{
    NostrEventOffset, NostrEventOffsetStoreApi,
    tests::tests::{node_id_test, node_id_test_other},
};
use bcr_ebill_core::protocol::Timestamp;

pub async fn test_get_offset_from_empty_table<S>(store: &S)
where
    S: NostrEventOffsetStoreApi + ?Sized,
{
    let offset = store
        .current_offset(&node_id_test())
        .await
        .expect("could not get offset");
    assert_eq!(offset, Timestamp::new(0).unwrap());
}

pub async fn test_add_event<S>(store: &S)
where
    S: NostrEventOffsetStoreApi + ?Sized,
{
    let data = NostrEventOffset {
        event_id: "test_event".to_string(),
        time: Timestamp::new(1000).unwrap(),
        success: true,
        node_id: node_id_test(),
    };
    store
        .add_event(data)
        .await
        .expect("could not add event offset");
    let offset = store
        .current_offset(&node_id_test())
        .await
        .expect("could not get offset");
    assert_eq!(offset, Timestamp::new(1000).unwrap());
}

pub async fn test_is_processed<S>(store: &S)
where
    S: NostrEventOffsetStoreApi + ?Sized,
{
    let data = NostrEventOffset {
        event_id: "test_event".to_string(),
        time: Timestamp::new(1000).unwrap(),
        success: false,
        node_id: node_id_test(),
    };
    let is_known = store
        .is_processed(&data.event_id)
        .await
        .expect("could not check if processed");
    assert!(!is_known, "new event should not be known");
    store
        .add_event(data.clone())
        .await
        .expect("could not add event offset");
    let is_processed = store
        .is_processed(&data.event_id)
        .await
        .expect("could not check if processed");
    assert!(is_processed, "existing event should be known");
}

pub async fn test_current_offset_returns_latest_event<S>(store: &S)
where
    S: NostrEventOffsetStoreApi + ?Sized,
{
    let node_id = node_id_test();
    store
        .add_event(NostrEventOffset {
            event_id: "event_1000".to_string(),
            time: Timestamp::new(1000).unwrap(),
            success: true,
            node_id: node_id.clone(),
        })
        .await
        .expect("could not add first event");
    store
        .add_event(NostrEventOffset {
            event_id: "event_3000".to_string(),
            time: Timestamp::new(3000).unwrap(),
            success: true,
            node_id: node_id.clone(),
        })
        .await
        .expect("could not add second event");
    store
        .add_event(NostrEventOffset {
            event_id: "event_2000".to_string(),
            time: Timestamp::new(2000).unwrap(),
            success: true,
            node_id: node_id.clone(),
        })
        .await
        .expect("could not add third event");
    let offset = store
        .current_offset(&node_id)
        .await
        .expect("could not get offset");
    assert_eq!(offset, Timestamp::new(3000).unwrap());
}

pub async fn test_current_offset_is_by_node_id<S>(store: &S)
where
    S: NostrEventOffsetStoreApi + ?Sized,
{
    let node_id = node_id_test();
    let other_node_id = node_id_test_other();
    store
        .add_event(NostrEventOffset {
            event_id: "node_1_event".to_string(),
            time: Timestamp::new(1000).unwrap(),
            success: true,
            node_id: node_id.clone(),
        })
        .await
        .expect("could not add first node event");
    store
        .add_event(NostrEventOffset {
            event_id: "node_2_event".to_string(),
            time: Timestamp::new(5000).unwrap(),
            success: true,
            node_id: other_node_id.clone(),
        })
        .await
        .expect("could not add second node event");
    let offset = store
        .current_offset(&node_id)
        .await
        .expect("could not get first node offset");
    assert_eq!(offset, Timestamp::new(1000).unwrap());
    let other_offset = store
        .current_offset(&other_node_id)
        .await
        .expect("could not get second node offset");
    assert_eq!(other_offset, Timestamp::new(5000).unwrap());
}

pub async fn test_failed_event_is_processed_and_advances_offset<S>(store: &S)
where
    S: NostrEventOffsetStoreApi + ?Sized,
{
    let node_id = node_id_test();
    let data = NostrEventOffset {
        event_id: "failed_event".to_string(),
        time: Timestamp::new(2000).unwrap(),
        success: false,
        node_id: node_id.clone(),
    };
    store
        .add_event(data.clone())
        .await
        .expect("could not add failed event");
    let processed = store
        .is_processed(&data.event_id)
        .await
        .expect("could not check event");
    assert!(processed, "failed events are still known/processed events");
    let offset = store
        .current_offset(&node_id)
        .await
        .expect("could not get offset");
    assert_eq!(offset, Timestamp::new(2000).unwrap());
}
