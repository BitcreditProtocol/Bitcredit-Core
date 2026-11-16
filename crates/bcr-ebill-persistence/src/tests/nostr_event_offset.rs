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
    assert!(!is_processed, "failed event must remain retryable");
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

pub async fn test_failed_event_is_retryable<S>(store: &S)
where
    S: NostrEventOffsetStoreApi + ?Sized,
{
    let node_id = node_id_test();
    let failed = NostrEventOffset {
        event_id: "retryable_event".into(),
        time: Timestamp::new(2000).unwrap(),
        success: false,
        node_id: node_id.clone(),
    };

    store.add_event(failed.clone()).await.unwrap();
    assert!(!store.is_processed(&failed.event_id).await.unwrap());
    assert_eq!(
        store.current_offset(&node_id).await.unwrap(),
        Timestamp::zero(),
    );
    // successful replay upgrades the existing failed row
    store
        .add_event(NostrEventOffset {
            success: true,
            ..failed.clone()
        })
        .await
        .unwrap();
    assert!(store.is_processed(&failed.event_id).await.unwrap());
    assert_eq!(
        store.current_offset(&node_id).await.unwrap(),
        Timestamp::new(2000).unwrap(),
    );
    // later failed duplicate cannot undo successful handling
    store.add_event(failed.clone()).await.unwrap();
    assert!(store.is_processed(&failed.event_id).await.unwrap());
}

pub async fn test_catchup_cursor_lifecycle(store: &dyn NostrEventOffsetStoreApi) {
    let relay1 = url::Url::parse("wss://r1.example").unwrap();
    let relay2 = url::Url::parse("wss://r2.example").unwrap();
    let subject = "test-recipient";
    assert_eq!(
        store
            .get_catchup_until("giftwrap", subject, &relay1)
            .await
            .unwrap(),
        None,
    );
    store
        .set_catchup_until("giftwrap", subject, &relay1, Some(1000))
        .await
        .unwrap();
    assert_eq!(
        store
            .get_catchup_until("giftwrap", subject, &relay1)
            .await
            .unwrap(),
        Some(1000),
    );
    // different relay and different scope are independent
    assert_eq!(
        store
            .get_catchup_until("giftwrap", subject, &relay2)
            .await
            .unwrap(),
        None,
    );
    assert_eq!(
        store
            .get_catchup_until("bill", subject, &relay1)
            .await
            .unwrap(),
        None,
    );
    store
        .set_catchup_until("giftwrap", subject, &relay1, Some(500))
        .await
        .unwrap();
    assert_eq!(
        store
            .get_catchup_until("giftwrap", subject, &relay1)
            .await
            .unwrap(),
        Some(500),
    );
    // completed historical sweep resets to newest
    store
        .set_catchup_until("giftwrap", subject, &relay1, None)
        .await
        .unwrap();
    assert_eq!(
        store
            .get_catchup_until("giftwrap", subject, &relay1)
            .await
            .unwrap(),
        None,
    );
}

pub async fn test_ignored_private_event_does_not_advance_offset(
    store: &dyn NostrEventOffsetStoreApi,
) {
    let node_id = node_id_test();
    let successful_time = Timestamp::new(1000).unwrap();
    let failed_time = Timestamp::new(2000).unwrap();
    let ignored_time = Timestamp::new(9000).unwrap();
    store
        .add_event(NostrEventOffset {
            event_id: "successful-event".into(),
            time: successful_time,
            success: true,
            node_id: node_id.clone(),
        })
        .await
        .unwrap();
    assert_eq!(
        store.current_offset(&node_id).await.unwrap(),
        successful_time,
    );

    // A newly encountered malformed private event can be ignored without advancing the offset
    store
        .ignore_private_event(
            "new-ignored-event",
            ignored_time,
            &node_id,
            "Malformed Bitcredit payload",
        )
        .await
        .unwrap();
    assert!(store.is_processed("new-ignored-event").await.unwrap(),);
    assert_eq!(
        store.current_offset(&node_id).await.unwrap(),
        successful_time,
    );

    // A previously failed event is initially retryable
    store
        .add_event(NostrEventOffset {
            event_id: "failed-event".into(),
            time: failed_time,
            success: false,
            node_id: node_id.clone(),
        })
        .await
        .unwrap();
    assert!(!store.is_processed("failed-event").await.unwrap(),);

    // It can then be classified as malformed and terminally ignored
    store
        .ignore_private_event(
            "failed-event",
            failed_time,
            &node_id,
            "Malformed Bitcredit payload",
        )
        .await
        .unwrap();
    assert!(store.is_processed("failed-event").await.unwrap(),);
    assert_eq!(
        store.current_offset(&node_id).await.unwrap(),
        successful_time,
    );
    // A late ignore attempt cannot overwrite an event that was previously processed successfully
    store
        .ignore_private_event(
            "successful-event",
            ignored_time,
            &node_id,
            "Late classification",
        )
        .await
        .unwrap();
    assert_eq!(
        store.current_offset(&node_id).await.unwrap(),
        successful_time,
    );

    // Real successful processing can still advance the offset, despite newer ignored events
    let next_successful_time = Timestamp::new(1500).unwrap();
    store
        .add_event(NostrEventOffset {
            event_id: "next-successful-event".into(),
            time: next_successful_time,
            success: true,
            node_id: node_id.clone(),
        })
        .await
        .unwrap();
    assert_eq!(
        store.current_offset(&node_id).await.unwrap(),
        next_successful_time,
    );

    // Rediscovery of an ignored event must not turn it into an offset-advancing successful event
    store
        .add_event(NostrEventOffset {
            event_id: "new-ignored-event".into(),
            time: ignored_time,
            success: true,
            node_id: node_id.clone(),
        })
        .await
        .unwrap();
    assert!(store.is_processed("new-ignored-event").await.unwrap(),);
    assert_eq!(
        store.current_offset(&node_id).await.unwrap(),
        next_successful_time,
    );
}
