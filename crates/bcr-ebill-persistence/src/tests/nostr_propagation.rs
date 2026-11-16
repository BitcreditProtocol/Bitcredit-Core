use crate::tests::propagation_transaction::sample_propagation;
use crate::traits::{
    propagation::{
        NostrPropagationStoreApi, PreparedPropagation, PreparedPropagationMessage,
        PropagationStatus, PropagationSubjectType,
    },
    transaction::TransactionManagerApi,
};
use bcr_ebill_core::protocol::{Sha256Hash, Timestamp, event::EventType};
use nostr::{
    event::{EventBuilder, FinalizeEvent, Kind},
    key::Keys,
};
use std::time::Duration;

use url::Url;
use uuid::Uuid;

pub async fn test_propagation_store(
    store: &dyn NostrPropagationStoreApi,
    manager: &dyn TransactionManagerApi,
) {
    let propagation = sample_propagation();
    let message = &propagation.messages[0];

    // enqueue and commit using the transactional API
    let mut tx = manager.begin().await.unwrap();
    tx.enqueue_propagation(&propagation).await.unwrap();
    tx.commit().await.unwrap();

    // 1. query propagation and relay statuses
    let status = store
        .get_propagation(&propagation.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status.id, propagation.id);
    assert_eq!(status.subject_id, propagation.subject_id);
    assert_eq!(status.messages.len(), 1);
    assert_eq!(status.messages[0].relays.len(), 2);
    assert!(
        status.messages[0]
            .relays
            .iter()
            .all(|r| { r.accepted_at.is_none() && r.attempts == 0 })
    );

    // 2. query subject
    let ids = store
        .list_propagation_ids(PropagationSubjectType::Bill, &propagation.subject_id)
        .await
        .unwrap();
    assert_eq!(ids, vec![propagation.id.clone()]);

    // 3. initially both relays need delivery
    let pending = store
        .get_pending_deliveries(Timestamp::now(), 10)
        .await
        .unwrap();
    assert_eq!(pending.len(), 2);
    assert!(pending.iter().all(|delivery| {
        delivery.message_id == message.id && delivery.event.id == message.event.id
    }));

    let group_pending = store
        .get_pending_deliveries_for_propagation(&propagation.id, Timestamp::now())
        .await
        .unwrap();
    assert_eq!(group_pending.len(), 2);

    // 4. one relay fails and gets scheduled for later
    let relay_a = &message.target_relays[0];
    let relay_b = &message.target_relays[1];
    let retry_at = Timestamp::new(Timestamp::now().inner() + 3600).unwrap();
    store
        .mark_relay_failed(&message.id, relay_b, retry_at, "relay timeout")
        .await
        .unwrap();

    // only relay A is currently pending
    let pending = store
        .get_pending_deliveries(Timestamp::now(), 10)
        .await
        .unwrap();

    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].relay_url, *relay_a);

    // 5. relay A accepts event
    store
        .mark_relay_accepted(&message.id, relay_a, Timestamp::now())
        .await
        .unwrap();

    // no deliveries are pending anymore
    assert!(
        store
            .get_pending_deliveries(Timestamp::now(), 10)
            .await
            .unwrap()
            .is_empty()
    );

    // 6. delayed failure does not erase acceptance
    store
        .mark_relay_failed(&message.id, relay_a, Timestamp::now(), "late failure")
        .await
        .unwrap();
    let status = store
        .get_propagation(&propagation.id)
        .await
        .unwrap()
        .unwrap();
    let accepted = status.messages[0]
        .relays
        .iter()
        .find(|r| &r.relay_url == relay_a)
        .unwrap();
    assert!(accepted.accepted_at.is_some());
    assert_eq!(accepted.attempts, 1);
    assert!(accepted.last_error.is_none());
    let failed = status.messages[0]
        .relays
        .iter()
        .find(|r| &r.relay_url == relay_b)
        .unwrap();
    assert!(failed.accepted_at.is_none());
    assert_eq!(failed.attempts, 1);
    assert_eq!(failed.last_error.as_deref(), Some("relay timeout"));

    // 7. late acceptance clears previous failure
    store
        .mark_relay_accepted(&message.id, relay_b, Timestamp::now())
        .await
        .unwrap();
    let status = store
        .get_propagation(&propagation.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        status.messages[0]
            .relays
            .iter()
            .all(|r| { r.accepted_at.is_some() && r.last_error.is_none() })
    );

    // nothing left to retry
    assert!(
        store
            .get_pending_deliveries(Timestamp::now(), 10)
            .await
            .unwrap()
            .is_empty()
    );
    // a missing propagation is not an error
    assert!(
        store
            .get_propagation("nonexistent")
            .await
            .unwrap()
            .is_none()
    );
}

fn relay_status<'a>(
    status: &'a PropagationStatus,
    message_id: &str,
    relay_url: &Url,
) -> &'a crate::traits::propagation::RelayPropagationStatus {
    status
        .messages
        .iter()
        .find(|message| message.id == message_id)
        .expect("message exists")
        .relays
        .iter()
        .find(|relay| &relay.relay_url == relay_url)
        .expect("relay exists")
}

pub async fn test_retry_now_preserves_accepted_deliveries<S, T>(store: &S, transaction_manager: &T)
where
    S: NostrPropagationStoreApi + ?Sized,
    T: TransactionManagerApi + ?Sized,
{
    let r1 = Url::parse("wss://r1.example").unwrap();
    let r2 = Url::parse("wss://r2.example").unwrap();
    let event = EventBuilder::new(Kind::TextNote, "manual retry persistence test")
        .finalize(&Keys::generate())
        .unwrap();
    let propagation_id = Uuid::new_v4().to_string();
    let message_id = Uuid::new_v4().to_string();
    let bill_id = crate::tests::tests::bill_id_test();
    let propagation = PreparedPropagation {
        id: propagation_id.clone(),
        subject_type: PropagationSubjectType::Bill,
        subject_id: bill_id.to_string(),
        created_at: Timestamp::now(),
        messages: vec![PreparedPropagationMessage {
            id: message_id.clone(),
            event_type: EventType::BillChain,
            recipient_id: None,
            chain_id: Some(bill_id.to_string()),
            block_hash: Some(Sha256Hash::new("retry-test-block")),
            event,
            target_relays: vec![r1.clone(), r2.clone()],
        }],
    };

    let mut tx = transaction_manager.begin().await.unwrap();
    tx.enqueue_propagation(&propagation).await.unwrap();
    tx.commit().await.unwrap();

    // r1 acknowledged
    let accepted_at = Timestamp::now();
    store
        .mark_relay_accepted(&message_id, &r1, accepted_at)
        .await
        .unwrap();

    // r2 failed and has a future retry time
    let future_retry = Timestamp::now() + 3600;
    store
        .mark_relay_failed(&message_id, &r2, future_retry, "relay offline")
        .await
        .unwrap();

    let before = store
        .get_propagation(&propagation_id)
        .await
        .unwrap()
        .unwrap();
    let accepted_before = relay_status(&before, &message_id, &r1).clone();
    let pending_before = relay_status(&before, &message_id, &r2).clone();
    assert_eq!(accepted_before.accepted_at, Some(accepted_at),);
    assert!(pending_before.accepted_at.is_none());
    assert_eq!(pending_before.next_try_at, future_retry,);
    assert_eq!(pending_before.last_error.as_deref(), Some("relay offline"),);

    // trigger reset
    store.make_pending_deliveries_due_now().await.unwrap();
    let after = store
        .get_propagation(&propagation_id)
        .await
        .unwrap()
        .unwrap();
    let accepted_after = relay_status(&after, &message_id, &r1);
    let pending_after = relay_status(&after, &message_id, &r2);

    // previously accepted relay: no changes
    assert_eq!(accepted_after.accepted_at, accepted_before.accepted_at,);
    assert_eq!(accepted_after.attempts, accepted_before.attempts,);
    assert_eq!(accepted_after.next_try_at, accepted_before.next_try_at,);
    assert_eq!(accepted_after.last_error, accepted_before.last_error,);
    // pending relay: backoff removed, history preserved
    assert_eq!(pending_after.accepted_at, None);
    assert_eq!(pending_after.next_try_at, Timestamp::zero(),);
    assert_eq!(pending_after.attempts, pending_before.attempts,);
    assert_eq!(pending_after.last_error, pending_before.last_error,);
}

pub async fn test_same_second_propagations_are_ordered_by_sequence(
    store: &dyn NostrPropagationStoreApi,
    manager: &dyn TransactionManagerApi,
) {
    // Deliberately use IDs whose lexical ordering is the opposite of their insertion order
    let mut older = sample_propagation();
    older.id = "ffffffff-ffff-4fff-8fff-ffffffffffff".to_owned();
    older.subject_id = "same-second-bill".to_owned();
    let mut newer = sample_propagation();
    newer.id = "00000000-0000-4000-8000-000000000000".to_owned();
    newer.subject_id = older.subject_id.clone();

    // propagations have the same timestamp
    newer.created_at = older.created_at;
    assert!(older.id > newer.id);

    for propagation in [&older, &newer] {
        let mut tx = manager.begin().await.unwrap();
        tx.enqueue_propagation(propagation).await.unwrap();
        tx.commit().await.unwrap();
    }
    for relay in &older.messages[0].target_relays {
        store
            .mark_relay_accepted(&older.messages[0].id, relay, Timestamp::now())
            .await
            .unwrap();
    }
    let ids = store
        .list_propagation_ids(PropagationSubjectType::Bill, &older.subject_id)
        .await
        .unwrap();
    assert_eq!(
        ids,
        vec![newer.id.clone(), older.id.clone()],
        "Newest insertion must be first, regardless of UUIDv4 ordering"
    );

    let latest = store.get_propagation(&ids[0]).await.unwrap().unwrap();
    assert_eq!(latest.id, newer.id);
    assert!(
        latest.messages[0]
            .relays
            .iter()
            .all(|relay| relay.accepted_at.is_none())
    );

    let previous = store.get_propagation(&older.id).await.unwrap().unwrap();
    assert!(
        previous.messages[0]
            .relays
            .iter()
            .all(|relay| relay.accepted_at.is_some())
    );
}

pub async fn test_unreadable_outgoing_deliveries_do_not_block_batches(
    store: &dyn NostrPropagationStoreApi,
    manager: &dyn TransactionManagerApi,
    other_key_manager: &dyn TransactionManagerApi,
) {
    let mut unreadable = sample_propagation();
    unreadable.messages[0].id = "00000000-0000-4000-8000-000000000000".into();
    let mut healthy = sample_propagation();
    healthy.messages[0].id = "ffffffff-ffff-4fff-8fff-ffffffffffff".into();
    healthy.subject_id = "healthy-bill".into();
    healthy.messages[0].chain_id = Some(healthy.subject_id.clone());

    // Write the unreadable propagation with another key
    let mut tx = other_key_manager.begin().await.unwrap();
    tx.enqueue_propagation(&unreadable).await.unwrap();
    tx.commit().await.unwrap();

    // Write a healthy propagation using the correct key
    let mut tx = manager.begin().await.unwrap();
    tx.enqueue_propagation(&healthy).await.unwrap();
    tx.commit().await.unwrap();
    store.make_pending_deliveries_due_now().await.unwrap();
    let now = Timestamp::now();
    // The oldest batch contains both unreadable relay deliveries. Both receive future retry deadlines
    assert!(
        store
            .get_pending_deliveries(now, 2)
            .await
            .unwrap()
            .is_empty()
    );
    // The next batch contains the healthy deliveries
    let due = store.get_pending_deliveries(now, 2).await.unwrap();
    assert_eq!(due.len(), 2);
    assert!(
        due.iter()
            .all(|delivery| { delivery.propagation_id == healthy.id })
    );
    let status = store
        .get_propagation(&unreadable.id)
        .await
        .unwrap()
        .unwrap();
    assert!(status.messages[0].relays.iter().all(|relay| {
        relay.accepted_at.is_none()
            && relay.attempts == 1
            && relay.next_try_at == now + Duration::from_secs(300)
            && relay
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("Unreadable persisted outgoing delivery"))
    }));
    // Also exercise the immediate propagation reader
    store.make_pending_deliveries_due_now().await.unwrap();
    assert!(
        store
            .get_pending_deliveries_for_propagation(&unreadable.id, now,)
            .await
            .unwrap()
            .is_empty()
    );
    let due = store
        .get_pending_deliveries_for_propagation(&healthy.id, now)
        .await
        .unwrap();
    assert_eq!(due.len(), 2);
    // Healthy deliveries can still be acknowledged
    for delivery in due {
        store
            .mark_relay_accepted(&delivery.message_id, &delivery.relay_url, now)
            .await
            .unwrap();
    }
    assert!(
        store
            .get_pending_deliveries(now, 10)
            .await
            .unwrap()
            .is_empty()
    );
    let status = store
        .get_propagation(&unreadable.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        status.messages[0]
            .relays
            .iter()
            .all(|relay| { relay.accepted_at.is_none() && relay.attempts == 2 })
    );
}
