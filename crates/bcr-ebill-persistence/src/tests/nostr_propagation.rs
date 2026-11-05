use crate::{
    tests::propagation_transaction::sample_propagation,
    traits::{
        propagation::{NostrPropagationStoreApi, PropagationSubjectType},
        transaction::TransactionManagerApi,
    },
};
use bcr_ebill_core::protocol::Timestamp;

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
