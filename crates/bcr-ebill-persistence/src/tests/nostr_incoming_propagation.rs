use crate::traits::propagation::{
    ApplicationWaitReason, IncomingChainCandidate, IncomingPropagationStoreApi,
};
use bcr_ebill_core::protocol::Timestamp;
use nostr::{
    event::{Event, EventBuilder, FinalizeEvent, Kind},
    key::Keys,
};
use url::Url;

fn event(content: &str) -> Event {
    EventBuilder::new(Kind::TextNote, content)
        .finalize(&Keys::generate())
        .unwrap()
}

fn candidate(event: Event) -> IncomingChainCandidate {
    IncomingChainCandidate {
        event,
        chain_type: "bill".into(),
        chain_id: "test-bill".into(),
        relays: ["wss://r1.example", "wss://r2.example", "wss://r3.example"]
            .into_iter()
            .map(|url| Url::parse(url).unwrap())
            .collect(),
        required_relays: 2,
        attempts: 0,
        application_attempts: 0,
    }
}

pub async fn test_incoming_candidate_lifecycle(store: &dyn IncomingPropagationStoreApi) {
    let received_at = Timestamp::now();
    let first_try_at = Timestamp::new(received_at.inner() + 3).unwrap();
    let retry_at = Timestamp::new(first_try_at.inner() + 60).unwrap();
    let first = candidate(event("first event"));
    let id = first.event.id.to_string();
    store.upsert_candidate(&first, first_try_at).await.unwrap();
    // 3 second grace period - no verification yet
    assert!(
        store
            .get_due_candidates(received_at, 10)
            .await
            .unwrap()
            .is_empty()
    );

    // duplicate delivery does not replace the original relay set or reset its timer
    let mut duplicate = first.clone();
    duplicate.relays = vec![Url::parse("wss://attacker.example").unwrap()];
    duplicate.required_relays = 1;
    store
        .upsert_candidate(&duplicate, received_at)
        .await
        .unwrap();
    assert!(
        store
            .get_due_candidates(received_at, 10)
            .await
            .unwrap()
            .is_empty()
    );

    let due = store.get_due_candidates(first_try_at, 10).await.unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].event.id, first.event.id);
    assert_eq!(due[0].required_relays, 2);
    assert_eq!(due[0].relays.len(), 3);
    assert_eq!(due[0].attempts, 0);

    // a failed verification is deferred - duplicates don't set it to pending
    store
        .mark_pending_retry(&id, retry_at, "only one relay confirmed")
        .await
        .unwrap();
    store.upsert_candidate(&first, received_at).await.unwrap();
    assert!(
        store
            .get_due_candidates(first_try_at, 10)
            .await
            .unwrap()
            .is_empty()
    );

    let due = store.get_due_candidates(retry_at, 10).await.unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].attempts, 1);

    // unverified event can never be marked applied
    store.mark_applied(&id).await.unwrap();
    assert_eq!(
        store.get_due_candidates(retry_at, 10).await.unwrap().len(),
        1
    );

    // quorum reached - record the relays
    let confirmations = [first.relays[0].clone(), first.relays[1].clone()];
    store
        .mark_verified(&id, retry_at, &confirmations)
        .await
        .unwrap();
    assert!(
        store
            .get_due_candidates(retry_at, 10)
            .await
            .unwrap()
            .is_empty()
    );
    let verified = store.get_verified_candidates(retry_at, 10).await.unwrap();
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].application_attempts, 0);
    assert_eq!(verified[0].event.id, first.event.id);

    // cannot revert a verified event to pending
    store.upsert_candidate(&first, received_at).await.unwrap();
    store
        .mark_pending_retry(&id, retry_at, "late failure")
        .await
        .unwrap();
    assert_eq!(
        store
            .get_verified_candidates(retry_at, 10)
            .await
            .unwrap()
            .len(),
        1
    );

    store
        .mark_application_deferred(
            &id,
            None,
            ApplicationWaitReason::MissingKeys,
            "Waiting for chain keys",
        )
        .await
        .unwrap();

    assert!(
        store
            .get_verified_candidates(Timestamp::now(), 10)
            .await
            .unwrap()
            .is_empty()
    );

    store
        .wake_application_for_keys(&first.chain_type, &first.chain_id)
        .await
        .unwrap();

    let verified = store
        .get_verified_candidates(Timestamp::now(), 10)
        .await
        .unwrap();

    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].application_attempts, 0);

    // candidate waits indefinitely for a missing predecessor
    store
        .mark_application_deferred(
            &id,
            None,
            ApplicationWaitReason::MissingPredecessor,
            "Waiting for predecessor",
        )
        .await
        .unwrap();
    assert!(
        store
            .get_verified_candidates(Timestamp::now(), 10)
            .await
            .unwrap()
            .is_empty()
    );

    // unrelated chain progress does not wake this candidate
    store
        .wake_application_for_predecessor(&first.chain_type, "another-bill")
        .await
        .unwrap();
    assert!(
        store
            .get_verified_candidates(Timestamp::now(), 10)
            .await
            .unwrap()
            .is_empty()
    );

    // progress on the candidate chain wakes it
    store
        .wake_application_for_predecessor(&first.chain_type, &first.chain_id)
        .await
        .unwrap();

    let verified = store
        .get_verified_candidates(Timestamp::now(), 10)
        .await
        .unwrap();

    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].event.id, first.event.id);

    // predecessor wake does not reset application attempts
    assert_eq!(verified[0].application_attempts, 1);

    // applied is permanent
    store.mark_applied(&id).await.unwrap();
    assert!(
        store
            .get_verified_candidates(Timestamp::now(), 10)
            .await
            .unwrap()
            .is_empty()
    );
    store.upsert_candidate(&first, received_at).await.unwrap();
    store
        .mark_pending_retry(&id, retry_at, "late error")
        .await
        .unwrap();
    assert!(
        store
            .get_due_candidates(retry_at, 10)
            .await
            .unwrap()
            .is_empty()
    );

    // rejected is permanent
    let second = candidate(event("second event"));
    let second_id = second.event.id.to_string();
    store.upsert_candidate(&second, received_at).await.unwrap();
    store
        .mark_rejected(&second_id, "invalid signature")
        .await
        .unwrap();
    store.upsert_candidate(&second, received_at).await.unwrap();
    assert!(
        store
            .get_due_candidates(retry_at, 10)
            .await
            .unwrap()
            .is_empty()
    );

    // quorum larger than the deduplicated relay set is invalid
    let mut invalid = candidate(event("invalid threshold"));
    invalid.required_relays = 4;
    assert!(store.upsert_candidate(&invalid, received_at).await.is_err());
}
