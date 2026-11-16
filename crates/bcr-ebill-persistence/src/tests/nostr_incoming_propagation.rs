use crate::traits::propagation::{
    ApplicationWaitReason, IncomingChainCandidate, IncomingChainQueueStatus,
    IncomingPropagationStoreApi,
};
use bcr_ebill_core::protocol::Timestamp;
use nostr::{
    event::{Event, EventBuilder, FinalizeEvent, Kind},
    key::Keys,
};
use std::time::Duration;
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

    // Candidate waits for a missing predecessor with a future retry deadline
    let predecessor_retry_at = Timestamp::new(Timestamp::now().inner() + 600).unwrap();
    store
        .mark_application_deferred(
            &id,
            Some(predecessor_retry_at),
            ApplicationWaitReason::MissingPredecessor,
            "Waiting for predecessor",
        )
        .await
        .unwrap();
    // Not currently due for application
    assert!(
        store
            .get_verified_candidates(Timestamp::now(), 10)
            .await
            .unwrap()
            .is_empty()
    );

    // Still eligible for fork selection
    let candidates = store
        .get_verified_candidates_for_chain(&first.chain_type, &first.chain_id)
        .await
        .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].event.id, first.event.id);

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

    let candidates = store
        .get_verified_candidates_for_chain(&first.chain_type, &first.chain_id)
        .await
        .unwrap();

    assert_eq!(candidates.len(), 0);

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

pub async fn test_incoming_chain_queue_status(store: &dyn IncomingPropagationStoreApi) {
    let empty = store
        .get_chain_queue_status("company", "status-test")
        .await
        .unwrap();
    assert_eq!(empty, IncomingChainQueueStatus::default());
    let candidates = (0..8)
        .map(|i| {
            let mut c = candidate(event(&format!("status-{i}")));
            c.chain_type = "company".into();
            c.chain_id = "status-test".into();
            c
        })
        .collect::<Vec<_>>();
    for c in &candidates {
        store.upsert_candidate(c, Timestamp::zero()).await.unwrap();
    }
    let confirmed = candidates[0].relays[..2].to_vec();
    // 0 stays pending. 1..=6 reach quorum
    for c in &candidates[1..=6] {
        store
            .mark_verified(&c.event.id.to_string(), Timestamp::now(), &confirmed)
            .await
            .unwrap();
    }
    // 1 is verified and ready to apply
    // 2..=5 wait for different application dependencies
    let future = Timestamp::new(Timestamp::now().inner() + 600).unwrap();

    for (index, reason, retry_at) in [
        (2, ApplicationWaitReason::MissingKeys, Some(future)),
        (3, ApplicationWaitReason::MissingPredecessor, Some(future)),
        (4, ApplicationWaitReason::Transient, Some(future)),
        (5, ApplicationWaitReason::ConflictingFork, None),
    ] {
        store
            .mark_application_deferred(
                &candidates[index].event.id.to_string(),
                retry_at,
                reason,
                "test deferred application",
            )
            .await
            .unwrap();
    }

    // 6 is applied, 7 rejected
    store
        .mark_applied(&candidates[6].event.id.to_string())
        .await
        .unwrap();
    store
        .mark_rejected(&candidates[7].event.id.to_string(), "invalid block")
        .await
        .unwrap();
    let status = store
        .get_chain_queue_status("company", "status-test")
        .await
        .unwrap();
    assert_eq!(
        status,
        IncomingChainQueueStatus {
            pending: 1,
            verified: 5,
            applied: 1,
            rejected: 1,
            ready_to_apply: 1,
            missing_keys: 1,
            missing_predecessor: 1,
            transient_application_failures: 1,
            conflicting_forks: 1,
        }
    );
    // No leakage between different chains or chain types
    assert_eq!(
        store
            .get_chain_queue_status("bill", "status-test")
            .await
            .unwrap(),
        IncomingChainQueueStatus::default(),
    );
    assert_eq!(
        store
            .get_chain_queue_status("company", "another-company")
            .await
            .unwrap(),
        IncomingChainQueueStatus::default(),
    );

    // Fork selection only considers verified candidates
    // This includes deferred candidates, independently of their application retry deadline
    let expected: std::collections::HashSet<_> = candidates[1..=4]
        .iter()
        .map(|candidate| candidate.event.id)
        .collect();
    let verified = store
        .get_verified_candidates_for_chain("company", "status-test")
        .await
        .unwrap();
    assert_eq!(verified.len(), 4);

    let actual: std::collections::HashSet<_> = verified
        .iter()
        .map(|candidate| candidate.event.id)
        .collect();
    assert_eq!(actual, expected);

    // Only candidate 1 is currently due for application
    let due = store
        .get_verified_candidates(Timestamp::now(), 16)
        .await
        .unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].event.id, candidates[1].event.id);

    // A different chain type with the same ID
    let mut other_type = candidate(event("other chain type"));
    other_type.chain_type = "bill".into();
    other_type.chain_id = "status-test".into();

    // The same chain type with a different ID
    let mut other_chain = candidate(event("other chain ID"));
    other_chain.chain_type = "company".into();
    other_chain.chain_id = "another-company".into();
    for other in [&other_type, &other_chain] {
        store
            .upsert_candidate(other, Timestamp::zero())
            .await
            .unwrap();
        store
            .mark_verified(
                &other.event.id.to_string(),
                Timestamp::zero(),
                &other.relays[..2],
            )
            .await
            .unwrap();
    }

    // Neither unrelated candidate may participate in selection for the original company
    let verified = store
        .get_verified_candidates_for_chain("company", "status-test")
        .await
        .unwrap();
    assert_eq!(verified.len(), 4);
    assert_eq!(
        verified
            .iter()
            .map(|candidate| candidate.event.id)
            .collect::<std::collections::HashSet<_>>(),
        expected,
    );

    let verified = store
        .get_verified_candidates_for_chain("bill", "status-test")
        .await
        .unwrap();
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].event.id, other_type.event.id);

    let verified = store
        .get_verified_candidates_for_chain("company", "another-company")
        .await
        .unwrap();
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].event.id, other_chain.event.id);
}

pub async fn test_unreadable_incoming_candidates_do_not_block_batches(
    store: &dyn IncomingPropagationStoreApi,
    other_key_store: &dyn IncomingPropagationStoreApi,
) {
    let now = Timestamp::new(1000).unwrap();
    let later = Timestamp::new(1).unwrap();
    let retry_at = now + Duration::from_secs(300);
    let unreadable = candidate(event("unreadable candidate"));
    let healthy = candidate(event("healthy candidate"));
    let unreadable_id = unreadable.event.id.to_string();
    let healthy_id = healthy.event.id.to_string();

    other_key_store
        .upsert_candidate(&unreadable, Timestamp::zero())
        .await
        .unwrap();
    store.upsert_candidate(&healthy, later).await.unwrap();

    // one bad row must not poison the batch
    let due = store.get_due_candidates(now, 2).await.unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].event.id, healthy.event.id);

    // Healthy candidate reaches quorum
    store
        .mark_verified(&healthy_id, later, &healthy.relays)
        .await
        .unwrap();

    // The unreadable candidate is no longer due
    assert!(store.get_due_candidates(now, 10).await.unwrap().is_empty());

    // can be read at retry
    let due = other_key_store
        .get_due_candidates(retry_at, 10)
        .await
        .unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].event.id, unreadable.event.id);
    assert_eq!(due[0].attempts, 1);
    assert_eq!(due[0].required_relays, unreadable.required_relays,);
    assert_eq!(due[0].relays, unreadable.relays);

    // previously verified row becoming unreadable under the current encryption key
    other_key_store
        .mark_verified(&unreadable_id, Timestamp::zero(), &unreadable.relays)
        .await
        .unwrap();
    assert!(
        store
            .get_verified_candidates(now, 1)
            .await
            .unwrap()
            .is_empty()
    );

    // deferral allows the next batch to progress
    let due = store.get_verified_candidates(now, 1).await.unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].event.id, healthy.event.id);
    assert!(
        store
            .get_verified_candidates_for_chain(&healthy.chain_type, &healthy.chain_id,)
            .await
            .is_err()
    );
    let status = store
        .get_chain_queue_status(&healthy.chain_type, &healthy.chain_id)
        .await
        .unwrap();
    assert_eq!(status.verified, 2);
    assert_eq!(status.rejected, 0);
    assert_eq!(status.transient_application_failures, 1);

    store.mark_applied(&healthy_id).await.unwrap();
    let due = other_key_store
        .get_verified_candidates(retry_at, 10)
        .await
        .unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].event.id, unreadable.event.id);
    assert_eq!(due[0].application_attempts, 1);
    assert_eq!(due[0].required_relays, unreadable.required_relays,);
}
