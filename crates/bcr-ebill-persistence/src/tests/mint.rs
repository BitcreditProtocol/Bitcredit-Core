use bcr_ebill_core::protocol::{Sum, mint::MintRequestStatus};

use crate::{
    tests::tests::{bill_id_test, node_id_test, node_id_test_other, test_ts},
    traits::mint::MintStoreApi,
};

pub async fn mint_store_contract<S>(store: &S)
where
    S: MintStoreApi + ?Sized,
{
    let request_id = uuid::uuid!("00000000-0000-0000-0000-000000000001");
    let request_id_2 = uuid::uuid!("00000000-0000-0000-0000-000000000002");
    let requester = node_id_test();
    let other_requester = node_id_test_other();
    let bill_id = bill_id_test();
    let mint_node = node_id_test_other();
    let timestamp = test_ts();

    // exists / add
    assert!(!store.exists_for_bill(&requester, &bill_id).await.unwrap());
    store
        .add_request(&requester, &bill_id, &mint_node, &request_id, timestamp)
        .await
        .unwrap();
    assert!(store.exists_for_bill(&requester, &bill_id).await.unwrap());

    // get
    let request = store.get_request(&request_id).await.unwrap().unwrap();
    assert!(matches!(request.status, MintRequestStatus::Pending));

    // filtered queries
    assert_eq!(
        store
            .get_requests(&requester, &bill_id, &mint_node,)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .get_requests_for_bill(&requester, &bill_id,)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(store.get_all_active_requests().await.unwrap().len(), 1);

    // status round-trip
    store
        .update_request(&request_id, &MintRequestStatus::Denied { timestamp })
        .await
        .unwrap();
    let request = store.get_request(&request_id).await.unwrap().unwrap();
    assert!(matches!(
        request.status,
        MintRequestStatus::Denied {
            timestamp: ts
        } if ts == timestamp
    ));

    // Denied is not active.
    assert!(store.get_all_active_requests().await.unwrap().is_empty());
    store
        .update_request(&request_id, &MintRequestStatus::Offered)
        .await
        .unwrap();
    assert_eq!(store.get_all_active_requests().await.unwrap().len(), 1);

    // Second requester / same bill.
    store
        .add_request(
            &other_requester,
            &bill_id,
            &mint_node,
            &request_id_2,
            timestamp,
        )
        .await
        .unwrap();
    assert!(
        store
            .exists_for_bill(&other_requester, &bill_id)
            .await
            .unwrap()
    );

    // Offer
    let sum = Sum::new_sat(1500).unwrap();
    store
        .add_offer(&request_id, "keyset_id", timestamp, sum.clone())
        .await
        .unwrap();
    let offer = store.get_offer(&request_id).await.unwrap().unwrap();
    assert_eq!(offer.mint_request_id, request_id);
    assert_eq!(offer.keyset_id, "keyset_id");
    assert_eq!(offer.expiration_timestamp, timestamp);
    assert_eq!(offer.discounted_sum, sum);
    assert!(offer.proofs.is_none());
    assert!(!offer.proofs_spent);
    assert!(offer.recovery_data.is_none());

    // Duplicate offer
    assert!(
        store
            .add_offer(
                &request_id,
                "another",
                timestamp,
                Sum::new_sat(2000).unwrap(),
            )
            .await
            .is_err()
    );

    // Recovery data
    store
        .add_recovery_data_to_offer(&request_id, &["secret".to_owned()], &["r".to_owned()])
        .await
        .unwrap();
    let offer = store.get_offer(&request_id).await.unwrap().unwrap();
    let recovery = offer.recovery_data.unwrap();
    assert_eq!(recovery.secrets, vec!["secret"]);
    assert_eq!(recovery.rs, vec!["r"]);

    // Proofs
    store
        .add_proofs_to_offer(&request_id, "proofs")
        .await
        .unwrap();
    let offer = store.get_offer(&request_id).await.unwrap().unwrap();
    assert_eq!(offer.proofs.as_deref(), Some("proofs"));
    assert!(!offer.proofs_spent);

    // Proofs can only be added once
    assert!(
        store
            .add_proofs_to_offer(&request_id, "other-proofs",)
            .await
            .is_err()
    );

    // Mark spent
    store
        .set_proofs_to_spent_for_offer(&request_id)
        .await
        .unwrap();
    assert!(
        store
            .get_offer(&request_id)
            .await
            .unwrap()
            .unwrap()
            .proofs_spent
    );

    // Reset bill: request + associated offer disappear
    store.dev_mode_reset_for_bill(&bill_id).await.unwrap();
    assert!(store.get_request(&request_id).await.unwrap().is_none());
    assert!(store.get_request(&request_id_2).await.unwrap().is_none());
    assert!(store.get_offer(&request_id).await.unwrap().is_none());
}
