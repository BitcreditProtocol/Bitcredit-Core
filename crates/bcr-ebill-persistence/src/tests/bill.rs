use crate::{
    tests::{
        bill_chain::get_first_block,
        tests::{
            bill_id_test, bill_id_test_other, bill_identified_participant_only_node_id,
            cached_bill, empty_address, get_bill_keys, node_id_test, node_id_test_other,
            private_key_test, signed_identity_proof_test, test_ts, valid_payment_address_testnet,
        },
    },
    traits::bill::{BillChainStoreApi, BillStoreApi},
};
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::{
    application::bill::{InMempoolData, PaidData, PaymentState},
    protocol::{
        BlockId, Sum, Timestamp,
        blockchain::bill::{
            BillBlock, BillOpCode,
            block::{
                BillOfferToSellBlockData, BillParticipantBlockData, BillPaymentBlockData,
                BillRecourseBlockData, BillRecourseReasonBlockData, BillRequestRecourseBlockData,
                BillRequestToAcceptBlockData, BillRequestToPayBlockData, BillSellBlockData,
            },
            participant::BillParticipant,
        },
        constants::{ACCEPT_DEADLINE_SECONDS, PAYMENT_DEADLINE_SECONDS, RECOURSE_DEADLINE_SECONDS},
        crypto::BcrKeys,
    },
};
use std::collections::HashSet;

fn paid_data() -> PaidData {
    PaidData {
        block_time: test_ts(),
        block_hash: "000000000061ad7b0d52af77e5a9dbcdc421bf00e93992259f16b2cf2693c4b1".to_owned(),
        confirmations: 6,
        tx_id: "80e4dc03b2ea934c97e265fa1855eba5c02788cb269e3f43a8e9a7bb0e114e2c".to_owned(),
    }
}

fn request_to_pay_block(id: &BillId, previous: &BillBlock, timestamp: Timestamp) -> BillBlock {
    BillBlock::create_block_for_request_to_pay(
        id.clone(),
        previous,
        &BillRequestToPayBlockData {
            requester: BillParticipantBlockData::Ident(
                bill_identified_participant_only_node_id(node_id_test()).into(),
            ),
            payment_data: BillPaymentBlockData {
                sum: Sum::new_sat(15_000).expect("sat works"),
                payment_address: valid_payment_address_testnet(),
                payment_deadline: timestamp + 2 * PAYMENT_DEADLINE_SECONDS,
            },
            signatory: None,
            signing_timestamp: timestamp,
            signing_address: Some(empty_address()),
            signer_identity_proof: Some(signed_identity_proof_test().into()),
        },
        &BcrKeys::from_private_key(&get_bill_keys().get_private_key()),
        None,
        &BcrKeys::from_private_key(&get_bill_keys().get_private_key()),
        timestamp,
    )
    .expect("request to pay block works")
}

fn request_to_accept_block(id: &BillId, previous: &BillBlock, timestamp: Timestamp) -> BillBlock {
    BillBlock::create_block_for_request_to_accept(
        id.clone(),
        previous,
        &BillRequestToAcceptBlockData {
            requester: BillParticipantBlockData::Ident(
                bill_identified_participant_only_node_id(node_id_test()).into(),
            ),
            signatory: None,
            signing_timestamp: timestamp,
            signing_address: Some(empty_address()),
            signer_identity_proof: Some(signed_identity_proof_test().into()),
            acceptance_deadline_timestamp: timestamp + 2 * ACCEPT_DEADLINE_SECONDS,
        },
        &BcrKeys::from_private_key(&private_key_test()),
        None,
        &BcrKeys::from_private_key(&get_bill_keys().get_private_key()),
        timestamp,
    )
    .expect("request to accept block works")
}

fn offer_to_sell_block(id: &BillId, previous: &BillBlock, timestamp: Timestamp) -> BillBlock {
    BillBlock::create_block_for_offer_to_sell(
        id.clone(),
        previous,
        &BillOfferToSellBlockData {
            seller: BillParticipantBlockData::Ident(
                bill_identified_participant_only_node_id(node_id_test()).into(),
            ),
            buyer: BillParticipantBlockData::Ident(
                bill_identified_participant_only_node_id(NodeId::new(
                    BcrKeys::new().pub_key(),
                    bitcoin::Network::Testnet,
                ))
                .into(),
            ),
            payment_data: BillPaymentBlockData {
                sum: Sum::new_sat(15_000).unwrap(),
                payment_address: valid_payment_address_testnet(),
                payment_deadline: timestamp + 2 * PAYMENT_DEADLINE_SECONDS,
            },
            signatory: None,
            signing_timestamp: timestamp,
            signing_address: Some(empty_address()),
            signer_identity_proof: Some(signed_identity_proof_test().into()),
        },
        &BcrKeys::from_private_key(&get_bill_keys().get_private_key()),
        None,
        &BcrKeys::from_private_key(&get_bill_keys().get_private_key()),
        timestamp,
    )
    .unwrap()
}

fn sell_block(id: &BillId, previous: &BillBlock, timestamp: Timestamp) -> BillBlock {
    BillBlock::create_block_for_sell(
        id.clone(),
        previous,
        &BillSellBlockData {
            seller: BillParticipantBlockData::Ident(
                bill_identified_participant_only_node_id(node_id_test()).into(),
            ),
            buyer: BillParticipantBlockData::Ident(
                bill_identified_participant_only_node_id(NodeId::new(
                    BcrKeys::new().pub_key(),
                    bitcoin::Network::Testnet,
                ))
                .into(),
            ),
            signatory: None,
            signing_timestamp: timestamp,
            signing_address: Some(empty_address()),
            signer_identity_proof: Some(signed_identity_proof_test().into()),
        },
        &BcrKeys::from_private_key(&private_key_test()),
        None,
        &BcrKeys::from_private_key(&get_bill_keys().get_private_key()),
        timestamp,
    )
    .unwrap()
}

fn request_recourse_block(id: &BillId, previous: &BillBlock, timestamp: Timestamp) -> BillBlock {
    BillBlock::create_block_for_request_recourse(
        id.clone(),
        previous,
        &BillRequestRecourseBlockData {
            recourser: BillParticipantBlockData::Ident(
                bill_identified_participant_only_node_id(node_id_test()).into(),
            ),
            recoursee: bill_identified_participant_only_node_id(NodeId::new(
                BcrKeys::new().pub_key(),
                bitcoin::Network::Testnet,
            ))
            .into(),
            payment_data: BillPaymentBlockData {
                sum: Sum::new_sat(15_000).unwrap(),

                payment_address: valid_payment_address_testnet(),

                payment_deadline: timestamp + 2 * RECOURSE_DEADLINE_SECONDS,
            },
            recourse_reason: BillRecourseReasonBlockData::Pay,
            signatory: None,
            signing_timestamp: timestamp,
            signing_address: Some(empty_address()),
            signer_identity_proof: Some(signed_identity_proof_test().into()),
        },
        &BcrKeys::from_private_key(&private_key_test()),
        None,
        &BcrKeys::from_private_key(&get_bill_keys().get_private_key()),
        timestamp,
    )
    .unwrap()
}

fn recourse_block(id: &BillId, previous: &BillBlock, timestamp: Timestamp) -> BillBlock {
    BillBlock::create_block_for_recourse(
        id.clone(),
        previous,
        &BillRecourseBlockData {
            recourser: BillParticipant::Ident(bill_identified_participant_only_node_id(
                node_id_test(),
            ))
            .into(),
            recoursee: bill_identified_participant_only_node_id(NodeId::new(
                BcrKeys::new().pub_key(),
                bitcoin::Network::Testnet,
            ))
            .into(),
            signatory: None,
            signing_timestamp: timestamp,
            signing_address: Some(empty_address()),
            signer_identity_proof: Some(signed_identity_proof_test().into()),
        },
        &BcrKeys::from_private_key(&private_key_test()),
        None,
        &BcrKeys::from_private_key(&get_bill_keys().get_private_key()),
        timestamp,
    )
    .unwrap()
}

pub async fn test_bill_store<B, C>(store: &B, chain_store: &C)
where
    B: BillStoreApi + ?Sized,
    C: BillChainStoreApi + ?Sized,
{
    let bill_id = bill_id_test();
    let other_bill_id = bill_id_test_other();

    // CACHE
    let bill = cached_bill(bill_id.clone());
    let other_bill = cached_bill(other_bill_id.clone());
    assert!(
        store
            .get_bill_from_cache(&bill_id, &node_id_test(),)
            .await
            .unwrap()
            .is_none()
    );
    store
        .save_bill_to_cache(&bill_id, &node_id_test(), &bill)
        .await
        .expect("save bill to cache");
    store
        .save_bill_to_cache(&other_bill_id, &node_id_test(), &other_bill)
        .await
        .expect("save other bill to cache");
    let cached = store
        .get_bill_from_cache(&bill_id, &node_id_test())
        .await
        .expect("get cached bill")
        .expect("cached bill exists");
    assert_eq!(cached.id, bill_id,);

    // saving the same bill for a different identity replaces the previous identity's cached bill
    store
        .save_bill_to_cache(&bill_id, &node_id_test_other(), &bill)
        .await
        .expect("save cache for other identity");
    assert!(
        store
            .get_bill_from_cache(&bill_id, &node_id_test(),)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_bill_from_cache(&bill_id, &node_id_test_other(),)
            .await
            .unwrap()
            .is_some()
    );

    // Bulk cache lookup.
    let cached_for_first_identity = store
        .get_bills_from_cache(&[bill_id.clone(), other_bill_id.clone()], &node_id_test())
        .await
        .expect("bulk cache lookup");
    assert_eq!(cached_for_first_identity.len(), 1,);
    assert_eq!(cached_for_first_identity[0].id, other_bill_id,);
    let cached_for_other_identity = store
        .get_bills_from_cache(
            &[bill_id.clone(), other_bill_id.clone()],
            &node_id_test_other(),
        )
        .await
        .expect("bulk cache lookup");
    assert_eq!(cached_for_other_identity.len(), 1,);
    assert_eq!(cached_for_other_identity[0].id, bill_id,);

    // invalidate_bill_in_cache
    store
        .invalidate_bill_in_cache(&bill_id)
        .await
        .expect("invalidate bill cache");
    assert!(
        store
            .get_bill_from_cache(&bill_id, &node_id_test_other(),)
            .await
            .unwrap()
            .is_none()
    );
    // other bill remains cached
    assert!(
        store
            .get_bill_from_cache(&other_bill_id, &node_id_test(),)
            .await
            .unwrap()
            .is_some()
    );

    // clear_bill_cache
    store
        .save_bill_to_cache(&bill_id, &node_id_test(), &bill)
        .await
        .unwrap();
    store.clear_bill_cache().await.expect("clear bill cache");
    assert!(
        store
            .get_bill_from_cache(&bill_id, &node_id_test(),)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_bill_from_cache(&other_bill_id, &node_id_test(),)
            .await
            .unwrap()
            .is_none()
    );

    // KEYS + EXISTS
    assert!(!store.exists(&bill_id).await.unwrap());
    let keys = BcrKeys::from_private_key(&private_key_test());

    // Key alone does not constitute an existing bill
    store
        .save_keys(&bill_id, &keys)
        .await
        .expect("save bill keys");
    assert!(!store.exists(&bill_id).await.unwrap());
    let stored_keys = store.get_keys(&bill_id).await.expect("get bill keys");
    assert_eq!(stored_keys.get_private_key(), private_key_test(),);

    // Bill + key means exists()
    let first = get_first_block(&bill_id);
    chain_store
        .add_block(&bill_id, &first)
        .await
        .expect("add first block");
    assert!(store.exists(&bill_id).await.unwrap());

    // A chain without keys still does not satisfy exists().
    let other_first = get_first_block(&other_bill_id);
    chain_store
        .add_block(&other_bill_id, &other_first)
        .await
        .expect("add other bill");
    assert!(!store.exists(&other_bill_id).await.unwrap());

    // GET IDS
    let ids = store.get_ids().await.expect("get bill ids");
    let ids: HashSet<_> = ids.into_iter().collect();
    assert_eq!(
        ids,
        HashSet::from([bill_id.clone(), other_bill_id.clone(),]),
    );

    // NORMAL PAYMENT STATE
    assert!(store.get_payment_state(&bill_id).await.unwrap().is_none());
    assert!(!store.is_paid(&bill_id).await.unwrap());

    // In mempool
    store
        .set_payment_state(
            &bill_id,
            &PaymentState::InMempool(InMempoolData {
                tx_id: "mempool-tx".to_owned(),
            }),
        )
        .await
        .unwrap();
    let state = store.get_payment_state(&bill_id).await.unwrap().unwrap();
    assert!(matches!(
        state,
        PaymentState::InMempool(
            InMempoolData { ref tx_id }
        ) if tx_id == "mempool-tx"
    ));

    assert!(!store.is_paid(&bill_id).await.unwrap());

    // Paid but unconfirmed
    store
        .set_payment_state(&bill_id, &PaymentState::PaidUnconfirmed(paid_data()))
        .await
        .unwrap();
    assert!(matches!(
        store.get_payment_state(&bill_id).await.unwrap().unwrap(),
        PaymentState::PaidUnconfirmed(..)
    ));
    assert!(!store.is_paid(&bill_id).await.unwrap());

    // Confirmed
    store
        .set_payment_state(&bill_id, &PaymentState::PaidConfirmed(paid_data()))
        .await
        .unwrap();
    let state = store.get_payment_state(&bill_id).await.unwrap().unwrap();
    match state {
        PaymentState::PaidConfirmed(data) => {
            let expected = paid_data();
            assert_eq!(data.block_time, expected.block_time,);
            assert_eq!(data.block_hash, expected.block_hash,);
            assert_eq!(data.confirmations, expected.confirmations,);
            assert_eq!(data.tx_id, expected.tx_id,);
        }
        other => panic!("expected PaidConfirmed, got {other:?}"),
    }
    assert!(store.is_paid(&bill_id).await.unwrap());

    store
        .set_payment_state(&bill_id, &PaymentState::NotFound)
        .await
        .unwrap();
    assert!(matches!(
        store.get_payment_state(&bill_id).await.unwrap(),
        Some(PaymentState::NotFound)
    ));
    assert!(!store.is_paid(&bill_id).await.unwrap());

    // OFFER-TO-SELL PAYMENT STATE
    let first_block_id = BlockId::first();
    store
        .set_offer_to_sell_payment_state(
            &bill_id,
            first_block_id,
            &PaymentState::PaidConfirmed(paid_data()),
        )
        .await
        .expect("set offer-to-sell payment");
    assert!(matches!(
        store
            .get_offer_to_sell_payment_state(&bill_id, first_block_id,)
            .await
            .unwrap(),
        Some(PaymentState::PaidConfirmed(..))
    ));
    let second_block_id = BlockId::next_from_previous_block_id(&first_block_id);
    assert!(
        store
            .get_offer_to_sell_payment_state(&bill_id, second_block_id,)
            .await
            .unwrap()
            .is_none()
    );

    // RECOURSE PAYMENT STATE
    store
        .set_recourse_payment_state(
            &bill_id,
            first_block_id,
            &PaymentState::PaidConfirmed(paid_data()),
        )
        .await
        .expect("set recourse payment");
    assert!(matches!(
        store
            .get_recourse_payment_state(&bill_id, first_block_id,)
            .await
            .unwrap(),
        Some(PaymentState::PaidConfirmed(..))
    ));
    assert!(
        store
            .get_recourse_payment_state(&bill_id, second_block_id,)
            .await
            .unwrap()
            .is_none()
    );

    // WAITING FOR NORMAL PAYMENT
    let request_to_pay = request_to_pay_block(&bill_id, &first, test_ts());
    chain_store
        .add_block(&bill_id, &request_to_pay)
        .await
        .expect("add request-to-pay block");

    // NotFound, so not confirmed-paid
    let waiting = store.get_bill_ids_waiting_for_payment().await.unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0], bill_id,);

    // confirmed payment removes it from waiting
    store
        .set_payment_state(&bill_id, &PaymentState::PaidConfirmed(paid_data()))
        .await
        .unwrap();
    assert!(
        store
            .get_bill_ids_waiting_for_payment()
            .await
            .unwrap()
            .is_empty()
    );

    // RESET CHAINS FOR LATEST-OP-CODE TESTS
    chain_store
        .remove_blocks_from_height(&bill_id, second_block_id)
        .await
        .unwrap();

    // WAITING FOR SELL PAYMENT
    let offer_to_sell = offer_to_sell_block(&bill_id, &first, test_ts());
    chain_store
        .add_block(&bill_id, &offer_to_sell)
        .await
        .unwrap();
    let waiting = store.get_bill_ids_waiting_for_sell_payment().await.unwrap();
    assert_eq!(waiting, vec![bill_id.clone()],);
    let sell = sell_block(&bill_id, &offer_to_sell, test_ts());
    chain_store.add_block(&bill_id, &sell).await.unwrap();
    assert!(
        store
            .get_bill_ids_waiting_for_sell_payment()
            .await
            .unwrap()
            .is_empty()
    );

    // WAITING FOR RECOURSE PAYMENT
    chain_store
        .remove_blocks_from_height(&bill_id, second_block_id)
        .await
        .unwrap();
    let request_recourse = request_recourse_block(&bill_id, &first, test_ts());
    chain_store
        .add_block(&bill_id, &request_recourse)
        .await
        .unwrap();
    let waiting = store
        .get_bill_ids_waiting_for_recourse_payment()
        .await
        .unwrap();
    assert_eq!(waiting, vec![bill_id.clone()],);
    let recourse = recourse_block(&bill_id, &request_recourse, test_ts());
    chain_store.add_block(&bill_id, &recourse).await.unwrap();
    assert!(
        store
            .get_bill_ids_waiting_for_recourse_payment()
            .await
            .unwrap()
            .is_empty()
    );

    // OP-CODES SINCE
    chain_store
        .remove_blocks_from_height(&bill_id, second_block_id)
        .await
        .unwrap();
    chain_store
        .remove_blocks_from_height(&other_bill_id, second_block_id)
        .await
        .unwrap();
    let base_ts = first.timestamp;
    let accept = request_to_accept_block(&bill_id, &first, base_ts + 1_000);
    chain_store.add_block(&bill_id, &accept).await.unwrap();
    let pay = request_to_pay_block(&other_bill_id, &other_first, base_ts + 1_500);
    chain_store.add_block(&other_bill_id, &pay).await.unwrap();
    let all = HashSet::from([BillOpCode::RequestToPay, BillOpCode::RequestToAccept]);
    let result = store
        .get_bill_ids_with_op_codes_since(all.clone(), Timestamp::new(0).unwrap())
        .await
        .unwrap();
    assert_eq!(
        result.into_iter().collect::<HashSet<_>>(),
        HashSet::from([bill_id.clone(), other_bill_id.clone(),]),
    );
    let result = store
        .get_bill_ids_with_op_codes_since(all, base_ts + 2_000)
        .await
        .unwrap();
    assert!(result.is_empty());
    let result = store
        .get_bill_ids_with_op_codes_since(
            HashSet::from([BillOpCode::RequestToAccept]),
            Timestamp::new(0).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(result, vec![bill_id.clone()],);
    let result = store
        .get_bill_ids_with_op_codes_since(
            HashSet::from([BillOpCode::RequestToPay]),
            Timestamp::new(0).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(result, vec![other_bill_id],);
}
