use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::protocol::{
    Date, Sha256Hash, Sum,
    blockchain::{
        Blockchain,
        bill::{
            BillBlock,
            block::{
                BillIssueBlockData, BillParticipantBlockData, BillPaymentBlockData,
                BillRequestToPayBlockData,
            },
            participant::BillParticipant,
        },
    },
    constants::PAYMENT_DEADLINE_SECONDS,
    crypto::BcrKeys,
};

use crate::{
    tests::tests::{
        bill_id_test, bill_identified_participant_only_node_id, empty_address,
        empty_bitcredit_bill, get_bill_keys, node_id_test, private_key_test,
        signed_identity_proof_test, test_ts, valid_payment_address_testnet,
    },
    traits::bill::BillChainStoreApi,
};

fn get_first_block(id: &BillId) -> BillBlock {
    let mut bill = empty_bitcredit_bill();
    bill.maturity_date = Date::new("2099-05-05").unwrap();
    bill.id = id.to_owned();
    bill.drawer = bill_identified_participant_only_node_id(NodeId::new(
        BcrKeys::new().pub_key(),
        bitcoin::Network::Testnet,
    ));
    bill.payee = BillParticipant::Ident(bill.drawer.clone());
    bill.drawee = bill_identified_participant_only_node_id(NodeId::new(
        BcrKeys::new().pub_key(),
        bitcoin::Network::Testnet,
    ));

    BillBlock::create_block_for_issue(
        id.to_owned(),
        Sha256Hash::new("prevhash"),
        &BillIssueBlockData::from(bill, None, test_ts(), signed_identity_proof_test()),
        &BcrKeys::from_private_key(&private_key_test()),
        None,
        &BcrKeys::from_private_key(&get_bill_keys().get_private_key()),
        test_ts(),
    )
    .unwrap()
}

fn get_second_block(block: &BillBlock) -> BillBlock {
    BillBlock::create_block_for_request_to_pay(
        block.bill_id.clone(),
        block,
        &BillRequestToPayBlockData {
            requester: BillParticipantBlockData::Ident(
                bill_identified_participant_only_node_id(node_id_test()).into(),
            ),
            payment_data: BillPaymentBlockData {
                sum: Sum::new_sat(15000).expect("sat works"),
                payment_address: valid_payment_address_testnet(),
                payment_deadline: test_ts() + 2 * PAYMENT_DEADLINE_SECONDS,
            },
            signatory: None,
            signing_timestamp: test_ts(),
            signing_address: Some(empty_address()),
            signer_identity_proof: Some(signed_identity_proof_test().into()),
        },
        &BcrKeys::from_private_key(&get_bill_keys().get_private_key()),
        None,
        &BcrKeys::from_private_key(&get_bill_keys().get_private_key()),
        test_ts(),
    )
    .unwrap()
}

pub async fn test_concurrent_first_block<S>(store: &S)
where
    S: BillChainStoreApi + ?Sized,
{
    let bill_id = bill_id_test();
    let block = get_first_block(&bill_id);
    let (result_a, result_b) = tokio::join!(
        store.add_block(&bill_id, &block,),
        store.add_block(&bill_id, &block,),
    );

    assert_ne!(
        result_a.is_ok(),
        result_b.is_ok(),
        "exactly one concurrent first block must succeed: \
     a={result_a:?}, b={result_b:?}"
    );

    let chain = store.get_chain(&bill_id).await.unwrap();
    assert_eq!(chain.blocks().len(), 1);
}

pub async fn test_concurrent_add<S>(store: &S)
where
    S: BillChainStoreApi + ?Sized,
{
    let bill_id = bill_id_test();
    let block = get_first_block(&bill_id);
    store
        .add_block(&bill_id, &block)
        .await
        .expect("add block works");
    let block2 = get_second_block(&block);
    let (result_a, result_b) = tokio::join!(
        store.add_block(&bill_id, &block2),
        store.add_block(&bill_id, &block2),
    );
    assert_ne!(
        result_a.is_ok(),
        result_b.is_ok(),
        "exactly one concurrent append must succeed: \
     a={result_a:?}, b={result_b:?}"
    );
    assert_eq!(store.get_chain(&bill_id).await.unwrap().blocks().len(), 2);
}

pub async fn test_chain<S>(store: &S)
where
    S: BillChainStoreApi + ?Sized,
{
    let bill_id = bill_id_test();

    // empty chain
    assert!(store.get_latest_block(&bill_id).await.is_err());

    // first block
    let block = get_first_block(&bill_id);
    store
        .add_block(&bill_id, &block)
        .await
        .expect("add first block works");
    let latest = store
        .get_latest_block(&bill_id)
        .await
        .expect("latest block exists");
    assert_eq!(latest, block);
    let chain = store.get_chain(&bill_id).await.expect("chain exists");
    assert_eq!(chain.blocks().len(), 1);
    assert_eq!(chain.blocks()[0], block);

    // second block
    let block2 = get_second_block(&block);
    store
        .add_block(&bill_id, &block2)
        .await
        .expect("add second block works");
    let latest = store
        .get_latest_block(&bill_id)
        .await
        .expect("latest block exists");
    assert_eq!(latest, block2);
    let chain = store.get_chain(&bill_id).await.expect("chain exists");
    assert_eq!(chain.blocks().len(), 2);
    assert_eq!(chain.blocks()[0], block);
    assert_eq!(chain.blocks()[1], block2);

    // remove second block
    store
        .remove_blocks_from_height(&bill_id, block2.id)
        .await
        .expect("remove block works");
    let latest = store
        .get_latest_block(&bill_id)
        .await
        .expect("first block remains");
    assert_eq!(latest, block);
    let chain = store.get_chain(&bill_id).await.expect("chain exists");
    assert_eq!(chain.blocks().len(), 1);
    assert_eq!(chain.blocks()[0], block);

    // re-append after truncation
    store
        .add_block(&bill_id, &block2)
        .await
        .expect("can append block again after truncation");

    let chain = store.get_chain(&bill_id).await.expect("chain exists");

    assert_eq!(chain.blocks().len(), 2);
    assert_eq!(chain.blocks()[1], block2);
}
