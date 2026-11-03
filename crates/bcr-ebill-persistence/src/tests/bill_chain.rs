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
    tests::{
        tests::{
            bill_id_test, bill_identified_participant_only_node_id, empty_address,
            empty_bitcredit_bill, get_bill_keys, node_id_test, private_key_test,
            signed_identity_proof_test, test_ts, valid_payment_address_testnet,
        },
        transaction_test_utils::{remove_bill_blocks_from_height, seed_bill_blocks},
    },
    traits::{bill::BillChainStoreApi, transaction::TransactionManagerApi},
};

pub fn get_first_block(id: &BillId) -> BillBlock {
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

async fn get_latest_block<S>(store: &S, bill_id: &BillId) -> crate::Result<BillBlock>
where
    S: BillChainStoreApi + ?Sized,
{
    Ok(store
        .get_chain(bill_id)
        .await?
        .get_latest_block()
        .to_owned())
}

pub async fn test_chain<S>(transaction_manager: &dyn TransactionManagerApi, store: &S)
where
    S: BillChainStoreApi + ?Sized,
{
    let bill_id = bill_id_test();

    // empty chain
    assert!(get_latest_block(store, &bill_id).await.is_err());

    // first block
    let block = get_first_block(&bill_id);
    seed_bill_blocks(
        transaction_manager,
        &bill_id,
        None,
        std::slice::from_ref(&block),
    )
    .await;
    let latest = get_latest_block(store, &bill_id)
        .await
        .expect("latest block exists");
    assert_eq!(latest, block);
    let chain = store.get_chain(&bill_id).await.expect("chain exists");
    assert_eq!(chain.blocks().len(), 1);
    assert_eq!(chain.blocks()[0], block);

    // second block
    let block2 = get_second_block(&block);
    seed_bill_blocks(
        transaction_manager,
        &bill_id,
        Some(&block),
        std::slice::from_ref(&block2),
    )
    .await;
    let latest = get_latest_block(store, &bill_id)
        .await
        .expect("latest block exists");
    assert_eq!(latest, block2);
    let chain = store.get_chain(&bill_id).await.expect("chain exists");
    assert_eq!(chain.blocks().len(), 2);
    assert_eq!(chain.blocks()[0], block);
    assert_eq!(chain.blocks()[1], block2);

    // remove second block
    remove_bill_blocks_from_height(transaction_manager, &bill_id, &block2, block2.id).await;
    let latest = get_latest_block(store, &bill_id)
        .await
        .expect("first block remains");
    assert_eq!(latest, block);
    let chain = store.get_chain(&bill_id).await.expect("chain exists");
    assert_eq!(chain.blocks().len(), 1);
    assert_eq!(chain.blocks()[0], block);

    // re-append after truncation
    seed_bill_blocks(
        transaction_manager,
        &bill_id,
        Some(&block),
        std::slice::from_ref(&block2),
    )
    .await;

    let chain = store.get_chain(&bill_id).await.expect("chain exists");

    assert_eq!(chain.blocks().len(), 2);
    assert_eq!(chain.blocks()[1], block2);
}
