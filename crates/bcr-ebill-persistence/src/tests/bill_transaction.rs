use crate::{
    Error,
    traits::{
        bill::{BillChainStoreApi, BillStoreApi},
        transaction::TransactionManagerApi,
    },
};
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::protocol::{
    BlockId, Sha256Hash, Timestamp,
    blockchain::{
        Blockchain,
        bill::{BillBlock, BillOpCode},
    },
    crypto::BcrKeys,
};

fn make_bill_id(keys: &BcrKeys) -> BillId {
    BillId::new(keys.pub_key(), bitcoin::Network::Testnet)
}

fn make_block(
    bill_id: &BillId,
    previous: Option<&BillBlock>,
    signer_keys: &BcrKeys,
    bill_keys: &BcrKeys,
    marker: &[u8],
) -> BillBlock {
    let (id, previous_hash, op_code, timestamp) = match previous {
        None => (
            BlockId::first(),
            Sha256Hash::from_bytes(b"bill-transaction-genesis"),
            BillOpCode::Issue,
            Timestamp::new(1_700_000_000).unwrap(),
        ),
        Some(previous) => (
            BlockId::next_from_previous_block_id(&previous.id),
            previous.hash.clone(),
            BillOpCode::Accept,
            previous.timestamp + 1,
        ),
    };
    BillBlock::new(
        bill_id.clone(),
        id,
        previous_hash,
        marker.to_vec(),
        op_code,
        signer_keys,
        None,
        bill_keys,
        timestamp,
        Sha256Hash::from_bytes(marker),
    )
    .expect("could not create bill block")
}

fn make_chain() -> (BillId, BcrKeys, BillBlock, BillBlock, BillBlock) {
    let bill_keys = BcrKeys::new();
    let signer_keys = BcrKeys::new();
    let bill_id = make_bill_id(&bill_keys);
    let first = make_block(&bill_id, None, &signer_keys, &bill_keys, b"first");
    let second = make_block(&bill_id, Some(&first), &signer_keys, &bill_keys, b"second");
    let third = make_block(&bill_id, Some(&second), &signer_keys, &bill_keys, b"third");
    (bill_id, bill_keys, first, second, third)
}

pub async fn test_bill_transaction_commit<M, S, C>(manager: &M, store: &S, chain_store: &C)
where
    M: TransactionManagerApi + ?Sized,
    S: BillStoreApi + ?Sized,
    C: BillChainStoreApi + ?Sized,
{
    let (bill_id, bill_keys, first, second, _) = make_chain();
    let mut tx = manager.begin().await.unwrap();
    tx.append_bill_blocks(&bill_id, None, &[first.clone(), second.clone()])
        .await
        .unwrap();
    tx.save_bill_keys(&bill_id, &bill_keys).await.unwrap();
    tx.commit().await.unwrap();
    let chain = chain_store.get_chain(&bill_id).await.unwrap();
    assert_eq!(chain.blocks().len(), 2);
    assert_eq!(chain.blocks()[0].hash, first.hash);
    assert_eq!(chain.blocks()[1].hash, second.hash);
    let stored_keys = store.get_keys(&bill_id).await.unwrap();
    assert_eq!(stored_keys.get_private_key(), bill_keys.get_private_key());
    assert!(store.exists(&bill_id).await.unwrap());
}

pub async fn test_bill_transaction_rollback<M, S, C>(manager: &M, store: &S, chain_store: &C)
where
    M: TransactionManagerApi + ?Sized,
    S: BillStoreApi + ?Sized,
    C: BillChainStoreApi + ?Sized,
{
    let (bill_id, bill_keys, first, _, _) = make_chain();
    {
        let mut tx = manager.begin().await.unwrap();
        tx.append_bill_blocks(&bill_id, None, std::slice::from_ref(&first))
            .await
            .unwrap();
        tx.save_bill_keys(&bill_id, &bill_keys).await.unwrap();
        // no commit
    }
    assert!(chain_store.get_chain(&bill_id).await.is_err());
    assert!(store.get_keys(&bill_id).await.is_err());
    assert!(!store.exists(&bill_id).await.unwrap());
}

pub async fn test_bill_transaction_rejects_stale_tip<M, C>(manager: &M, chain_store: &C)
where
    M: TransactionManagerApi + ?Sized,
    C: BillChainStoreApi + ?Sized,
{
    let (bill_id, bill_keys, first, second, _) = make_chain();
    let signer_keys = BcrKeys::new();
    chain_store.add_block(&bill_id, &first).await.unwrap();
    let stale_expected = first.clone();
    chain_store.add_block(&bill_id, &second).await.unwrap();
    let third = make_block(
        &bill_id,
        Some(&second),
        &signer_keys,
        &bill_keys,
        b"stale-third",
    );
    let mut tx = manager.begin().await.unwrap();
    let result = tx
        .append_bill_blocks(&bill_id, Some(&stale_expected), &[third])
        .await;
    assert!(matches!(result, Err(Error::ConcurrentModification(_))));
    drop(tx);
    let chain = chain_store.get_chain(&bill_id).await.unwrap();
    assert_eq!(chain.blocks().len(), 2);
    assert_eq!(chain.get_latest_block().hash, second.hash);
}

pub async fn test_bill_transaction_replace<M, C>(manager: &M, chain_store: &C)
where
    M: TransactionManagerApi + ?Sized,
    C: BillChainStoreApi + ?Sized,
{
    let (bill_id, bill_keys, first, second_a, third_a) = make_chain();
    chain_store.add_block(&bill_id, &first).await.unwrap();
    chain_store.add_block(&bill_id, &second_a).await.unwrap();
    chain_store.add_block(&bill_id, &third_a).await.unwrap();
    let signer_keys = BcrKeys::new();
    let second_b = make_block(
        &bill_id,
        Some(&first),
        &signer_keys,
        &bill_keys,
        b"second-b",
    );
    let third_b = make_block(
        &bill_id,
        Some(&second_b),
        &signer_keys,
        &bill_keys,
        b"third-b",
    );
    let mut tx = manager.begin().await.unwrap();
    tx.replace_bill_blocks_from_height(
        &bill_id,
        &third_a,
        second_a.id,
        &[second_b.clone(), third_b.clone()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let chain = chain_store.get_chain(&bill_id).await.unwrap();
    assert_eq!(chain.blocks().len(), 3);
    assert_eq!(chain.blocks()[0].hash, first.hash);
    assert_eq!(chain.blocks()[1].hash, second_b.hash);
    assert_eq!(chain.blocks()[2].hash, third_b.hash);
}

pub async fn test_company_lock_after_bill_lock_is_rejected<M>(manager: &M)
where
    M: TransactionManagerApi + ?Sized,
{
    let (bill_id, _, first, _, _) = make_chain();
    let mut tx = manager.begin().await.unwrap();
    tx.append_bill_blocks(&bill_id, None, &[first])
        .await
        .unwrap();
    let company_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
    let result = tx.append_company_blocks(&company_id, None, &[]).await;
    assert!(matches!(result, Err(Error::InvalidData(_))));
}

pub async fn test_identity_lock_after_bill_lock_is_rejected<M>(manager: &M)
where
    M: TransactionManagerApi + ?Sized,
{
    let (bill_id, _, first, _, _) = make_chain();
    let mut tx = manager.begin().await.unwrap();
    tx.append_bill_blocks(&bill_id, None, &[first])
        .await
        .unwrap();
    let result = tx.append_identity_blocks(None, &[]).await;
    assert!(matches!(result, Err(Error::InvalidData(_))));
}
