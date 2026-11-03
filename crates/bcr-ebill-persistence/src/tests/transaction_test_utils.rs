use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::{
    application::{company::Company, identity::Identity},
    protocol::{
        BlockId,
        blockchain::{bill::BillBlock, company::CompanyBlock, identity::IdentityBlock},
        crypto::BcrKeys,
    },
};

use crate::traits::transaction::TransactionManagerApi;

pub async fn seed_identity_blocks(
    manager: &dyn TransactionManagerApi,
    expected_latest: Option<&IdentityBlock>,
    blocks: &[IdentityBlock],
) {
    let mut tx = manager
        .begin()
        .await
        .expect("begin identity seed transaction");
    tx.append_identity_blocks(expected_latest, blocks)
        .await
        .expect("seed identity blocks");
    tx.commit().await.expect("commit identity seed transaction");
}

pub async fn seed_company_blocks(
    manager: &dyn TransactionManagerApi,
    company_id: &NodeId,
    expected_latest: Option<&CompanyBlock>,
    blocks: &[CompanyBlock],
) {
    let mut tx = manager
        .begin()
        .await
        .expect("begin company seed transaction");
    tx.append_company_blocks(company_id, expected_latest, blocks)
        .await
        .expect("seed company blocks");
    tx.commit().await.expect("commit company seed transaction");
}

pub async fn seed_bill_blocks(
    manager: &dyn TransactionManagerApi,
    bill_id: &BillId,
    expected_latest: Option<&BillBlock>,
    blocks: &[BillBlock],
) {
    let mut tx = manager.begin().await.expect("begin bill seed transaction");
    tx.append_bill_blocks(bill_id, expected_latest, blocks)
        .await
        .expect("seed bill blocks");
    tx.commit().await.expect("commit bill seed transaction");
}

pub async fn seed_bill_keys(manager: &dyn TransactionManagerApi, bill_id: &BillId, keys: &BcrKeys) {
    let mut tx = manager
        .begin()
        .await
        .expect("begin bill key seed transaction");
    tx.save_bill_keys(bill_id, keys)
        .await
        .expect("seed bill keys");
    tx.commit().await.expect("commit bill key seed transaction");
}

pub async fn remove_identity_blocks_from_height(
    manager: &dyn TransactionManagerApi,
    expected_latest: &IdentityBlock,
    from_block_id: BlockId,
) {
    let mut tx = manager
        .begin()
        .await
        .expect("begin identity truncate transaction");
    tx.replace_identity_blocks_from_height(expected_latest, from_block_id, &[])
        .await
        .expect("remove identity blocks from height");
    tx.commit()
        .await
        .expect("commit identity truncate transaction");
}

pub async fn remove_company_blocks_from_height(
    manager: &dyn TransactionManagerApi,
    company_id: &NodeId,
    expected_latest: &CompanyBlock,
    from_block_id: BlockId,
) {
    let mut tx = manager
        .begin()
        .await
        .expect("begin company truncate transaction");
    tx.replace_company_blocks_from_height(company_id, expected_latest, from_block_id, &[])
        .await
        .expect("remove company blocks from height");
    tx.commit()
        .await
        .expect("commit company truncate transaction");
}

pub async fn remove_bill_blocks_from_height(
    manager: &dyn TransactionManagerApi,
    bill_id: &BillId,
    expected_latest: &BillBlock,
    from_block_id: BlockId,
) {
    let mut tx = manager
        .begin()
        .await
        .expect("begin bill truncate transaction");
    tx.replace_bill_blocks_from_height(bill_id, expected_latest, from_block_id, &[])
        .await
        .expect("remove bill blocks from height");
    tx.commit().await.expect("commit bill truncate transaction");
}

pub async fn seed_identity(manager: &dyn TransactionManagerApi, identity: &Identity) {
    let mut tx = manager
        .begin()
        .await
        .expect("begin identity seed transaction");
    tx.save_identity(identity).await.expect("seed identity");
    tx.commit().await.expect("commit identity seed transaction");
}

pub async fn seed_company(manager: &dyn TransactionManagerApi, company: &Company) {
    let mut tx = manager
        .begin()
        .await
        .expect("begin company seed transaction");
    tx.insert_company(company).await.expect("seed company");
    tx.commit().await.expect("commit company seed transaction");
}

pub async fn update_company(
    manager: &dyn TransactionManagerApi,
    company_id: &NodeId,
    company: &Company,
) {
    let mut tx = manager
        .begin()
        .await
        .expect("begin company update transaction");
    tx.update_company(company_id, company)
        .await
        .expect("update company");
    tx.commit()
        .await
        .expect("commit company update transaction");
}
