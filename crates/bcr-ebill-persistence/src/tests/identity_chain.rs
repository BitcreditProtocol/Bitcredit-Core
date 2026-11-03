use bcr_ebill_core::protocol::{
    EditOptionalFieldMode, Sha256Hash,
    blockchain::{
        Blockchain,
        identity::{IdentityBlock, IdentityUpdateBlockData},
    },
    crypto::BcrKeys,
};

use crate::{
    tests::{
        tests::{empty_identity, test_ts},
        transaction_test_utils::{remove_identity_blocks_from_height, seed_identity_blocks},
    },
    traits::{identity::IdentityChainStoreApi, transaction::TransactionManagerApi},
};

pub fn get_first_identity_block() -> IdentityBlock {
    IdentityBlock::create_block_for_create(
        Sha256Hash::new("genesis hash"),
        &empty_identity().into(),
        &BcrKeys::new(),
        test_ts(),
    )
    .unwrap()
}

pub fn get_second_identity_block(previous: &IdentityBlock) -> IdentityBlock {
    IdentityBlock::create_block_for_update(
        previous,
        &IdentityUpdateBlockData {
            t: None,
            name: None,
            email: None,
            country: None,
            city: None,
            zip: EditOptionalFieldMode::Ignore,
            address: None,
            date_of_birth: EditOptionalFieldMode::Ignore,
            country_of_birth: EditOptionalFieldMode::Ignore,
            city_of_birth: EditOptionalFieldMode::Ignore,
            identification_number: EditOptionalFieldMode::Ignore,
            profile_picture_file: EditOptionalFieldMode::Ignore,
            identity_document_file: EditOptionalFieldMode::Ignore,
        },
        &BcrKeys::new(),
        test_ts(),
    )
    .unwrap()
}

async fn get_latest_block<S>(store: &S) -> crate::Result<IdentityBlock>
where
    S: IdentityChainStoreApi + ?Sized,
{
    Ok(store.get_chain().await?.get_latest_block().to_owned())
}

pub async fn test_identity_chain<S>(transaction_manager: &dyn TransactionManagerApi, store: &S)
where
    S: IdentityChainStoreApi + ?Sized,
{
    assert!(get_latest_block(store).await.is_err());
    let block = get_first_identity_block();
    seed_identity_blocks(transaction_manager, None, std::slice::from_ref(&block)).await;
    let latest = get_latest_block(store).await.unwrap();
    assert_eq!(latest, block);
    let chain = store.get_chain().await.unwrap();
    assert_eq!(chain.blocks().len(), 1);
    assert_eq!(chain.blocks()[0], block);

    // Second block
    let block2 = get_second_identity_block(&block);
    seed_identity_blocks(
        transaction_manager,
        Some(&block),
        std::slice::from_ref(&block2),
    )
    .await;
    assert_eq!(get_latest_block(store).await.unwrap(), block2);
    let chain = store.get_chain().await.unwrap();
    assert_eq!(chain.blocks().len(), 2);
    assert_eq!(chain.blocks()[0], block);
    assert_eq!(chain.blocks()[1], block2);

    // Truncate block 2.
    remove_identity_blocks_from_height(transaction_manager, &block2, block2.id).await;
    assert_eq!(get_latest_block(store).await.unwrap(), block);

    // Re-add after truncation.
    seed_identity_blocks(
        transaction_manager,
        Some(&block),
        std::slice::from_ref(&block2),
    )
    .await;
    let chain = store.get_chain().await.unwrap();
    assert_eq!(chain.blocks().len(), 2);
    assert_eq!(chain.blocks()[1], block2);
}
