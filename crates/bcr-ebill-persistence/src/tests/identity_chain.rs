use bcr_ebill_core::protocol::{
    EditOptionalFieldMode, Sha256Hash,
    blockchain::{
        Blockchain,
        identity::{IdentityBlock, IdentityUpdateBlockData},
    },
    crypto::BcrKeys,
};

use crate::{
    tests::tests::{empty_identity, test_ts},
    traits::identity::IdentityChainStoreApi,
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

pub async fn test_identity_chain<S>(store: &S)
where
    S: IdentityChainStoreApi + ?Sized,
{
    assert!(store.get_latest_block().await.is_err());
    let block = get_first_identity_block();
    store
        .add_block(&block)
        .await
        .expect("add first identity block");
    let latest = store.get_latest_block().await.unwrap();
    assert_eq!(latest, block);
    let chain = store.get_chain().await.unwrap();
    assert_eq!(chain.blocks().len(), 1);
    assert_eq!(chain.blocks()[0], block);

    // Second block
    let block2 = get_second_identity_block(&block);
    store
        .add_block(&block2)
        .await
        .expect("add second identity block");
    assert_eq!(store.get_latest_block().await.unwrap(), block2);
    let chain = store.get_chain().await.unwrap();
    assert_eq!(chain.blocks().len(), 2);
    assert_eq!(chain.blocks()[0], block);
    assert_eq!(chain.blocks()[1], block2);

    // Truncate block 2.
    store.remove_blocks_from_height(block2.id).await.unwrap();
    assert_eq!(store.get_latest_block().await.unwrap(), block);

    // Re-add after truncation.
    store
        .add_block(&block2)
        .await
        .expect("re-add block after truncation");
    let chain = store.get_chain().await.unwrap();
    assert_eq!(chain.blocks().len(), 2);
    assert_eq!(chain.blocks()[1], block2);
}

pub async fn test_concurrent_identity_first_block<S>(store: &S)
where
    S: IdentityChainStoreApi + ?Sized,
{
    let block = get_first_identity_block();
    let (result_a, result_b) = tokio::join!(store.add_block(&block), store.add_block(&block),);
    assert_ne!(
        result_a.is_ok(),
        result_b.is_ok(),
        "exactly one concurrent first block \
         must succeed: \
         a={result_a:?}, b={result_b:?}"
    );
    let chain = store.get_chain().await.unwrap();
    assert_eq!(chain.blocks().len(), 1);
    assert_eq!(chain.blocks()[0], block);
}

pub async fn test_concurrent_identity_add<S>(store: &S)
where
    S: IdentityChainStoreApi + ?Sized,
{
    let block = get_first_identity_block();
    store.add_block(&block).await.unwrap();
    let block2 = get_second_identity_block(&block);
    let (result_a, result_b) = tokio::join!(store.add_block(&block2), store.add_block(&block2),);
    assert_ne!(
        result_a.is_ok(),
        result_b.is_ok(),
        "exactly one concurrent append \
         must succeed: \
         a={result_a:?}, b={result_b:?}"
    );
    let chain = store.get_chain().await.unwrap();
    assert_eq!(chain.blocks().len(), 2);
    assert_eq!(chain.blocks()[0], block);
    assert_eq!(chain.blocks()[1], block2);
}
