use crate::{
    tests::tests::{empty_address, node_id_test, private_key_test, test_ts},
    traits::company::CompanyChainStoreApi,
};
use bcr_ebill_core::protocol::{
    Address, City, Country, Date, EditOptionalFieldMode, Email, Identification, Name, Sha256Hash,
    Zip,
    blockchain::{
        Blockchain,
        company::{
            CompanyBlock,
            block::{CompanyCreateBlockData, CompanyUpdateBlockData},
        },
    },
    crypto::BcrKeys,
};

fn get_company_keys() -> BcrKeys {
    BcrKeys::from_private_key(&private_key_test())
}

pub fn get_first_company_block() -> CompanyBlock {
    CompanyBlock::create_block_for_create(
        node_id_test(),
        Sha256Hash::new("genesis hash"),
        &CompanyCreateBlockData {
            id: node_id_test(),
            name: Name::new("Hayek Ltd").unwrap(),
            country_of_registration: Some(Country::AT),
            city_of_registration: Some(City::new("Vienna").unwrap()),
            postal_address: empty_address(),
            email: Email::new("hayekltd@example.com").unwrap(),
            registration_number: Some(Identification::new("123124123").unwrap()),
            registration_date: Some(Date::new("2024-01-01").unwrap()),
            proof_of_registration_file: None,
            logo_file: None,
            creation_time: test_ts(),
            creator: node_id_test(),
        },
        &BcrKeys::from_private_key(&private_key_test()),
        &get_company_keys(),
        test_ts(),
    )
    .unwrap()
}

pub fn get_second_company_block(previous: &CompanyBlock) -> CompanyBlock {
    CompanyBlock::create_block_for_update(
        node_id_test(),
        previous,
        &CompanyUpdateBlockData {
            name: None,
            email: None,
            country: Some(Country::AT),
            city: Some(City::new("Vienna").unwrap()),
            zip: EditOptionalFieldMode::Set(Zip::new("1010").unwrap()),
            address: Some(Address::new("Kärntner Straße 1").unwrap()),
            country_of_registration: EditOptionalFieldMode::Ignore,
            city_of_registration: EditOptionalFieldMode::Ignore,
            registration_number: EditOptionalFieldMode::Ignore,
            registration_date: EditOptionalFieldMode::Ignore,
            logo_file: EditOptionalFieldMode::Ignore,
            proof_of_registration_file: EditOptionalFieldMode::Ignore,
        },
        &BcrKeys::new(),
        &get_company_keys(),
        test_ts(),
    )
    .unwrap()
}

pub async fn test_company_chain<S>(store: &S)
where
    S: CompanyChainStoreApi + ?Sized,
{
    let id = node_id_test();

    assert!(store.get_latest_block(&id).await.is_err());

    // First block
    let block = get_first_company_block();
    store
        .add_block(&id, &block)
        .await
        .expect("add first company block");
    let latest = store.get_latest_block(&id).await.unwrap();
    assert_eq!(latest, block);
    let chain = store.get_chain(&id).await.unwrap();
    assert_eq!(chain.blocks().len(), 1);
    assert_eq!(chain.blocks()[0], block);

    // Second block
    let block2 = get_second_company_block(&block);
    store
        .add_block(&id, &block2)
        .await
        .expect("add second company block");
    let latest = store.get_latest_block(&id).await.unwrap();
    assert_eq!(latest, block2);
    let chain = store.get_chain(&id).await.unwrap();
    assert_eq!(chain.blocks().len(), 2);
    assert_eq!(chain.blocks()[0], block);
    assert_eq!(chain.blocks()[1], block2);

    // Truncate second block
    store
        .remove_blocks_from_height(&id, block2.id)
        .await
        .unwrap();
    let latest = store.get_latest_block(&id).await.unwrap();
    assert_eq!(latest, block);

    // Re-add after truncation
    store
        .add_block(&id, &block2)
        .await
        .expect("re-add after truncation");
    assert_eq!(store.get_chain(&id).await.unwrap().blocks().len(), 2);

    // Remove whole chain
    store.remove(&id).await.expect("remove company chain");
    assert!(store.get_latest_block(&id).await.is_err());

    // lock anchor still exists, but this must not prevent creating a new chain
    store
        .add_block(&id, &block)
        .await
        .expect("recreate chain after remove");
    assert_eq!(store.get_chain(&id).await.unwrap().blocks().len(), 1);
}

pub async fn test_concurrent_company_first_block<S>(store: &S)
where
    S: CompanyChainStoreApi + ?Sized,
{
    let id = node_id_test();
    let block = get_first_company_block();
    let (result_a, result_b) =
        tokio::join!(store.add_block(&id, &block), store.add_block(&id, &block),);
    assert_ne!(
        result_a.is_ok(),
        result_b.is_ok(),
        "exactly one concurrent first block \
         must succeed: \
         a={result_a:?}, b={result_b:?}"
    );
    let chain = store.get_chain(&id).await.unwrap();
    assert_eq!(chain.blocks().len(), 1);
    assert_eq!(chain.blocks()[0], block);
}

pub async fn test_concurrent_company_add<S>(store: &S)
where
    S: CompanyChainStoreApi + ?Sized,
{
    let id = node_id_test();
    let block = get_first_company_block();
    store.add_block(&id, &block).await.unwrap();
    let block2 = get_second_company_block(&block);
    let (result_a, result_b) =
        tokio::join!(store.add_block(&id, &block2), store.add_block(&id, &block2),);
    assert_ne!(
        result_a.is_ok(),
        result_b.is_ok(),
        "exactly one concurrent append \
         must succeed: \
         a={result_a:?}, b={result_b:?}"
    );
    let chain = store.get_chain(&id).await.unwrap();
    assert_eq!(chain.blocks().len(), 2);
    assert_eq!(chain.blocks()[0], block);
    assert_eq!(chain.blocks()[1], block2);
}
