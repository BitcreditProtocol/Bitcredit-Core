use crate::{
    tests::{
        tests::{empty_address, node_id_test, private_key_test, test_ts},
        transaction_test_utils::{remove_company_blocks_from_height, seed_company_blocks},
    },
    traits::{company::CompanyChainStoreApi, transaction::TransactionManagerApi},
};
use bcr_common::core::NodeId;
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

async fn get_latest_block<S>(store: &S, company_id: &NodeId) -> crate::Result<CompanyBlock>
where
    S: CompanyChainStoreApi + ?Sized,
{
    Ok(store
        .get_chain(company_id)
        .await?
        .get_latest_block()
        .to_owned())
}

pub async fn test_company_chain<S>(transaction_manager: &dyn TransactionManagerApi, store: &S)
where
    S: CompanyChainStoreApi + ?Sized,
{
    let id = node_id_test();

    assert!(get_latest_block(store, &id).await.is_err());

    // First block
    let block = get_first_company_block();
    seed_company_blocks(transaction_manager, &id, None, std::slice::from_ref(&block)).await;
    let latest = get_latest_block(store, &id).await.unwrap();
    assert_eq!(latest, block);
    let chain = store.get_chain(&id).await.unwrap();
    assert_eq!(chain.blocks().len(), 1);
    assert_eq!(chain.blocks()[0], block);

    // Second block
    let block2 = get_second_company_block(&block);
    seed_company_blocks(
        transaction_manager,
        &id,
        Some(&block),
        std::slice::from_ref(&block2),
    )
    .await;
    let latest = get_latest_block(store, &id).await.unwrap();
    assert_eq!(latest, block2);
    let chain = store.get_chain(&id).await.unwrap();
    assert_eq!(chain.blocks().len(), 2);
    assert_eq!(chain.blocks()[0], block);
    assert_eq!(chain.blocks()[1], block2);

    // Truncate second block
    remove_company_blocks_from_height(transaction_manager, &id, &block2, block2.id).await;
    let latest = get_latest_block(store, &id).await.unwrap();
    assert_eq!(latest, block);

    // Re-add after truncation
    seed_company_blocks(
        transaction_manager,
        &id,
        Some(&block),
        std::slice::from_ref(&block2),
    )
    .await;
    assert_eq!(store.get_chain(&id).await.unwrap().blocks().len(), 2);

    // Remove whole chain
    store.remove(&id).await.expect("remove company chain");
    assert!(get_latest_block(store, &id).await.is_err());

    // lock anchor still exists, but this must not prevent creating a new chain
    seed_company_blocks(transaction_manager, &id, None, std::slice::from_ref(&block)).await;
    assert_eq!(store.get_chain(&id).await.unwrap().blocks().len(), 1);
}
