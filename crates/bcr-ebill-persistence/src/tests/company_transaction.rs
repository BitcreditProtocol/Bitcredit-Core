use crate::{
    Error,
    traits::{
        company::{CompanyChainStoreApi, CompanyStoreApi},
        identity::IdentityChainStoreApi,
        transaction::TransactionManagerApi,
    },
};
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    application::{
        company::{Company, CompanySignatory, CompanySignatoryStatus, CompanyStatus},
        identity::Identity,
    },
    protocol::{
        Address, City, Country, EditOptionalFieldMode, Email, Name, OptionalPostalAddress,
        PostalAddress, Timestamp,
        blockchain::{
            Blockchain,
            company::{
                CompanyBlock, CompanyBlockchain,
                block::{CompanyCreateBlockData, CompanyUpdateBlockData, SignatoryType},
            },
            identity::{
                IdentityBlock, IdentityBlockchain, IdentityCreateBlockData,
                IdentityCreateCompanyBlockData, IdentityType,
            },
        },
        crypto::BcrKeys,
    },
};

fn test_identity(keys: &BcrKeys) -> Identity {
    Identity {
        t: IdentityType::Anon,
        node_id: NodeId::new(keys.pub_key(), bitcoin::Network::Testnet),
        name: Name::new("Alice").unwrap(),
        email: None,
        postal_address: OptionalPostalAddress::empty(),
        date_of_birth: None,
        country_of_birth: None,
        city_of_birth: None,
        identification_number: None,
        profile_picture_file: None,
        identity_document_file: None,
        nostr_relays: vec![],
    }
}

fn test_company(identity_id: &NodeId, company_keys: &BcrKeys, timestamp: Timestamp) -> Company {
    let company_id = NodeId::new(company_keys.pub_key(), bitcoin::Network::Testnet);
    Company {
        id: company_id,
        name: Name::new("Test Company").unwrap(),
        country_of_registration: Some(Country::AT),
        city_of_registration: Some(City::new("Vienna").unwrap()),
        postal_address: PostalAddress {
            country: Country::AT,
            city: City::new("Vienna").unwrap(),
            zip: None,
            address: Address::new("Test Street 1").unwrap(),
        },
        email: Email::new("company@example.com").unwrap(),
        registration_number: None,
        registration_date: None,
        proof_of_registration_file: None,
        logo_file: None,
        signatories: vec![CompanySignatory {
            node_id: identity_id.clone(),
            t: SignatoryType::Solo,
            status: CompanySignatoryStatus::Invited {
                ts: timestamp,
                inviter: identity_id.clone(),
            },
        }],
        creation_time: timestamp,
        status: CompanyStatus::Active,
    }
}

fn identity_create_block(
    identity: &Identity,
    keys: &BcrKeys,
    timestamp: Timestamp,
) -> IdentityBlock {
    let data: IdentityCreateBlockData = identity.clone().into();
    IdentityBlockchain::new(&data, keys, timestamp)
        .unwrap()
        .get_first_block()
        .clone()
}

fn company_create_block(
    company: &Company,
    identity_id: &NodeId,
    identity_keys: &BcrKeys,
    company_keys: &BcrKeys,
    timestamp: Timestamp,
) -> CompanyBlock {
    CompanyBlockchain::new(
        &CompanyCreateBlockData {
            id: company.id.clone(),
            name: company.name.clone(),
            country_of_registration: company.country_of_registration.clone(),
            city_of_registration: company.city_of_registration.clone(),
            postal_address: company.postal_address.clone(),
            email: company.email.clone(),
            registration_number: company.registration_number.clone(),
            registration_date: company.registration_date.clone(),
            proof_of_registration_file: company.proof_of_registration_file.clone(),
            logo_file: company.logo_file.clone(),
            creation_time: company.creation_time,
            creator: identity_id.clone(),
        },
        identity_keys,
        company_keys,
        timestamp,
    )
    .unwrap()
    .get_first_block()
    .clone()
}

fn company_update_block(
    company_id: &NodeId,
    previous: &CompanyBlock,
    identity_keys: &BcrKeys,
    company_keys: &BcrKeys,
    name: &str,
    timestamp: Timestamp,
) -> CompanyBlock {
    CompanyBlock::create_block_for_update(
        company_id.clone(),
        previous,
        &CompanyUpdateBlockData {
            name: Some(Name::new(name).unwrap()),
            email: None,
            country: None,
            city: None,
            zip: EditOptionalFieldMode::Ignore,
            address: None,
            country_of_registration: EditOptionalFieldMode::Ignore,
            city_of_registration: EditOptionalFieldMode::Ignore,
            registration_number: EditOptionalFieldMode::Ignore,
            registration_date: EditOptionalFieldMode::Ignore,
            logo_file: EditOptionalFieldMode::Ignore,
            proof_of_registration_file: EditOptionalFieldMode::Ignore,
        },
        identity_keys,
        company_keys,
        timestamp,
    )
    .unwrap()
}

fn identity_create_company_block(
    previous: &IdentityBlock,
    identity_keys: &BcrKeys,
    company_keys: &BcrKeys,
    company_block: &CompanyBlock,
    timestamp: Timestamp,
) -> IdentityBlock {
    IdentityBlock::create_block_for_create_company(
        previous,
        &IdentityCreateCompanyBlockData {
            company_id: company_block.company_id.clone(),
            company_key: company_keys.get_private_key(),
            block_hash: company_block.hash.clone(),
        },
        identity_keys,
        timestamp,
    )
    .unwrap()
}

/// create-company transaction
/// identity chain/company chain/company//company email confirmation commit together
pub async fn test_company_transaction_commit(
    transaction_manager: &dyn TransactionManagerApi,
    company_store: &dyn CompanyStoreApi,
    company_chain_store: &dyn CompanyChainStoreApi,
    identity_chain_store: &dyn IdentityChainStoreApi,
) {
    let now = Timestamp::now();

    let identity_keys = BcrKeys::new();
    let identity = test_identity(&identity_keys);
    let identity_create = identity_create_block(&identity, &identity_keys, now - 10);
    identity_chain_store
        .add_block(&identity_create)
        .await
        .unwrap();

    let company_keys = BcrKeys::new();
    let company = test_company(&identity.node_id, &company_keys, now - 9);
    company_store
        .save_key_pair(&company.id, &company_keys)
        .await
        .unwrap();
    let company_create = company_create_block(
        &company,
        &identity.node_id,
        &identity_keys,
        &company_keys,
        now - 8,
    );
    let company_update = company_update_block(
        &company.id,
        &company_create,
        &identity_keys,
        &company_keys,
        "Updated Company",
        now - 7,
    );

    let mut final_company = company.clone();
    final_company.name = Name::new("Updated Company").unwrap();
    let identity_company = identity_create_company_block(
        &identity_create,
        &identity_keys,
        &company_keys,
        &company_create,
        now - 6,
    );

    let confirmation_data = bcr_ebill_core::protocol::EmailIdentityProofData {
        node_id: identity.node_id.clone(),
        company_node_id: Some(company.id.clone()),
        email: Email::new("alice@example.com").unwrap(),
        created_at: now - 5,
    };
    let confirmation_proof = confirmation_data
        .sign(&identity.node_id, &identity_keys.get_private_key())
        .unwrap();

    let mut tx = transaction_manager.begin().await.unwrap();
    tx.append_identity_blocks(
        Some(&identity_create),
        std::slice::from_ref(&identity_company),
    )
    .await
    .unwrap();
    tx.append_company_blocks(
        &company.id,
        None,
        &[company_create.clone(), company_update.clone()],
    )
    .await
    .unwrap();
    tx.insert_company(&final_company).await.unwrap();
    tx.set_company_email_confirmation(&company.id, &confirmation_proof, &confirmation_data)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let identity_latest = identity_chain_store.get_latest_block().await.unwrap();
    assert_eq!(identity_latest.hash, identity_company.hash);
    let company_chain = company_chain_store.get_chain(&company.id).await.unwrap();
    assert_eq!(company_chain.blocks().len(), 2);
    assert_eq!(company_chain.blocks()[0].hash, company_create.hash);
    assert_eq!(company_chain.blocks()[1].hash, company_update.hash);

    let persisted_company = company_store.get(&company.id).await.unwrap();
    assert_eq!(
        persisted_company.name,
        Name::new("Updated Company").unwrap()
    );
    assert_eq!(
        persisted_company.signatories.len(),
        final_company.signatories.len()
    );

    let confirmations = company_store
        .get_email_confirmations(&company.id)
        .await
        .unwrap();

    assert_eq!(confirmations.len(), 1);
    assert_eq!(confirmations[0].1.company_node_id, Some(company.id.clone()));
    assert_eq!(confirmations[0].1.email, confirmation_data.email);
}

/// valid data in the transaction, then fail - the transaction must roll everything back
pub async fn test_company_transaction_rollback(
    transaction_manager: &dyn TransactionManagerApi,
    company_store: &dyn CompanyStoreApi,
    company_chain_store: &dyn CompanyChainStoreApi,
    identity_chain_store: &dyn IdentityChainStoreApi,
) {
    let now = Timestamp::now();

    let identity_keys = BcrKeys::new();
    let identity = test_identity(&identity_keys);
    let identity_create = identity_create_block(&identity, &identity_keys, now - 10);
    identity_chain_store
        .add_block(&identity_create)
        .await
        .unwrap();
    let company_keys = BcrKeys::new();
    let company = test_company(&identity.node_id, &company_keys, now - 9);
    let company_create = company_create_block(
        &company,
        &identity.node_id,
        &identity_keys,
        &company_keys,
        now - 8,
    );
    let identity_company = identity_create_company_block(
        &identity_create,
        &identity_keys,
        &company_keys,
        &company_create,
        now - 7,
    );

    let mut tx = transaction_manager.begin().await.unwrap();
    tx.append_identity_blocks(
        Some(&identity_create),
        std::slice::from_ref(&identity_company),
    )
    .await
    .unwrap();
    tx.append_company_blocks(&company.id, None, std::slice::from_ref(&company_create))
        .await
        .unwrap();
    tx.insert_company(&company).await.unwrap();

    // error after all three writes have happened
    let other_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
    let result = tx.update_company(&other_id, &company).await;
    assert!(matches!(result, Err(Error::InvalidData(_))));
    // no commit
    drop(tx);

    let identity_latest = identity_chain_store.get_latest_block().await.unwrap();
    assert_eq!(identity_latest.hash, identity_create.hash);
    assert!(
        company_chain_store
            .get_latest_block(&company.id)
            .await
            .is_err()
    );
    assert!(company_store.get(&company.id).await.is_err());
}

/// the normal edit-company - company block + Company aggregate/signatories
pub async fn test_company_transaction_update(
    transaction_manager: &dyn TransactionManagerApi,
    company_store: &dyn CompanyStoreApi,
    company_chain_store: &dyn CompanyChainStoreApi,
) {
    let now = Timestamp::now();
    let identity_keys = BcrKeys::new();
    let identity = test_identity(&identity_keys);
    let company_keys = BcrKeys::new();
    let company = test_company(&identity.node_id, &company_keys, now - 10);
    company_store.insert(&company).await.unwrap();
    let create = company_create_block(
        &company,
        &identity.node_id,
        &identity_keys,
        &company_keys,
        now - 9,
    );
    company_chain_store
        .add_block(&company.id, &create)
        .await
        .unwrap();
    let update = company_update_block(
        &company.id,
        &create,
        &identity_keys,
        &company_keys,
        "Company After Update",
        now - 8,
    );

    let mut updated_company = company.clone();
    updated_company.name = Name::new("Company After Update").unwrap();
    let second_signatory_keys = BcrKeys::new();
    let second_signatory = NodeId::new(second_signatory_keys.pub_key(), bitcoin::Network::Testnet);
    updated_company.signatories.push(CompanySignatory {
        node_id: second_signatory,
        t: SignatoryType::Solo,
        status: CompanySignatoryStatus::Invited {
            ts: now - 7,
            inviter: identity.node_id.clone(),
        },
    });

    let mut tx = transaction_manager.begin().await.unwrap();
    tx.append_company_blocks(&company.id, Some(&create), std::slice::from_ref(&update))
        .await
        .unwrap();
    tx.update_company(&company.id, &updated_company)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let persisted = company_store.get(&company.id).await.unwrap();
    assert_eq!(persisted.name, Name::new("Company After Update").unwrap());
    assert_eq!(persisted.signatories.len(), 2);
    let latest = company_chain_store
        .get_latest_block(&company.id)
        .await
        .unwrap();
    assert_eq!(latest.hash, update.hash);
}

/// prepared against tip N, but another writer committed N+1 before - reject transaction
pub async fn test_company_transaction_rejects_stale_tip(
    transaction_manager: &dyn TransactionManagerApi,
    company_chain_store: &dyn CompanyChainStoreApi,
) {
    let now = Timestamp::now();
    let identity_keys = BcrKeys::new();
    let identity = test_identity(&identity_keys);
    let company_keys = BcrKeys::new();
    let company = test_company(&identity.node_id, &company_keys, now - 10);
    let create = company_create_block(
        &company,
        &identity.node_id,
        &identity_keys,
        &company_keys,
        now - 9,
    );
    company_chain_store
        .add_block(&company.id, &create)
        .await
        .unwrap();

    // latest tip prepared against
    let expected_latest = create.clone();
    // other writer wins first
    let competing = company_update_block(
        &company.id,
        &create,
        &identity_keys,
        &company_keys,
        "Competing Update",
        now - 8,
    );
    company_chain_store
        .add_block(&company.id, &competing)
        .await
        .unwrap();

    // stale candidate was also built on block 1
    let stale_candidate = company_update_block(
        &company.id,
        &create,
        &identity_keys,
        &company_keys,
        "Stale Update",
        now - 7,
    );

    let mut tx = transaction_manager.begin().await.unwrap();
    let result = tx
        .append_company_blocks(
            &company.id,
            Some(&expected_latest),
            std::slice::from_ref(&stale_candidate),
        )
        .await;
    assert!(result.is_err());
    drop(tx);
    let latest = company_chain_store
        .get_latest_block(&company.id)
        .await
        .unwrap();
    assert_eq!(latest.hash, competing.hash);
}

/// atomic fork replacement plus company rebuild
pub async fn test_company_transaction_replace(
    transaction_manager: &dyn TransactionManagerApi,
    company_store: &dyn CompanyStoreApi,
    company_chain_store: &dyn CompanyChainStoreApi,
) {
    let now = Timestamp::now();
    let identity_keys = BcrKeys::new();
    let identity = test_identity(&identity_keys);
    let company_keys = BcrKeys::new();
    let company = test_company(&identity.node_id, &company_keys, now - 10);
    company_store.insert(&company).await.unwrap();
    let create = company_create_block(
        &company,
        &identity.node_id,
        &identity_keys,
        &company_keys,
        now - 9,
    );
    let old_2 = company_update_block(
        &company.id,
        &create,
        &identity_keys,
        &company_keys,
        "Old 2",
        now - 8,
    );
    let old_3 = company_update_block(
        &company.id,
        &old_2,
        &identity_keys,
        &company_keys,
        "Old 3",
        now - 7,
    );
    company_chain_store
        .add_block(&company.id, &create)
        .await
        .unwrap();
    company_chain_store
        .add_block(&company.id, &old_2)
        .await
        .unwrap();
    company_chain_store
        .add_block(&company.id, &old_3)
        .await
        .unwrap();
    let new_2 = company_update_block(
        &company.id,
        &create,
        &identity_keys,
        &company_keys,
        "New 2",
        now - 6,
    );
    let new_3 = company_update_block(
        &company.id,
        &new_2,
        &identity_keys,
        &company_keys,
        "New 3",
        now - 5,
    );

    let mut rebuilt_company = company.clone();
    rebuilt_company.name = Name::new("New 3").unwrap();
    let mut tx = transaction_manager.begin().await.unwrap();
    tx.replace_company_blocks_from_height(
        &company.id,
        &old_3,
        old_2.id,
        &[new_2.clone(), new_3.clone()],
    )
    .await
    .unwrap();
    tx.update_company(&company.id, &rebuilt_company)
        .await
        .unwrap();

    tx.commit().await.unwrap();
    let chain = company_chain_store.get_chain(&company.id).await.unwrap();
    assert_eq!(chain.blocks().len(), 3);
    assert_eq!(chain.blocks()[0].hash, create.hash);
    assert_eq!(chain.blocks()[1].hash, new_2.hash);
    assert_eq!(chain.blocks()[2].hash, new_3.hash);
    let persisted = company_store.get(&company.id).await.unwrap();
    assert_eq!(persisted.name, Name::new("New 3").unwrap());
}

/// cross-store rollback test
/// identity succeeds, then the company stale-tip check fails
/// Dropping the transaction rolls back the identity as well
pub async fn test_cross_chain_rollback_when_company_tip_is_stale(
    transaction_manager: &dyn TransactionManagerApi,
    company_store: &dyn CompanyStoreApi,
    company_chain_store: &dyn CompanyChainStoreApi,
    identity_chain_store: &dyn IdentityChainStoreApi,
) {
    let now = Timestamp::now();

    let identity_keys = BcrKeys::new();
    let identity = test_identity(&identity_keys);
    let identity_create = identity_create_block(&identity, &identity_keys, now - 10);
    identity_chain_store
        .add_block(&identity_create)
        .await
        .unwrap();
    let company_keys = BcrKeys::new();
    let company = test_company(&identity.node_id, &company_keys, now - 9);
    company_store.insert(&company).await.unwrap();
    let company_create = company_create_block(
        &company,
        &identity.node_id,
        &identity_keys,
        &company_keys,
        now - 8,
    );
    company_chain_store
        .add_block(&company.id, &company_create)
        .await
        .unwrap();

    // prepared against this tip
    let expected_company_latest = company_create.clone();
    // other company write commits before tx starts
    let competing_company_block = company_update_block(
        &company.id,
        &company_create,
        &identity_keys,
        &company_keys,
        "Competing",
        now - 7,
    );
    company_chain_store
        .add_block(&company.id, &competing_company_block)
        .await
        .unwrap();
    // stale company
    let stale_company_block = company_update_block(
        &company.id,
        &company_create,
        &identity_keys,
        &company_keys,
        "Stale",
        now - 6,
    );
    // valid identity mutation
    let identity_company_block = identity_create_company_block(
        &identity_create,
        &identity_keys,
        &company_keys,
        &company_create,
        now - 5,
    );
    let mut tx = transaction_manager.begin().await.unwrap();
    // identity lock happens first and succeeds
    tx.append_identity_blocks(
        Some(&identity_create),
        std::slice::from_ref(&identity_company_block),
    )
    .await
    .unwrap();

    // company lock succeeds, but stale-tip check fails
    let company_result = tx
        .append_company_blocks(
            &company.id,
            Some(&expected_company_latest),
            std::slice::from_ref(&stale_company_block),
        )
        .await;
    assert!(company_result.is_err());

    // roll back the identity block as well
    drop(tx);
    let identity_latest = identity_chain_store.get_latest_block().await.unwrap();
    assert_eq!(identity_latest.hash, identity_create.hash);
    let company_latest = company_chain_store
        .get_latest_block(&company.id)
        .await
        .unwrap();
    assert_eq!(company_latest.hash, competing_company_block.hash);
}

/// implementation enforces Identity -> Company ordering
pub async fn test_identity_lock_after_company_lock_is_rejected(
    transaction_manager: &dyn TransactionManagerApi,
    company_chain_store: &dyn CompanyChainStoreApi,
    identity_chain_store: &dyn IdentityChainStoreApi,
) {
    let now = Timestamp::now();
    let identity_keys = BcrKeys::new();
    let identity = test_identity(&identity_keys);
    let identity_create = identity_create_block(&identity, &identity_keys, now - 10);
    identity_chain_store
        .add_block(&identity_create)
        .await
        .unwrap();
    let company_keys = BcrKeys::new();
    let company = test_company(&identity.node_id, &company_keys, now - 9);
    let company_create = company_create_block(
        &company,
        &identity.node_id,
        &identity_keys,
        &company_keys,
        now - 8,
    );
    company_chain_store
        .add_block(&company.id, &company_create)
        .await
        .unwrap();
    let company_update = company_update_block(
        &company.id,
        &company_create,
        &identity_keys,
        &company_keys,
        "Update",
        now - 7,
    );
    let identity_company = identity_create_company_block(
        &identity_create,
        &identity_keys,
        &company_keys,
        &company_create,
        now - 6,
    );
    let mut tx = transaction_manager.begin().await.unwrap();

    // wrong order intentionally
    tx.append_company_blocks(
        &company.id,
        Some(&company_create),
        std::slice::from_ref(&company_update),
    )
    .await
    .unwrap();
    let result = tx
        .append_identity_blocks(
            Some(&identity_create),
            std::slice::from_ref(&identity_company),
        )
        .await;
    assert!(matches!(result, Err(Error::InvalidData(_))));
    drop(tx);
    // company mutation rolled back as well
    let latest = company_chain_store
        .get_latest_block(&company.id)
        .await
        .unwrap();
    assert_eq!(latest.hash, company_create.hash);
}
