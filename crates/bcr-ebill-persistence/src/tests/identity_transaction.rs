use crate::traits::{
    identity::{IdentityChainStoreApi, IdentityStoreApi},
    transaction::TransactionManagerApi,
};
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    application::identity::Identity,
    protocol::{
        EditOptionalFieldMode, Email, EmailIdentityProofData, Name, OptionalPostalAddress,
        Sha256Hash, Timestamp,
        blockchain::{
            Blockchain,
            identity::{
                IdentityBlock, IdentityCreateBlockData, IdentityType, IdentityUpdateBlockData,
            },
        },
        crypto::BcrKeys,
    },
};

const TEST_SEED: &str = "transaction test seed";

fn ts(value: u64) -> Timestamp {
    Timestamp::new(value).unwrap()
}

fn test_identity(keys: &BcrKeys, name: &str) -> Identity {
    Identity {
        t: IdentityType::Anon,
        node_id: NodeId::new(keys.pub_key(), bitcoin::Network::Testnet),
        name: Name::new(name).unwrap(),
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

fn create_block(identity: &Identity, keys: &BcrKeys, timestamp: Timestamp) -> IdentityBlock {
    let data: IdentityCreateBlockData = identity.clone().into();
    IdentityBlock::create_block_for_create(Sha256Hash::new("genesis hash"), &data, keys, timestamp)
        .unwrap()
}

fn update_block(
    previous: &IdentityBlock,
    keys: &BcrKeys,
    name: &str,
    timestamp: Timestamp,
) -> IdentityBlock {
    let data = IdentityUpdateBlockData {
        t: None,
        name: Some(Name::new(name).unwrap()),
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
    };
    IdentityBlock::create_block_for_update(previous, &data, keys, timestamp).unwrap()
}

fn matching_email_confirmation(
    identity: &Identity,
    keys: &BcrKeys,
) -> (
    bcr_ebill_core::protocol::SignedIdentityProof,
    EmailIdentityProofData,
) {
    let data = EmailIdentityProofData {
        node_id: identity.node_id.clone(),
        company_node_id: None,
        email: Email::new("alice@example.com").unwrap(),
        created_at: ts(1_700_000_100),
    };
    let proof = data
        .sign(&identity.node_id, &keys.get_private_key())
        .unwrap();
    (proof, data)
}

pub async fn test_identity_transaction_commit(
    transaction_manager: &dyn TransactionManagerApi,
    identity_store: &dyn IdentityStoreApi,
    chain_store: &dyn IdentityChainStoreApi,
) {
    let keys = BcrKeys::new();
    identity_store
        .save_key_pair(&keys, TEST_SEED)
        .await
        .unwrap();
    let mut identity = test_identity(&keys, "Alice");
    let create = create_block(&identity, &keys, ts(1_700_000_001));
    let update = update_block(&create, &keys, "Alice Updated", ts(1_700_000_002));
    identity.name = Name::new("Alice Updated").unwrap();
    let (proof, confirmation) = matching_email_confirmation(&identity, &keys);

    let mut tx = transaction_manager.begin().await.unwrap();
    tx.append_identity_blocks(None, &[create.clone(), update.clone()])
        .await
        .unwrap();
    tx.save_identity(&identity).await.unwrap();
    tx.set_identity_email_confirmation(&proof, &confirmation)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let chain = chain_store.get_chain().await.unwrap();
    assert_eq!(chain.blocks().len(), 2);
    assert_eq!(&chain.blocks()[0], &create);
    assert_eq!(&chain.blocks()[1], &update);
    let stored_identity = identity_store.get().await.unwrap();
    assert_eq!(stored_identity.name, identity.name);
    assert_eq!(stored_identity.node_id, identity.node_id);
    let confirmations = identity_store.get_email_confirmations().await.unwrap();
    assert_eq!(confirmations.len(), 1);
    assert_eq!(confirmations[0].1.node_id, identity.node_id);
    assert_eq!(confirmations[0].1.email, confirmation.email);
}

pub async fn test_identity_transaction_rollback(
    transaction_manager: &dyn TransactionManagerApi,
    identity_store: &dyn IdentityStoreApi,
    chain_store: &dyn IdentityChainStoreApi,
) {
    let keys = BcrKeys::new();
    identity_store
        .save_key_pair(&keys, TEST_SEED)
        .await
        .unwrap();
    let identity = test_identity(&keys, "Alice");
    let create = create_block(&identity, &keys, ts(1_700_000_001));
    // Confirmation belongs to another key so set_identity_email_confirmation fails
    let other_keys = BcrKeys::new();
    let wrong_node_id = NodeId::new(other_keys.pub_key(), bitcoin::Network::Testnet);
    let wrong_data = EmailIdentityProofData {
        node_id: wrong_node_id.clone(),
        company_node_id: None,
        email: Email::new("wrong@example.com").unwrap(),
        created_at: ts(1_700_000_100),
    };
    let wrong_proof = wrong_data
        .sign(&wrong_node_id, &other_keys.get_private_key())
        .unwrap();

    {
        let mut tx = transaction_manager.begin().await.unwrap();
        tx.append_identity_blocks(None, std::slice::from_ref(&create))
            .await
            .unwrap();
        tx.save_identity(&identity).await.unwrap();
        let result = tx
            .set_identity_email_confirmation(&wrong_proof, &wrong_data)
            .await;
        assert!(result.is_err());
        // No commit - Dropping tx must roll back both the chain and identity writes
    }
    assert!(chain_store.get_chain().await.is_err());
    assert!(identity_store.get().await.is_err());
    let confirmations = identity_store.get_email_confirmations().await.unwrap();
    assert!(confirmations.is_empty());
}

pub async fn test_identity_transaction_rejects_stale_tip(
    transaction_manager: &dyn TransactionManagerApi,
    chain_store: &dyn IdentityChainStoreApi,
) {
    let keys = BcrKeys::new();
    let identity = test_identity(&keys, "Alice");
    let create = create_block(&identity, &keys, ts(1_700_000_001));
    chain_store.add_block(&create).await.unwrap();
    let expected_tip = create.clone();
    // Another writer writes first against the same tip
    let concurrent = update_block(&create, &keys, "Concurrent", ts(1_700_000_002));
    chain_store.add_block(&concurrent).await.unwrap();
    // This block was also prepared against the now-stale Create tip
    let stale = update_block(&create, &keys, "Stale", ts(1_700_000_003));
    {
        let mut tx = transaction_manager.begin().await.unwrap();
        let result = tx
            .append_identity_blocks(Some(&expected_tip), &[stale])
            .await;
        assert!(result.is_err());
    }
    let chain = chain_store.get_chain().await.unwrap();
    assert_eq!(chain.blocks().len(), 2);
    assert_eq!(chain.get_latest_block().hash, concurrent.hash);
}

pub async fn test_identity_transaction_replace(
    transaction_manager: &dyn TransactionManagerApi,
    chain_store: &dyn IdentityChainStoreApi,
) {
    let keys = BcrKeys::new();
    let identity = test_identity(&keys, "Alice");
    let b1 = create_block(&identity, &keys, ts(1_700_000_001));
    let b2 = update_block(&b1, &keys, "2", ts(1_700_000_002));
    let a3 = update_block(&b2, &keys, "A3", ts(1_700_000_003));
    let a4 = update_block(&a3, &keys, "A4", ts(1_700_000_004));
    for block in [&b1, &b2, &a3, &a4] {
        chain_store.add_block(block).await.unwrap();
    }
    let b3 = update_block(&b2, &keys, "B3", ts(1_700_000_103));
    let b4 = update_block(&b3, &keys, "B4", ts(1_700_000_104));

    let mut tx = transaction_manager.begin().await.unwrap();
    tx.replace_identity_blocks_from_height(&a4, a3.id, &[b3.clone(), b4.clone()])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let chain = chain_store.get_chain().await.unwrap();
    assert_eq!(chain.blocks().len(), 4);
    assert_eq!(&chain.blocks()[0], &b1);
    assert_eq!(&chain.blocks()[1], &b2);
    assert_eq!(&chain.blocks()[2], &b3);
    assert_eq!(&chain.blocks()[3], &b4);
}

pub async fn test_identity_transaction_replace_rollback(
    transaction_manager: &dyn TransactionManagerApi,
    chain_store: &dyn IdentityChainStoreApi,
) {
    let keys = BcrKeys::new();
    let identity = test_identity(&keys, "Alice");
    let b1 = create_block(&identity, &keys, ts(1_700_000_001));
    let b2 = update_block(&b1, &keys, "2", ts(1_700_000_002));
    let a3 = update_block(&b2, &keys, "A3", ts(1_700_000_003));
    let a4 = update_block(&a3, &keys, "A4", ts(1_700_000_004));
    for block in [&b1, &b2, &a3, &a4] {
        chain_store.add_block(block).await.unwrap();
    }
    let b3 = update_block(&b2, &keys, "B3", ts(1_700_000_103));
    let mut invalid_b4 = update_block(&b3, &keys, "B4", ts(1_700_000_104));
    // make the second replacement invalid after the DELETE and first INSERT have happened
    invalid_b4.previous_hash = Sha256Hash::new("invalid previous hash");
    {
        let mut tx = transaction_manager.begin().await.unwrap();
        let result = tx
            .replace_identity_blocks_from_height(&a4, a3.id, &[b3, invalid_b4])
            .await;
        assert!(result.is_err());
        // rollback DELETE + inserted B3
    }
    let chain = chain_store.get_chain().await.unwrap();
    assert_eq!(chain.blocks().len(), 4);
    assert_eq!(&chain.blocks()[0], &b1);
    assert_eq!(&chain.blocks()[1], &b2);
    assert_eq!(&chain.blocks()[2], &a3);
    assert_eq!(&chain.blocks()[3], &a4);
}

pub async fn test_identity_transaction_rejects_second_genesis(
    transaction_manager: &dyn TransactionManagerApi,
    chain_store: &dyn IdentityChainStoreApi,
) {
    let keys = BcrKeys::new();
    let first_identity = test_identity(&keys, "First");
    let first = create_block(&first_identity, &keys, ts(1_700_000_001));
    chain_store.add_block(&first).await.unwrap();
    let second_identity = test_identity(&keys, "Second");
    let second = create_block(&second_identity, &keys, ts(1_700_000_002));
    {
        let mut tx = transaction_manager.begin().await.unwrap();
        let result = tx.append_identity_blocks(None, &[second]).await;
        assert!(result.is_err());
    }
    let chain = chain_store.get_chain().await.unwrap();
    assert_eq!(chain.blocks().len(), 1);
    assert_eq!(chain.get_latest_block().hash, first.hash);
}
