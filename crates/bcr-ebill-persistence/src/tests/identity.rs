use bcr_ebill_core::{application::identity::ActiveIdentityState, protocol::Name};
use bitcoin::Network;
use url::Url;

use crate::{
    protocol::crypto::BcrKeys,
    tests::tests::{
        empty_identity, node_id_test_other, private_key_test, signed_identity_proof_test,
    },
    traits::identity::IdentityStoreApi,
};

pub async fn test_identity_store<S>(store: &S)
where
    S: IdentityStoreApi + ?Sized,
{
    // EXISTS
    assert!(!store.exists().await);

    // IDENTITY ROUND TRIP
    let mut identity = empty_identity();
    identity.name = Name::new("Minka").unwrap();
    identity.nostr_relays = vec![
        Url::parse("wss://relay.example.com").unwrap(),
        Url::parse("wss://relay2.example.com").unwrap(),
    ];
    store.save(&identity).await.expect("identity can be saved");
    let fetched = store.get().await;
    assert!(
        fetched.is_ok(),
        "identity was saved but could not be fetched: {fetched:?}"
    );
    assert!(store.exists().await);
    let fetched = store.get().await.expect("identity can be fetched");
    assert_eq!(fetched, identity);

    // UPSERT IDENTITY
    let mut updated = identity.clone();
    updated.name = Name::new("Updated Minka").unwrap();
    store.save(&updated).await.expect("identity can be updated");
    assert_eq!(store.get().await.unwrap(), updated);

    // ACTIVE IDENTITY DEFAULT
    let current = store
        .get_current_identity()
        .await
        .expect("current identity works");
    assert_eq!(current.personal, updated.node_id);
    assert!(current.company.is_none());

    // ACTIVE IDENTITY EXPLICIT
    let active = ActiveIdentityState {
        personal: updated.node_id.clone(),
        company: Some(node_id_test_other()),
    };
    store
        .set_current_identity(&active)
        .await
        .expect("active identity can be set");

    assert_eq!(
        store.get_current_identity().await.unwrap().personal,
        active.personal
    );
    assert_eq!(
        store.get_current_identity().await.unwrap().company,
        active.company
    );

    // Update it again
    let active_personal_only = ActiveIdentityState {
        personal: updated.node_id.clone(),
        company: None,
    };
    store
        .set_current_identity(&active_personal_only)
        .await
        .unwrap();
    assert_eq!(
        store.get_current_identity().await.unwrap().personal,
        active_personal_only.personal
    );
    assert_eq!(store.get_current_identity().await.unwrap().company, None);

    // NETWORK
    store
        .set_or_check_network(Network::Testnet)
        .await
        .expect("initial network can be stored");

    // Same network is fine
    store
        .set_or_check_network(Network::Testnet)
        .await
        .expect("same network works");

    // Different network fails
    assert!(store.set_or_check_network(Network::Bitcoin).await.is_err());

    // KEYS
    let (keys, seed) = BcrKeys::new_with_seed_phrase().expect("key can be generated");
    store
        .save_key_pair(&keys, &seed)
        .await
        .expect("keys can be saved");
    let fetched_keys = store.get_key_pair().await.expect("keys can be fetched");
    assert_eq!(fetched_keys.get_private_key(), keys.get_private_key());
    assert_eq!(store.get_seedphrase().await.unwrap(), seed);

    // KEY UPSERT
    let replacement_keys = BcrKeys::from_private_key(&private_key_test());
    let replacement_seed = "replacement seed";
    store
        .save_key_pair(&replacement_keys, replacement_seed)
        .await
        .expect("keys can be replaced");
    assert_eq!(
        store.get_key_pair().await.unwrap().get_private_key(),
        replacement_keys.get_private_key()
    );
    assert_eq!(store.get_seedphrase().await.unwrap(), replacement_seed);

    // FULL IDENTITY
    let full = store.get_full().await.expect("full identity works");
    assert_eq!(full.identity, updated);
    assert_eq!(
        full.key_pair.get_private_key(),
        replacement_keys.get_private_key()
    );

    // EMAIL CONFIRMATION
    let (proof, data) = signed_identity_proof_test();
    store
        .set_email_confirmation(&proof, &data)
        .await
        .expect("email confirmation can be stored");
    let confirmations = store
        .get_email_confirmations()
        .await
        .expect("email confirmations can be fetched");
    assert_eq!(confirmations.len(), 1);
    assert_eq!(confirmations[0].0.signature, proof.signature);
    assert_eq!(confirmations[0].0.witness, proof.witness);
    assert_eq!(confirmations[0].1.node_id, data.node_id);

    // Same witness = upsert, not duplicate
    store
        .set_email_confirmation(&proof, &data)
        .await
        .expect("email confirmation can be upserted");
    let confirmations = store.get_email_confirmations().await.unwrap();
    assert_eq!(confirmations.len(), 1);
}

pub async fn test_get_or_create_key_pair<S>(store: &S)
where
    S: IdentityStoreApi + ?Sized,
{
    let generated = store
        .get_or_create_key_pair()
        .await
        .expect("key is generated");
    let persisted = store
        .get_key_pair()
        .await
        .expect("generated key is persisted");
    assert_eq!(generated.get_private_key(), persisted.get_private_key());
    let seed = store.get_seedphrase().await.expect("seed is persisted");
    assert!(!seed.is_empty());

    // Existing key is returned rather than
    // another key being generated
    let generated_again = store.get_or_create_key_pair().await.unwrap();
    assert_eq!(
        generated_again.get_private_key(),
        generated.get_private_key()
    );
}
