use bcr_ebill_core::{
    application::contact::Contact,
    protocol::{Email, Name, blockchain::bill::ContactType},
};

use crate::{
    ContactStoreApi,
    tests::tests::{empty_address, node_id_test, node_id_test_other},
};

pub fn get_baseline_contact() -> Contact {
    Contact {
        t: ContactType::Person,
        node_id: node_id_test(),
        name: Name::new("some_name").unwrap(),
        email: Some(Email::new("some_mail@example.com").unwrap()),
        postal_address: Some(empty_address()),
        date_of_birth_or_registration: None,
        country_of_birth_or_registration: None,
        city_of_birth_or_registration: None,
        identification_number: None,
        avatar_file: None,
        proof_document_file: None,
        nostr_relays: vec![],
        is_logical: false,
        mint_url: None,
    }
}

pub async fn test_insert_contact<S>(store: &S)
where
    S: ContactStoreApi + ?Sized,
{
    let contact = get_baseline_contact();
    store
        .insert(&contact.node_id, contact.clone())
        .await
        .expect("could not create contact");
    let stored = store
        .get(&contact.node_id)
        .await
        .expect("could not query contact")
        .expect("could not find created contact");
    assert_eq!(stored.name, Name::new("some_name").unwrap());
    assert_eq!(stored.node_id, contact.node_id);
    assert_eq!(stored.email, contact.email);
    assert_eq!(stored.postal_address, contact.postal_address);
}

pub async fn test_delete_contact<S>(store: &S)
where
    S: ContactStoreApi + ?Sized,
{
    let contact = get_baseline_contact();
    store
        .insert(&contact.node_id, contact.clone())
        .await
        .unwrap();
    store
        .delete(&contact.node_id)
        .await
        .expect("could not delete contact");
    let stored = store.get(&contact.node_id).await.unwrap();
    assert!(stored.is_none());
}

pub async fn test_update_contact<S>(store: &S)
where
    S: ContactStoreApi + ?Sized,
{
    let contact = get_baseline_contact();
    store
        .insert(&contact.node_id, contact.clone())
        .await
        .unwrap();
    let mut updated = contact.clone();
    updated.name = Name::new("other_name").unwrap();
    updated.nostr_relays = vec![
        url::Url::parse("wss://relay1.example.com").unwrap(),
        url::Url::parse("wss://relay2.example.com").unwrap(),
    ];
    updated.mint_url = Some(url::Url::parse("https://mint.example.com").unwrap());
    store
        .update(&updated.node_id, updated.clone())
        .await
        .expect("could not update contact");
    let stored = store
        .get(&updated.node_id)
        .await
        .unwrap()
        .expect("contact missing");
    assert_eq!(stored.name, Name::new("other_name").unwrap());
    assert_eq!(stored.nostr_relays, updated.nostr_relays);
    assert_eq!(stored.mint_url, updated.mint_url);
}

pub async fn test_get_map<S>(store: &S)
where
    S: ContactStoreApi + ?Sized,
{
    let contact1 = get_baseline_contact();
    let mut contact2 = get_baseline_contact();
    contact2.node_id = node_id_test_other();
    contact2.name = Name::new("other_name").unwrap();
    store
        .insert(&contact1.node_id, contact1.clone())
        .await
        .unwrap();
    store
        .insert(&contact2.node_id, contact2.clone())
        .await
        .unwrap();
    let all = store.get_map().await.expect("all query failed");
    assert_eq!(all.len(), 2);
    assert!(all.contains_key(&contact1.node_id));
    assert!(all.contains_key(&contact2.node_id));
    assert_eq!(
        all.get(&contact2.node_id).unwrap().name,
        Name::new("other_name").unwrap()
    );
}

pub async fn test_search<S>(store: &S)
where
    S: ContactStoreApi + ?Sized,
{
    let mut contact = get_baseline_contact();
    contact.name = Name::new("Some Name").unwrap();
    store
        .insert(&contact.node_id, contact.clone())
        .await
        .unwrap();
    let found = store.search("SOME NAME").await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].node_id, contact.node_id);
    let found = store.search("Some").await.unwrap();
    assert!(found.is_empty());
}

pub async fn test_nostr_relays_roundtrip<S>(store: &S)
where
    S: ContactStoreApi + ?Sized,
{
    let mut contact = get_baseline_contact();
    contact.nostr_relays = vec![
        url::Url::parse("wss://relay1.example.com").unwrap(),
        url::Url::parse("wss://relay2.example.com").unwrap(),
    ];
    store
        .insert(&contact.node_id, contact.clone())
        .await
        .unwrap();
    let stored = store.get(&contact.node_id).await.unwrap().unwrap();
    assert_eq!(stored.nostr_relays, contact.nostr_relays);
}
