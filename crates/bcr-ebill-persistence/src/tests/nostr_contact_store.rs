use crate::traits::nostr::{NostrStoreApi, PendingContactShare, ShareDirection, SyncStatus};
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    application::{
        contact::Contact,
        nostr_contact::{HandshakeStatus, NostrContact, TrustLevel},
    },
    protocol::{Name, Timestamp, blockchain::bill::ContactType, crypto::BcrKeys},
};
use nostr::event::{EventBuilder, FinalizeEvent};

fn node_id() -> NodeId {
    let keys = BcrKeys::new();
    NodeId::new(keys.pub_key(), bitcoin::Network::Testnet)
}

fn get_test_contact(node_id: &NodeId, name: Option<Name>) -> NostrContact {
    NostrContact {
        npub: node_id.npub(),
        node_id: node_id.clone(),
        name: name.or(Some(Name::new("contact_name").unwrap())),
        relays: vec![url::Url::parse("ws://localhost:8080").unwrap()],
        blossom_servers: vec![url::Url::parse("https://blossom.example.com").unwrap()],
        trust_level: TrustLevel::None,
        handshake_status: HandshakeStatus::None,
        contact_private_key: None,
        mint_url: Some(url::Url::parse("https://mint.example.com").unwrap()),
    }
}

fn get_test_pending_share(
    id: &str,
    node_id: &NodeId,
    receiver_node_id: &NodeId,
    direction: ShareDirection,
) -> PendingContactShare {
    let keys = BcrKeys::new();
    PendingContactShare {
        id: id.to_string(),
        node_id: node_id.clone(),
        contact: Contact {
            t: ContactType::Person,
            node_id: node_id.clone(),
            name: Name::new("Test Contact").unwrap(),
            email: None,
            postal_address: None,
            date_of_birth_or_registration: None,
            country_of_birth_or_registration: None,
            city_of_birth_or_registration: None,
            identification_number: None,
            avatar_file: None,
            proof_document_file: None,
            nostr_relays: vec![],
            is_logical: false,
            mint_url: None,
        },
        sender_node_id: node_id.clone(),
        contact_private_key: keys.get_private_key(),
        receiver_node_id: receiver_node_id.clone(),
        received_at: Timestamp::now(),
        direction,
        initial_share_id: Some("initial-123".to_string()),
    }
}

pub async fn test_upsert_and_retrieve_by_node_id<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let node_id = node_id();
    let contact = get_test_contact(&node_id, None);
    store.upsert(&contact).await.unwrap();
    let retrieved = store.by_node_id(&node_id).await.unwrap().unwrap();
    assert_eq!(retrieved.npub, contact.npub);
    assert_eq!(retrieved.name, contact.name);
    assert_eq!(retrieved.relays, contact.relays);
    assert_eq!(retrieved.blossom_servers, contact.blossom_servers);
    assert_eq!(retrieved.trust_level, contact.trust_level);
    assert_eq!(retrieved.handshake_status, contact.handshake_status);
    assert_eq!(retrieved.mint_url, contact.mint_url);
}

pub async fn test_upsert_and_retrieve_by_npub<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let node_id = node_id();
    let contact = get_test_contact(&node_id, None);
    store.upsert(&contact).await.unwrap();
    let retrieved = store.by_npub(&node_id.npub()).await.unwrap().unwrap();
    assert_eq!(retrieved.npub, contact.npub);
}

pub async fn test_get_all<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let node1 = node_id();
    let node2 = node_id();
    store.upsert(&get_test_contact(&node1, None)).await.unwrap();
    store.upsert(&get_test_contact(&node2, None)).await.unwrap();
    let all = store.get_all().await.unwrap();
    assert_eq!(all.len(), 2);
}

pub async fn test_delete_contact<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let node_id = node_id();
    let contact = get_test_contact(&node_id, None);
    store.upsert(&contact).await.unwrap();
    store.delete(&node_id).await.unwrap();
    assert!(store.by_node_id(&node_id).await.unwrap().is_none());
}

pub async fn test_set_handshake_status<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let node_id = node_id();
    let contact = get_test_contact(&node_id, None);
    store.upsert(&contact).await.unwrap();
    store
        .set_handshake_status(&node_id, HandshakeStatus::InProgress)
        .await
        .unwrap();
    let retrieved = store.by_node_id(&node_id).await.unwrap().unwrap();
    assert_eq!(retrieved.handshake_status, HandshakeStatus::InProgress);
}

pub async fn test_set_trust_level<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let node_id = node_id();
    let contact = get_test_contact(&node_id, None);
    store.upsert(&contact).await.unwrap();
    store
        .set_trust_level(&node_id, TrustLevel::Participant)
        .await
        .unwrap();
    let retrieved = store.by_node_id(&node_id).await.unwrap().unwrap();
    assert_eq!(retrieved.trust_level, TrustLevel::Participant);
}

pub async fn test_get_npubs<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let node_id = node_id();
    let contact = get_test_contact(&node_id, None);
    store.upsert(&contact).await.unwrap();
    store
        .set_trust_level(&node_id, TrustLevel::Participant)
        .await
        .unwrap();
    let keys = store
        .get_npubs(vec![TrustLevel::Participant])
        .await
        .unwrap();
    assert_eq!(keys, vec![node_id.npub()]);
}

pub async fn test_search<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let node1 = node_id();
    let node2 = node_id();
    let node3 = node_id();
    store
        .upsert(&get_test_contact(
            &node1,
            Some(Name::new("Albert").unwrap()),
        ))
        .await
        .unwrap();
    store
        .set_trust_level(&node1, TrustLevel::Participant)
        .await
        .unwrap();
    store
        .upsert(&get_test_contact(&node2, Some(Name::new("Berta").unwrap())))
        .await
        .unwrap();
    store
        .set_trust_level(&node2, TrustLevel::Trusted)
        .await
        .unwrap();
    store
        .upsert(&get_test_contact(
            &node3,
            Some(Name::new("Bertrand").unwrap()),
        ))
        .await
        .unwrap();
    let result = store
        .search(
            "bert",
            vec![
                TrustLevel::Participant,
                TrustLevel::Trusted,
                TrustLevel::None,
            ],
        )
        .await
        .unwrap();
    assert_eq!(result.len(), 3);
    let result = store
        .search("bert", vec![TrustLevel::Participant, TrustLevel::Trusted])
        .await
        .unwrap();
    assert_eq!(result.len(), 2);
    let result = store
        .search("ALB", vec![TrustLevel::Participant, TrustLevel::Trusted])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
}

pub async fn test_by_node_ids<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let node1 = node_id();
    let node2 = node_id();
    let missing = node_id();
    store.upsert(&get_test_contact(&node1, None)).await.unwrap();
    store.upsert(&get_test_contact(&node2, None)).await.unwrap();
    let result = store
        .by_node_ids(vec![node1, node2, missing])
        .await
        .unwrap();
    assert_eq!(result.len(), 2);
}

pub async fn test_pending_share_crud<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let sender = node_id();
    let receiver = node_id();
    let share = get_test_pending_share("share", &sender, &receiver, ShareDirection::Incoming);
    let private_key = share.contact_private_key;
    store.add_pending_share(share.clone()).await.unwrap();
    let loaded = store.get_pending_share("share").await.unwrap().unwrap();
    assert_eq!(loaded.id, share.id);
    assert_eq!(loaded.contact.node_id, share.contact.node_id);
    assert_eq!(loaded.receiver_node_id, receiver);
    let by_key = store
        .get_pending_share_by_private_key(&private_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_key.id, "share");
    let by_receiver = store
        .list_pending_shares_by_receiver(&receiver)
        .await
        .unwrap();
    assert_eq!(by_receiver.len(), 1);
    let incoming = store
        .list_pending_shares_by_receiver_and_direction(&receiver, ShareDirection::Incoming)
        .await
        .unwrap();
    assert_eq!(incoming.len(), 1);
    let outgoing = store
        .list_pending_shares_by_receiver_and_direction(&receiver, ShareDirection::Outgoing)
        .await
        .unwrap();
    assert!(outgoing.is_empty());
    store.delete_pending_share("share").await.unwrap();
    assert!(store.get_pending_share("share").await.unwrap().is_none());
}

pub async fn test_pending_share_exists_distinguishes_direction<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let alice = node_id();
    let bob = node_id();
    store
        .add_pending_share(get_test_pending_share(
            "alice-to-bob",
            &alice,
            &bob,
            ShareDirection::Incoming,
        ))
        .await
        .unwrap();
    assert!(
        store
            .pending_share_exists_for_node_and_receiver(&alice, &bob, ShareDirection::Incoming,)
            .await
            .unwrap()
    );
    assert!(
        !store
            .pending_share_exists_for_node_and_receiver(&alice, &bob, ShareDirection::Outgoing,)
            .await
            .unwrap()
    );
}

pub async fn test_update_relay_last_seen_creates_new_status<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let relay = url::Url::parse("wss://relay.example.com").unwrap();
    let now = Timestamp::now();
    store.update_relay_last_seen(&relay, now).await.unwrap();
    let status = store.get_relay_sync_status(&relay).await.unwrap().unwrap();
    assert_eq!(status.relay_url, relay);
    assert_eq!(status.last_seen_in_config, now);
    assert_eq!(status.sync_status, SyncStatus::Pending);
    assert_eq!(status.events_synced, 0);
    assert!(status.last_synced_timestamp.is_none());
    assert!(status.last_error.is_none());
}

pub async fn test_update_relay_last_seen_updates_existing<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let relay = url::Url::parse("wss://relay.example.com").unwrap();
    let first = Timestamp::new(1000).unwrap();
    let second = Timestamp::new(2000).unwrap();
    store.update_relay_last_seen(&relay, first).await.unwrap();
    store.update_relay_last_seen(&relay, second).await.unwrap();
    let status = store.get_relay_sync_status(&relay).await.unwrap().unwrap();
    assert_eq!(status.last_seen_in_config, second);
}

pub async fn test_update_relay_sync_status<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let relay = url::Url::parse("wss://relay.example.com").unwrap();
    store
        .update_relay_sync_status(&relay, SyncStatus::Pending)
        .await
        .unwrap();
    store
        .update_relay_sync_status(&relay, SyncStatus::InProgress)
        .await
        .unwrap();
    assert_eq!(
        store
            .get_relay_sync_status(&relay)
            .await
            .unwrap()
            .unwrap()
            .sync_status,
        SyncStatus::InProgress
    );
    store
        .update_relay_sync_status(&relay, SyncStatus::Completed)
        .await
        .unwrap();
    let status = store.get_relay_sync_status(&relay).await.unwrap().unwrap();
    assert_eq!(status.sync_status, SyncStatus::Completed);
    assert!(status.last_error.is_none());
}

pub async fn test_get_pending_relays<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let pending = url::Url::parse("wss://relay1.example.com").unwrap();
    let in_progress = url::Url::parse("wss://relay2.example.com").unwrap();
    let completed = url::Url::parse("wss://relay3.example.com").unwrap();
    let failed = url::Url::parse("wss://relay4.example.com").unwrap();
    store
        .update_relay_sync_status(&pending, SyncStatus::Pending)
        .await
        .unwrap();
    store
        .update_relay_sync_status(&in_progress, SyncStatus::InProgress)
        .await
        .unwrap();
    store
        .update_relay_sync_status(&completed, SyncStatus::Completed)
        .await
        .unwrap();
    store
        .update_relay_sync_status(&failed, SyncStatus::Failed)
        .await
        .unwrap();
    let result = store.get_pending_relays().await.unwrap();
    assert_eq!(result.len(), 3);
    assert!(result.contains(&pending));
    assert!(result.contains(&in_progress));
    assert!(result.contains(&failed));
    assert!(!result.contains(&completed));
}

pub async fn test_update_relay_sync_progress<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let relay = url::Url::parse("wss://relay.example.com").unwrap();
    let first = Timestamp::new(1000).unwrap();
    let second = Timestamp::new(2000).unwrap();
    store
        .update_relay_sync_status(&relay, SyncStatus::InProgress)
        .await
        .unwrap();
    store
        .update_relay_sync_progress(&relay, first)
        .await
        .unwrap();
    let status = store.get_relay_sync_status(&relay).await.unwrap().unwrap();
    assert_eq!(status.events_synced, 1);
    assert_eq!(status.last_synced_timestamp, Some(first));
    store
        .update_relay_sync_progress(&relay, second)
        .await
        .unwrap();
    let status = store.get_relay_sync_status(&relay).await.unwrap().unwrap();
    assert_eq!(status.events_synced, 2);
    assert_eq!(status.last_synced_timestamp, Some(second));
}

pub async fn test_add_and_get_pending_relay_retries<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let relay = url::Url::parse("wss://relay.example.com").unwrap();
    let keys = nostr::key::Keys::generate();
    let event1 = EventBuilder::new(nostr::event::Kind::TextNote, "test 1")
        .finalize(&keys)
        .unwrap();
    let event2 = EventBuilder::new(nostr::event::Kind::TextNote, "test 2")
        .finalize(&keys)
        .unwrap();
    store
        .add_failed_relay_sync(&relay, event1.clone())
        .await
        .unwrap();
    store
        .add_failed_relay_sync(&relay, event2.clone())
        .await
        .unwrap();
    let retries = store.get_pending_relay_retries(&relay, 10).await.unwrap();
    assert_eq!(retries.len(), 2);
    assert!(retries.iter().any(|event| event.id == event1.id));
    assert!(retries.iter().any(|event| event.id == event2.id));
}

pub async fn test_mark_relay_retry_success<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let relay = url::Url::parse("wss://relay.example.com").unwrap();
    let keys = nostr::key::Keys::generate();
    let event = EventBuilder::new(nostr::event::Kind::TextNote, "test")
        .finalize(&keys)
        .unwrap();
    store
        .add_failed_relay_sync(&relay, event.clone())
        .await
        .unwrap();
    store
        .mark_relay_retry_success(&relay, &event.id.to_hex())
        .await
        .unwrap();
    assert!(
        store
            .get_pending_relay_retries(&relay, 10,)
            .await
            .unwrap()
            .is_empty()
    );
}

pub async fn test_mark_relay_retry_failed_increments_count<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let relay = url::Url::parse("wss://relay.example.com").unwrap();
    let keys = nostr::key::Keys::generate();
    let event = EventBuilder::new(nostr::event::Kind::TextNote, "test")
        .finalize(&keys)
        .unwrap();
    store
        .add_failed_relay_sync(&relay, event.clone())
        .await
        .unwrap();
    for _ in 0..3 {
        store
            .mark_relay_retry_failed(&relay, &event.id.to_hex(), 3)
            .await
            .unwrap();
        assert_eq!(
            store
                .get_pending_relay_retries(&relay, 10,)
                .await
                .unwrap()
                .len(),
            1
        );
    }
    store
        .mark_relay_retry_failed(&relay, &event.id.to_hex(), 3)
        .await
        .unwrap();
    assert!(
        store
            .get_pending_relay_retries(&relay, 10,)
            .await
            .unwrap()
            .is_empty()
    );
}

pub async fn test_get_pending_relay_retries_filters_by_relay<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let relay1 = url::Url::parse("wss://relay1.example.com").unwrap();
    let relay2 = url::Url::parse("wss://relay2.example.com").unwrap();
    let keys = nostr::key::Keys::generate();
    let event1 = EventBuilder::new(nostr::event::Kind::TextNote, "test 1")
        .finalize(&keys)
        .unwrap();
    let event2 = EventBuilder::new(nostr::event::Kind::TextNote, "test 2")
        .finalize(&keys)
        .unwrap();
    store
        .add_failed_relay_sync(&relay1, event1.clone())
        .await
        .unwrap();
    store.add_failed_relay_sync(&relay2, event2).await.unwrap();
    let retries = store.get_pending_relay_retries(&relay1, 10).await.unwrap();
    assert_eq!(retries.len(), 1);
    assert_eq!(retries[0].id, event1.id);
}

pub async fn test_get_pending_relay_retries_respects_limit<S>(store: &S)
where
    S: NostrStoreApi + ?Sized,
{
    let relay = url::Url::parse("wss://relay.example.com").unwrap();
    let keys = nostr::key::Keys::generate();
    for i in 0..5 {
        let event = EventBuilder::new(nostr::event::Kind::TextNote, format!("test {i}"))
            .finalize(&keys)
            .unwrap();
        store.add_failed_relay_sync(&relay, event).await.unwrap();
    }
    let retries = store.get_pending_relay_retries(&relay, 3).await.unwrap();
    assert_eq!(retries.len(), 3);
}
