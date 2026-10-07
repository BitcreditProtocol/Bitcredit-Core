use crate::traits::nostr::{NostrChainEvent, NostrChainEventStoreApi};
use bcr_ebill_core::protocol::{
    Sha256Hash, Timestamp, blockchain::BlockchainType, crypto::BcrKeys,
};
use nostr::event::{Event, EventBuilder, FinalizeEvent};

fn get_root_event() -> NostrChainEvent {
    get_test_chain_event(
        "root_event_id",
        "root_event_id",
        None,
        1,
        &Sha256Hash::new("root_hash"),
    )
}

fn get_child_event(
    id: &str,
    height: usize,
    hash: &Sha256Hash,
    root: &NostrChainEvent,
    parent: Option<&NostrChainEvent>,
) -> NostrChainEvent {
    get_test_chain_event(
        id,
        &root.event_id,
        parent.map(|parent| parent.event_id.clone()),
        height,
        hash,
    )
}

fn get_test_chain_event(
    event_id: &str,
    root_id: &str,
    reply_id: Option<String>,
    block_height: usize,
    block_hash: &Sha256Hash,
) -> NostrChainEvent {
    NostrChainEvent {
        event_id: event_id.to_string(),
        root_id: root_id.to_string(),
        reply_id,
        author: "author".to_string(),
        chain_id: "chain_id".to_string(),
        chain_type: BlockchainType::Bill,
        block_height,
        block_hash: block_hash.clone(),
        received: Timestamp::now(),
        time: Timestamp::now(),
        payload: get_test_event(event_id),
    }
}

fn get_test_event(content: &str) -> Event {
    let keys = BcrKeys::new().get_nostr_keys();
    EventBuilder::new(nostr::event::Kind::TextNote, content)
        .finalize(&keys)
        .expect("could not create nostr test event")
}

pub async fn test_add_event<S>(store: &S)
where
    S: NostrChainEventStoreApi + ?Sized,
{
    let event = get_root_event();
    store
        .add_chain_event(event.clone())
        .await
        .expect("could not add chain event");
    let stored = store
        .by_event_id(&event.event_id)
        .await
        .expect("could not query event by id")
        .expect("stored event missing");
    assert_eq!(stored.event_id, event.event_id);
    assert_eq!(stored.root_id, event.root_id);
    assert_eq!(stored.chain_id, event.chain_id);
    assert_eq!(stored.chain_type, event.chain_type);
    assert_eq!(stored.block_height, event.block_height);
    assert_eq!(stored.block_hash, event.block_hash);
    assert_eq!(stored.payload.id, event.payload.id);
    assert_eq!(stored.payload.content, event.payload.content);
}

pub async fn test_event_by_hash<S>(store: &S)
where
    S: NostrChainEventStoreApi + ?Sized,
{
    let root = get_root_event();
    let child = get_child_event("child_id", 2, &Sha256Hash::new("child_hash"), &root, None);
    store
        .add_chain_event(root)
        .await
        .expect("root event creation failed");
    store
        .add_chain_event(child)
        .await
        .expect("child event creation failed");
    let by_hash = store
        .find_by_block_hash(&Sha256Hash::new("child_hash"))
        .await
        .expect("could not find by hash")
        .expect("event not found by hash");
    assert_eq!(by_hash.event_id, "child_id");
}

pub async fn test_find_by_block_hash_prefers_latest<S>(store: &S)
where
    S: NostrChainEventStoreApi + ?Sized,
{
    let root = get_root_event();
    let hash = Sha256Hash::new("shared_hash");
    let mut lower = get_child_event("lower", 2, &hash, &root, None);
    lower.received = Timestamp::new(5000).unwrap();
    let mut higher_old = get_child_event("higher_old", 3, &hash, &root, None);
    higher_old.received = Timestamp::new(1000).unwrap();
    let mut higher_new = get_child_event("higher_new", 3, &hash, &root, None);
    higher_new.received = Timestamp::new(2000).unwrap();
    store.add_chain_event(lower).await.unwrap();
    store.add_chain_event(higher_old).await.unwrap();
    store.add_chain_event(higher_new).await.unwrap();
    let result = store
        .find_by_block_hash(&hash)
        .await
        .unwrap()
        .expect("event missing");
    assert_eq!(result.event_id, "higher_new");
}

pub async fn test_find_root_event<S>(store: &S)
where
    S: NostrChainEventStoreApi + ?Sized,
{
    let root = get_root_event();
    let child = get_child_event("child_id", 2, &Sha256Hash::new("child_hash"), &root, None);
    store
        .add_chain_event(root)
        .await
        .expect("root event creation failed");
    store
        .add_chain_event(child)
        .await
        .expect("child event creation failed");
    let root_result = store
        .find_root_event("chain_id", BlockchainType::Bill)
        .await
        .expect("could not find root event")
        .expect("root event missing");
    assert_eq!(root_result.event_id, "root_event_id");
    assert_eq!(root_result.root_id, "root_event_id");
}

pub async fn test_find_latest_block_events<S>(store: &S)
where
    S: NostrChainEventStoreApi + ?Sized,
{
    let root = get_root_event();
    let child = get_child_event(
        "child_event",
        2,
        &Sha256Hash::new("child_hash"),
        &root,
        None,
    );
    let target1 = get_child_event(
        "child_event_a",
        3,
        &Sha256Hash::new("child_hash_a"),
        &root,
        Some(&child),
    );
    let target2 = get_child_event(
        "child_event_b",
        3,
        &Sha256Hash::new("child_hash_b"),
        &root,
        Some(&child),
    );
    store.add_chain_event(root).await.unwrap();
    store.add_chain_event(child).await.unwrap();
    store.add_chain_event(target1).await.unwrap();
    let latest = store
        .find_latest_block_events("chain_id", BlockchainType::Bill)
        .await
        .expect("could not find latest block events");
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0].event_id, "child_event_a");
    store.add_chain_event(target2).await.unwrap();
    let latest = store
        .find_latest_block_events("chain_id", BlockchainType::Bill)
        .await
        .expect("could not find latest block events");
    assert_eq!(latest.len(), 2);
    let mut ids = latest
        .into_iter()
        .map(|event| event.event_id)
        .collect::<Vec<_>>();
    ids.sort();
    assert_eq!(
        ids,
        vec!["child_event_a".to_string(), "child_event_b".to_string(),]
    );
}

pub async fn test_find_all_events<S>(store: &S)
where
    S: NostrChainEventStoreApi + ?Sized,
{
    let root = get_root_event();
    let child = get_child_event(
        "child_event",
        2,
        &Sha256Hash::new("child_hash"),
        &root,
        None,
    );
    let target1 = get_child_event(
        "child_event_a",
        3,
        &Sha256Hash::new("child_hash_a"),
        &root,
        Some(&child),
    );
    let target2 = get_child_event(
        "child_event_b",
        3,
        &Sha256Hash::new("child_hash_b"),
        &root,
        Some(&child),
    );
    store.add_chain_event(root).await.unwrap();
    store.add_chain_event(child).await.unwrap();
    store.add_chain_event(target1).await.unwrap();
    store.add_chain_event(target2).await.unwrap();
    let all = store
        .find_chain_events("chain_id", BlockchainType::Bill)
        .await
        .expect("could not find all events");
    assert_eq!(all.len(), 4);
    let heights = all
        .iter()
        .map(|event| event.block_height)
        .collect::<Vec<_>>();
    assert_eq!(heights, vec![3, 3, 2, 1]);
}

pub async fn test_upsert_existing_event<S>(store: &S)
where
    S: NostrChainEventStoreApi + ?Sized,
{
    let event = get_root_event();
    store
        .add_chain_event(event.clone())
        .await
        .expect("initial insert failed");
    let mut updated = event.clone();
    updated.block_height = 42;
    updated.block_hash = Sha256Hash::new("updated_hash");
    updated.payload = get_test_event("updated content");
    store
        .add_chain_event(updated.clone())
        .await
        .expect("upsert failed");
    let stored = store
        .by_event_id(&event.event_id)
        .await
        .unwrap()
        .expect("event missing");
    assert_eq!(stored.block_height, 42);
    assert_eq!(stored.block_hash, Sha256Hash::new("updated_hash"));
    assert_eq!(stored.payload.content, "updated content");
    let all = store
        .find_chain_events("chain_id", BlockchainType::Bill)
        .await
        .unwrap();
    assert_eq!(all.len(), 1);
}

pub async fn test_chain_type_scoping<S>(store: &S)
where
    S: NostrChainEventStoreApi + ?Sized,
{
    let bill = get_root_event();
    let mut company = get_root_event();
    company.event_id = "company_root".to_string();
    company.root_id = "company_root".to_string();
    company.chain_type = BlockchainType::Company;
    company.block_hash = Sha256Hash::new("company_hash");
    store.add_chain_event(bill).await.unwrap();
    store.add_chain_event(company).await.unwrap();
    let bill_events = store
        .find_chain_events("chain_id", BlockchainType::Bill)
        .await
        .unwrap();
    let company_events = store
        .find_chain_events("chain_id", BlockchainType::Company)
        .await
        .unwrap();
    assert_eq!(bill_events.len(), 1);
    assert_eq!(company_events.len(), 1);
    assert_eq!(company_events[0].event_id, "company_root");
}

pub async fn test_remove_chain_events<S>(store: &S)
where
    S: NostrChainEventStoreApi + ?Sized,
{
    let bill = get_root_event();
    let child = get_child_event(
        "bill_child",
        2,
        &Sha256Hash::new("bill_child_hash"),
        &bill,
        None,
    );
    let mut company = get_root_event();
    company.event_id = "company_root".to_string();
    company.root_id = "company_root".to_string();
    company.chain_type = BlockchainType::Company;
    company.block_hash = Sha256Hash::new("company_hash");
    store.add_chain_event(bill).await.unwrap();
    store.add_chain_event(child).await.unwrap();
    store.add_chain_event(company).await.unwrap();
    store
        .remove_chain_events("chain_id", BlockchainType::Bill)
        .await
        .expect("could not remove chain events");
    let bill_events = store
        .find_chain_events("chain_id", BlockchainType::Bill)
        .await
        .unwrap();
    assert!(bill_events.is_empty());
    // removal must be scoped by chain type
    let company_events = store
        .find_chain_events("chain_id", BlockchainType::Company)
        .await
        .unwrap();
    assert_eq!(company_events.len(), 1);
    assert_eq!(company_events[0].event_id, "company_root");
}
