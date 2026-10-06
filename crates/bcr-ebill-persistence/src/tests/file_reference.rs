use crate::FileReferenceStoreApi;
use bcr_ebill_core::protocol::{Name, Sha256Hash, file_reference::FileReferenceContext};
use bitcoin::hashes::sha256::Hash as Sha256HexHash;

fn test_hash() -> Sha256Hash {
    Sha256Hash::new("test_hash_12345678901234567890123456789012")
}

fn test_nostr_hash() -> Sha256HexHash {
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        .parse()
        .unwrap()
}

fn test_nostr_hash_2() -> Sha256HexHash {
    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
        .parse()
        .unwrap()
}

pub async fn test_upsert_creates_new<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let hash = test_hash();
    let nostr_hash = test_nostr_hash();
    let name = Name::new("test_file.txt").unwrap();
    let url = url::Url::parse("https://blossom.example.com").unwrap();
    let result = store
        .upsert(
            &hash,
            &nostr_hash,
            Some(name.clone()),
            vec![url.clone()],
            Some(true),
            vec![],
        )
        .await
        .expect("upsert failed");
    assert_eq!(result.hash, hash);
    assert_eq!(result.nostr_hash, nostr_hash);
    assert_eq!(result.name, Some(name.clone()));
    assert_eq!(result.server_urls.len(), 1);
    assert_eq!(result.server_urls[0], url);
    assert!(result.is_important);
    let stored = store
        .get(&hash)
        .await
        .expect("get failed")
        .expect("created file reference missing");
    assert_eq!(stored.hash, hash);
    assert_eq!(stored.nostr_hash, nostr_hash);
    assert_eq!(stored.name, Some(name));
    assert_eq!(stored.server_urls.len(), 1);
    assert!(stored.is_important);
}

pub async fn test_upsert_updates_existing<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let hash = test_hash();
    let nostr_hash = test_nostr_hash();
    let nostr_hash_2 = test_nostr_hash_2();
    let name = Name::new("test_file.txt").unwrap();
    let name_2 = Name::new("updated_file.txt").unwrap();
    let url1 = url::Url::parse("https://blossom1.example.com").unwrap();
    let url2 = url::Url::parse("https://blossom2.example.com").unwrap();
    store
        .upsert(
            &hash,
            &nostr_hash,
            Some(name),
            vec![url1.clone()],
            Some(false),
            vec![],
        )
        .await
        .expect("first upsert failed");
    let result = store
        .upsert(
            &hash,
            &nostr_hash_2,
            Some(name_2.clone()),
            vec![url2.clone()],
            Some(true),
            vec![],
        )
        .await
        .expect("second upsert failed");
    assert_eq!(result.nostr_hash, nostr_hash_2);
    assert_eq!(result.name, Some(name_2.clone()));
    assert_eq!(result.server_urls.len(), 2);
    assert!(result.server_urls.contains(&url1));
    assert!(result.server_urls.contains(&url2));
    assert!(result.is_important);
    let stored = store
        .get(&hash)
        .await
        .expect("get failed")
        .expect("updated file reference missing");
    assert_eq!(stored.nostr_hash, nostr_hash_2);
    assert_eq!(stored.name, Some(name_2));
    assert_eq!(stored.server_urls.len(), 2);
    assert!(stored.server_urls.contains(&url1));
    assert!(stored.server_urls.contains(&url2));
    assert!(stored.is_important);
}

pub async fn test_find_by_nostr_hash<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let hash = test_hash();
    let nostr_hash = test_nostr_hash();
    store
        .upsert(&hash, &nostr_hash, None, vec![], Some(false), vec![])
        .await
        .expect("upsert failed");
    let result = store
        .find_by_nostr_hash(&nostr_hash)
        .await
        .expect("find_by_nostr_hash failed");
    let result = result.expect("file reference not found by nostr hash");
    assert_eq!(result.hash, hash);
    assert_eq!(result.nostr_hash, nostr_hash);
}

pub async fn test_find_by_nostr_hash_missing<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let result = store
        .find_by_nostr_hash(&test_nostr_hash())
        .await
        .expect("find_by_nostr_hash failed");
    assert!(result.is_none());
}

pub async fn test_upsert_deduplicates_server_urls<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let hash = test_hash();
    let nostr_hash = test_nostr_hash();
    let url1 = url::Url::parse("https://blossom.example.com").unwrap();
    let url2 = url::Url::parse("https://blossom.example.com/").unwrap();
    let url3 = url::Url::parse("https://blossom2.example.com").unwrap();
    let result = store
        .upsert(
            &hash,
            &nostr_hash,
            None,
            vec![url1, url2, url3],
            None,
            vec![],
        )
        .await
        .expect("upsert failed");
    assert_eq!(result.server_urls.len(), 2);
    let stored = store
        .get(&hash)
        .await
        .expect("get failed")
        .expect("file reference missing");
    assert_eq!(stored.server_urls.len(), 2);
}

pub async fn test_get_existing<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let hash = test_hash();
    let nostr_hash = test_nostr_hash();
    let name = Name::new("test_file.txt").unwrap();
    store
        .upsert(
            &hash,
            &nostr_hash,
            Some(name.clone()),
            vec![],
            Some(false),
            vec![],
        )
        .await
        .expect("upsert failed");
    let result = store.get(&hash).await.expect("get failed");
    let result = result.expect("file reference missing");
    assert_eq!(result.hash, hash);
    assert_eq!(result.nostr_hash, nostr_hash);
    assert_eq!(result.name, Some(name));
}

pub async fn test_get_nonexistent<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let hash = test_hash();
    let result = store.get(&hash).await.expect("get failed");
    assert!(result.is_none());
}

pub async fn test_delete<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let hash = test_hash();
    let nostr_hash = test_nostr_hash();
    store
        .upsert(&hash, &nostr_hash, None, vec![], None, vec![])
        .await
        .expect("upsert failed");
    assert!(store.get(&hash).await.expect("get failed").is_some());
    store.delete(&hash).await.expect("delete failed");
    assert!(store.get(&hash).await.expect("get failed").is_none());
}

pub async fn test_list<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let hash1 = Sha256Hash::new("test_hash_12345678901234567890123456789011");
    let hash2 = Sha256Hash::new("test_hash_12345678901234567890123456789022");
    let nostr_hash = test_nostr_hash();
    store
        .upsert(&hash1, &nostr_hash, None, vec![], None, vec![])
        .await
        .expect("upsert 1 failed");
    store
        .upsert(&hash2, &nostr_hash, None, vec![], None, vec![])
        .await
        .expect("upsert 2 failed");
    let results = store.list().await.expect("list failed");
    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|reference| reference.hash == hash1));
    assert!(results.iter().any(|reference| reference.hash == hash2));
}

pub async fn test_list_important<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let hash1 = Sha256Hash::new("test_hash_12345678901234567890123456789011");
    let hash2 = Sha256Hash::new("test_hash_12345678901234567890123456789022");
    let nostr_hash = test_nostr_hash();
    store
        .upsert(&hash1, &nostr_hash, None, vec![], Some(true), vec![])
        .await
        .expect("upsert 1 failed");
    store
        .upsert(&hash2, &nostr_hash, None, vec![], Some(false), vec![])
        .await
        .expect("upsert 2 failed");
    let results = store.list_important().await.expect("list_important failed");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].hash, hash1);
    assert!(results[0].is_important);
}

pub async fn test_add_server_urls<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let hash = test_hash();
    let nostr_hash = test_nostr_hash();
    let url1 = url::Url::parse("https://blossom1.example.com").unwrap();
    store
        .upsert(&hash, &nostr_hash, None, vec![url1.clone()], None, vec![])
        .await
        .expect("upsert failed");
    let url2 = url::Url::parse("https://blossom2.example.com").unwrap();
    let added = store
        .add_server_urls(&hash, vec![url2.clone()])
        .await
        .expect("add_server_urls failed");
    assert!(added);
    let result = store
        .get(&hash)
        .await
        .expect("get failed")
        .expect("file reference missing");
    assert_eq!(result.server_urls.len(), 2);
    assert!(result.server_urls.contains(&url1));
    assert!(result.server_urls.contains(&url2));
}

pub async fn test_add_server_urls_no_change_for_duplicates<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let hash = test_hash();
    let nostr_hash = test_nostr_hash();
    let url = url::Url::parse("https://blossom.example.com").unwrap();
    store
        .upsert(&hash, &nostr_hash, None, vec![url.clone()], None, vec![])
        .await
        .expect("upsert failed");
    let added = store
        .add_server_urls(&hash, vec![url])
        .await
        .expect("add_server_urls failed");

    assert!(!added);
    let result = store
        .get(&hash)
        .await
        .expect("get failed")
        .expect("file reference missing");
    assert_eq!(result.server_urls.len(), 1);
}

pub async fn test_mark_important<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let hash = test_hash();
    let nostr_hash = test_nostr_hash();
    store
        .upsert(&hash, &nostr_hash, None, vec![], Some(false), vec![])
        .await
        .expect("upsert failed");
    store
        .mark_important(&hash, true)
        .await
        .expect("mark_important failed");
    let result = store
        .get(&hash)
        .await
        .expect("get failed")
        .expect("file reference missing");
    assert!(result.is_important);
}

pub async fn test_update_nostr_hash<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let hash = test_hash();
    let nostr_hash = test_nostr_hash();
    let nostr_hash_2 = test_nostr_hash_2();
    store
        .upsert(&hash, &nostr_hash, None, vec![], None, vec![])
        .await
        .expect("upsert failed");
    store
        .update_nostr_hash(&hash, &nostr_hash_2)
        .await
        .expect("update_nostr_hash failed");
    let result = store
        .get(&hash)
        .await
        .expect("get failed")
        .expect("file reference missing");
    assert_eq!(result.nostr_hash, nostr_hash_2);
    let found = store
        .find_by_nostr_hash(&nostr_hash_2)
        .await
        .expect("find_by_nostr_hash failed")
        .expect("file reference not found by new nostr hash");
    assert_eq!(found.hash, hash);
}

pub async fn test_upsert_preserves_existing_name_when_none_provided<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let hash = test_hash();
    let nostr_hash = test_nostr_hash();
    let name = Name::new("original_name.txt").unwrap();
    store
        .upsert(&hash, &nostr_hash, Some(name.clone()), vec![], None, vec![])
        .await
        .expect("first upsert failed");
    let result = store
        .upsert(&hash, &nostr_hash, None, vec![], None, vec![])
        .await
        .expect("second upsert failed");
    assert_eq!(result.name, Some(name.clone()));
    let stored = store
        .get(&hash)
        .await
        .expect("get failed")
        .expect("file reference missing");
    assert_eq!(stored.name, Some(name));
}

pub async fn test_coexistence_with_existing_file_fields<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let file_hash = Sha256Hash::new("file_hash_12345678901234567890123456789012");
    let nostr_hash = test_nostr_hash();
    let name = Name::new("avatar.png").unwrap();
    let server_url = url::Url::parse("https://blossom.example.com").unwrap();
    let file_ref = store
        .upsert(
            &file_hash,
            &nostr_hash,
            Some(name.clone()),
            vec![server_url.clone()],
            Some(true),
            vec![],
        )
        .await
        .expect("upsert failed");
    assert_eq!(file_ref.hash, file_hash);
    assert_eq!(file_ref.nostr_hash, nostr_hash);
    assert_eq!(file_ref.name, Some(name.clone()));
    assert_eq!(file_ref.server_urls, vec![server_url.clone()]);
    assert!(file_ref.is_important);
    let retrieved = store
        .get(&file_hash)
        .await
        .expect("get failed")
        .expect("file reference missing");
    assert_eq!(retrieved.hash, file_hash);
    assert_eq!(retrieved.nostr_hash, nostr_hash);
    assert_eq!(retrieved.name, Some(name));
    assert_eq!(retrieved.server_urls, vec![server_url]);
    assert!(retrieved.is_important);
}

pub async fn test_upsert_with_context<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let hash = test_hash();
    let nostr_hash = test_nostr_hash();
    let context = vec![
        FileReferenceContext::Identity {
            field: "avatar_file".to_string(),
        },
        FileReferenceContext::Company {
            company_id: "company123".to_string(),
            field: "logo_file".to_string(),
        },
    ];
    let result = store
        .upsert(&hash, &nostr_hash, None, vec![], None, context.clone())
        .await
        .expect("upsert failed");
    assert_eq!(result.context, context);
    let stored = store
        .get(&hash)
        .await
        .expect("get failed")
        .expect("file reference missing");
    assert_eq!(stored.context, context);
}

pub async fn test_add_and_remove_context<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let hash = test_hash();
    let nostr_hash = test_nostr_hash();
    store
        .upsert(&hash, &nostr_hash, None, vec![], None, vec![])
        .await
        .expect("upsert failed");
    let context = FileReferenceContext::Identity {
        field: "avatar_file".to_string(),
    };
    let added = store
        .add_context(&hash, context.clone())
        .await
        .expect("add_context failed");
    assert!(added, "context should have been added");
    let result = store
        .get(&hash)
        .await
        .expect("get failed")
        .expect("file reference missing");
    assert_eq!(result.context.len(), 1);
    assert!(result.context.contains(&context));
    let removed = store
        .remove_context(&hash, &context)
        .await
        .expect("remove_context failed");
    assert!(removed, "context should have been removed");
    let result = store
        .get(&hash)
        .await
        .expect("get failed")
        .expect("file reference missing");
    assert!(result.context.is_empty());
}

pub async fn test_context_deduplication_on_upsert<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let hash = test_hash();
    let nostr_hash = test_nostr_hash();
    let context = FileReferenceContext::Identity {
        field: "avatar_file".to_string(),
    };
    store
        .upsert(
            &hash,
            &nostr_hash,
            None,
            vec![],
            None,
            vec![context.clone()],
        )
        .await
        .expect("first upsert failed");
    let result = store
        .upsert(
            &hash,
            &nostr_hash,
            None,
            vec![],
            None,
            vec![context.clone()],
        )
        .await
        .expect("second upsert failed");
    assert_eq!(result.context.len(), 1);
    assert_eq!(result.context[0], context);
    let stored = store
        .get(&hash)
        .await
        .expect("get failed")
        .expect("file reference missing");
    assert_eq!(stored.context.len(), 1);
}

pub async fn test_add_context_to_nonexistent_record<S>(store: &S)
where
    S: FileReferenceStoreApi + ?Sized,
{
    let hash = test_hash();
    let context = FileReferenceContext::Identity {
        field: "avatar_file".to_string(),
    };
    let added = store
        .add_context(&hash, context)
        .await
        .expect("add_context should not fail");
    assert!(!added, "should not add context to non-existent record");
    assert!(store.get(&hash).await.expect("get failed").is_none());
}
