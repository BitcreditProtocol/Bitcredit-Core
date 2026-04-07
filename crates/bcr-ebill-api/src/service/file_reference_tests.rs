use crate::service::file_reference_helper::{
    bill_file_context, company_file_context, contact_file_context, identity_file_context,
    upsert_important_file_reference,
};
use crate::tests::tests::MockFileReferenceStoreApiMock;
use bcr_common::core::NodeId;
use bcr_ebill_core::protocol::{File, Name, Sha256Hash};
use mockall::predicate;
use std::str::FromStr;
use std::sync::Arc;

fn test_file() -> File {
    File {
        name: Name::new("test_file.txt").unwrap(),
        hash: Sha256Hash::new("test_hash_12345678901234567890123456789012"),
        nostr_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .parse()
            .unwrap(),
    }
}

fn test_node_id() -> NodeId {
    NodeId::from_str("bitcrt02295fb5f4eeb2f21e01eaf3a2d9a3be10f39db870d28f02146130317973a40ac0")
        .unwrap()
}

fn create_mock_store() -> Arc<dyn bcr_ebill_persistence::FileReferenceStoreApi> {
    let mut mock_store = MockFileReferenceStoreApiMock::new();

    mock_store
        .expect_upsert()
        .with(
            predicate::always(),
            predicate::always(),
            predicate::always(),
            predicate::always(),
            predicate::eq(Some(true)),
            predicate::always(),
        )
        .returning(|hash, nostr_hash, name, _, _, _context| {
            Ok(
                bcr_ebill_core::protocol::file_reference::FileReference::new(
                    hash.clone(),
                    *nostr_hash,
                    name,
                ),
            )
        });

    Arc::new(mock_store)
}

fn test_server_urls() -> Vec<url::Url> {
    vec![url::Url::parse("https://blossom.example.com").unwrap()]
}

#[tokio::test]
async fn important_file_upsert_identity_file() {
    let file = test_file();
    let mock_store = create_mock_store();

    let result = upsert_important_file_reference(
        &mock_store,
        &file,
        identity_file_context("profile_picture_file"),
        test_server_urls(),
    )
    .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn important_file_upsert_company_file() {
    let file = test_file();
    let company_id = test_node_id();
    let mock_store = create_mock_store();

    let result = upsert_important_file_reference(
        &mock_store,
        &file,
        company_file_context(&company_id, "logo_file"),
        test_server_urls(),
    )
    .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn important_file_upsert_contact_file() {
    let file = test_file();
    let node_id = test_node_id();
    let mock_store = create_mock_store();

    let result = upsert_important_file_reference(
        &mock_store,
        &file,
        contact_file_context(&node_id, "avatar_file"),
        test_server_urls(),
    )
    .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn important_file_upsert_bill_file() {
    let file = test_file();
    let mock_store = create_mock_store();

    let result = upsert_important_file_reference(
        &mock_store,
        &file,
        bill_file_context("bill123", "attachment_0"),
        test_server_urls(),
    )
    .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn important_file_upsert_marks_as_important() {
    let file = test_file();
    let mut mock_store = MockFileReferenceStoreApiMock::new();

    mock_store
        .expect_upsert()
        .with(
            predicate::always(),
            predicate::always(),
            predicate::always(),
            predicate::always(),
            predicate::eq(Some(true)),
            predicate::always(),
        )
        .returning(|hash, nostr_hash, name, _, _, _| {
            Ok(
                bcr_ebill_core::protocol::file_reference::FileReference::new(
                    hash.clone(),
                    *nostr_hash,
                    name,
                ),
            )
        })
        .once();

    let mock_store: Arc<dyn bcr_ebill_persistence::FileReferenceStoreApi> = Arc::new(mock_store);

    let result = upsert_important_file_reference(
        &mock_store,
        &file,
        identity_file_context("identity_document_file"),
        test_server_urls(),
    )
    .await;

    assert!(result.is_ok());
}
