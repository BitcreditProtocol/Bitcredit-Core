use async_trait::async_trait;
use bcr_ebill_core::protocol::Timestamp;
use bitcoin::base58;

use crate::{
    Result,
    tests::tests::node_id_test,
    traits::nostr::{NostrQueuedMessage, NostrQueuedMessageStatus, NostrQueuedMessageStoreApi},
};

pub(crate) const SELECT_MESSAGE: &str = r#"
    SELECT
        id,
        sender_id,
        recipient,
        payload,
        created,
        last_try,
        num_retries,
        max_retries,
        completed,
        failed,
        processing_started_at
    FROM nostr_send_queue
    WHERE id = $1
"#;

#[derive(Debug)]
pub(crate) struct NostrQueuedMessageTestState {
    pub num_retries: i32,
    pub completed: bool,
    pub failed: bool,
    pub processing_started_at: Timestamp,
}

#[async_trait]
pub(crate) trait NostrQueuedMessageStoreTestApi {
    async fn get_state_for_test(&self, id: &str) -> Result<Option<NostrQueuedMessageTestState>>;
    async fn set_processing_started_at_for_test(
        &self,
        id: &str,
        timestamp: Timestamp,
    ) -> Result<()>;
}

fn get_test_message(id: &str) -> NostrQueuedMessage {
    NostrQueuedMessage {
        id: id.to_string(),
        sender_id: node_id_test(),
        recipient: Some(node_id_test()),
        payload: base58::encode(&borsh::to_vec(r#"{"foo": "bar"}"#).unwrap()),
    }
}

pub async fn test_insert_query_and_mark_succeeded<S>(store: &S)
where
    S: NostrQueuedMessageStoreApi + ?Sized,
{
    store
        .add_message(get_test_message("test_message"), 3)
        .await
        .expect("could not add message");
    let messages = store
        .get_retry_messages(1)
        .await
        .expect("could not get messages");
    assert_eq!(messages.len(), 1);
    let messages_empty = store
        .get_retry_messages(1)
        .await
        .expect("could not get messages");
    assert!(
        messages_empty.is_empty(),
        "lease should block immediate retry"
    );
    store
        .succeed_retry(&messages[0].id)
        .await
        .expect("could not mark message as succeeded");
    let messages_done = store
        .get_retry_messages(1)
        .await
        .expect("could not get messages");
    assert!(messages_done.is_empty());
}

pub async fn test_insert_query_and_mark_failed<S>(store: &S)
where
    S: NostrQueuedMessageStoreApi + ?Sized,
{
    store
        .add_message(get_test_message("test_message"), 2)
        .await
        .expect("could not add message");
    let messages = store
        .get_retry_messages(1)
        .await
        .expect("could not get messages");
    assert_eq!(messages.len(), 1);
    let messages_empty = store
        .get_retry_messages(1)
        .await
        .expect("could not get messages");
    assert!(messages_empty.is_empty());
    store
        .fail_retry(&messages[0].id)
        .await
        .expect("could not mark message as failed");
    let messages_failed = store
        .get_retry_messages(1)
        .await
        .expect("could not get failed messages");
    assert_eq!(messages_failed.len(), 1);
    store
        .fail_retry(&messages_failed[0].id)
        .await
        .expect("could not mark message as failed");
    let messages_failed_again = store
        .get_retry_messages(1)
        .await
        .expect("could not get failed messages");
    assert!(
        messages_failed_again.is_empty(),
        "should have exceeded retry limit"
    );
}

pub async fn test_stale_processing_started_at_is_retryable_again<S>(store: &S)
where
    S: NostrQueuedMessageStoreApi + NostrQueuedMessageStoreTestApi + ?Sized,
{
    store
        .add_message(get_test_message("test_message"), 3)
        .await
        .expect("could not add message");
    let messages = store
        .get_retry_messages(1)
        .await
        .expect("could not get messages");
    assert_eq!(messages.len(), 1);
    assert!(
        store
            .get_retry_messages(1)
            .await
            .expect("could not get messages")
            .is_empty()
    );
    store
        .set_processing_started_at_for_test(&messages[0].id, Timestamp::zero())
        .await
        .expect("could not reset stale lease");
    let retried = store
        .get_retry_messages(1)
        .await
        .expect("could not get retried messages");
    assert_eq!(retried.len(), 1);
}

pub async fn test_fail_retry_resets_processing_started_at<S>(store: &S)
where
    S: NostrQueuedMessageStoreApi + NostrQueuedMessageStoreTestApi + ?Sized,
{
    store
        .add_message(get_test_message("test_message"), 3)
        .await
        .unwrap();
    let messages = store.get_retry_messages(1).await.unwrap();
    store.fail_retry(&messages[0].id).await.unwrap();
    let state = store
        .get_state_for_test(&messages[0].id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.processing_started_at, Timestamp::zero());
    assert_eq!(state.num_retries, 1);
    assert_eq!(store.get_retry_messages(1).await.unwrap().len(), 1);
}

pub async fn test_fail_retry_with_more_than_max_retries_fails_the_entry<S>(store: &S)
where
    S: NostrQueuedMessageStoreApi + NostrQueuedMessageStoreTestApi + ?Sized,
{
    store
        .add_message(get_test_message("test_message"), 3)
        .await
        .unwrap();
    let messages = store.get_retry_messages(1).await.unwrap();
    let id = &messages[0].id;
    store.fail_retry(id).await.unwrap();
    store.fail_retry(id).await.unwrap();
    let state = store.get_state_for_test(id).await.unwrap().unwrap();
    assert_eq!(state.num_retries, 2);
    assert!(!state.completed);
    assert!(!state.failed);
    store.fail_retry(id).await.unwrap();
    let state = store.get_state_for_test(id).await.unwrap().unwrap();
    assert_eq!(state.num_retries, 3);
    assert!(state.completed);
    assert!(state.failed);
}

pub async fn test_succeed_retry_resets_processing_started_at<S>(store: &S)
where
    S: NostrQueuedMessageStoreApi + NostrQueuedMessageStoreTestApi + ?Sized,
{
    store
        .add_message(get_test_message("test_message"), 3)
        .await
        .unwrap();
    let messages = store.get_retry_messages(1).await.unwrap();
    store.succeed_retry(&messages[0].id).await.unwrap();
    let state = store
        .get_state_for_test(&messages[0].id)
        .await
        .unwrap()
        .unwrap();
    assert!(state.completed);
    assert_eq!(state.processing_started_at, Timestamp::zero());
}

pub async fn test_succeed_retry_doesnt_set_failed<S>(store: &S)
where
    S: NostrQueuedMessageStoreApi + NostrQueuedMessageStoreTestApi + ?Sized,
{
    store
        .add_message(get_test_message("test_message"), 3)
        .await
        .unwrap();
    let messages = store.get_retry_messages(1).await.unwrap();
    store.succeed_retry(&messages[0].id).await.unwrap();
    let state = store
        .get_state_for_test(&messages[0].id)
        .await
        .unwrap()
        .unwrap();
    assert!(state.completed);
    assert!(!state.failed);
    let remaining = store.get_non_succeeded_retry_messages().await.unwrap();
    assert!(remaining.is_empty());
}

pub async fn test_requeue_failed_entry_resets_entry<S>(store: &S)
where
    S: NostrQueuedMessageStoreApi + NostrQueuedMessageStoreTestApi + ?Sized,
{
    store
        .add_message(get_test_message("test_message"), 1)
        .await
        .unwrap();
    let messages = store.get_retry_messages(1).await.unwrap();
    store.fail_retry(&messages[0].id).await.unwrap();
    let state = store
        .get_state_for_test(&messages[0].id)
        .await
        .unwrap()
        .unwrap();
    assert!(state.completed);
    assert!(state.failed);
    store.requeue_failed_entry(&messages[0].id).await.unwrap();
    let state = store
        .get_state_for_test(&messages[0].id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.num_retries, 0);
    assert!(!state.completed);
    assert!(!state.failed);
    assert_eq!(state.processing_started_at, Timestamp::zero());
    assert_eq!(store.get_retry_messages(1).await.unwrap().len(), 1);
}

pub async fn test_get_non_succeeded_retry_messages<S>(store: &S)
where
    S: NostrQueuedMessageStoreApi + ?Sized,
{
    store
        .add_message(get_test_message("test_message_succeed"), 1)
        .await
        .unwrap();
    store
        .add_message(get_test_message("test_message_fail"), 1)
        .await
        .unwrap();
    let messages = store.get_non_succeeded_retry_messages().await.unwrap();
    assert_eq!(messages.len(), 2);
    assert!(matches!(messages[0].1, NostrQueuedMessageStatus::Pending));
    assert!(matches!(messages[1].1, NostrQueuedMessageStatus::Pending));
    store.succeed_retry(&messages[0].0.id).await.unwrap();
    let messages = store.get_non_succeeded_retry_messages().await.unwrap();
    assert_eq!(messages.len(), 1);
    assert!(matches!(messages[0].1, NostrQueuedMessageStatus::Pending));
    store.fail_retry(&messages[0].0.id).await.unwrap();
    let messages = store.get_non_succeeded_retry_messages().await.unwrap();
    assert_eq!(messages.len(), 1);
    assert!(matches!(messages[0].1, NostrQueuedMessageStatus::Failed));
    store.requeue_failed_entry(&messages[0].0.id).await.unwrap();
    let messages = store.get_non_succeeded_retry_messages().await.unwrap();
    assert_eq!(messages.len(), 1);
    assert!(matches!(messages[0].1, NostrQueuedMessageStatus::Pending));
}
