use crate::{tests::tests::node_id_test, traits::notification::EmailNotificationStoreApi};

pub async fn test_email_preferences_link<S>(store: &S)
where
    S: EmailNotificationStoreApi + ?Sized,
{
    let node_id = node_id_test();

    let link_before = store
        .get_email_preferences_link_for_node_id(&node_id)
        .await
        .expect("can fetch empty link if it is not set");

    assert!(link_before.is_none());

    let first_link = url::Url::parse("https://www.bit.cr/").unwrap();

    store
        .add_email_preferences_link_for_node_id(&first_link, &node_id)
        .await
        .unwrap();

    let link = store
        .get_email_preferences_link_for_node_id(&node_id)
        .await
        .expect("can fetch link after it was set");

    assert_eq!(link, Some(first_link));
}
