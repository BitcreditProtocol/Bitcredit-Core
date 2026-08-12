use std::{str::FromStr, sync::Arc};

use crate::ffi::{
    api::identity::get_current_identity_node_id,
    context::get_ctx,
    data::{
        NotificationFiltersFfi,
        notification::{NotificationFfi, NotificationStatusFfi},
    },
    error::EbillFfiError,
};
use bcr_common::core::NodeId;
use bcr_ebill_core::protocol::ProtocolValidationError;
use bcr_ebill_persistence::notification::NotificationFilter;
use flutter_rust_bridge::{DartFnFuture, frb};
use log::info;

#[frb]
pub async fn active_notifications_for_node_ids(
    node_ids: Vec<String>,
) -> Result<Vec<NotificationStatusFfi>, EbillFfiError> {
    let node_ids_parsed: Vec<NodeId> = node_ids
        .into_iter()
        .map(|n| NodeId::from_str(&n))
        .collect::<Result<_, _>>()
        .map_err(ProtocolValidationError::from)?;
    let notification_status = get_ctx()
        .await
        .transport_service
        .notification_transport()
        .get_active_notification_status_for_node_ids(&node_ids_parsed)
        .await?;
    let web: Vec<NotificationStatusFfi> = notification_status
        .into_iter()
        .map(|(node_id, active)| NotificationStatusFfi {
            node_id: node_id.to_string(),
            active,
        })
        .collect();
    Ok(web)
}

#[derive(Debug, Clone)]
pub struct NotificationSubscriptionResponse {
    pub value: String,
}

pub type NotificationSubscriptionCb = Arc<dyn Fn(String) + Send + Sync + 'static>;

#[frb]
pub async fn subscribe(
    callback: impl Fn(NotificationSubscriptionResponse) -> DartFnFuture<()> + Send + Sync + 'static,
) {
    let dart_callback = Arc::new(callback);
    let callback: NotificationSubscriptionCb = Arc::new(move |v| {
        let dart_callback = dart_callback.clone();
        flutter_rust_bridge::spawn(async move {
            let _ = dart_callback(NotificationSubscriptionResponse {
                value: v.to_string(),
            })
            .await;
        });
    });

    flutter_rust_bridge::spawn(async move {
        info!("Subscribed to notifications");
        let mut receiver = get_ctx().await.push_service.subscribe().await;
        while let Ok(msg) = receiver.recv().await {
            callback(msg.to_string());
        }
    });
}

#[frb]
pub async fn list(filters: NotificationFiltersFfi) -> Result<Vec<NotificationFfi>, EbillFfiError> {
    let filter = NotificationFilter::try_from(filters)?;

    let notifications = get_ctx()
        .await
        .transport_service
        .notification_transport()
        .get_client_notifications(filter)
        .await?;

    let web: Vec<NotificationFfi> = notifications.into_iter().map(|n| n.into()).collect();
    Ok(web)
}

#[frb]
pub async fn mark_as_done(notification_id: &str) -> Result<(), EbillFfiError> {
    get_ctx()
        .await
        .transport_service
        .notification_transport()
        .mark_notification_as_done(notification_id)
        .await?;
    Ok(())
}

#[frb]
/// Fetch email notifications preferences link for the currently selected identity
pub async fn get_email_notifications_preferences_link() -> Result<String, EbillFfiError> {
    let preferences_link = get_ctx()
        .await
        .transport_service
        .notification_transport()
        .get_email_notifications_preferences_link(&get_current_identity_node_id().await?)
        .await?;
    Ok(preferences_link.to_string())
}
