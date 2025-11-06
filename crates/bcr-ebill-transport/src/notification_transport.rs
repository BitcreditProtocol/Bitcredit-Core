use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};

use bcr_ebill_api::external::email::EmailClientApi;
use bcr_ebill_api::service::transport_service::NotificationTransportServiceApi;
use bcr_ebill_api::service::transport_service::{Error, Result};
use bcr_ebill_api::util::{validate_bill_id_network, validate_node_id_network};
use bcr_ebill_core::ServiceTraitBounds;
use bcr_ebill_core::notification::{ActionType, Notification, NotificationType};
use bcr_ebill_core::{
    contact::BillParticipant,
    email::Email,
    protocol::{BillChainEventPayload, Event},
    sum::Sum,
    util::BcrKeys,
};
use bcr_ebill_persistence::NotificationStoreApi;
use bcr_ebill_persistence::notification::{EmailNotificationStoreApi, NotificationFilter};
use log::{error, warn};

use crate::NostrTransportService;

pub struct NotificationTransportService {
    nostr_transport: Arc<NostrTransportService>,
    notification_store: Arc<dyn NotificationStoreApi>,
    email_notification_store: Arc<dyn EmailNotificationStoreApi>,
    email_client: Arc<dyn EmailClientApi>,
}

impl NotificationTransportService {
    pub fn new(
        nostr_transport: Arc<NostrTransportService>,
        notification_store: Arc<dyn NotificationStoreApi>,
        email_notification_store: Arc<dyn EmailNotificationStoreApi>,
        email_client: Arc<dyn EmailClientApi>,
    ) -> Self {
        Self {
            nostr_transport,
            notification_store,
            email_notification_store,
            email_client,
        }
    }
}

impl ServiceTraitBounds for NotificationTransportService {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationTransportServiceApi for NotificationTransportService {
    async fn get_client_notifications(
        &self,
        filter: NotificationFilter,
    ) -> Result<Vec<Notification>> {
        for node_id in filter.node_ids.iter() {
            validate_node_id_network(node_id)?;
        }
        let result = self.notification_store.list(filter).await.map_err(|e| {
            error!("Failed to get client notifications: {e}");
            Error::Persistence("Failed to get client notifications".to_string())
        })?;
        Ok(result)
    }

    async fn mark_notification_as_done(&self, notification_id: &str) -> Result<()> {
        let _ = self
            .notification_store
            .mark_as_done(notification_id)
            .await
            .map_err(|e| {
                error!("Failed to mark notification as done: {e}");
                Error::Persistence("Failed to mark notification as done".to_string())
            })?;
        Ok(())
    }

    async fn get_active_bill_notification(&self, bill_id: &BillId) -> Option<Notification> {
        validate_bill_id_network(bill_id).ok()?;
        self.notification_store
            .get_latest_by_reference(&bill_id.to_string(), NotificationType::Bill)
            .await
            .unwrap_or_default()
    }

    async fn get_active_bill_notifications(
        &self,
        bill_ids: &[BillId],
    ) -> HashMap<BillId, Notification> {
        let ids: Vec<String> = bill_ids.iter().map(|bill_id| bill_id.to_string()).collect();
        let refs = self
            .notification_store
            .get_latest_by_references(&ids, NotificationType::Bill)
            .await
            .unwrap_or_default();
        refs.into_iter()
            .filter_map(|(key, value)| match BillId::from_str(&key) {
                Ok(bill_id) => Some((bill_id, value)),
                Err(_) => None,
            })
            .collect()
    }

    async fn get_active_notification_status_for_node_ids(
        &self,
        node_ids: &[NodeId],
    ) -> Result<HashMap<NodeId, bool>> {
        Ok(self
            .notification_store
            .get_active_status_for_node_ids(node_ids)
            .await
            .unwrap_or_default())
    }

    async fn send_request_to_action_timed_out_event(
        &self,
        sender_node_id: &NodeId,
        bill_id: &BillId,
        sum: Option<Sum>,
        timed_out_action: ActionType,
        recipients: Vec<BillParticipant>,
        holder: &NodeId,
        drawee: &NodeId,
        recoursee: &Option<NodeId>,
    ) -> Result<()> {
        if let Some(node) = self
            .nostr_transport
            .get_node_transport(sender_node_id)
            .await
            && let Some(event_type) = timed_out_action.get_timeout_event_type()
        {
            // only send to a recipient once
            let unique: HashMap<NodeId, BillParticipant> =
                HashMap::from_iter(recipients.iter().map(|r| (r.node_id().clone(), r.clone())));

            let payload = BillChainEventPayload {
                event_type,
                bill_id: bill_id.to_owned(),
                action_type: Some(ActionType::CheckBill),
                sum,
            };
            for (_, recipient) in unique {
                let event = Event::new_bill(payload.clone());
                node.send_private_event(&recipient, event.clone().try_into()?)
                    .await?;

                // Only send email to holder, and only if we are drawee, or recoursee
                if let Some(r) = recoursee {
                    if sender_node_id == r {
                        self.send_email_notification(sender_node_id, holder, &event)
                            .await;
                    }
                } else if sender_node_id == drawee {
                    self.send_email_notification(sender_node_id, holder, &event)
                        .await;
                }
            }
        }
        Ok(())
    }

    async fn check_bill_notification_sent(
        &self,
        bill_id: &BillId,
        block_height: i32,
        action: ActionType,
    ) -> Result<bool> {
        validate_bill_id_network(bill_id)?;
        Ok(self
            .notification_store
            .bill_notification_sent(bill_id, block_height, action)
            .await
            .map_err(|e| {
                error!("Failed to check if bill notification was already sent: {e}");
                Error::Persistence(
                    "Failed to check if bill notification was already sent".to_string(),
                )
            })?)
    }

    /// Stores that a notification was sent for the given bill id and action
    async fn mark_bill_notification_sent(
        &self,
        bill_id: &BillId,
        block_height: i32,
        action: ActionType,
    ) -> Result<()> {
        validate_bill_id_network(bill_id)?;
        self.notification_store
            .set_bill_notification_sent(bill_id, block_height, action)
            .await
            .map_err(|e| {
                error!("Failed to mark bill notification as sent: {e}");
                Error::Persistence("Failed to mark bill notification as sent".to_string())
            })?;
        Ok(())
    }

    /// Register email notifications for the currently selected identity
    async fn register_email_notifications(
        &self,
        relay_url: &url::Url,
        email: &Email,
        node_id: &NodeId,
        caller_keys: &BcrKeys,
    ) -> Result<()> {
        let challenge = self.email_client.start(relay_url, node_id).await?;

        let preferences_link = self
            .email_client
            .register(
                relay_url,
                email,
                caller_keys.get_nostr_keys().secret_key(),
                &challenge,
            )
            .await?;
        self.email_notification_store
            .add_email_preferences_link_for_node_id(&preferences_link, node_id)
            .await
            .map_err(|e| Error::Persistence(e.to_string()))?;
        Ok(())
    }

    /// Fetch email notifications preferences link for the currently selected identity
    async fn get_email_notifications_preferences_link(&self, node_id: &NodeId) -> Result<url::Url> {
        match self
            .email_notification_store
            .get_email_preferences_link_for_node_id(node_id)
            .await
        {
            Ok(Some(link)) => Ok(link),
            Ok(None) => Err(Error::NotFound),
            Err(e) => Err(Error::Persistence(e.to_string())),
        }
    }

    /// Attempts to send an email notification for an event to the receiver
    /// if the receiver does not have email notifications enabled, the relay
    /// ignores the request and returns a quick 200 OK.
    async fn send_email_notification(
        &self,
        sender: &NodeId,
        receiver: &NodeId,
        event: &Event<BillChainEventPayload>,
    ) {
        if let Some(node) = self.nostr_transport.get_node_transport(sender).await {
            if let Some(identity) = self.nostr_transport.resolve_identity(receiver).await {
                // TODO(multi-relay): don't default to first, but to notification relay of receiver
                if let Some(nostr_relay) = identity.nostr_relays().first() {
                    // send asynchronously and don't fail on error
                    let email_client = self.email_client.clone();
                    let relay_clone = nostr_relay.clone();
                    let rcv_clone = receiver.clone();
                    let private_key = node.get_sender_keys().get_nostr_keys().secret_key().clone();
                    let evt_clone = event.clone();
                    if let Err(e) = email_client
                        .send_bill_notification(
                            &relay_clone,
                            evt_clone.data.event_type.to_owned(),
                            &evt_clone.data.bill_id,
                            &rcv_clone,
                            &private_key,
                        )
                        .await
                    {
                        warn!("Failed to send email notification: {e}");
                    }
                }
            } else {
                warn!("Failed to find recipient in contacts for node_id: {receiver}");
            }
        } else {
            warn!("No transport node found for sender node_id: {sender}");
        }
    }
}
