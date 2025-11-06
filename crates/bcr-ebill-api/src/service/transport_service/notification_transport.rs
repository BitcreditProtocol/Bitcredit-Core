use super::Result;
use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::{
    ServiceTraitBounds,
    contact::BillParticipant,
    email::Email,
    notification::{ActionType, Notification},
    protocol::{BillChainEventPayload, Event},
    sum::Sum,
    util::BcrKeys,
};
use bcr_ebill_persistence::notification::NotificationFilter;
use std::collections::HashMap;

#[cfg(test)]
use mockall::automock;

/// Allows to sync and manage contacts with the remote transport network
#[allow(dead_code)]
#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait NotificationTransportServiceApi: ServiceTraitBounds {
    /// Returns filtered client notifications
    async fn get_client_notifications(
        &self,
        filter: NotificationFilter,
    ) -> Result<Vec<Notification>>;

    /// Marks the notification with given id as done
    async fn mark_notification_as_done(&self, notification_id: &str) -> Result<()>;

    /// Returns the active bill notification for the given bill id
    async fn get_active_bill_notification(&self, bill_id: &BillId) -> Option<Notification>;

    async fn get_active_bill_notifications(
        &self,
        bill_ids: &[BillId],
    ) -> HashMap<BillId, Notification>;

    async fn get_active_notification_status_for_node_ids(
        &self,
        node_ids: &[NodeId],
    ) -> Result<HashMap<NodeId, bool>>;

    /// In case a participant did not perform an action (e.g. request to accept, request
    /// to pay) in time we notify all bill participants about the timed out action. Will
    /// only send the event if the given action can be a timed out action.
    /// Arguments:
    /// * bill_id: The id of the bill affected
    /// * timed_out_action: The action that has timed out
    /// * recipients: The list of recipients that should receive the notification
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
    ) -> Result<()>;

    /// Returns whether a notification was already sent for the given bill id and action
    async fn check_bill_notification_sent(
        &self,
        bill_id: &BillId,
        block_height: i32,
        action: ActionType,
    ) -> Result<bool>;

    /// Stores that a notification was sent for the given bill id and action
    async fn mark_bill_notification_sent(
        &self,
        bill_id: &BillId,
        block_height: i32,
        action: ActionType,
    ) -> Result<()>;

    /// Register email notifications for the currently selected identity
    async fn register_email_notifications(
        &self,
        relay_url: &url::Url,
        email: &Email,
        node_id: &NodeId,
        caller_keys: &BcrKeys,
    ) -> Result<()>;

    /// Fetch email notifications preferences link for the currently selected identity
    async fn get_email_notifications_preferences_link(&self, node_id: &NodeId) -> Result<url::Url>;

    /// Attempts to send an email notification for an event to the receiver
    /// if the receiver does not have email notifications enabled, the relay
    /// ignores the request and returns a quick 200 OK.
    async fn send_email_notification(
        &self,
        sender: &NodeId,
        receiver: &NodeId,
        event: &Event<BillChainEventPayload>,
    );
}

#[cfg(test)]
impl ServiceTraitBounds for MockNotificationTransportServiceApi {}
