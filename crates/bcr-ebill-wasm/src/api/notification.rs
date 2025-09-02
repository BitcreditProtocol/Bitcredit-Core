use super::Result;
use crate::{
    api::{bill::get_signer_public_data_and_keys, identity::get_current_identity_node_id},
    context::get_ctx,
    data::{
        NotificationFilters,
        notification::{NotificationStatusWeb, NotificationWeb},
    },
};
use bcr_ebill_api::{
    NotificationFilter,
    data::NodeId,
    service::Error,
    util::{Field, ValidationError},
};
use log::{error, info};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Notification;

#[wasm_bindgen]
impl Notification {
    #[wasm_bindgen]
    pub fn new() -> Self {
        Notification
    }

    #[wasm_bindgen(unchecked_return_type = "NotificationStatusWeb[]")]
    pub async fn active_notifications_for_node_ids(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Vec<String>")] node_ids: JsValue,
    ) -> Result<JsValue> {
        let node_ids_parsed: Vec<NodeId> = serde_wasm_bindgen::from_value(node_ids)?;
        let notification_status = get_ctx()
            .notification_service
            .get_active_notification_status_for_node_ids(&node_ids_parsed)
            .await?;
        let web: Vec<NotificationStatusWeb> = notification_status
            .into_iter()
            .map(|(node_id, active)| NotificationStatusWeb { node_id, active })
            .collect();
        let res = serde_wasm_bindgen::to_value(&web)?;
        Ok(res)
    }

    #[wasm_bindgen]
    pub async fn subscribe(&self, callback: js_sys::Function) {
        wasm_bindgen_futures::spawn_local(async move {
            info!("Subscribed to notifications");
            let mut receiver = get_ctx().push_service.subscribe().await;
            while let Ok(msg) = receiver.recv().await {
                match serde_wasm_bindgen::to_value(&msg) {
                    Ok(event) => {
                        if let Err(e) = callback.call1(&JsValue::NULL, &event) {
                            error!("Error while sending notification: {e:?}");
                        }
                    }
                    Err(e) => {
                        error!("Error while serializing notification: {e}");
                    }
                }
            }
        });
    }

    #[wasm_bindgen(unchecked_return_type = "NotificationWeb[]")]
    pub async fn list(
        &self,
        #[wasm_bindgen(unchecked_param_type = "NotificationFilters")] filters: JsValue,
    ) -> Result<JsValue> {
        let filter = NotificationFilter::from(
            serde_wasm_bindgen::from_value::<NotificationFilters>(filters)
                .ok()
                .unwrap_or_default(),
        );

        let notifications = get_ctx()
            .notification_service
            .get_client_notifications(filter)
            .await?;

        let web: Vec<NotificationWeb> = notifications.into_iter().map(|n| n.into()).collect();
        let res = serde_wasm_bindgen::to_value(&web)?;
        Ok(res)
    }

    #[wasm_bindgen]
    pub async fn mark_as_done(&self, notification_id: &str) -> Result<()> {
        get_ctx()
            .notification_service
            .mark_notification_as_done(notification_id)
            .await?;
        Ok(())
    }

    #[wasm_bindgen]
    /// Register email notifications for the currently selected identity
    pub async fn register_email_notifications(&self, relay_url: &str) -> Result<()> {
        let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;

        // check if the given relay URL is one of the current selected identity's relays
        if !caller_public_data
            .nostr_relays()
            .iter()
            .any(|nr| nr == relay_url)
        {
            return Err(Error::Validation(ValidationError::InvalidRelayUrl).into());
        }

        // check if there is an email set
        let email = caller_public_data
            .email()
            .ok_or(Error::Validation(ValidationError::FieldEmpty(Field::Email)))?;

        get_ctx()
            .notification_service
            .register_email_notifications(
                relay_url,
                &email,
                &caller_public_data.node_id(),
                &caller_keys,
            )
            .await?;
        Ok(())
    }

    #[wasm_bindgen]
    /// Fetch email notifications preferences link for the currently selected identity
    pub async fn get_email_notifications_preferences_link(&self) -> Result<String> {
        let preferences_link = get_ctx()
            .notification_service
            .get_email_notifications_preferences_link(&get_current_identity_node_id().await?)
            .await?;
        Ok(preferences_link.to_string())
    }

    #[wasm_bindgen]
    pub async fn trigger_test_msg(&self, payload: JsValue) -> Result<()> {
        let msg: serde_json::Value = serde_wasm_bindgen::from_value(payload)?;
        get_ctx()
            .push_service
            .send(serde_json::to_value(msg).unwrap())
            .await;
        Ok(())
    }
}

impl Default for Notification {
    fn default() -> Self {
        Notification
    }
}
