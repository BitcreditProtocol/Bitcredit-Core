use super::Result;
use crate::data::{IntoWeb, NotificationWeb, SuccessResponse};
use crate::service_context::ServiceContext;
use bcr_ebill_api::NotificationFilter;
use bcr_ebill_api::data::notification::Notification;
use rocket::response::stream::{Event, EventStream};
use rocket::serde::json::Json;
use rocket::{State, get, post};
use rocket_ws::{Message, Stream, WebSocket};
use serde_json::Value;

#[utoipa::path(
    tag = "Notifications",
    description = "Get all active notifications",
    responses(
        (status = 200, description = "List of notifications", body = Vec<NotificationWeb>)
    ),
    params(
        ("active" = Option<bool>, Query, description = "Returns only active notifications when true, inactive when false and all when left out"),
        ("reference_id" = Option<String>, Query, description = "The id of the entity to filter by (eg. a bill id)"),
        ("notification_type" = Option<String>, Query, description = "The type of notifications to return (eg. Bill)"),
        ("node_id" = Option<String>, Query, description = "The node_id of the identity for which to query notifications"),
        ("limit" = Option<i64>, Query, description = "The max number of notifications to return"),
        ("offset" = Option<i64>, Query, description = "The number of notifications to skip at the start of the result")
    )
)]
#[get("/notifications?<active>&<reference_id>&<notification_type>&<limit>&<offset>&<node_ids>")]
pub async fn list_notifications(
    state: &State<ServiceContext>,
    active: Option<bool>,
    reference_id: Option<String>,
    notification_type: Option<String>,
    node_ids: Option<Vec<String>>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Json<Vec<NotificationWeb>>> {
    //let node_ids = node_id.map(|id| vec![id]).unwrap_or_default();
    let notifications: Vec<Notification> = state
        .notification_service
        .get_client_notifications(NotificationFilter {
            active,
            reference_id,
            notification_type,
            node_ids: node_ids.unwrap_or_default(),
            limit,
            offset,
        })
        .await?;
    Ok(Json(
        notifications.into_iter().map(|n| n.into_web()).collect(),
    ))
}

#[utoipa::path(
    tag = "Notifications",
    description = "Marks a notification as done",
    params(
        ("notification_id" = String, description = "Id of the notification to marks as done")
    ),
    responses(
        (status = 200, description = "Notification set to done")
    )
)]
#[post("/notifications/<notification_id>/done")]
pub async fn mark_notification_done(
    state: &State<ServiceContext>,
    notification_id: &str,
) -> Result<Json<SuccessResponse>> {
    state
        .notification_service
        .mark_notification_as_done(notification_id)
        .await?;
    Ok(Json(SuccessResponse::new()))
}

#[utoipa::path(
    tag = "Push notifications",
    description = "Subscribe to push notifications via websocket",
    responses(
        (status = 101, description = "Switching protocols. Instructs the browser to open the WS connection")
    )
)]
#[get("/subscribe/websocket")]
pub fn websocket(state: &State<ServiceContext>, _ws: WebSocket) -> Stream!['_] {
    Stream! { _ws =>
        let mut receiver = state.push_service.subscribe().await;
        loop {
            if let Ok(message) = receiver.recv().await {
                yield Message::text(message.to_string());
            }
        }
    }
}

#[utoipa::path(
    tag = "Push notifications",
    description = "subscribe to push notifications via server sent events (SSE)",
    responses(
        (status = 200, description = "Effectively there will never be a real response as this will open an infinite stream of events.")
    )
)]
#[get("/subscribe/sse")]
pub async fn sse(state: &State<ServiceContext>) -> EventStream![Event + '_] {
    EventStream! {
        let mut receiver = state.push_service.subscribe().await;
        loop {
            if let Ok(message) = receiver.recv().await {
                yield Event::data(message.to_string());
            }
        }
    }
}

#[post("/send_sse", format = "json", data = "<msg>")]
pub async fn trigger_msg(
    state: &State<ServiceContext>,
    msg: Json<Value>,
) -> Result<Json<SuccessResponse>> {
    state
        .push_service
        .send(serde_json::to_value(msg.into_inner()).unwrap())
        .await;
    Ok(Json(SuccessResponse::new()))
}
