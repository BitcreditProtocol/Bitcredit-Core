pub mod bill_events;
pub mod chain_event;

use crate::{Error, Result};
use bcr_ebill_core::notification::EventType;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

/// A generic event that can be sent to a specific recipient
/// and is serializable. The recipient is currently just a string,
/// and we have to decide what the identifier is.
/// This event should contain all the information that is needed
/// to send to different channels including email, push and Nostr.
#[derive(Serialize, Debug, Clone)]
pub struct Event<T: Serialize> {
    pub event_type: EventType,
    pub version: String,
    pub node_id: String,
    pub data: T,
}

impl<T: Serialize> Event<T> {
    #[allow(dead_code)]
    pub fn new(event_type: EventType, node_id: &str, data: T) -> Self {
        Self {
            event_type: event_type.to_owned(),
            version: get_version(&event_type),
            node_id: node_id.to_owned(),
            data,
        }
    }
}

/// The event version that is used for all events if no specific version
/// is set via get_version.
const DEFAULT_EVENT_VERSION: &str = "1.0";

/// If we want to bump the version of a single event type, we can do so
/// by matching the event type and returning the new version here.
fn get_version(_event_type: &EventType) -> String {
    DEFAULT_EVENT_VERSION.into()
}

/// When we receive an event, we need to know what type it is and
/// how to handle it. This payload envelope allows us to find out
/// the type of event to later deserialize the data into the correct
/// type.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EventEnvelope {
    pub event_type: EventType,
    pub version: String,
    pub node_id: String,
    pub data: Value,
}

impl<T: Serialize> TryFrom<Event<T>> for EventEnvelope {
    type Error = Error;

    fn try_from(event: Event<T>) -> Result<Self> {
        Ok(Self {
            event_type: event.event_type,
            version: event.version,
            node_id: event.node_id,
            data: serde_json::to_value(event.data)?,
        })
    }
}

/// Allows generic deserialization of an event from an envelope.
/// # Example
///
/// ```ignore
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct MyEventPayload {
///     foo: String,
///     bar: u32,
/// }
///
/// let payload = MyEventPayload {
///     foo: "foo".to_string(),
///     bar: 42,
/// };
///
/// let event = Event::new(EventType::BillSigned, "recipient".to_string(), payload);
/// let event: EventEnvelope = event.try_into().unwrap();
/// let deserialized_event: Event<MyEventPayload> = event.try_into().unwrap();
/// assert_eq!(deserialized_event.data, payload);
///
/// ```
///
impl<T: DeserializeOwned + Serialize> TryFrom<EventEnvelope> for Event<T> {
    type Error = Error;
    fn try_from(envelope: EventEnvelope) -> Result<Self> {
        let data: T = serde_json::from_value(envelope.data)?;
        Ok(Self {
            event_type: envelope.event_type,
            version: envelope.version,
            node_id: envelope.node_id,
            data,
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_event_serialization() {
        // give payload
        let payload = create_test_event_payload();
        // create event
        let event = Event::new(EventType::BillSigned, "node_id", payload.clone());
        // create envelope
        let envelope: EventEnvelope = event.clone().try_into().unwrap();

        // check that the envelope is correct
        assert_eq!(
            &event.event_type, &envelope.event_type,
            "envelope has wrong event type"
        );
        assert_eq!(
            &event.node_id, &envelope.node_id,
            "envelope has wrong node id"
        );

        // check that the deserialization works
        let deserialized_event: Event<TestEventPayload> = envelope.try_into().unwrap();
        assert_eq!(
            &deserialized_event.data, &payload,
            "payload was not deserialized correctly"
        );
        assert_eq!(
            &deserialized_event.event_type, &event.event_type,
            "deserialized event has wrong event type"
        );
        assert_eq!(
            &deserialized_event.node_id, &event.node_id,
            "deserialized event has wrong node id"
        );
    }

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
    pub struct TestEventPayload {
        pub foo: String,
        pub bar: u32,
    }

    pub fn create_test_event_payload() -> TestEventPayload {
        TestEventPayload {
            foo: "foo".to_string(),
            bar: 42,
        }
    }
}
