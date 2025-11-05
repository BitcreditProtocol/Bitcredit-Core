use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

pub mod bill_events;
pub mod blockchain_event;
pub mod company_events;
pub mod identity_events;

pub use bill_events::{ActionType, BillChainEvent, BillChainEventPayload, BillEventType};
pub use blockchain_event::{
    BillBlockEvent, ChainInvite, ChainKeys, CompanyBlockEvent, IdentityBlockEvent,
};
pub use company_events::CompanyChainEvent;
pub use identity_events::IdentityChainEvent;

use crate::protocol::{ProtocolError, Result};

/// The global event type that is used for all events.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub enum EventType {
    /// Private Bill related events
    Bill,
    /// Public Bill chain events
    BillChain,
    /// Private Bill invites with keys
    BillChainInvite,
    /// Public identity events
    IdentityChain,
    /// Public company chain events
    CompanyChain,
    /// Private company invites with keys
    CompanyChainInvite,
    /// Share private company or identity contact details
    ContactShare,
}

impl EventType {
    pub fn all() -> Vec<EventType> {
        vec![
            EventType::Bill,
            EventType::BillChain,
            EventType::BillChainInvite,
            EventType::IdentityChain,
            EventType::CompanyChain,
            EventType::CompanyChainInvite,
            EventType::ContactShare,
        ]
    }
}

impl Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A generic event that can be sent to a specific recipient
/// and is serializable.
/// This event should contain all the information that is needed
/// to send to different channels including email, push and Nostr.
#[derive(Debug, Clone, BorshSerialize)]
pub struct Event<T: BorshSerialize> {
    pub event_type: EventType,
    pub version: String,
    pub data: T,
}

impl<T: BorshSerialize> Event<T> {
    pub fn new(event_type: EventType, data: T) -> Self {
        Self {
            event_type: event_type.to_owned(),
            version: get_version(&event_type),
            data,
        }
    }

    pub fn new_bill(data: T) -> Self {
        Self::new(EventType::Bill, data)
    }

    pub fn new_bill_chain(data: T) -> Self {
        Self::new(EventType::BillChain, data)
    }

    pub fn new_identity_chain(data: T) -> Self {
        Self::new(EventType::IdentityChain, data)
    }

    pub fn new_company_chain(data: T) -> Self {
        Self::new(EventType::CompanyChain, data)
    }

    pub fn new_bill_invite(data: T) -> Self {
        Self::new(EventType::BillChainInvite, data)
    }
    pub fn new_company_invite(data: T) -> Self {
        Self::new(EventType::CompanyChainInvite, data)
    }

    pub fn new_contact_share(data: T) -> Self {
        Self::new(EventType::ContactShare, data)
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
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct EventEnvelope {
    pub event_type: EventType,
    pub version: String,
    pub data: Vec<u8>,
}

impl<T: BorshSerialize> TryFrom<Event<T>> for EventEnvelope {
    type Error = ProtocolError;

    fn try_from(event: Event<T>) -> Result<Self> {
        let serialized = &borsh::to_vec(&event.data)?;
        Ok(Self {
            event_type: event.event_type,
            version: event.version,
            data: serialized.to_vec(),
        })
    }
}

/// Allows generic deserialization of an event from an envelope.
/// # Example
///
/// ```
/// use borsh::{BorshDeserialize, BorshSerialize};
/// use bcr_ebill_transport::{EventType, Event, EventEnvelope};
///
/// #[derive(BorshSerialize, BorshDeserialize)]
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
/// let event = Event::new(EventType::Bill, "recipient", payload);
/// let event: EventEnvelope = event.try_into().unwrap();
/// let deserialized_event: Event<MyEventPayload> = event.try_into().unwrap();
///
/// ```
///
impl<T: BorshDeserialize + BorshSerialize> TryFrom<EventEnvelope> for Event<T> {
    type Error = ProtocolError;
    fn try_from(envelope: EventEnvelope) -> Result<Self> {
        let data: T = borsh::from_slice(&envelope.data)?;
        Ok(Self {
            event_type: envelope.event_type,
            version: envelope.version,
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
        let event = Event::new(EventType::Bill, payload.clone());
        // create envelope
        let envelope: EventEnvelope = event.clone().try_into().unwrap();

        // check that the envelope is correct
        assert_eq!(
            &event.event_type, &envelope.event_type,
            "envelope has wrong event type"
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
    }

    #[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
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
