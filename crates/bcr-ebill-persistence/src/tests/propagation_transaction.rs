use crate::traits::propagation::{
    PreparedPropagation, PreparedPropagationMessage, PropagationSubjectType,
};
use bcr_ebill_core::protocol::{Sha256Hash, Timestamp, event::EventType};
use nostr::event::{EventBuilder, FinalizeEvent, Kind};
use nostr::key::Keys;

pub fn sample_propagation() -> PreparedPropagation {
    let event = EventBuilder::new(Kind::TextNote, "test block")
        .finalize(&Keys::generate())
        .unwrap();
    PreparedPropagation {
        id: uuid::Uuid::new_v4().to_string(),
        subject_type: PropagationSubjectType::Bill,
        subject_id: "test-bill".to_owned(),
        created_at: Timestamp::now(),
        messages: vec![PreparedPropagationMessage {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::BillChain,
            recipient_id: None,
            chain_id: Some("test-bill".to_owned()),
            block_hash: Some(Sha256Hash::new("test-block")),
            event,
            target_relays: vec![
                url::Url::parse("wss://relay-a.example").unwrap(),
                url::Url::parse("wss://relay-b.example").unwrap(),
            ],
        }],
    }
}
