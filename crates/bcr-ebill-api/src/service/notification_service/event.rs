// Re-export protocol events from bcr-ebill-core
pub use bcr_ebill_core::protocol::{
    BillBlockEvent, BillChainEvent, BillChainEventPayload, ChainInvite, ChainKeys,
    CompanyBlockEvent, CompanyChainEvent, ContactShareEvent, Event, EventEnvelope, EventType,
    IdentityBlockEvent, IdentityChainEvent, ProtocolError,
};

// Re-export for backward compatibility with notification_service Error
use super::Error;

// Convert ProtocolError to notification_service Error
impl From<bcr_ebill_core::protocol::ProtocolError> for Error {
    fn from(e: bcr_ebill_core::protocol::ProtocolError) -> Self {
        Error::Message(e.to_string())
    }
}
