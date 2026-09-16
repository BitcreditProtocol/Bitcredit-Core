use bcr_common::core::NodeId;

/// Represents a resend queue entry fetched from the DB
/// block_height and block_op_code are set for events of chain block types
/// recipient is only set for private messages
#[derive(Debug, Clone)]
pub struct ResendQueueEntry {
    pub id: String,
    pub sender_id: NodeId,
    pub event_type: String,
    pub status: ResendQueueEntryStatus,
    pub recipient: Option<NodeId>,
    pub block_height: Option<usize>,
    pub block_op_code: Option<String>,
}

/// Fetched Resend Queue entries can either be pending being sent, or failed to have been sent
/// since there is no point in showing, or re-queuing re-sent events
#[derive(Debug, Clone)]
pub enum ResendQueueEntryStatus {
    Pending,
    Failed,
}
