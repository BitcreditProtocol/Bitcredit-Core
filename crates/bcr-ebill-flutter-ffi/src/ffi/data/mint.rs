use bcr_ebill_core::protocol::mint::{MintOffer, MintRequest, MintRequestState, MintRequestStatus};

#[derive(Debug, Clone)]
pub struct MintRequestFfi {
    pub requester_node_id: String,
    pub bill_id: String,
    pub mint_node_id: String,
    pub mint_request_id: String,
    pub timestamp: u64,
    pub status: MintRequestStatusFfi,
}

impl From<MintRequest> for MintRequestFfi {
    fn from(val: MintRequest) -> Self {
        MintRequestFfi {
            requester_node_id: val.requester_node_id.to_string(),
            bill_id: val.bill_id.to_string(),
            mint_node_id: val.mint_node_id.to_string(),
            mint_request_id: val.mint_request_id.to_string(),
            timestamp: val.timestamp.inner(),
            status: val.status.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum MintRequestStatusFfi {
    Pending,
    Denied { timestamp: u64 },
    Offered,
    Accepted,
    MintingEnabled,
    Rejected { timestamp: u64 },
    Cancelled { timestamp: u64 },
    Expired { timestamp: u64 },
}
impl From<MintRequestStatus> for MintRequestStatusFfi {
    fn from(val: MintRequestStatus) -> Self {
        match val {
            MintRequestStatus::Pending => MintRequestStatusFfi::Pending,
            MintRequestStatus::Denied { timestamp } => MintRequestStatusFfi::Denied {
                timestamp: timestamp.inner(),
            },
            MintRequestStatus::Offered => MintRequestStatusFfi::Offered,
            MintRequestStatus::Accepted => MintRequestStatusFfi::Accepted,
            MintRequestStatus::MintingEnabled => MintRequestStatusFfi::MintingEnabled,
            MintRequestStatus::Rejected { timestamp } => MintRequestStatusFfi::Rejected {
                timestamp: timestamp.inner(),
            },
            MintRequestStatus::Cancelled { timestamp } => MintRequestStatusFfi::Cancelled {
                timestamp: timestamp.inner(),
            },
            MintRequestStatus::Expired { timestamp } => MintRequestStatusFfi::Expired {
                timestamp: timestamp.inner(),
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct MintOfferFfi {
    pub mint_request_id: String,
    pub keyset_id: String,
    pub expiration_timestamp: u64,
    pub discounted_sum: String,
    pub proofs: Option<String>,
    pub proofs_spent: bool,
}

impl From<MintOffer> for MintOfferFfi {
    fn from(val: MintOffer) -> Self {
        MintOfferFfi {
            mint_request_id: val.mint_request_id.to_string(),
            keyset_id: val.keyset_id.to_owned(),
            expiration_timestamp: val.expiration_timestamp.inner(),
            discounted_sum: val.discounted_sum.as_sat_string(),
            proofs: val.proofs.to_owned(),
            proofs_spent: val.proofs_spent,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MintRequestStateResponse {
    pub request_states: Vec<MintRequestStateFfi>,
}

#[derive(Debug, Clone)]
pub struct MintRequestStateFfi {
    pub request: MintRequestFfi,
    pub offer: Option<MintOfferFfi>,
}

impl From<MintRequestState> for MintRequestStateFfi {
    fn from(val: MintRequestState) -> Self {
        MintRequestStateFfi {
            request: val.request.into(),
            offer: val.offer.map(|o| o.into()),
        }
    }
}
