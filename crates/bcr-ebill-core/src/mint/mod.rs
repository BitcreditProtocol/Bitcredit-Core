#[derive(Debug, Clone)]
pub struct MintRequest {
    pub requester_node_id: String,
    pub bill_id: String,
    pub mint_node_id: String,
    pub mint_request_id: String,
    pub timestamp: u64,
    pub status: MintRequestStatus,
}

#[derive(Debug, Clone)]
pub enum MintRequestStatus {
    Pending,
    Denied,
    Offered {
        keyset_id: String,
        expiration_timestamp: u64,
        discounted: u64,
    },
    Accepted {
        keyset_id: String,
    },
    Rejected {
        timestamp: u64,
    },
}
