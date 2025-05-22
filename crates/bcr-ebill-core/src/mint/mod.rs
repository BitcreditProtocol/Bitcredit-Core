/// A request to mint
#[derive(Debug, Clone)]
pub struct MintRequest {
    /// The requester
    pub requester_node_id: String,
    /// The bill to request to mint
    pub bill_id: String,
    /// The mint to be requested against
    pub mint_node_id: String,
    /// The id returned from the mint
    pub mint_request_id: String,
    /// The time of the request
    pub timestamp: u64,
    /// The status of the request to mint
    pub status: MintRequestStatus,
}

#[derive(Debug, Clone)]
pub enum MintRequestStatus {
    /// Waiting for an answer from the mint
    Pending,
    /// Denied by the requester
    Denied,
    /// Offer was made
    Offered,
    /// Offer was accepted
    Accepted,
    /// Rejected by the mint
    Rejected,
}

/// An offer from a mint as a response to a request to mint
#[derive(Debug, Clone)]
pub struct MintOffer {}

#[derive(Debug, Clone)]
pub struct MintRequestState {
    /// There always is a request
    pub request: MintRequest,
    /// There might be an offer
    pub offer: Option<MintOffer>,
}
