use crate::{NodeId, bill::BillId};

/// A request to mint
#[derive(Debug, Clone)]
pub struct MintRequest {
    /// The requester
    pub requester_node_id: NodeId,
    /// The bill to request to mint
    pub bill_id: BillId,
    /// The mint to be requested against
    pub mint_node_id: NodeId,
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
    /// Denied by the mint
    Denied { timestamp: u64 },
    /// Offer was made
    Offered,
    /// Offer was accepted
    Accepted,
    /// The offer was rejected by the requester
    Rejected { timestamp: u64 },
    /// The request was cancelled by the requester
    Cancelled { timestamp: u64 },
    /// The offer expired
    Expired { timestamp: u64 },
}

/// An offer from a mint as a response to a request to mint
#[derive(Debug, Clone)]
pub struct MintOffer {
    /// The request id on the mint side
    pub mint_request_id: String,
    /// The keyset id returned from the mint
    pub keyset_id: String,
    /// The expiration of the offer
    pub expiration_timestamp: u64,
    /// The discounted sum the mint offers us
    pub discounted_sum: u64,
    /// The proofs, encoded as a bitcrB token
    pub proofs: Option<String>,
    /// Whether the proofs were spent according to the mint
    pub proofs_spent: bool,
    /// The recovery data, if something goes wrong between minting and token generation
    pub recovery_data: Option<MintOfferRecoveryData>,
}

/// Mint offer recovery data
#[derive(Debug, Clone)]
pub struct MintOfferRecoveryData {
    /// The secrets of the blinds we used
    pub secrets: Vec<String>,
    /// The rs of the blinds we used
    pub rs: Vec<String>,
}

/// The state of a mint request
#[derive(Debug, Clone)]
pub struct MintRequestState {
    /// There always is a request
    pub request: MintRequest,
    /// There might be an offer
    pub offer: Option<MintOffer>,
}
