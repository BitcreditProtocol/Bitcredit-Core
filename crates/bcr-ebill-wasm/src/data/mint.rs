use bcr_ebill_api::data::mint::{MintOffer, MintRequest, MintRequestState, MintRequestStatus};
use serde::Serialize;
use tsify::Tsify;

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct MintRequestWeb {
    pub requester_node_id: String,
    pub bill_id: String,
    pub mint_node_id: String,
    pub mint_request_id: String,
    pub timestamp: u64,
    pub status: MintRequestStatusWeb,
}

impl From<MintRequest> for MintRequestWeb {
    fn from(val: MintRequest) -> Self {
        MintRequestWeb {
            requester_node_id: val.requester_node_id,
            bill_id: val.bill_id,
            mint_node_id: val.mint_node_id,
            mint_request_id: val.mint_request_id,
            timestamp: val.timestamp,
            status: val.status.into(),
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub enum MintRequestStatusWeb {
    Pending,
    Denied { timestamp: u64 },
    Offered,
    Accepted,
    Rejected { timestamp: u64 },
    Cancelled { timestamp: u64 },
    Expired { timestamp: u64 },
}
impl From<MintRequestStatus> for MintRequestStatusWeb {
    fn from(val: MintRequestStatus) -> Self {
        match val {
            MintRequestStatus::Pending => MintRequestStatusWeb::Pending,
            MintRequestStatus::Denied { timestamp } => MintRequestStatusWeb::Denied { timestamp },
            MintRequestStatus::Offered => MintRequestStatusWeb::Offered,
            MintRequestStatus::Accepted => MintRequestStatusWeb::Accepted,
            MintRequestStatus::Rejected { timestamp } => {
                MintRequestStatusWeb::Rejected { timestamp }
            }
            MintRequestStatus::Cancelled { timestamp } => {
                MintRequestStatusWeb::Cancelled { timestamp }
            }
            MintRequestStatus::Expired { timestamp } => MintRequestStatusWeb::Expired { timestamp },
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct MintOfferWeb {
    pub mint_request_id: String,
    pub keyset_id: String,
    pub expiration_timestamp: u64,
    pub discounted_sum: u64,
    pub proofs: Option<String>,
    pub proofs_spent: bool,
}

impl From<MintOffer> for MintOfferWeb {
    fn from(val: MintOffer) -> Self {
        MintOfferWeb {
            mint_request_id: val.mint_request_id.to_owned(),
            keyset_id: val.keyset_id.to_owned(),
            expiration_timestamp: val.expiration_timestamp,
            discounted_sum: val.discounted_sum,
            proofs: val.proofs.to_owned(),
            proofs_spent: val.proofs_spent,
        }
    }
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct MintRequestStateResponse {
    pub request_states: Vec<MintRequestStateWeb>,
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct MintRequestStateWeb {
    pub request: MintRequestWeb,
    pub offer: Option<MintOfferWeb>,
}

impl From<MintRequestState> for MintRequestStateWeb {
    fn from(val: MintRequestState) -> Self {
        MintRequestStateWeb {
            request: val.request.into(),
            offer: val.offer.map(|o| o.into()),
        }
    }
}
