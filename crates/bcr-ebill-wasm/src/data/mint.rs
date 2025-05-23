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
    Denied,
    Offered,
    Accepted,
    Rejected,
    Cancelled,
    Expired,
}
impl From<MintRequestStatus> for MintRequestStatusWeb {
    fn from(val: MintRequestStatus) -> Self {
        match val {
            MintRequestStatus::Pending => MintRequestStatusWeb::Pending,
            MintRequestStatus::Denied => MintRequestStatusWeb::Denied,
            MintRequestStatus::Offered => MintRequestStatusWeb::Offered,
            MintRequestStatus::Accepted => MintRequestStatusWeb::Accepted,
            MintRequestStatus::Rejected => MintRequestStatusWeb::Rejected,
            MintRequestStatus::Cancelled => MintRequestStatusWeb::Cancelled,
            MintRequestStatus::Expired => MintRequestStatusWeb::Expired,
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct MintOfferWeb {}

impl From<MintOffer> for MintOfferWeb {
    fn from(_val: MintOffer) -> Self {
        MintOfferWeb {}
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
