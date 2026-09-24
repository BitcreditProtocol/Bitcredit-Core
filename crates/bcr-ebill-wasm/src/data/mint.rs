use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::{
    protocol::Timestamp,
    protocol::mint::{MintOffer, MintRequest, MintRequestState, MintRequestStatus},
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use uuid::Uuid;

/// Opens an application only; it never accepts an offer or authorizes minting.
#[derive(Tsify, Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintApplicationAdmissionPayload {
    #[tsify(type = "string")]
    pub bill_id: BillId,
    #[tsify(type = "string")]
    pub mint_node: NodeId,
    #[tsify(type = "string")]
    pub mint_quote_id: Uuid,
    #[tsify(type = "string")]
    pub case_id: Uuid,
    pub application_token_digest: String,
}

#[derive(Tsify, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintApplicationAdmission {
    pub schema_version: String,
    pub action: String,
    pub bill_id: String,
    pub mint_node_id: String,
    pub mint_quote_id: String,
    pub case_id: String,
    pub holder_ref: String,
    pub application_token_digest: String,
    #[tsify(type = "number")]
    pub issued_at: u64,
    #[tsify(type = "number")]
    pub expires_at: u64,
}

#[derive(Tsify, Debug, Clone, Serialize)]
pub struct SignedMintApplicationAdmission {
    pub admission: MintApplicationAdmission,
    /// BIP340 signature over SHA256 of the canonical admission lines, lowercase hex.
    pub signature: String,
}

#[derive(Tsify, Debug, Serialize, Clone)]
pub struct MintRequestWeb {
    #[tsify(type = "string")]
    pub requester_node_id: NodeId,
    #[tsify(type = "string")]
    pub bill_id: BillId,
    #[tsify(type = "string")]
    pub mint_node_id: NodeId,
    #[tsify(type = "string")]
    pub mint_request_id: Uuid,
    #[tsify(type = "number")]
    pub timestamp: Timestamp,
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
pub enum MintRequestStatusWeb {
    Pending,
    Denied { timestamp: u64 },
    Offered,
    Accepted,
    MintingEnabled,
    Rejected { timestamp: u64 },
    Cancelled { timestamp: u64 },
    Expired { timestamp: u64 },
}
impl From<MintRequestStatus> for MintRequestStatusWeb {
    fn from(val: MintRequestStatus) -> Self {
        match val {
            MintRequestStatus::Pending => MintRequestStatusWeb::Pending,
            MintRequestStatus::Denied { timestamp } => MintRequestStatusWeb::Denied {
                timestamp: timestamp.inner(),
            },
            MintRequestStatus::Offered => MintRequestStatusWeb::Offered,
            MintRequestStatus::Accepted => MintRequestStatusWeb::Accepted,
            MintRequestStatus::MintingEnabled => MintRequestStatusWeb::MintingEnabled,
            MintRequestStatus::Rejected { timestamp } => MintRequestStatusWeb::Rejected {
                timestamp: timestamp.inner(),
            },
            MintRequestStatus::Cancelled { timestamp } => MintRequestStatusWeb::Cancelled {
                timestamp: timestamp.inner(),
            },
            MintRequestStatus::Expired { timestamp } => MintRequestStatusWeb::Expired {
                timestamp: timestamp.inner(),
            },
        }
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
pub struct MintOfferWeb {
    #[tsify(type = "string")]
    pub mint_request_id: Uuid,
    pub keyset_id: String,
    #[tsify(type = "number")]
    pub expiration_timestamp: Timestamp,
    pub discounted_sum: String,
    pub proofs: Option<String>,
    pub proofs_spent: bool,
}

impl From<MintOffer> for MintOfferWeb {
    fn from(val: MintOffer) -> Self {
        MintOfferWeb {
            mint_request_id: val.mint_request_id.to_owned(),
            keyset_id: val.keyset_id.to_owned(),
            expiration_timestamp: val.expiration_timestamp,
            discounted_sum: val.discounted_sum.as_sat_string(),
            proofs: val.proofs.to_owned(),
            proofs_spent: val.proofs_spent,
        }
    }
}

#[derive(Tsify, Debug, Clone, Serialize)]
pub struct MintRequestStateResponse {
    pub request_states: Vec<MintRequestStateWeb>,
}

#[derive(Tsify, Debug, Serialize, Clone)]
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
