use bcr_ebill_api::data::{
    NodeId,
    identity_proof::{IdentityProof, IdentityProofStamp, IdentityProofStatus},
};
use serde::Serialize;
use tsify::Tsify;
use url::Url;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Debug, Serialize)]
#[tsify(into_wasm_abi)]
pub struct IdentityProofWeb {
    pub id: String,
    #[tsify(type = "string")]
    pub node_id: NodeId,
    #[tsify(type = "string")]
    pub stamp: IdentityProofStamp,
    #[tsify(type = "string")]
    pub url: Url,
    pub timestamp: u64,
    pub status: IdentityProofStatusWeb,
    pub status_last_checked_timestamp: u64,
    pub block_id: u64,
}

impl From<IdentityProof> for IdentityProofWeb {
    fn from(value: IdentityProof) -> Self {
        Self {
            id: value.id(),
            node_id: value.node_id,
            stamp: value.stamp,
            url: value.url,
            timestamp: value.timestamp,
            status: value.status.into(),
            status_last_checked_timestamp: value.status_last_checked_timestamp,
            block_id: value.block_id,
        }
    }
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub enum IdentityProofStatusWeb {
    Success,
    NotFound,
    FailureConnect,
    FailureClient,
    FailureServer,
}

impl From<IdentityProofStatus> for IdentityProofStatusWeb {
    fn from(value: IdentityProofStatus) -> Self {
        match value {
            IdentityProofStatus::Success => IdentityProofStatusWeb::Success,
            IdentityProofStatus::NotFound => IdentityProofStatusWeb::NotFound,
            IdentityProofStatus::FailureConnect => IdentityProofStatusWeb::FailureConnect,
            IdentityProofStatus::FailureClient => IdentityProofStatusWeb::FailureClient,
            IdentityProofStatus::FailureServer => IdentityProofStatusWeb::FailureServer,
        }
    }
}
