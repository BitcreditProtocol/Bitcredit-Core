//! Short-lived holder/applicant admissions for Mint and facility applications. They prove key
//! control for one application capability only; they never accept terms or authorize value.
use bcr_common::core::{BillId, NodeId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod facility;
pub mod mint;

/// Opens an application only; it never accepts an offer or authorizes minting.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintApplicationAdmissionPayload {
    pub bill_id: BillId,
    pub mint_node: NodeId,
    pub mint_quote_id: Uuid,
    pub case_id: Uuid,
    pub application_token_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignedMintApplicationAdmission {
    pub admission: MintApplicationAdmission,
    /// BIP340 signature over SHA256 of the canonical admission lines, lowercase hex.
    pub signature: String,
}

/// Which facility capability the proof admits. Neither accepts terms nor authorizes minting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FacilityApplicationAdmissionAction {
    OpenFacilityApplication,
    UpgradeFacilityIdentity,
}

/// The signer, network and timestamps are never caller-selected; Core adds them.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacilityApplicationAdmissionPayload {
    pub action: FacilityApplicationAdmissionAction,
    pub application_id: Uuid,
    pub mint_node: NodeId,
    pub application_token_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FacilityApplicationAdmission {
    pub schema_version: String,
    pub action: String,
    pub application_id: String,
    pub mint_node_id: String,
    pub applicant_ref: String,
    pub application_token_digest: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignedFacilityApplicationAdmission {
    pub admission: FacilityApplicationAdmission,
    /// BIP340 signature over SHA256 of the canonical admission lines, lowercase hex.
    pub signature: String,
}
