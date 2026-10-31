//! Public, purpose-bound inputs. Signing keys, subject binding, clocks and nonces stay in Core.
use bcr_common::core::BillId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DirectorySubjectType {
    SoleTrader,
    Company,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryRegistration {
    pub country: String,
    pub registry: String,
    pub number: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryProduct {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryActingPerson {
    pub public_name: String,
    pub public_role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryBusinessAddress {
    pub country: String,
    pub city: String,
    pub zip: Option<String>,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryBusinessContact {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
}

/// Only reviewed public fields; never an identity/contact struct export.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryListingPayload {
    #[serde(rename = "type")]
    pub subject_type: DirectorySubjectType,
    pub name: String,
    #[serde(default)]
    pub trading_names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration: Option<DirectoryRegistration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default)]
    pub products: Vec<DirectoryProduct>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub acting_persons: Vec<DirectoryActingPerson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub business_address: Option<DirectoryBusinessAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub business_contact: Option<DirectoryBusinessContact>,
    #[serde(default)]
    pub contact_relays: Vec<String>,
    pub valid_until: u64,
    pub notice_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryWithdrawalPayload {
    pub prior_events: Vec<SignedDirectoryEvent>,
}

/// A complete NIP-01 event, ready for the host to POST. Core does not publish it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDirectoryEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDirectoryWithdrawal {
    pub withdrawal: SignedDirectoryEvent,
    pub deletion: SignedDirectoryEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossMintOperation {
    BillStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossMintGrantPayload {
    pub grant_id: Uuid,
    pub requesting_mint_pubkey: String,
    pub answering_mint_pubkey: String,
    pub operation: CrossMintOperation,
    pub bill_id: BillId,
    pub case_binding: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifetime_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossMintRevokePayload {
    pub grant_id: Uuid,
    pub requesting_mint_pubkey: String,
    pub answering_mint_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossMintGrant {
    pub schema: String,
    pub grant_id: String,
    /// Bitcoin Network display string: testnet, testnet4, signet or regtest.
    pub network: String,
    pub subject_node_id: String,
    pub requesting_mint_pubkey: String,
    pub answering_mint_pubkey: String,
    pub operation: CrossMintOperation,
    pub bill_id: String,
    pub case_binding: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossMintRevoke {
    pub schema: String,
    pub grant_id: String,
    pub network: String,
    pub subject_node_id: String,
    pub requesting_mint_pubkey: String,
    pub answering_mint_pubkey: String,
    pub nonce: String,
    pub issued_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCrossMintGrant {
    pub grant: CrossMintGrant,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCrossMintRevoke {
    pub revoke: CrossMintRevoke,
    pub signature: String,
}

/// Purpose-bound transcription admission, never a case/application admission.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceVoiceAdmissionPayload {
    pub service_mint_node_id: bcr_common::core::NodeId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifetime_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceVoiceAdmission {
    pub schema: String,
    pub network: String,
    pub subject_node_id: String,
    pub service_mint_node_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedServiceVoiceAdmission {
    pub admission: ServiceVoiceAdmission,
    pub signature: String,
}
