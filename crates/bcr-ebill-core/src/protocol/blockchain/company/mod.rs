use crate::protocol::crypto::BcrKeys;
use crate::protocol::{BlockId, EmailIdentityProofData, SignedIdentityProof};

use super::Result;
use super::{Block, Blockchain};
use bcr_common::core::NodeId;
use borsh_derive::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

pub mod block;
pub mod chain;
pub mod validation;

pub use block::CompanyBlock;
pub use block::CompanyBlockPayload;
pub use chain::CompanyBlockchain;

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum CompanyOpCode {
    Create,
    Update,
    InviteSignatory,
    RemoveSignatory,
    SignatoryAcceptInvite,
    SignatoryRejectInvite,
    SignCompanyBill,
    IdentityProof,
}

#[derive(Debug, Clone)]
pub struct CompanyValidateActionData {
    pub blockchain: CompanyBlockchain,
    pub company_id: NodeId,
    pub signer_node_id: NodeId,
    pub op: CompanyOpCode,
    pub company_keys: BcrKeys,
    pub invitee: Option<NodeId>,
    pub removee: Option<NodeId>,
    pub identity_proof_data: Option<(SignedIdentityProof, EmailIdentityProofData, Option<BlockId>)>,
}
