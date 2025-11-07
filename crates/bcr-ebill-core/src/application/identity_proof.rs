use std::fmt;

use url::Url;

use crate::protocol::{BlockId, IdentityProofStamp, Sha256Hash, Timestamp};
use bcr_common::core::NodeId;

#[derive(Debug, Clone)]
pub enum IdentityProofStatus {
    /// The request succeeded and we found the signature we were looking for in the response
    Success,
    /// The request succeeded, but we didn't find the signature we were looking for in the response
    NotFound,
    /// The request failed with a connection error
    FailureConnect,
    /// The request failed with a client error (4xx)
    FailureClient,
    /// The request failed with a server error (5xx)
    FailureServer,
}

impl fmt::Display for IdentityProofStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            IdentityProofStatus::Success => "Success",
            IdentityProofStatus::NotFound => "NotFound",
            IdentityProofStatus::FailureConnect => "FailureConnect",
            IdentityProofStatus::FailureClient => "FailureClient",
            IdentityProofStatus::FailureServer => "FailureServer",
        };
        write!(f, "{}", s)
    }
}

/// An identity proof
#[derive(Debug, Clone)]
pub struct IdentityProof {
    pub node_id: NodeId,
    pub stamp: IdentityProofStamp,
    pub url: Url,
    pub timestamp: Timestamp,
    pub status: IdentityProofStatus,
    pub status_last_checked_timestamp: Timestamp,
    pub block_id: BlockId,
}

impl IdentityProof {
    pub fn id(&self) -> String {
        // The id is the base58 sha256 hash of the node_id:url:timestamp triple
        Sha256Hash::from_bytes(
            format!("{}:{}:{}", &self.node_id, &self.url, self.timestamp).as_bytes(),
        )
        .to_string()
    }
}
