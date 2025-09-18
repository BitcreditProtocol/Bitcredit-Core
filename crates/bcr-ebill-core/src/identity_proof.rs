use std::{fmt, str::FromStr};

use log::warn;
use secp256k1::{SECP256K1, SecretKey, schnorr::Signature};
use url::Url;

use crate::{NodeId, ValidationError, util};

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
    pub timestamp: u64,
    pub status: IdentityProofStatus,
    pub status_last_checked_timestamp: u64,
    pub block_id: u64,
}

impl IdentityProof {
    pub fn id(&self) -> String {
        // The id is the base58 sha256 hash of the node_id:url:timestamp triple
        util::sha256_hash(format!("{}:{}:{}", &self.node_id, &self.url, self.timestamp).as_bytes())
    }
}

/// This is the string users are supposed to post on their social media to prove their identity
#[derive(Debug, Clone, PartialEq)]
pub struct IdentityProofStamp {
    inner: Signature,
}

impl IdentityProofStamp {
    /// Sign the base58 sha256 hash of the given node_id using the given key and returns the resulting signature
    pub fn new(node_id: &NodeId, private_key: &SecretKey) -> Result<Self, ValidationError> {
        // check that the node id and the private key match
        if node_id.pub_key() != private_key.public_key(SECP256K1) {
            return Err(ValidationError::InvalidNodeId);
        }
        // hash the node id
        let hash = util::sha256_hash(node_id.to_string().as_bytes());
        // sign it
        let signature = util::crypto::signature(&hash, private_key)
            .map_err(|_| ValidationError::InvalidSignature)?;
        IdentityProofStamp::from_str(&signature)
    }

    /// Checks if the identity proof signature string is within the given body of text
    pub fn is_contained_in(&self, body: &str) -> bool {
        let self_str = self.to_string();
        body.contains(&self_str)
    }

    pub fn verify_against_node_id(&self, node_id: &NodeId) -> bool {
        let hash = util::sha256_hash(node_id.to_string().as_bytes());
        match util::crypto::verify(&hash, &self.to_string(), &node_id.pub_key()) {
            Ok(verified) => verified,
            Err(e) => {
                warn!(
                    "could not verify identity proof stamp {self} against node id {node_id}: {e}"
                );
                false
            }
        }
    }
}

impl fmt::Display for IdentityProofStamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", util::base58_encode(&self.inner.serialize()))
    }
}

impl From<Signature> for IdentityProofStamp {
    fn from(value: Signature) -> Self {
        Self { inner: value }
    }
}

impl FromStr for IdentityProofStamp {
    type Err = ValidationError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self {
            inner: Signature::from_slice(
                &util::base58_decode(s).map_err(|_| ValidationError::InvalidBase58)?,
            )
            .map_err(|_| ValidationError::InvalidSignature)?,
        })
    }
}

impl serde::Serialize for IdentityProofStamp {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for IdentityProofStamp {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        IdentityProofStamp::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl borsh::BorshSerialize for IdentityProofStamp {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let stamp_str = self.to_string();
        borsh::BorshSerialize::serialize(&stamp_str, writer)
    }
}

impl borsh::BorshDeserialize for IdentityProofStamp {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let stamp_str: String = borsh::BorshDeserialize::deserialize_reader(reader)?;
        IdentityProofStamp::from_str(&stamp_str)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

#[cfg(test)]
pub mod tests {
    use crate::tests::tests::{node_id_test, private_key_test};

    use super::*;

    #[test]
    fn test_create_and_verify() {
        let node_id = node_id_test();
        let private_key = private_key_test();

        let identity_proof_stamp =
            IdentityProofStamp::new(&node_id, &private_key).expect("is valid");
        assert!(identity_proof_stamp.verify_against_node_id(&node_id));
    }
}
