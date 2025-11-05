use std::{fmt, str::FromStr};

use log::warn;
use secp256k1::{SECP256K1, SecretKey};

use bcr_common::core::NodeId;

use crate::protocol::{ProtocolValidationError, SchnorrSignature, Sha256Hash};

/// This is the string users are supposed to post on their social media to prove their identity
#[derive(Debug, Clone, PartialEq)]
pub struct IdentityProofStamp {
    inner: SchnorrSignature,
}

impl IdentityProofStamp {
    /// Sign the base58 sha256 hash of the given node_id using the given key and returns the resulting signature
    pub fn new(node_id: &NodeId, private_key: &SecretKey) -> Result<Self, ProtocolValidationError> {
        // check that the node id and the private key match
        if node_id.pub_key() != private_key.public_key(SECP256K1) {
            return Err(ProtocolValidationError::InvalidNodeId);
        }
        // hash the node id
        let hash = Sha256Hash::from_bytes(node_id.to_string().as_bytes());
        // sign it
        let signature = SchnorrSignature::sign(&hash, private_key)
            .map_err(|_| ProtocolValidationError::InvalidSignature)?;
        Ok(IdentityProofStamp::from(signature))
    }

    /// Checks if the identity proof signature string is within the given body of text
    pub fn is_contained_in(&self, body: &str) -> bool {
        let self_str = self.to_string();
        body.contains(&self_str)
    }

    pub fn verify_against_node_id(&self, node_id: &NodeId) -> bool {
        let hash = Sha256Hash::from_bytes(node_id.to_string().as_bytes());
        match self.inner.verify(&hash, &node_id.pub_key()) {
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
        self.inner.fmt(f)
    }
}

impl From<SchnorrSignature> for IdentityProofStamp {
    fn from(value: SchnorrSignature) -> Self {
        Self { inner: value }
    }
}

impl FromStr for IdentityProofStamp {
    type Err = ProtocolValidationError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self {
            inner: SchnorrSignature::from_str(s)?,
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
    use crate::protocol::tests::tests::{node_id_test, private_key_test};

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
