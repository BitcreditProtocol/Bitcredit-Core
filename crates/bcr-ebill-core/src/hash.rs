use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256;
use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};

use crate::util::base58_encode;
use crate::{ValidationError, util::base58_decode};

/// Type for representing a base58-encoded sha256 Hash
#[derive(Debug, Clone, Eq, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Hash)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Hash(String);

impl Sha256Hash {
    // Creates a base58 encoded sha256 hash of the given string
    pub fn new(s: &str) -> Self {
        Self::from_bytes(s.as_bytes())
    }

    // Creates a base58 encoded sha256 hash of the given bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let hash = sha256::Hash::hash(bytes).to_byte_array();
        Sha256Hash(base58_encode(hash.as_slice()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn decode(&self) -> Vec<u8> {
        // safe, because we only create and deserialize from base58 encoded sha256 hashes
        base58_decode(&self.0).expect("is base58 encoded")
    }
}

impl Display for Sha256Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

// Attempts to parse a given String as a Sha256Hash
impl FromStr for Sha256Hash {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = base58_decode(s).map_err(|_| ValidationError::InvalidHash)?;
        sha256::Hash::from_slice(&decoded).map_err(|_| ValidationError::InvalidHash)?;
        Ok(Sha256Hash(s.to_owned()))
    }
}

impl TryFrom<String> for Sha256Hash {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Sha256Hash> for String {
    fn from(value: Sha256Hash) -> Self {
        value.0
    }
}

impl borsh::BorshSerialize for Sha256Hash {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        borsh::BorshSerialize::serialize(&self.0, writer)
    }
}

impl borsh::BorshDeserialize for Sha256Hash {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let hash_str: String = borsh::BorshDeserialize::deserialize_reader(reader)?;
        Sha256Hash::from_str(&hash_str)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::BorshDeserialize;
    use serde::{Deserialize, Serialize};

    const VALID_HASH: &str = "7t1xpVmsCqupDqy9ZCnieMrGuXdbJL7QWuPjsdhZgPiR";

    #[derive(
        Debug,
        Clone,
        Eq,
        PartialEq,
        borsh_derive::BorshSerialize,
        borsh_derive::BorshDeserialize,
        Serialize,
        Deserialize,
    )]
    pub struct TestHash {
        pub hash: Sha256Hash,
    }

    #[test]
    fn test_serialization() {
        let hash = Sha256Hash::from_str(VALID_HASH).expect("works");
        let test = TestHash { hash: hash.clone() };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!(
            "{\"hash\":\"7t1xpVmsCqupDqy9ZCnieMrGuXdbJL7QWuPjsdhZgPiR\"}",
            json
        );
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(test, deserialized);
        assert_eq!(hash, deserialized.hash);

        let borsh = borsh::to_vec(&hash).unwrap();
        let borsh_de = Sha256Hash::try_from_slice(&borsh).unwrap();
        assert_eq!(hash, borsh_de);

        let borsh_test = borsh::to_vec(&test).unwrap();
        let borsh_de_test = TestHash::try_from_slice(&borsh_test).unwrap();
        assert_eq!(test, borsh_de_test);
        assert_eq!(hash, borsh_de_test.hash);
    }

    #[test]
    fn test_invalid_serde_serialization() {
        let json = "{\"hash\":\"invalid\"}";
        let deserialized = serde_json::from_str::<TestHash>(json);
        assert!(deserialized.is_err());

        let borsh = borsh::to_vec(&String::from("invalid")).expect("works");
        let res = Sha256Hash::try_from_slice(&borsh);
        assert!(res.is_err());

        let borsh = borsh::to_vec(VALID_HASH).expect("works");
        let res = Sha256Hash::try_from_slice(&borsh);
        assert!(res.is_ok());
    }

    #[test]
    fn test_hash() {
        let n = Sha256Hash::from_str(VALID_HASH).expect("works");
        let n_owned: Sha256Hash = String::from(VALID_HASH).try_into().expect("works");
        assert_eq!(n, n_owned);

        assert!(matches!(
            Sha256Hash::from_str("blablub"),
            Err(ValidationError::InvalidHash)
        ));
        assert!(matches!(
            Sha256Hash::from_str("ABAB7t1xpVmsCqupDqy9ZCnieMrGuXdbJL7QWuPjsdhZgPiR"),
            Err(ValidationError::InvalidHash)
        ));
    }
}
