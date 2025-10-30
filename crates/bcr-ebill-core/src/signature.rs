use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};

use secp256k1::schnorr;

use crate::{
    ValidationError,
    util::{base58_decode, base58_encode},
};

/// Type for representing a base58-encoded schnorr Signature
#[derive(Debug, Clone, Eq, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Hash)]
#[serde(try_from = "String", into = "String")]
pub struct SchnorrSignature(String);

impl SchnorrSignature {
    pub fn new(s: &str) -> Result<Self, ValidationError> {
        Self::from_str(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_sig(&self) -> schnorr::Signature {
        // safe, since we validate this to be a base58 encoded schnorr signature
        let decoded = base58_decode(&self.0).expect("is base58 encoded");
        schnorr::Signature::from_slice(&decoded).expect("is a valid schnorr signature")
    }
}

impl Display for SchnorrSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<schnorr::Signature> for SchnorrSignature {
    fn from(value: schnorr::Signature) -> Self {
        SchnorrSignature(base58_encode(&value.serialize()))
    }
}

impl FromStr for SchnorrSignature {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = base58_decode(s).map_err(|_| ValidationError::InvalidSignature)?;
        schnorr::Signature::from_slice(&decoded).map_err(|_| ValidationError::InvalidSignature)?;
        Ok(SchnorrSignature(s.to_owned()))
    }
}

impl TryFrom<String> for SchnorrSignature {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<SchnorrSignature> for String {
    fn from(value: SchnorrSignature) -> Self {
        value.0
    }
}

impl borsh::BorshSerialize for SchnorrSignature {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        borsh::BorshSerialize::serialize(&self.0, writer)
    }
}

impl borsh::BorshDeserialize for SchnorrSignature {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let sig_str: String = borsh::BorshDeserialize::deserialize_reader(reader)?;
        SchnorrSignature::new(&sig_str)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::BorshDeserialize;
    use serde::{Deserialize, Serialize};

    const VALID_SIG: &str =
        "23u7iXhvpRBYhdHQW3jEk5LyQWJGDcnCoCfiPvjPHXQqmun6z3ZrYX7eXMrBmZk4mHW4Y5DQbASJb1LZU1KrkgGH";

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
    pub struct TestSig {
        pub sig: SchnorrSignature,
    }

    #[test]
    fn test_serialization() {
        let sig = SchnorrSignature::new(VALID_SIG).expect("works");
        let test = TestSig { sig: sig.clone() };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!(
            "{\"sig\":\"23u7iXhvpRBYhdHQW3jEk5LyQWJGDcnCoCfiPvjPHXQqmun6z3ZrYX7eXMrBmZk4mHW4Y5DQbASJb1LZU1KrkgGH\"}",
            json
        );
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(test, deserialized);
        assert_eq!(sig, deserialized.sig);

        let borsh = borsh::to_vec(&sig).unwrap();
        let borsh_de = SchnorrSignature::try_from_slice(&borsh).unwrap();
        assert_eq!(sig, borsh_de);

        let borsh_test = borsh::to_vec(&test).unwrap();
        let borsh_de_test = TestSig::try_from_slice(&borsh_test).unwrap();
        assert_eq!(test, borsh_de_test);
        assert_eq!(sig, borsh_de_test.sig);
    }

    #[test]
    fn test_invalid_serde_serialization() {
        let json = "{\"sig\":\"invalid\"}";
        let deserialized = serde_json::from_str::<TestSig>(json);
        assert!(deserialized.is_err());

        let borsh = borsh::to_vec(&String::from("invalid")).expect("works");
        let res = SchnorrSignature::try_from_slice(&borsh);
        assert!(res.is_err());

        let borsh = borsh::to_vec(VALID_SIG).expect("works");
        let res = SchnorrSignature::try_from_slice(&borsh);
        assert!(res.is_ok());
    }

    #[test]
    fn test_sig() {
        let n = SchnorrSignature::from_str(VALID_SIG).expect("works");
        let n_owned: SchnorrSignature = String::from(VALID_SIG).try_into().expect("works");
        assert_eq!(n, n_owned);

        assert!(matches!(
            SchnorrSignature::new("blablub"),
            Err(ValidationError::InvalidSignature)
        ));
        assert!(matches!(
            SchnorrSignature::new(
                "ABAB23u7iXhvpRBYhdHQW3jEk5LyQWJGDcnCoCfiPvjPHXQqmun6z3ZrYX7eXMrBmZk4mHW4Y5DQbASJb1LZU1KrkgGH"
            ),
            Err(ValidationError::InvalidSignature)
        ));
    }
}
