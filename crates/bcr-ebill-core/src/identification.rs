use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{Field, ValidationError};

const MAX_IDENTIFICATION_LEN: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct Identification(String);

impl Identification {
    pub fn new(n: impl Into<String>) -> Result<Self, ValidationError> {
        let s = ammonia::clean(&n.into());

        if s.trim().is_empty() {
            return Err(ValidationError::FieldEmpty(Field::Identification));
        }

        if s.len() > MAX_IDENTIFICATION_LEN {
            return Err(ValidationError::FieldInvalid(Field::Identification));
        }

        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for Identification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Identification {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Identification::new(s)
    }
}

impl borsh::BorshSerialize for Identification {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        borsh::BorshSerialize::serialize(&self.0, writer)
    }
}

impl borsh::BorshDeserialize for Identification {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let identification_str: String = borsh::BorshDeserialize::deserialize_reader(reader)?;
        Identification::new(&identification_str)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::BorshDeserialize;
    use serde::{Deserialize, Serialize};

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
    pub struct TestIdentification {
        pub identification: Identification,
    }

    #[test]
    fn test_serialization() {
        let identification = Identification::new("51234").expect("works");
        let test = TestIdentification {
            identification: identification.clone(),
        };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!("{\"identification\":\"51234\"}", json);
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(test, deserialized);
        assert_eq!(identification, deserialized.identification);

        let borsh = borsh::to_vec(&identification).unwrap();
        let borsh_de = Identification::try_from_slice(&borsh).unwrap();
        assert_eq!(identification, borsh_de);

        let borsh_test = borsh::to_vec(&test).unwrap();
        let borsh_de_test = TestIdentification::try_from_slice(&borsh_test).unwrap();
        assert_eq!(test, borsh_de_test);
        assert_eq!(identification, borsh_de_test.identification);
    }

    #[test]
    fn test_name() {
        let n = Identification::new("51234").expect("works");
        let n_owned = Identification::new(String::from("51234")).expect("works");
        assert_eq!(n, n_owned);
        assert_eq!(
            Identification::new("512<script>window.alert('HELLO');</script>34")
                .expect("works")
                .as_str(),
            "51234"
        );

        assert!(matches!(
            Identification::new(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            Err(ValidationError::FieldInvalid(Field::Identification))
        ));
        assert!(matches!(
            Identification::new(""),
            Err(ValidationError::FieldEmpty(Field::Identification))
        ));
        assert!(matches!(
            Identification::new("            "),
            Err(ValidationError::FieldEmpty(Field::Identification))
        ));
    }
}
