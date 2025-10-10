use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{Field, ValidationError};

const MAX_ADDRESS_LEN: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct Address(String);

impl Address {
    pub fn new(n: impl Into<String>) -> Result<Self, ValidationError> {
        let s = ammonia::clean(&n.into());

        if s.trim().is_empty() {
            return Err(ValidationError::FieldEmpty(Field::Address));
        }

        if s.len() > MAX_ADDRESS_LEN {
            return Err(ValidationError::FieldInvalid(Field::Address));
        }

        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Address {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::new(s)
    }
}

impl borsh::BorshSerialize for Address {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        borsh::BorshSerialize::serialize(&self.0, writer)
    }
}

impl borsh::BorshDeserialize for Address {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let addr_str: String = borsh::BorshDeserialize::deserialize_reader(reader)?;
        Address::new(&addr_str).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
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
    pub struct TestAddress {
        pub address: Address,
    }

    #[test]
    fn test_serialization() {
        let address = Address::new("Praterstrasse 1").expect("works");
        let test = TestAddress {
            address: address.clone(),
        };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!("{\"address\":\"Praterstrasse 1\"}", json);
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(test, deserialized);
        assert_eq!(address, deserialized.address);

        let borsh = borsh::to_vec(&address).unwrap();
        let borsh_de = Address::try_from_slice(&borsh).unwrap();
        assert_eq!(address, borsh_de);

        let borsh_test = borsh::to_vec(&test).unwrap();
        let borsh_de_test = TestAddress::try_from_slice(&borsh_test).unwrap();
        assert_eq!(test, borsh_de_test);
        assert_eq!(address, borsh_de_test.address);
    }

    #[test]
    fn test_name() {
        let n = Address::new("Praterstrasse 1").expect("works");
        let n_owned = Address::new(String::from("Praterstrasse 1")).expect("works");
        assert_eq!(n, n_owned);
        assert_eq!(
            Address::new("Prater<script>window.alert('HELLO');</script>strasse 1")
                .expect("works")
                .as_str(),
            "Praterstrasse 1"
        );

        assert!(matches!(
            Address::new(
                "papapapappapapapappapapapappapapapappapapapappapapapappapapapappapapapappapapapappapapapappapapapappapapapappapapapappapapapappapapapappapapapappapapapappapapapappapapapappapapapappapapapapaaaaaaaaaaaaaaaaaaaaapapapapapa"
            ),
            Err(ValidationError::FieldInvalid(Field::Address))
        ));
        assert!(matches!(
            Address::new(""),
            Err(ValidationError::FieldEmpty(Field::Address))
        ));
        assert!(matches!(
            Address::new("            "),
            Err(ValidationError::FieldEmpty(Field::Address))
        ));
    }
}
