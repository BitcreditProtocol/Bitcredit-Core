use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{Field, ValidationError};

const MAX_NAME_LEN: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct Name(String);

impl Name {
    pub fn new(n: impl Into<String>) -> Result<Self, ValidationError> {
        let s = ammonia::clean(&n.into());

        if s.trim().is_empty() {
            return Err(ValidationError::FieldEmpty(Field::Name));
        }

        if s.len() > MAX_NAME_LEN {
            return Err(ValidationError::FieldInvalid(Field::Name));
        }

        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Name {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Name::new(s)
    }
}

impl borsh::BorshSerialize for Name {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        borsh::BorshSerialize::serialize(&self.0, writer)
    }
}

impl borsh::BorshDeserialize for Name {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let name_str: String = borsh::BorshDeserialize::deserialize_reader(reader)?;
        Name::new(&name_str).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
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
    pub struct TestName {
        pub name: Name,
    }

    #[test]
    fn test_serialization() {
        let name = Name::new("minka").expect("works");
        let test = TestName { name: name.clone() };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!("{\"name\":\"minka\"}", json);
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(test, deserialized);
        assert_eq!(name, deserialized.name);

        let borsh = borsh::to_vec(&name).unwrap();
        let borsh_de = Name::try_from_slice(&borsh).unwrap();
        assert_eq!(name, borsh_de);

        let borsh_test = borsh::to_vec(&test).unwrap();
        let borsh_de_test = TestName::try_from_slice(&borsh_test).unwrap();
        assert_eq!(test, borsh_de_test);
        assert_eq!(name, borsh_de_test.name);
    }

    #[test]
    fn test_name() {
        let n = Name::new("minka").expect("works");
        let n_owned = Name::new(String::from("minka")).expect("works");
        assert_eq!(n, n_owned);
        assert_eq!(
            Name::new("Min<script>window.alert('HELLO');</script>ka")
                .expect("works")
                .as_str(),
            "Minka"
        );

        assert!(matches!(
            Name::new(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            Err(ValidationError::FieldInvalid(Field::Name))
        ));
        assert!(matches!(
            Name::new(""),
            Err(ValidationError::FieldEmpty(Field::Name))
        ));
        assert!(matches!(
            Name::new("            "),
            Err(ValidationError::FieldEmpty(Field::Name))
        ));
    }
}
