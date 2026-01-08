use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::protocol::{Field, ProtocolValidationError};

const MAX_NAME_LEN: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
#[serde(try_from = "String", into = "String")]
pub struct Name(String);

impl Name {
    pub fn new(n: impl Into<String>) -> Result<Self, ProtocolValidationError> {
        let s = ammonia::clean(&n.into());

        if s.trim().is_empty() {
            return Err(ProtocolValidationError::FieldEmpty(Field::Name));
        }

        if s.trim().chars().count() > MAX_NAME_LEN {
            return Err(ProtocolValidationError::FieldInvalid(Field::Name));
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
    type Err = ProtocolValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Name::new(s)
    }
}

impl TryFrom<String> for Name {
    type Error = ProtocolValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Name> for String {
    fn from(value: Name) -> Self {
        value.0
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
    fn test_invalid_serialization() {
        let json = "{\"name\":\"\"}";
        let deserialized = serde_json::from_str::<TestName>(json);
        assert!(deserialized.is_err());

        let borsh = borsh::to_vec(&String::from("")).expect("works");
        let res = Name::try_from_slice(&borsh);
        assert!(res.is_err());

        let borsh = borsh::to_vec(&String::from("Minka")).expect("works");
        let res = Name::try_from_slice(&borsh);
        assert!(res.is_ok());
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
            Err(ProtocolValidationError::FieldInvalid(Field::Name))
        ));
        assert!(matches!(
            Name::new(""),
            Err(ProtocolValidationError::FieldEmpty(Field::Name))
        ));
        assert!(matches!(
            Name::new("            "),
            Err(ProtocolValidationError::FieldEmpty(Field::Name))
        ));
    }

    #[test]
    fn test_name_utf8() {
        // Test Arabic name (multi-byte UTF-8 characters)
        let arabic_name = "محمد أحمد";
        let n = Name::new(arabic_name).expect("Arabic name should work");
        assert_eq!(n.as_str(), arabic_name);

        // Test Chinese name
        let chinese_name = "李明";
        let n = Name::new(chinese_name).expect("Chinese name should work");
        assert_eq!(n.as_str(), chinese_name);

        // Test name with emojis
        let emoji_name = "John 👨‍💼";
        let n = Name::new(emoji_name).expect("Name with emoji should work");
        assert_eq!(n.as_str(), emoji_name);

        // Create a string with exactly 200 Arabic characters (which would be more than 200 bytes)
        let long_arabic = "أ".repeat(200);
        assert!(
            Name::new(&long_arabic).is_ok(),
            "200 Arabic chars should be OK"
        );

        // Create a string with 201 Arabic characters (should fail)
        let too_long_arabic = "أ".repeat(201);
        assert!(
            matches!(
                Name::new(&too_long_arabic),
                Err(ProtocolValidationError::FieldInvalid(Field::Name))
            ),
            "201 Arabic chars should fail"
        );
    }
}
