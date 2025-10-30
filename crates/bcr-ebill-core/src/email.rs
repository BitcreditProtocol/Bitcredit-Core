use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{Field, ValidationError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
#[serde(try_from = "String", into = "String")]
pub struct Email(String);

impl Email {
    pub fn new(n: impl Into<String>) -> Result<Self, ValidationError> {
        let s = n.into();
        if s.trim().is_empty() {
            return Err(ValidationError::FieldEmpty(Field::Email));
        }

        if !email_address::EmailAddress::is_valid(&s) {
            return Err(ValidationError::FieldInvalid(Field::Email));
        }

        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Email {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Email::new(s)
    }
}

impl TryFrom<String> for Email {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Email> for String {
    fn from(value: Email) -> Self {
        value.0
    }
}

impl borsh::BorshSerialize for Email {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        borsh::BorshSerialize::serialize(&self.0, writer)
    }
}

impl borsh::BorshDeserialize for Email {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let email_str: String = borsh::BorshDeserialize::deserialize_reader(reader)?;
        Email::new(&email_str).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
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
    pub struct TestEmail {
        pub email: Email,
    }

    #[test]
    fn test_serialization() {
        let email = Email::new("test@example.com").expect("works");
        let test = TestEmail {
            email: email.clone(),
        };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!("{\"email\":\"test@example.com\"}", json);
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(test, deserialized);
        assert_eq!(email, deserialized.email);

        let borsh = borsh::to_vec(&email).unwrap();
        let borsh_de = Email::try_from_slice(&borsh).unwrap();
        assert_eq!(email, borsh_de);

        let borsh_test = borsh::to_vec(&test).unwrap();
        let borsh_de_test = TestEmail::try_from_slice(&borsh_test).unwrap();
        assert_eq!(test, borsh_de_test);
        assert_eq!(email, borsh_de_test.email);
    }

    #[test]
    fn test_invalid_serialization() {
        let json = "{\"email\":\"\"}";
        let deserialized = serde_json::from_str::<TestEmail>(json);
        assert!(deserialized.is_err());

        let borsh = borsh::to_vec(&String::from("")).expect("works");
        let res = Email::try_from_slice(&borsh);
        assert!(res.is_err());

        let borsh = borsh::to_vec(&String::from("test@example.com")).expect("works");
        let res = Email::try_from_slice(&borsh);
        assert!(res.is_ok());
    }

    #[test]
    fn test_email() {
        let n = Email::new("test@example.com").expect("works");
        let n_owned = Email::new(String::from("test@example.com")).expect("works");
        assert_eq!(n, n_owned);

        assert!(matches!(
            Email::new("totally@$$$12312@sdfds.com"),
            Err(ValidationError::FieldInvalid(Field::Email))
        ));
        assert!(matches!(
            Email::new("12312"),
            Err(ValidationError::FieldInvalid(Field::Email))
        ));
        assert!(matches!(
            Email::new(""),
            Err(ValidationError::FieldEmpty(Field::Email))
        ));
        assert!(matches!(
            Email::new("            "),
            Err(ValidationError::FieldEmpty(Field::Email))
        ));
    }
}
