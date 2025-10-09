use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{Field, ValidationError};

const MAX_ZIP_LEN: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct Zip(String);

impl Zip {
    pub fn new(n: impl Into<String>) -> Result<Self, ValidationError> {
        let s = ammonia::clean(&n.into());

        if s.trim().is_empty() {
            return Err(ValidationError::FieldEmpty(Field::Zip));
        }

        if s.len() > MAX_ZIP_LEN {
            return Err(ValidationError::FieldInvalid(Field::Zip));
        }

        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for Zip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Zip {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Zip::new(s)
    }
}

impl borsh::BorshSerialize for Zip {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        borsh::BorshSerialize::serialize(&self.0, writer)
    }
}

impl borsh::BorshDeserialize for Zip {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let zip_str: String = borsh::BorshDeserialize::deserialize_reader(reader)?;
        Zip::new(&zip_str).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
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
    pub struct TestZip {
        pub zip: Zip,
    }

    #[test]
    fn test_serialization() {
        let zip = Zip::new("Wien").expect("works");
        let test = TestZip { zip: zip.clone() };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!("{\"zip\":\"Wien\"}", json);
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(test, deserialized);
        assert_eq!(zip, deserialized.zip);

        let borsh = borsh::to_vec(&zip).unwrap();
        let borsh_de = Zip::try_from_slice(&borsh).unwrap();
        assert_eq!(zip, borsh_de);

        let borsh_test = borsh::to_vec(&test).unwrap();
        let borsh_de_test = TestZip::try_from_slice(&borsh_test).unwrap();
        assert_eq!(test, borsh_de_test);
        assert_eq!(zip, borsh_de_test.zip);
    }

    #[test]
    fn test_name() {
        let n = Zip::new("1020").expect("works");
        let n_owned = Zip::new(String::from("1020")).expect("works");
        assert_eq!(n, n_owned);
        assert_eq!(
            Zip::new("10<script>window.alert('HELLO');</script>20")
                .expect("works")
                .as_str(),
            "1020"
        );

        assert!(matches!(
            Zip::new("1021021021021021020000001020"),
            Err(ValidationError::FieldInvalid(Field::Zip))
        ));
        assert!(matches!(
            Zip::new(""),
            Err(ValidationError::FieldEmpty(Field::Zip))
        ));
        assert!(matches!(
            Zip::new("            "),
            Err(ValidationError::FieldEmpty(Field::Zip))
        ));
    }
}
