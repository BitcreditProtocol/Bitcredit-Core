use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{Field, ValidationError};

const MAX_CITY_LEN: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct City(String);

impl City {
    pub fn new(n: impl Into<String>) -> Result<Self, ValidationError> {
        let s = ammonia::clean(&n.into());

        if s.trim().is_empty() {
            return Err(ValidationError::FieldEmpty(Field::City));
        }

        if s.len() > MAX_CITY_LEN {
            return Err(ValidationError::FieldInvalid(Field::City));
        }

        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for City {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for City {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        City::new(s)
    }
}

impl borsh::BorshSerialize for City {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        borsh::BorshSerialize::serialize(&self.0, writer)
    }
}

impl borsh::BorshDeserialize for City {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let city_str: String = borsh::BorshDeserialize::deserialize_reader(reader)?;
        City::new(&city_str).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
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
    pub struct TestCity {
        pub city: City,
    }

    #[test]
    fn test_serialization() {
        let city = City::new("Wien").expect("works");
        let test = TestCity { city: city.clone() };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!("{\"city\":\"Wien\"}", json);
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(test, deserialized);
        assert_eq!(city, deserialized.city);

        let borsh = borsh::to_vec(&city).unwrap();
        let borsh_de = City::try_from_slice(&borsh).unwrap();
        assert_eq!(city, borsh_de);

        let borsh_test = borsh::to_vec(&test).unwrap();
        let borsh_de_test = TestCity::try_from_slice(&borsh_test).unwrap();
        assert_eq!(test, borsh_de_test);
        assert_eq!(city, borsh_de_test.city);
    }

    #[test]
    fn test_name() {
        let n = City::new("Wien").expect("works");
        let n_owned = City::new(String::from("Wien")).expect("works");
        assert_eq!(n, n_owned);
        assert_eq!(
            City::new("Wi<script>window.alert('HELLO');</script>en")
                .expect("works")
                .as_str(),
            "Wien"
        );

        assert!(matches!(
            City::new(
                "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww"
            ),
            Err(ValidationError::FieldInvalid(Field::City))
        ));
        assert!(matches!(
            City::new(""),
            Err(ValidationError::FieldEmpty(Field::City))
        ));
        assert!(matches!(
            City::new("            "),
            Err(ValidationError::FieldEmpty(Field::City))
        ));
    }
}
