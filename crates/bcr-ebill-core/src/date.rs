use std::{fmt::Display, str::FromStr};

use chrono::{NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::{ValidationError, util::date::DateTimeUtc};

pub const DEFAULT_DATE_FORMAT: &str = "%Y-%m-%d";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct Date(String);

impl Date {
    pub fn new(n: impl Into<String>) -> Result<Self, ValidationError> {
        let s = n.into();
        NaiveDate::parse_from_str(&s, DEFAULT_DATE_FORMAT)
            .map_err(|_| ValidationError::InvalidDate)?
            .and_hms_opt(0, 0, 0)
            .ok_or(ValidationError::InvalidDate)?;

        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_timestamp(&self) -> u64 {
        let naive_date_time = NaiveDate::parse_from_str(&self.0, DEFAULT_DATE_FORMAT)
            .expect("has the right format")
            .and_hms_opt(0, 0, 0)
            .expect("can set time");
        let date_utc = Utc.from_utc_datetime(&naive_date_time);

        date_utc.timestamp() as u64
    }
}

impl From<DateTimeUtc> for Date {
    fn from(value: DateTimeUtc) -> Self {
        Date(value.format(DEFAULT_DATE_FORMAT).to_string())
    }
}

impl Display for Date {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Date {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Date::new(s)
    }
}

impl borsh::BorshSerialize for Date {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        borsh::BorshSerialize::serialize(&self.0, writer)
    }
}

impl borsh::BorshDeserialize for Date {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let date_str: String = borsh::BorshDeserialize::deserialize_reader(reader)?;
        Date::new(&date_str).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
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
    pub struct TestDate {
        pub date: Date,
    }

    #[test]
    fn test_serialization() {
        let date = Date::new("2025-01-15").expect("works");
        let test = TestDate { date: date.clone() };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!("{\"date\":\"2025-01-15\"}", json);
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(test, deserialized);
        assert_eq!(date, deserialized.date);

        let borsh = borsh::to_vec(&date).unwrap();
        let borsh_de = Date::try_from_slice(&borsh).unwrap();
        assert_eq!(date, borsh_de);

        let borsh_test = borsh::to_vec(&test).unwrap();
        let borsh_de_test = TestDate::try_from_slice(&borsh_test).unwrap();
        assert_eq!(test, borsh_de_test);
        assert_eq!(date, borsh_de_test.date);
    }

    #[test]
    fn test_date() {
        let n = Date::new("2025-01-15").expect("works");
        let n_owned = Date::new(String::from("2025-01-15")).expect("works");
        assert_eq!(n, n_owned);

        assert!(matches!(
            Date::new("1234"),
            Err(ValidationError::InvalidDate)
        ));
        assert!(matches!(
            Date::new("01.03.2025"),
            Err(ValidationError::InvalidDate)
        ));
    }

    #[test]
    fn test_date_string_to_timestamp_with_default_format() {
        let date_str = "2025-01-15";
        let expected_timestamp = Utc
            .with_ymd_and_hms(2025, 1, 15, 0, 0, 0)
            .unwrap()
            .timestamp() as u64;
        assert_eq!(
            Date::new(date_str).unwrap().to_timestamp(),
            expected_timestamp
        );
    }

    #[test]
    fn test_date_string_to_timestamp_with_invalid_date() {
        assert!(Date::new("2025-32-99").is_err());
        assert!(Date::new("2025/01/15").is_err());
        assert!(Date::new("").is_err());
    }
}
