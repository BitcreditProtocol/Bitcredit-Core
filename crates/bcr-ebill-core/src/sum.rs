use std::fmt::Display;

use crate::{ValidationError, constants::CURRENCY_SAT};
use borsh_derive::{BorshDeserialize, BorshSerialize};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct Sum {
    /// Amount in minor-unit scale, e.g. 1225 for 12.25 EUR, 1000 for 1000 SAT, the scale is gotten from the currency's decimal value
    /// We use u64, since u64::MAX is ~8700x larger than the maximum possible amount of satoshis
    amount: u64,
    /// The currency
    currency: Currency,
    /// The exchange rate against our reference (SAT), e.g. 1 for SAT, 1021 for EUR
    reference_exchange_rate: ExchangeRate,
}

impl Sum {
    pub fn new(
        amount: u64,
        currency: Currency,
        reference_exchange_rate: ExchangeRate,
    ) -> Result<Self, ValidationError> {
        if amount == 0 {
            return Err(ValidationError::InvalidSum);
        }

        Ok(Self {
            amount,
            currency,
            reference_exchange_rate,
        })
    }

    /// Allows to create zero sums - useful to e.g. show balances, where 0 is a valid value
    fn new_zero_allowed(
        amount: u64,
        currency: Currency,
        reference_exchange_rate: ExchangeRate,
    ) -> Self {
        Self {
            amount,
            currency,
            reference_exchange_rate,
        }
    }

    pub fn currency(&self) -> &Currency {
        &self.currency
    }

    pub fn new_sat(amount: u64) -> Result<Self, ValidationError> {
        Self::new(amount, Currency::sat(), ExchangeRate::sat())
    }

    pub fn new_sat_from_str(amount: &str) -> Result<Self, ValidationError> {
        match amount.parse::<u64>() {
            Ok(num) => Self::new(num, Currency::sat(), ExchangeRate::sat()),
            Err(_) => Err(ValidationError::InvalidSum),
        }
    }

    pub fn new_sat_zero_allowed(amount: u64) -> Self {
        Self::new_zero_allowed(amount, Currency::sat(), ExchangeRate::sat())
    }

    pub fn as_btc_string(&self) -> String {
        // TODO (currency): in the future, we have to calculate this based on the exchange rate, if the currency is not SAT
        let amount = bitcoin::Amount::from_sat(self.amount);
        amount.to_string_in(bitcoin::Denomination::Bitcoin)
    }

    pub fn as_sat(&self) -> u64 {
        // TODO (currency): in the future, we have to calculate this based on the exchange rate, if the currency is not SAT
        self.amount
    }

    pub fn as_sat_string(&self) -> String {
        // TODO (currency): in the future, we have to calculate this based on the exchange rate, if the currency is not SAT
        self.amount.to_string()
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, PartialOrd, Ord, Hash,
)]
pub struct Currency {
    #[serde(
        serialize_with = "serialize_currency_code",
        deserialize_with = "deserialize_currency_code"
    )]
    /// ISO 4217 code for the currency, e.g. [83,65,84] for "sat", serialized as a string with serde for human readability
    code: [u8; 3],
    #[serde(deserialize_with = "deserialize_decimals")]
    /// Number of decimals for the currency in minor-unit scale - e.g. 0 for SAT, 2 for EUR etc.
    decimals: u8,
}

impl Display for Currency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.code().fmt(f)
    }
}

impl From<bitcoin::Amount> for Sum {
    fn from(value: bitcoin::Amount) -> Self {
        Self::new_sat_zero_allowed(value.to_sat())
    }
}

impl Currency {
    pub fn new(code: &str, decimals: u8) -> Result<Self, ValidationError> {
        Ok(Self {
            code: canonicalize_code(code)?,
            decimals: validate_decimals(decimals)?,
        })
    }

    pub fn code(&self) -> &str {
        // safe, because we only store and deserialize to ascii uppercase bytes
        std::str::from_utf8(&self.code).expect("code is safe ascii")
    }

    pub fn decimals(&self) -> u8 {
        self.decimals
    }

    pub fn sat() -> Self {
        Self::new(CURRENCY_SAT, 0).expect("sat is a valid currency")
    }
}

// currency code is iso 4217 - 3 uppercase ascii characters
fn canonicalize_code(code: &str) -> Result<[u8; 3], ValidationError> {
    let up = code.to_ascii_uppercase();
    if up.len() != 3
        || !up
            .chars()
            .all(|c| c.is_ascii_uppercase() && c.is_ascii_alphabetic())
    {
        return Err(ValidationError::InvalidCurrency);
    }
    let mut arr = [0u8; 3];
    arr.copy_from_slice(up.as_bytes());
    Ok(arr)
}

fn validate_decimals(d: u8) -> Result<u8, ValidationError> {
    // we don't support other crypto currencies
    if d > 5 {
        Err(ValidationError::InvalidCurrency)
    } else {
        Ok(d)
    }
}

fn serialize_currency_code<S>(code: &[u8; 3], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let s = std::str::from_utf8(code).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(s)
}

// Custom deserialization, to make sure it's validated
fn deserialize_currency_code<'de, D>(deserializer: D) -> Result<[u8; 3], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = <String>::deserialize(deserializer)?;
    canonicalize_code(&s).map_err(serde::de::Error::custom)
}

// Custom deserialization, to make sure it's validated
fn deserialize_decimals<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let d = u8::deserialize(deserializer)?;
    validate_decimals(d).map_err(serde::de::Error::custom)
}

// Custom deserialization, to make sure it's validated
impl borsh::BorshDeserialize for Currency {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let code_raw: [u8; 3] = <[u8; 3]>::deserialize_reader(reader)?;
        let decimals_raw: u8 = u8::deserialize_reader(reader)?;

        let code_str = std::str::from_utf8(&code_raw).map_err(|_| {
            borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "currency code must be ASCII",
            )
        })?;

        let code = canonicalize_code(code_str).map_err(|_| {
            borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, "invalid currency code")
        })?;

        let decimals = validate_decimals(decimals_raw).map_err(|_| {
            borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "invalid currency decimals",
            )
        })?;

        Ok(Currency { code, decimals })
    }
}

/// The exchange rate, stored as a fixed decimal number
/// Serialized as mantissa/scale in borsh
/// Serialized as string with serde for human readability
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
pub struct ExchangeRate(Decimal);

impl ExchangeRate {
    pub fn sat() -> Self {
        // sats convert to each other 1:1
        ExchangeRate(Decimal::new(1, 0))
    }
}

impl borsh::BorshSerialize for ExchangeRate {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        let mantissa: i128 = self.0.mantissa();
        let scale: u32 = self.0.scale();
        borsh::BorshSerialize::serialize(&mantissa, writer)?;
        borsh::BorshSerialize::serialize(&scale, writer)?;
        Ok(())
    }
}

impl borsh::BorshDeserialize for ExchangeRate {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let mantissa: i128 = borsh::BorshDeserialize::deserialize_reader(reader)?;
        let scale: u32 = borsh::BorshDeserialize::deserialize_reader(reader)?;
        let d = Decimal::from_i128_with_scale(mantissa, scale);
        Ok(ExchangeRate(d))
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
    pub struct TestSum {
        pub sum: Sum,
    }

    #[test]
    fn test_serialization() {
        let sum = Sum::new_sat(1500).expect("works");
        let test = TestSum { sum: sum.clone() };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!(
            "{\"sum\":{\"amount\":1500,\"currency\":{\"code\":\"SAT\",\"decimals\":0},\"reference_exchange_rate\":\"1\"}}",
            json
        );
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(test, deserialized);
        assert_eq!(sum, deserialized.sum);

        let sum = Sum::new(
            1500,
            Currency::new("EUR", 2).expect("works"),
            ExchangeRate(Decimal::new(102100, 2)),
        )
        .expect("works");
        let test = TestSum { sum: sum.clone() };
        let json = serde_json::to_string(&test).unwrap();
        assert_eq!(
            "{\"sum\":{\"amount\":1500,\"currency\":{\"code\":\"EUR\",\"decimals\":2},\"reference_exchange_rate\":\"1021.00\"}}",
            json
        );
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(test, deserialized);
        assert_eq!(sum, deserialized.sum);

        let borsh = borsh::to_vec(&sum).unwrap();
        let borsh_de = Sum::try_from_slice(&borsh).unwrap();
        assert_eq!(sum, borsh_de);

        let borsh_test = borsh::to_vec(&test).unwrap();
        let borsh_de_test = TestSum::try_from_slice(&borsh_test).unwrap();
        assert_eq!(test, borsh_de_test);
        assert_eq!(sum, borsh_de_test.sum);
        assert_eq!(
            sum.reference_exchange_rate,
            borsh_de_test.sum.reference_exchange_rate
        );
    }

    #[test]
    fn test_sum() {
        let n = Sum::new_sat(1500).expect("works");
        let n_other = Sum::new(1500, Currency::sat(), ExchangeRate::sat()).expect("works");
        assert_eq!(n, n_other);
        let n_other_str = Sum::new_sat_from_str("1500").expect("works");
        assert_eq!(n, n_other_str);

        assert!(matches!(
            Currency::new("invalidcurrency", 2),
            Err(ValidationError::InvalidCurrency)
        ));
        assert!(matches!(
            Currency::new("sa", 2),
            Err(ValidationError::InvalidCurrency)
        ));
        assert!(matches!(Sum::new_sat(0), Err(ValidationError::InvalidSum)));
    }

    #[test]
    fn serde_accepts_lowercase_and_canonicalizes() {
        let res: Currency =
            serde_json::from_str(r#"{ "code": "eur", "decimals": 2 }"#).expect("works");
        assert_eq!(res.code(), "EUR");
        assert_eq!(res.decimals(), 2);
    }

    #[test]
    fn serde_rejects_wrong_length() {
        let res = serde_json::from_str::<Currency>(r#"{ "code": "EU", "decimals": 2 }"#);
        assert!(res.is_err());
    }

    #[test]
    fn serde_rejects_non_letters() {
        let res = serde_json::from_str::<Currency>(r#"{ "code": "E2R", "decimals": 2 }"#);
        assert!(res.is_err());
    }

    #[test]
    fn serde_rejects_too_many_decimals() {
        let res = serde_json::from_str::<Currency>(r#"{ "code": "EUR", "decimals": 6 }"#);
        assert!(res.is_err());
    }

    #[test]
    fn borsh_roundtrip_valid() {
        let c = Currency::new("eur", 2).expect("works");
        let bytes = borsh::to_vec(&c).expect("works");
        let res = Currency::try_from_slice(&bytes).expect("works");
        assert_eq!(res, c);
        assert_eq!(res.code(), "EUR");
    }

    #[test]
    fn borsh_accepts_lowercase_bytes_and_canonicalizes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"eur");
        bytes.push(2);
        let res = Currency::try_from_slice(&bytes).expect("works");
        assert_eq!(res.code(), "EUR");
        assert_eq!(res.decimals(), 2);
    }

    #[test]
    fn borsh_rejects_invalid_utf8_code_bytes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0xFF, 0xFE, 0xFD]); // invalid UTF-8
        bytes.push(2);
        let res = Currency::try_from_slice(&bytes);
        assert!(res.is_err());
    }

    #[test]
    fn borsh_rejects_non_alphabet() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"E2R");
        bytes.push(2);
        let res = Currency::try_from_slice(&bytes);
        assert!(res.is_err());
    }

    #[test]
    fn borsh_rejects_wrong_length() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"Eu "); // space is not alphabetic
        bytes.push(2);
        let res = Currency::try_from_slice(&bytes);
        assert!(res.is_err());
    }

    #[test]
    fn borsh_rejects_too_many_decimals() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"EUR");
        bytes.push(6);
        let res = Currency::try_from_slice(&bytes);
        assert!(res.is_err());
    }

    #[test]
    fn constructor_validates_same_rules() {
        assert!(Currency::new("sat", 2).is_ok()); // normalized to SAT
        assert!(Currency::new("s4t", 2).is_err()); // only alphabetic
        assert!(Currency::new("SA", 2).is_err()); // wrong length
        assert!(Currency::new("EUR", 6).is_err()); // decimals > 5
        assert_eq!(Currency::new("eur", 2).unwrap().code(), "EUR"); // uppercases
    }
}
