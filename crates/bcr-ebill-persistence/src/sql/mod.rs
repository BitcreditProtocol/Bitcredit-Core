use crate::{Error, Result};
use bcr_ebill_core::protocol::{
    Address, City, Country, Currency, ExchangeRate, File, Name, PostalAddress, Sha256Hash, Sum,
    Timestamp, Zip, blockchain::bill::ContactType,
};
use bitcoin::hashes::sha256::Hash as Sha256HexHash;
use sqlx::types::Text;

pub mod contact;
pub mod email_notification;
pub mod mint;

pub(crate) fn decode_file(
    name: Option<Text<Name>>,
    hash: Option<Text<Sha256Hash>>,
    nostr_hash: Option<Text<Sha256HexHash>>,
) -> Result<Option<File>> {
    match (name, hash, nostr_hash) {
        (None, None, None) => Ok(None),
        (Some(name), Some(hash), Some(nostr_hash)) => Ok(Some(File {
            name: name.0,
            hash: hash.0,
            nostr_hash: nostr_hash.0,
        })),
        _ => Err(Error::InvalidData("partially populated file".into())),
    }
}

pub(crate) fn decode_postal_address(
    postal_address_country: Option<Text<Country>>,
    postal_address_city: Option<Text<City>>,
    postal_address_zip: Option<Text<Zip>>,
    postal_address_address: Option<Text<Address>>,
) -> Result<Option<PostalAddress>> {
    match (
        postal_address_country,
        postal_address_city,
        postal_address_zip,
        postal_address_address,
    ) {
        (None, None, None, None) => Ok(None),
        (Some(country), Some(city), zip, Some(address)) => Ok(Some(PostalAddress {
            country: country.0,
            city: city.0,
            zip: zip.map(|v| v.0),
            address: address.0,
        })),
        _ => Err(Error::InvalidData(
            "partially populated postal address".into(),
        )),
    }
}

pub(crate) fn contact_type_to_db(value: &ContactType) -> i64 {
    match value {
        ContactType::Person => 0,
        ContactType::Company => 1,
        ContactType::Anon => 2,
    }
}

pub(crate) fn contact_type_from_db(value: i64) -> Result<ContactType> {
    match value {
        0 => Ok(ContactType::Person),
        1 => Ok(ContactType::Company),
        2 => Ok(ContactType::Anon),
        value => Err(Error::InvalidData(format!("invalid contact type: {value}"))),
    }
}

pub(crate) fn u64_to_db(value: u64, field: &'static str) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| Error::InvalidData(format!("{field} exceeds SQL integer range: {value}")))
}

pub(crate) fn u64_from_db(value: i64, field: &'static str) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| Error::InvalidData(format!("invalid negative {field}: {value}")))
}

pub(crate) fn timestamp_to_db(timestamp: Timestamp) -> Result<i64> {
    let value: u64 = timestamp.into();
    u64_to_db(value, "timestamp")
}

pub(crate) fn timestamp_from_db(value: i64) -> Result<Timestamp> {
    let value = u64_from_db(value, "timestamp")?;
    Timestamp::try_from(value)
        .map_err(|_| Error::InvalidData(format!("invalid timestamp: {value}")))
}

pub(crate) struct SumColumns {
    pub amount: i64,
    pub currency_code: String,
    pub currency_decimals: i64,
    pub reference_exchange_rate: Text<ExchangeRate>,
}

impl TryFrom<&Sum> for SumColumns {
    type Error = Error;

    fn try_from(sum: &Sum) -> Result<Self> {
        Ok(Self {
            amount: u64_to_db(sum.amount(), "sum amount")?,
            currency_code: sum.currency().code().to_owned(),
            currency_decimals: i64::from(sum.currency().decimals()),
            reference_exchange_rate: Text(sum.reference_exchange_rate().clone()),
        })
    }
}

pub(crate) fn sum_from_db(
    amount: i64,
    currency_code: String,
    currency_decimals: i64,
    reference_exchange_rate: ExchangeRate,
) -> Result<Sum> {
    let amount = u64_from_db(amount, "sum amount")?;
    let decimals = u8::try_from(currency_decimals).map_err(|_| {
        Error::InvalidData(format!("invalid currency decimals: {currency_decimals}"))
    })?;
    let currency = Currency::new(&currency_code, decimals)
        .map_err(|e| Error::InvalidData(format!("invalid persisted currency: {e}")))?;
    Sum::new(amount, currency, reference_exchange_rate)
        .map_err(|e| Error::InvalidData(format!("invalid persisted sum: {e}")))
}
