use crate::{Error, Result};
use bcr_ebill_core::protocol::{
    Address, City, Country, File, Name, PostalAddress, Sha256Hash, Zip,
    blockchain::bill::ContactType,
};
use bitcoin::hashes::sha256::Hash as Sha256HexHash;
use sqlx::types::Text;

pub mod contact;
pub mod email_notification;

pub fn decode_file(
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

pub fn decode_postal_address(
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

fn contact_type_to_db(value: &ContactType) -> i64 {
    match value {
        ContactType::Person => 0,
        ContactType::Company => 1,
        ContactType::Anon => 2,
    }
}

fn contact_type_from_db(value: i64) -> Result<ContactType> {
    match value {
        0 => Ok(ContactType::Person),
        1 => Ok(ContactType::Company),
        2 => Ok(ContactType::Anon),
        value => Err(Error::InvalidData(format!("invalid contact type: {value}"))),
    }
}
