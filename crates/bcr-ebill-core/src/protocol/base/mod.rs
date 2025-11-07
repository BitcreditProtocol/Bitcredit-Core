use borsh_derive::{BorshDeserialize, BorshSerialize};
use chrono::{DateTime, Utc};
use nostr::hashes::sha256::Hash as Sha256HexHash;
use serde::{Deserialize, Serialize};
use std::fmt;

pub mod address;
pub mod block_id;
pub mod city;
pub mod country;
pub mod date;
pub mod email;
pub mod hash;
pub mod identification;
pub mod identity_proof;
pub mod name;
pub mod signature;
pub mod sum;
pub mod timestamp;
pub mod zip;

use address::Address;
use city::City;
use country::Country;
use hash::Sha256Hash;
use name::Name;
use zip::Zip;

use crate::protocol::{Field, ProtocolValidationError};

pub type DateTimeUtc = DateTime<Utc>;
pub type BitcoinAddress = bitcoin::Address<bitcoin::address::NetworkUnchecked>;

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PostalAddress {
    pub country: Country,
    pub city: City,
    pub zip: Option<Zip>,
    pub address: Address,
}

impl fmt::Display for PostalAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.zip {
            Some(ref zip) => {
                write!(
                    f,
                    "{}, {} {}, {}",
                    self.address, zip, self.city, self.country
                )
            }
            None => {
                write!(f, "{}, {}, {}", self.address, self.city, self.country)
            }
        }
    }
}

#[derive(
    BorshSerialize, BorshDeserialize, Default, Serialize, Deserialize, Debug, Clone, PartialEq, Eq,
)]
pub struct OptionalPostalAddress {
    pub country: Option<Country>,
    pub city: Option<City>,
    pub zip: Option<Zip>,
    pub address: Option<Address>,
}

impl OptionalPostalAddress {
    pub fn empty() -> Self {
        Self {
            country: None,
            city: None,
            zip: None,
            address: None,
        }
    }

    pub fn from_postal_address(address: &PostalAddress) -> Self {
        Self {
            country: Some(address.country.clone()),
            city: Some(address.city.clone()),
            zip: address.zip.clone(),
            address: Some(address.address.clone()),
        }
    }

    pub fn is_fully_set(&self) -> bool {
        self.country.is_some() && self.city.is_some() && self.address.is_some()
    }

    pub fn to_full_postal_address(&self) -> Option<PostalAddress> {
        if self.is_fully_set() {
            return Some(PostalAddress {
                country: self.country.clone().expect("checked above"),
                city: self.city.clone().expect("checked above"),
                zip: self.zip.clone(),
                address: self.address.clone().expect("checked above"),
            });
        }
        None
    }

    pub fn validate_to_be_non_optional(&self) -> Result<(), ProtocolValidationError> {
        if self.country.is_none() {
            return Err(ProtocolValidationError::FieldEmpty(Field::Country));
        }

        if self.city.is_none() {
            return Err(ProtocolValidationError::FieldEmpty(Field::City));
        }

        if self.address.is_none() {
            return Err(ProtocolValidationError::FieldEmpty(Field::Address));
        }

        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub name: Name,
    pub hash: Sha256Hash, // the hash over the unencrypted file
    #[borsh(
        serialize_with = "crate::protocol::serialization::serialize_sha256_hex_hash",
        deserialize_with = "crate::protocol::serialization::deserialize_sha256_hex_hash"
    )]
    pub nostr_hash: Sha256HexHash, // the identification hash on Nostr for the encrypted file, sha256 as hex
}
