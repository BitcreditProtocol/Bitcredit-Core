pub mod borsh;
pub mod crypto;
pub mod currency;
pub mod date;

pub use crypto::BcrKeys;

use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256;
use thiserror::Error;
use uuid::Uuid;

use crate::ValidationError;

pub fn validate_file_upload_id(file_upload_id: Option<&str>) -> Result<(), ValidationError> {
    if let Some(id) = file_upload_id
        && id.trim().is_empty()
    {
        return Err(ValidationError::InvalidFileUploadId);
    }
    Ok(())
}

pub fn is_blank(value: &Option<String>) -> bool {
    matches!(value, Some(s) if s.trim().is_empty())
}

pub fn get_uuid_v4() -> Uuid {
    Uuid::new_v4()
}

pub fn sha256_hash(bytes: &[u8]) -> String {
    let hash = sha256::Hash::hash(bytes).to_byte_array();
    base58_encode(hash.as_slice())
}

#[derive(Debug, Error)]
pub enum Error {
    /// Errors stemming base58 decoding
    #[error("Decode base58 error: {0}")]
    Base58(bitcoin::base58::InvalidCharacterError),
}

pub fn base58_encode(bytes: &[u8]) -> String {
    bitcoin::base58::encode(bytes)
}

pub fn base58_decode(input: &str) -> std::result::Result<Vec<u8>, Error> {
    bitcoin::base58::decode(input).map_err(Error::Base58)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validate_file_upload_id_baseline() {
        assert!(validate_file_upload_id(Some("")).is_err(),);
        assert!(validate_file_upload_id(Some("test")).is_ok(),);
    }
}
