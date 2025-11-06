pub mod borsh;
pub mod crypto;

pub use crypto::BcrKeys;

use uuid::Uuid;

pub fn is_blank(value: &Option<String>) -> bool {
    matches!(value, Some(s) if s.trim().is_empty())
}

pub fn get_uuid_v4() -> Uuid {
    Uuid::new_v4()
}

pub fn base58_encode(bytes: &[u8]) -> String {
    bitcoin::base58::encode(bytes)
}

pub fn base58_decode(
    input: &str,
) -> std::result::Result<Vec<u8>, bitcoin::base58::InvalidCharacterError> {
    bitcoin::base58::decode(input)
}
