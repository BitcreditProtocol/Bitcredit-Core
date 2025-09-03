pub mod file;
pub mod numbers_to_words;

pub use bcr_ebill_core::Field;
pub use bcr_ebill_core::ValidationError;
pub use bcr_ebill_core::constants::VALID_CURRENCIES;
pub use bcr_ebill_core::util::crypto;
pub use bcr_ebill_core::util::currency;
pub use bcr_ebill_core::util::date;
pub use bcr_ebill_core::util::validate_file_upload_id;

pub use bcr_ebill_core::util::BcrKeys;
pub use bcr_ebill_core::util::Error;

pub use bcr_ebill_core::util::base58_decode;
pub use bcr_ebill_core::util::base58_encode;

#[cfg(not(test))]
pub use bcr_ebill_core::util::get_uuid_v4;

#[cfg(test)]
use uuid::{Uuid, uuid};

#[cfg(test)]
pub fn get_uuid_v4() -> Uuid {
    uuid!("00000000-0000-0000-0000-000000000000")
}

pub use bcr_ebill_core::util::sha256_hash;

pub fn update_optional_field(
    field_to_update: &mut Option<String>,
    field: &Option<String>,
    changed: &mut bool,
) {
    match field_to_update {
        Some(_) => {
            if let Some(field_to_set) = field {
                *field_to_update = Some(field_to_set.clone());
                *changed = true;
            } else {
                *field_to_update = None;
                *changed = true;
            }
        }
        None => {
            if let Some(field_to_set) = field {
                *field_to_update = Some(field_to_set.clone());
                *changed = true;
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_optional_field_baseline() {
        let mut field_to_update = Some(String::from("hi"));
        let mut changed = false;
        update_optional_field(
            &mut field_to_update,
            &Some(String::from("hello")),
            &mut changed,
        );
        assert!(changed);
        assert_eq!(Some(String::from("hello")), field_to_update);
    }

    #[test]
    fn update_optional_field_none() {
        let mut field_to_update = None;
        let mut changed = false;
        update_optional_field(&mut field_to_update, &None, &mut changed);
        assert!(!changed);
        assert_eq!(None, field_to_update);
    }

    #[test]
    fn update_optional_field_some_none() {
        let mut field_to_update = Some(String::from("hi"));
        let mut changed = false;
        update_optional_field(&mut field_to_update, &None, &mut changed);
        assert!(changed);
        assert_eq!(None, field_to_update);
    }
}
