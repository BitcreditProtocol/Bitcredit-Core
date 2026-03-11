use bcr_common::core::BillId;
use bcr_common::core::NodeId;
use bcr_ebill_core::application::ValidationError;
use bcr_ebill_core::protocol::EditOptionalFieldMode;
use bcr_ebill_core::protocol::ProtocolValidationError;
use uuid::Uuid;

#[cfg(not(test))]
pub fn get_uuid_v4() -> Uuid {
    Uuid::new_v4()
}

use log::warn;
#[cfg(test)]
use uuid::uuid;

use crate::get_config;

#[cfg(test)]
pub fn get_uuid_v4() -> Uuid {
    uuid!("00000000-0000-0000-0000-000000000000")
}

pub fn update_optional_field<T: Clone + PartialEq>(
    field_to_update: &mut Option<T>,
    field: &Option<T>,
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

pub fn handle_optional_field<T: Clone + PartialEq>(
    field_to_update: &mut Option<T>,
    field: &EditOptionalFieldMode<T>,
    changed: &mut bool,
) {
    match field {
        EditOptionalFieldMode::Set(new_data) => {
            // set the field if the value is different
            if field_to_update.as_ref() != Some(new_data) {
                *field_to_update = Some(new_data.to_owned());
                *changed = true;
            }
        }
        EditOptionalFieldMode::Unset => {
            // if it's set, unset it
            if field_to_update.is_some() {
                *field_to_update = None;
                *changed = true;
            }
        }
        EditOptionalFieldMode::Ignore => {
            // nothing to do
        }
    }
}

pub fn validate_node_id_network(node_id: &NodeId) -> Result<(), ValidationError> {
    if node_id.network() != get_config().bitcoin_network() {
        warn!("Detected node id of wrong network {node_id}");
        return Err(ProtocolValidationError::InvalidNodeId.into());
    }

    Ok(())
}

pub fn validate_bill_id_network(bill_id: &BillId) -> Result<(), ValidationError> {
    if bill_id.network() != get_config().bitcoin_network() {
        warn!("Detected bill id of wrong network {bill_id}");
        return Err(ProtocolValidationError::InvalidBillId.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use bcr_ebill_core::protocol::Country;

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
        let mut field_to_update: Option<Country> = None;
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

    #[test]
    fn handle_optional_field_set() {
        let mut field_to_update = Some(String::from("hi"));
        let mut changed = false;
        handle_optional_field(
            &mut field_to_update,
            &EditOptionalFieldMode::Set(String::from("hello")),
            &mut changed,
        );
        assert!(changed);
        assert_eq!(Some(String::from("hello")), field_to_update);
    }

    #[test]
    fn handle_optional_field_set_same_value() {
        let mut field_to_update = Some(String::from("hi"));
        let mut changed = false;
        handle_optional_field(
            &mut field_to_update,
            &EditOptionalFieldMode::Set(String::from("hi")),
            &mut changed,
        );
        assert!(!changed);
        assert_eq!(Some(String::from("hi")), field_to_update);
    }

    #[test]
    fn handle_optional_field_unset() {
        let mut field_to_update = Some(String::from("hi"));
        let mut changed = false;
        handle_optional_field(
            &mut field_to_update,
            &EditOptionalFieldMode::Unset,
            &mut changed,
        );
        assert!(changed);
        assert_eq!(None, field_to_update);
    }

    #[test]
    fn handle_optional_field_ignore() {
        let mut field_to_update = Some(String::from("hi"));
        let mut changed = false;
        handle_optional_field(
            &mut field_to_update,
            &EditOptionalFieldMode::Ignore,
            &mut changed,
        );
        assert!(!changed);
        assert_eq!(Some(String::from("hi")), field_to_update);
    }
}
