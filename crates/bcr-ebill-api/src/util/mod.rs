use bcr_common::core::BillId;
use bcr_common::core::NodeId;
use bcr_ebill_core::ValidationError;

#[cfg(not(test))]
pub(crate) use bcr_ebill_core::util::get_uuid_v4;

use log::warn;
#[cfg(test)]
use uuid::{Uuid, uuid};

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

pub fn validate_node_id_network(node_id: &NodeId) -> Result<(), ValidationError> {
    if node_id.network() != get_config().bitcoin_network() {
        warn!("Detected node id of wrong network {node_id}");
        return Err(ValidationError::InvalidNodeId);
    }

    Ok(())
}

pub fn validate_bill_id_network(bill_id: &BillId) -> Result<(), ValidationError> {
    if bill_id.network() != get_config().bitcoin_network() {
        warn!("Detected bill id of wrong network {bill_id}");
        return Err(ValidationError::InvalidBillId);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use bcr_ebill_core::country::Country;

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
}
