pub use bcr_ebill_core::bill;
pub use bcr_ebill_core::company;
pub use bcr_ebill_core::contact;
pub use bcr_ebill_core::identity;
pub use bcr_ebill_core::mint;
pub use bcr_ebill_core::nostr_contact;
pub use bcr_ebill_core::notification;

pub use bcr_ebill_core::File;
pub use bcr_ebill_core::GeneralSearchFilterItemType;
pub use bcr_ebill_core::GeneralSearchResult;
pub use bcr_ebill_core::NodeId;
pub use bcr_ebill_core::OptionalPostalAddress;
pub use bcr_ebill_core::PostalAddress;
pub use bcr_ebill_core::PublicKey;
pub use bcr_ebill_core::SecretKey;
pub use bcr_ebill_core::UploadFileResult;
use bcr_ebill_core::ValidationError;
use log::warn;

use crate::get_config;

pub fn validate_node_id_network(node_id: &NodeId) -> Result<(), ValidationError> {
    if node_id.network() != get_config().bitcoin_network() {
        warn!("Detected node id of wrong network {node_id}");
        return Err(ValidationError::InvalidNodeId);
    }

    Ok(())
}

pub fn validate_bill_id_network(bill_id: &bill::BillId) -> Result<(), ValidationError> {
    if bill_id.network() != get_config().bitcoin_network() {
        warn!("Detected bill id of wrong network {bill_id}");
        return Err(ValidationError::InvalidBillId);
    }

    Ok(())
}
