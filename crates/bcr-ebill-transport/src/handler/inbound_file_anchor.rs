use crate::{Error, Result};
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::protocol::{File, file_reference::FileReferenceContext};
use bcr_ebill_persistence::FileReferenceStoreApi;
use std::sync::Arc;

pub async fn anchor_important_file(
    file_reference_store: &Arc<dyn FileReferenceStoreApi>,
    file: &File,
    context: FileReferenceContext,
) -> Result<()> {
    file_reference_store
        .upsert(
            &file.hash,
            &file.nostr_hash,
            Some(file.name.clone()),
            vec![],
            Some(true),
            vec![context],
        )
        .await
        .map_err(|e| Error::Persistence(e.to_string()))?;

    Ok(())
}

pub fn company_file_context(company_id: &NodeId, field: &str) -> FileReferenceContext {
    FileReferenceContext::Company {
        company_id: company_id.to_string(),
        field: field.to_string(),
    }
}

pub fn identity_file_context(field: &str) -> FileReferenceContext {
    FileReferenceContext::Identity {
        field: field.to_string(),
    }
}

pub fn contact_file_context(node_id: &NodeId, field: &str) -> FileReferenceContext {
    FileReferenceContext::Contact {
        node_id: node_id.to_string(),
        field: field.to_string(),
    }
}

pub fn bill_file_context(bill_id: &BillId, field: &str) -> FileReferenceContext {
    FileReferenceContext::Bill {
        bill_id: bill_id.to_string(),
        field: field.to_string(),
    }
}
