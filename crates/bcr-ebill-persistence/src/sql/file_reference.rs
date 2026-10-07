use crate::{
    Error, Result,
    sql::{timestamp_from_db, timestamp_to_db},
};
use bcr_ebill_core::protocol::{
    Name, Sha256Hash,
    file_reference::{FileReference, FileReferenceContext},
};
use bitcoin::hashes::sha256::Hash as Sha256HexHash;
use sqlx::types::Text;

// SQL
pub(crate) const SELECT_FILE_REFERENCE: &str = r#"
    SELECT
        hash,
        nostr_hash,
        name,
        server_urls,
        is_important,
        created_at,
        updated_at
    FROM file_reference
    WHERE hash = $1
"#;

pub(crate) const SELECT_BY_NOSTR_HASH: &str = r#"
    SELECT
        hash,
        nostr_hash,
        name,
        server_urls,
        is_important,
        created_at,
        updated_at
    FROM file_reference
    WHERE nostr_hash = $1
    LIMIT 1
"#;

pub(crate) const SELECT_CONTEXTS: &str = r#"
    SELECT
        file_reference_hash,
        position,
        context_type,
        context_field,
        context_company_id,
        context_node_id,
        context_bill_id
    FROM file_reference_context
    WHERE file_reference_hash = $1
    ORDER BY position ASC
"#;

pub(crate) const INSERT_FILE_REFERENCE_IF_ABSENT: &str = r#"
    INSERT INTO file_reference (
        hash,
        nostr_hash,
        name,
        server_urls,
        is_important,
        created_at,
        updated_at
    )
    VALUES (
        $1, $2, $3, $4,
        $5, $6, $7
    )
    ON CONFLICT (hash) DO NOTHING
"#;

pub(crate) const UPDATE_FILE_REFERENCE: &str = r#"
    UPDATE file_reference
    SET
        nostr_hash = $2,
        name = $3,
        server_urls = $4,
        is_important = $5,
        updated_at = $6
    WHERE hash = $1
"#;

pub(crate) const INSERT_CONTEXT: &str = r#"
    INSERT INTO file_reference_context (
        file_reference_hash,
        position,
        context_type,
        context_field,
        context_company_id,
        context_node_id,
        context_bill_id
    )
    VALUES (
        $1, $2, $3, $4,
        $5, $6, $7
    )
"#;

pub(crate) const DELETE_CONTEXTS: &str = r#"
    DELETE FROM file_reference_context
    WHERE file_reference_hash = $1
"#;

pub(crate) const DELETE_FILE_REFERENCE: &str = r#"
    DELETE FROM file_reference
    WHERE hash = $1
"#;

pub(crate) const SELECT_ALL: &str = r#"
    SELECT
        hash,
        nostr_hash,
        name,
        server_urls,
        is_important,
        created_at,
        updated_at
    FROM file_reference
"#;

pub(crate) const SELECT_IMPORTANT: &str = r#"
    SELECT
        hash,
        nostr_hash,
        name,
        server_urls,
        is_important,
        created_at,
        updated_at
    FROM file_reference
    WHERE is_important = true
"#;

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct FileReferenceRow {
    pub hash: Text<Sha256Hash>,
    pub nostr_hash: Text<Sha256HexHash>,
    pub name: Option<Text<Name>>,
    pub server_urls: String,
    pub is_important: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct FileReferenceContextRow {
    pub file_reference_hash: Text<Sha256Hash>,
    pub position: i64,
    pub context_type: String,
    pub context_field: Option<String>,
    pub context_company_id: Option<String>,
    pub context_node_id: Option<String>,
    pub context_bill_id: Option<String>,
}

pub(crate) fn context_to_row(
    hash: &Sha256Hash,
    position: usize,
    context: &FileReferenceContext,
) -> Result<FileReferenceContextRow> {
    let position = i64::try_from(position).map_err(|_| {
        Error::InvalidData("file reference context position exceeds i64".to_owned())
    })?;

    let mut row = FileReferenceContextRow {
        file_reference_hash: Text(hash.clone()),
        position,
        context_type: String::new(),
        context_field: None,
        context_company_id: None,
        context_node_id: None,
        context_bill_id: None,
    };

    match context {
        FileReferenceContext::Identity { field } => {
            row.context_type = "identity".to_owned();
            row.context_field = Some(field.clone());
        }
        FileReferenceContext::Company { company_id, field } => {
            row.context_type = "company".to_owned();
            row.context_field = Some(field.clone());
            row.context_company_id = Some(company_id.clone());
        }
        FileReferenceContext::Contact { node_id, field } => {
            row.context_type = "contact".to_owned();
            row.context_field = Some(field.clone());
            row.context_node_id = Some(node_id.clone());
        }
        FileReferenceContext::Bill { bill_id, field } => {
            row.context_type = "bill".to_owned();
            row.context_field = Some(field.clone());
            row.context_bill_id = Some(bill_id.clone());
        }
        FileReferenceContext::DirectUpload => {
            row.context_type = "direct_upload".to_owned();
        }
        FileReferenceContext::Unknown => {
            row.context_type = "unknown".to_owned();
        }
    }
    Ok(row)
}

impl TryFrom<FileReferenceContextRow> for FileReferenceContext {
    type Error = Error;

    fn try_from(row: FileReferenceContextRow) -> Result<Self> {
        match row.context_type.as_str() {
            "identity" => Ok(FileReferenceContext::Identity {
                field: row.context_field.ok_or_else(|| {
                    Error::InvalidData("missing identity context field".to_owned())
                })?,
            }),
            "company" => Ok(FileReferenceContext::Company {
                company_id: row
                    .context_company_id
                    .ok_or_else(|| Error::InvalidData("missing company context id".to_owned()))?,
                field: row.context_field.ok_or_else(|| {
                    Error::InvalidData("missing company context field".to_owned())
                })?,
            }),
            "contact" => Ok(FileReferenceContext::Contact {
                node_id: row.context_node_id.ok_or_else(|| {
                    Error::InvalidData("missing contact context node id".to_owned())
                })?,
                field: row.context_field.ok_or_else(|| {
                    Error::InvalidData("missing contact context field".to_owned())
                })?,
            }),
            "bill" => Ok(FileReferenceContext::Bill {
                bill_id: row
                    .context_bill_id
                    .ok_or_else(|| Error::InvalidData("missing bill context id".to_owned()))?,
                field: row
                    .context_field
                    .ok_or_else(|| Error::InvalidData("missing bill context field".to_owned()))?,
            }),
            "direct_upload" => Ok(FileReferenceContext::DirectUpload),
            "unknown" => Ok(FileReferenceContext::Unknown),
            other => Err(Error::InvalidData(format!(
                "invalid file reference context type: {other}"
            ))),
        }
    }
}

pub(crate) fn file_reference_to_row(reference: &FileReference) -> Result<FileReferenceRow> {
    let server_urls = serde_json::to_string(&reference.server_urls)
        .map_err(|e| Error::InvalidData(format!("could not serialize file reference urls: {e}")))?;
    Ok(FileReferenceRow {
        hash: Text(reference.hash.clone()),
        nostr_hash: Text(reference.nostr_hash),
        name: reference.name.clone().map(Text),
        server_urls,
        is_important: reference.is_important,
        created_at: timestamp_to_db(reference.created_at)?,
        updated_at: timestamp_to_db(reference.updated_at)?,
    })
}

pub(crate) fn file_reference_from_row(
    row: FileReferenceRow,
    contexts: Vec<FileReferenceContext>,
) -> Result<FileReference> {
    let server_urls = serde_json::from_str(&row.server_urls)
        .map_err(|e| Error::InvalidData(format!("invalid persisted file reference urls: {e}")))?;
    Ok(FileReference {
        hash: row.hash.into_inner(),
        nostr_hash: row.nostr_hash.into_inner(),
        name: row.name.map(Text::into_inner),
        server_urls,
        is_important: row.is_important,
        context: contexts,
        created_at: timestamp_from_db(row.created_at)?,
        updated_at: timestamp_from_db(row.updated_at)?,
    })
}

pub(crate) fn add_url_deduped(urls: &mut Vec<url::Url>, url: url::Url) {
    let normalized = normalize_url(&url);
    if !urls.iter().any(|u| urls_equal(u, &normalized)) {
        urls.push(url);
    }
}

pub(crate) fn urls_equal(a: &url::Url, b: &str) -> bool {
    normalize_url(a) == b
}

pub(crate) fn normalize_url(url: &url::Url) -> String {
    let mut s = url.to_string();
    if s.ends_with('/') {
        s.pop();
    }
    s.to_lowercase()
}
