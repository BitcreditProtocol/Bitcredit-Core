use crate::{
    Error, Result,
    sql::{block_id_from_db, block_id_to_db, timestamp_from_db, timestamp_to_db},
};
use bcr_common::core::NodeId;
use bcr_ebill_core::protocol::{
    PublicKey, SchnorrSignature, Sha256Hash,
    blockchain::{
        Block,
        company::{CompanyBlock, CompanyOpCode},
    },
};
use sqlx::{FromRow, types::Text};

// SQL

pub(crate) const SELECT_LATEST: &str = r#"
    SELECT
        company_id,
        block_id,
        plaintext_hash,
        hash,
        previous_hash,
        signature,
        timestamp,
        public_key,
        signatory_node_id,
        data,
        op_code
    FROM company_chain
    WHERE company_id = $1
    ORDER BY block_id DESC
    LIMIT 1
"#;

pub(crate) const SELECT_CHAIN: &str = r#"
    SELECT
        company_id,
        block_id,
        plaintext_hash,
        hash,
        previous_hash,
        signature,
        timestamp,
        public_key,
        signatory_node_id,
        data,
        op_code
    FROM company_chain
    WHERE company_id = $1
    ORDER BY block_id ASC
"#;

pub(crate) const INSERT_BLOCK: &str = r#"
    INSERT INTO company_chain (
        company_id,
        block_id,
        plaintext_hash,
        hash,
        previous_hash,
        signature,
        timestamp,
        public_key,
        signatory_node_id,
        data,
        op_code
    )
    VALUES (
        $1, $2, $3, $4, $5,
        $6, $7, $8, $9, $10,
        $11
    )
"#;

pub(crate) const DELETE_CHAIN: &str = r#"
    DELETE FROM company_chain
    WHERE company_id = $1
"#;

pub(crate) const DELETE_FROM_HEIGHT: &str = r#"
    DELETE FROM company_chain
    WHERE company_id = $1
      AND block_id >= $2
"#;

pub(crate) const ENSURE_CHAIN_LOCK: &str = r#"
    INSERT INTO company_chain_locks (
        company_id
    )
    VALUES ($1)
    ON CONFLICT(company_id) DO NOTHING
"#;

macro_rules! bind_insert_block {
    ($query:expr, $row:expr) => {
        $query
            .bind(&$row.company_id)
            .bind($row.block_id)
            .bind(&$row.plaintext_hash)
            .bind(&$row.hash)
            .bind(&$row.previous_hash)
            .bind(&$row.signature)
            .bind($row.timestamp)
            .bind(&$row.public_key)
            .bind(&$row.signatory_node_id)
            .bind(&$row.data)
            .bind(&$row.op_code)
    };
}

pub(crate) use bind_insert_block;

pub(crate) fn validate_block_append(
    id: &NodeId,
    block: &CompanyBlock,
    latest: Option<&CompanyBlock>,
) -> Result<()> {
    if &block.company_id != id {
        return Err(Error::InsertFailed(format!(
            "company id mismatch: expected {id}, \
                 block has {}",
            block.company_id
        )));
    }

    match latest {
        None => {
            if !block.id.is_first() || !block.verify() || !block.validate_hash() {
                return Err(Error::InsertFailed(format!(
                    "First Company Block validation \
                             error: block id: {}",
                    block.id
                )));
            }
        }
        Some(latest) => {
            let expected_block_id = latest
                .id
                .inner()
                .checked_add(1)
                .ok_or_else(|| Error::InsertFailed("company block id overflow".to_owned()))?;
            if block.id.inner() != expected_block_id
                || block.previous_hash != latest.hash
                || !block.validate_with_previous(latest)
            {
                return Err(Error::InsertFailed(format!(
                    "Company Block validation error: block id: {}, latest block id: {}",
                    block.id, latest.id,
                )));
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, FromRow)]
pub(crate) struct CompanyBlockRow {
    pub company_id: Text<NodeId>,
    pub block_id: i64,
    pub plaintext_hash: Text<Sha256Hash>,
    pub hash: Text<Sha256Hash>,
    pub previous_hash: Text<Sha256Hash>,
    pub signature: Text<SchnorrSignature>,
    pub timestamp: i64,
    pub public_key: Text<PublicKey>,
    pub signatory_node_id: Text<NodeId>,
    pub data: Vec<u8>,
    pub op_code: Text<CompanyOpCode>,
}

impl TryFrom<&CompanyBlock> for CompanyBlockRow {
    type Error = Error;

    fn try_from(value: &CompanyBlock) -> Result<Self> {
        Ok(Self {
            company_id: Text(value.company_id.clone()),
            block_id: block_id_to_db(value.id)?,
            plaintext_hash: Text(value.plaintext_hash.clone()),
            hash: Text(value.hash.clone()),
            previous_hash: Text(value.previous_hash.clone()),
            signature: Text(value.signature.clone()),
            timestamp: timestamp_to_db(value.timestamp)?,
            public_key: Text(value.public_key),
            signatory_node_id: Text(value.signatory_node_id.clone()),
            data: value.data.clone(),
            op_code: Text(value.op_code.clone()),
        })
    }
}

impl TryFrom<CompanyBlockRow> for CompanyBlock {
    type Error = Error;

    fn try_from(row: CompanyBlockRow) -> Result<Self> {
        Ok(Self {
            company_id: row.company_id.into_inner(),
            id: block_id_from_db(row.block_id)?,
            plaintext_hash: row.plaintext_hash.into_inner(),
            hash: row.hash.into_inner(),
            previous_hash: row.previous_hash.into_inner(),
            timestamp: timestamp_from_db(row.timestamp)?,
            data: row.data,
            public_key: row.public_key.into_inner(),
            signatory_node_id: row.signatory_node_id.into_inner(),
            signature: row.signature.into_inner(),
            op_code: row.op_code.into_inner(),
        })
    }
}
