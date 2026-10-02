use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::protocol::{
    ExchangeRate, Sum, Timestamp,
    mint::{
        MintOffer, MintOfferRecoveryData, MintRequest, MintRequestStatus, MintRequestStatusKind,
    },
};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, types::Text};
use uuid::Uuid;

use crate::{
    Error, Result,
    sql::{SumColumns, sum_from_db, timestamp_from_db, timestamp_to_db},
};

// SQL
pub(crate) const EXISTS_FOR_BILL: &str = r#"
    SELECT EXISTS (
        SELECT 1
        FROM mint_requests
        WHERE requester_node_id = $1
          AND bill_id = $2
    )
"#;

pub(crate) const DELETE_REQUESTS_FOR_BILL: &str = r#"
    DELETE FROM mint_requests
    WHERE bill_id = $1
"#;

pub(crate) const SELECT_ACTIVE_REQUESTS: &str = r#"
    SELECT
        requester_node_id,
        bill_id,
        mint_node_id,
        mint_request_id,
        timestamp,
        status,
        status_timestamp
    FROM mint_requests
    WHERE status IN (
        'pending',
        'offered',
        'accepted',
        'minting_enabled'
    )
"#;

pub(crate) const SELECT_REQUESTS: &str = r#"
    SELECT
        requester_node_id,
        bill_id,
        mint_node_id,
        mint_request_id,
        timestamp,
        status,
        status_timestamp
    FROM mint_requests
    WHERE requester_node_id = $1
      AND bill_id = $2
      AND mint_node_id = $3
"#;

pub(crate) const SELECT_REQUESTS_FOR_BILL: &str = r#"
    SELECT
        requester_node_id,
        bill_id,
        mint_node_id,
        mint_request_id,
        timestamp,
        status,
        status_timestamp
    FROM mint_requests
    WHERE requester_node_id = $1
      AND bill_id = $2
"#;

pub(crate) const SELECT_REQUEST: &str = r#"
    SELECT
        requester_node_id,
        bill_id,
        mint_node_id,
        mint_request_id,
        timestamp,
        status,
        status_timestamp
    FROM mint_requests
    WHERE mint_request_id = $1
"#;

pub(crate) const INSERT_REQUEST: &str = r#"
    INSERT INTO mint_requests (
        requester_node_id,
        bill_id,
        mint_node_id,
        mint_request_id,
        timestamp,
        status,
        status_timestamp
    )
    VALUES (
        $1, $2, $3, $4, $5, $6, $7
    )
    ON CONFLICT(mint_request_id) DO NOTHING
"#;

pub(crate) const UPDATE_REQUEST: &str = r#"
    UPDATE mint_requests
    SET
        status = $1,
        status_timestamp = $2
    WHERE mint_request_id = $3
"#;

pub(crate) const SELECT_OFFER: &str = r#"
    SELECT
        mint_request_id,
        keyset_id,
        expiration_timestamp,

        discounted_sum_amount,
        discounted_sum_currency_code,
        discounted_sum_currency_decimals,
        discounted_sum_reference_exchange_rate,

        proofs,
        proofs_spent,
        recovery_data
    FROM mint_offers
    WHERE mint_request_id = $1
"#;

pub(crate) const INSERT_OFFER: &str = r#"
    INSERT INTO mint_offers (
        mint_request_id,
        keyset_id,
        expiration_timestamp,

        discounted_sum_amount,
        discounted_sum_currency_code,
        discounted_sum_currency_decimals,
        discounted_sum_reference_exchange_rate,

        proofs,
        proofs_spent,
        recovery_data
    )
    VALUES (
        $1, $2, $3,
        $4, $5, $6, $7,
        $8, $9, $10
    )
    ON CONFLICT(mint_request_id) DO NOTHING
"#;

pub(crate) const ADD_PROOFS: &str = r#"
    UPDATE mint_offers
    SET proofs = $1
    WHERE mint_request_id = $2
      AND proofs IS NULL
"#;

pub(crate) const ADD_RECOVERY_DATA: &str = r#"
    UPDATE mint_offers
    SET recovery_data = $1
    WHERE mint_request_id = $2
      AND proofs IS NULL
      AND recovery_data IS NULL
"#;

pub(crate) const SET_PROOFS_SPENT: &str = r#"
    UPDATE mint_offers
    SET proofs_spent = TRUE
    WHERE mint_request_id = $1
      AND proofs IS NOT NULL
"#;

#[derive(Debug, Clone, FromRow)]
pub(crate) struct MintRequestRow {
    pub requester_node_id: Text<NodeId>,
    pub bill_id: Text<BillId>,
    pub mint_node_id: Text<NodeId>,
    pub mint_request_id: Text<Uuid>,
    pub timestamp: i64,
    pub status: String,
    pub status_timestamp: Option<i64>,
}

#[derive(Debug, Clone, FromRow)]
pub(crate) struct MintOfferRow {
    pub mint_request_id: Text<Uuid>,
    pub keyset_id: String,
    pub expiration_timestamp: i64,
    pub discounted_sum_amount: i64,
    pub discounted_sum_currency_code: String,
    pub discounted_sum_currency_decimals: i64,
    pub discounted_sum_reference_exchange_rate: Text<ExchangeRate>,
    pub proofs: Option<String>,
    pub proofs_spent: bool,
    pub recovery_data: Option<String>,
}

pub(crate) fn status_to_db(status: &MintRequestStatus) -> Result<(&'static str, Option<i64>)> {
    let timestamp = match status {
        MintRequestStatus::Denied { timestamp }
        | MintRequestStatus::Rejected { timestamp }
        | MintRequestStatus::Cancelled { timestamp }
        | MintRequestStatus::Expired { timestamp } => Some(timestamp_to_db(*timestamp)?),
        _ => None,
    };

    let kind: &'static str = MintRequestStatusKind::from(status.clone()).into();
    Ok((kind, timestamp))
}

fn status_from_db(status: &str, timestamp: Option<i64>) -> Result<MintRequestStatus> {
    let kind = status
        .parse::<MintRequestStatusKind>()
        .map_err(|_| Error::InvalidData(format!("invalid mint request status: {status}")))?;

    match (kind, timestamp) {
        (MintRequestStatusKind::Pending, None) => Ok(MintRequestStatus::Pending),
        (MintRequestStatusKind::Denied, Some(timestamp)) => Ok(MintRequestStatus::Denied {
            timestamp: timestamp_from_db(timestamp)?,
        }),
        (MintRequestStatusKind::Offered, None) => Ok(MintRequestStatus::Offered),
        (MintRequestStatusKind::Accepted, None) => Ok(MintRequestStatus::Accepted),
        (MintRequestStatusKind::MintingEnabled, None) => Ok(MintRequestStatus::MintingEnabled),
        (MintRequestStatusKind::Rejected, Some(timestamp)) => Ok(MintRequestStatus::Rejected {
            timestamp: timestamp_from_db(timestamp)?,
        }),
        (MintRequestStatusKind::Cancelled, Some(timestamp)) => Ok(MintRequestStatus::Cancelled {
            timestamp: timestamp_from_db(timestamp)?,
        }),
        (MintRequestStatusKind::Expired, Some(timestamp)) => Ok(MintRequestStatus::Expired {
            timestamp: timestamp_from_db(timestamp)?,
        }),
        (kind, timestamp) => Err(Error::InvalidData(format!(
            "invalid mint request status data: kind={}, timestamp={timestamp:?}",
            kind.as_ref(),
        ))),
    }
}

impl TryFrom<MintRequestRow> for MintRequest {
    type Error = Error;

    fn try_from(row: MintRequestRow) -> Result<Self> {
        Ok(Self {
            requester_node_id: row.requester_node_id.into_inner(),
            bill_id: row.bill_id.into_inner(),
            mint_node_id: row.mint_node_id.into_inner(),
            mint_request_id: row.mint_request_id.into_inner(),
            timestamp: timestamp_from_db(row.timestamp)?,
            status: status_from_db(&row.status, row.status_timestamp)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RecoveryDataJson {
    secrets: Vec<String>,
    rs: Vec<String>,
}

pub(crate) fn recovery_data_to_json(secrets: &[String], rs: &[String]) -> Result<String> {
    serde_json::to_string(&RecoveryDataJson {
        secrets: secrets.to_vec(),
        rs: rs.to_vec(),
    })
    .map_err(|e| Error::InvalidData(format!("could not serialize mint recovery data: {e}")))
}

fn recovery_data_from_json(value: Option<String>) -> Result<Option<MintOfferRecoveryData>> {
    value
        .map(|value| {
            let value: RecoveryDataJson = serde_json::from_str(&value)
                .map_err(|e| Error::InvalidData(format!("invalid mint recovery data: {e}")))?;
            Ok(MintOfferRecoveryData {
                secrets: value.secrets,
                rs: value.rs,
            })
        })
        .transpose()
}

impl TryFrom<MintOfferRow> for MintOffer {
    type Error = Error;

    fn try_from(row: MintOfferRow) -> Result<Self> {
        Ok(Self {
            mint_request_id: row.mint_request_id.into_inner(),
            keyset_id: row.keyset_id,
            expiration_timestamp: timestamp_from_db(row.expiration_timestamp)?,
            discounted_sum: sum_from_db(
                row.discounted_sum_amount,
                row.discounted_sum_currency_code,
                row.discounted_sum_currency_decimals,
                row.discounted_sum_reference_exchange_rate.into_inner(),
            )?,
            proofs: row.proofs,
            proofs_spent: row.proofs_spent,
            recovery_data: recovery_data_from_json(row.recovery_data)?,
        })
    }
}

pub(crate) struct NewMintOffer {
    pub mint_request_id: Text<Uuid>,
    pub keyset_id: String,
    pub expiration_timestamp: i64,
    pub discounted_sum_amount: i64,
    pub discounted_sum_currency_code: String,
    pub discounted_sum_currency_decimals: i64,
    pub discounted_sum_reference_exchange_rate: Text<ExchangeRate>,
}

impl NewMintOffer {
    pub(crate) fn new(
        mint_request_id: &Uuid,
        keyset_id: &str,
        expiration_timestamp: Timestamp,
        discounted_sum: &Sum,
    ) -> Result<Self> {
        let sum = SumColumns::try_from(discounted_sum)?;
        Ok(Self {
            mint_request_id: Text(*mint_request_id),
            keyset_id: keyset_id.to_owned(),
            expiration_timestamp: timestamp_to_db(expiration_timestamp)?,
            discounted_sum_amount: sum.amount,
            discounted_sum_currency_code: sum.currency_code,
            discounted_sum_currency_decimals: sum.currency_decimals,
            discounted_sum_reference_exchange_rate: sum.reference_exchange_rate,
        })
    }
}
