//! Portable Mint records in the applicant's own identity or company chain.
//! `company_id: None` selects the personal identity chain, `Some(id)` that company's chain.
use crate::ffi::{error::EbillFfiError, get_active_ctx};
use bcr_common::core::NodeId;
use bcr_ebill_api::service::Error;
use bcr_ebill_core::protocol::{
    BlockId, ProtocolValidationError,
    mint_record::{
        AddMintRecordResult, MintRecordBlockData, MintRecordDisputeView, MintRecordHeader,
        MintRecordSnapshot, MintRecordSnapshotRequest, MintRecordView,
    },
};
use flutter_rust_bridge::frb;
use std::str::FromStr;

/// A Mint-signed entry exactly as the Mint returned it.
#[derive(Debug, Clone)]
pub struct AddMintRecordPayloadFfi {
    /// The exact entry text the Mint signed; never re-serialize it
    pub entry: String,
    /// BIP340 signature over the entry, lowercase hex
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct AddMintRecordDisputePayloadFfi {
    /// The `block_id` of the disputed record
    pub entry_block_id: u64,
    pub statement: String,
}

#[derive(Debug, Clone)]
pub struct MintRecordSnapshotRequestFfi {
    /// x-only public key of the Mint that receives the snapshot, lowercase hex
    pub receiving_mint_key: String,
    pub application_ref: String,
}

#[derive(Debug, Clone)]
pub struct AddMintRecordResultFfi {
    pub block_id: u64,
    pub sequence: u64,
    pub signing_key: String,
    pub already_present: bool,
}

#[derive(Debug, Clone)]
pub struct MintRecordIssuerFfi {
    pub signing_key: String,
    pub mint_node_id: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct MintRecordSubjectFfi {
    pub chain: String,
    pub node_id: String,
    pub company_node_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MintRecordHeaderFfi {
    pub schema: String,
    pub network: String,
    pub issuer: MintRecordIssuerFfi,
    pub subject: MintRecordSubjectFfi,
    pub sequence: u64,
    pub previous_entry_digest: Option<String>,
    pub created_at: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct MintRecordDisputeFfi {
    pub block_id: u64,
    pub block_hash: String,
    pub timestamp: u64,
    pub entry_block_id: u64,
    pub entry_digest: String,
    pub statement: String,
    pub created_at: u64,
}

/// A Mint record and the holder's disputes of it. A record states what one Mint said; it is
/// authenticated by the Mint's signature, not proven true.
#[derive(Debug, Clone)]
pub struct MintRecordFfi {
    pub block_id: u64,
    pub block_hash: String,
    pub timestamp: u64,
    /// Parsed from `entry` for display; `entry` stays the signed source
    pub header: MintRecordHeaderFfi,
    /// The exact signed entry text
    pub entry: String,
    pub signature: String,
    pub digest: String,
    pub disputes: Vec<MintRecordDisputeFfi>,
}

/// Every Mint entry and dispute in the chain, signed by the chain's key for one receiving Mint
/// and application. Send `payload` byte for byte; the signature covers these exact bytes.
#[derive(Debug, Clone)]
pub struct SignedMintRecordSnapshotFfi {
    pub payload: String,
    pub signature: String,
}

impl From<AddMintRecordResult> for AddMintRecordResultFfi {
    fn from(value: AddMintRecordResult) -> Self {
        Self {
            block_id: value.block_id.inner(),
            sequence: value.sequence,
            signing_key: value.signing_key,
            already_present: value.already_present,
        }
    }
}

impl From<MintRecordHeader> for MintRecordHeaderFfi {
    fn from(value: MintRecordHeader) -> Self {
        Self {
            schema: value.schema,
            network: value.network,
            issuer: MintRecordIssuerFfi {
                signing_key: value.issuer.signing_key,
                mint_node_id: value.issuer.mint_node_id,
                name: value.issuer.name,
            },
            subject: MintRecordSubjectFfi {
                chain: value.subject.chain,
                node_id: value.subject.node_id,
                company_node_id: value.subject.company_node_id,
            },
            sequence: value.sequence,
            previous_entry_digest: value.previous_entry_digest,
            created_at: value.created_at,
            reason: value.reason,
        }
    }
}

impl From<MintRecordDisputeView> for MintRecordDisputeFfi {
    fn from(value: MintRecordDisputeView) -> Self {
        Self {
            block_id: value.block_id.inner(),
            block_hash: value.block_hash,
            timestamp: value.timestamp.inner(),
            entry_block_id: value.entry_block_id.inner(),
            entry_digest: value.entry_digest,
            statement: value.statement,
            created_at: value.created_at.inner(),
        }
    }
}

impl From<MintRecordView> for MintRecordFfi {
    fn from(value: MintRecordView) -> Self {
        Self {
            block_id: value.block_id.inner(),
            block_hash: value.block_hash,
            timestamp: value.timestamp.inner(),
            header: value.header.into(),
            entry: value.entry,
            signature: value.signature,
            digest: value.digest,
            disputes: value.disputes.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<MintRecordSnapshot> for SignedMintRecordSnapshotFfi {
    fn from(value: MintRecordSnapshot) -> Self {
        Self {
            payload: value.payload,
            signature: value.signature,
        }
    }
}

fn parse_company_id(company_id: Option<String>) -> Result<Option<NodeId>, EbillFfiError> {
    company_id
        .map(|id| NodeId::from_str(&id).map_err(|_| ProtocolValidationError::InvalidNodeId.into()))
        .transpose()
}

fn parse_block_id(entry_block_id: u64) -> Result<BlockId, EbillFfiError> {
    Ok(BlockId::first().add(
        entry_block_id
            .checked_sub(1)
            .ok_or(ProtocolValidationError::InvalidReferenceBlock)?,
    ))
}

fn parse_entry(payload: AddMintRecordPayloadFfi) -> Result<MintRecordBlockData, EbillFfiError> {
    MintRecordBlockData::from_text(payload.entry, &payload.signature)
        .map_err(|e| Error::Protocol(e.into()).into())
}

/// The chain's Mint records, oldest first. Core verified each entry's signature on append.
#[frb]
pub async fn mint_records(company_id: Option<String>) -> Result<Vec<MintRecordFfi>, EbillFfiError> {
    let ctx = get_active_ctx().await?;
    let records = match parse_company_id(company_id)? {
        None => ctx.identity_service.mint_records().await?,
        Some(id) => ctx.company_service.mint_records(&id).await?,
    };
    Ok(records.into_iter().map(Into::into).collect())
}

/// Appends a Mint-signed entry. Core checks the Mint's signature, subject and sequence and
/// reports `already_present` for an entry the chain already holds; it does not check which
/// Mint delivered it.
#[frb]
pub async fn add_mint_record(
    company_id: Option<String>,
    payload: AddMintRecordPayloadFfi,
) -> Result<AddMintRecordResultFfi, EbillFfiError> {
    let company_id = parse_company_id(company_id)?;
    let data = parse_entry(payload)?;
    let ctx = get_active_ctx().await?;
    let result = match company_id {
        None => ctx.identity_service.add_mint_record(data).await?,
        Some(id) => ctx.company_service.add_mint_record(&id, data).await?,
    };
    Ok(result.into())
}

/// Appends the holder's own dispute of a record to the chain. Telling the Mint is separate.
#[frb]
pub async fn add_mint_record_dispute(
    company_id: Option<String>,
    payload: AddMintRecordDisputePayloadFfi,
) -> Result<(), EbillFfiError> {
    let company_id = parse_company_id(company_id)?;
    let entry_block_id = parse_block_id(payload.entry_block_id)?;
    let ctx = get_active_ctx().await?;
    match company_id {
        None => {
            ctx.identity_service
                .add_mint_record_dispute(entry_block_id, payload.statement)
                .await?
        }
        Some(id) => {
            ctx.company_service
                .add_mint_record_dispute(&id, entry_block_id, payload.statement)
                .await?
        }
    }
    Ok(())
}

/// Signs every Mint entry and dispute in the chain for one receiving Mint and application;
/// nothing is selected or left out. Keys stay inside Core.
#[frb]
pub async fn mint_record_snapshot(
    company_id: Option<String>,
    payload: MintRecordSnapshotRequestFfi,
) -> Result<SignedMintRecordSnapshotFfi, EbillFfiError> {
    let company_id = parse_company_id(company_id)?;
    let request = MintRecordSnapshotRequest {
        receiving_mint_key: payload.receiving_mint_key,
        application_ref: payload.application_ref,
    };
    let ctx = get_active_ctx().await?;
    let snapshot = match company_id {
        None => ctx.identity_service.mint_record_snapshot(request).await?,
        Some(id) => {
            ctx.company_service
                .mint_record_snapshot(&id, request)
                .await?
        }
    };
    Ok(snapshot.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bcr_ebill_core::protocol::Timestamp;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!(
            "../../../../bcr-ebill-core/tests/vectors/mint-record-v1.json"
        ))
        .unwrap()
    }

    fn entry(chain: &str) -> AddMintRecordPayloadFfi {
        let v = &vectors()["positive"][chain]["entries"][0];
        AddMintRecordPayloadFfi {
            entry: v["entry"].as_str().unwrap().into(),
            signature: v["signature"].as_str().unwrap().into(),
        }
    }

    fn view(
        payload: AddMintRecordPayloadFfi,
        disputes: Vec<MintRecordDisputeView>,
    ) -> MintRecordView {
        let data = parse_entry(payload.clone()).unwrap();
        MintRecordView {
            block_id: BlockId::first().add(1),
            block_hash: "hash".into(),
            timestamp: Timestamp::new(1_793_361_601).unwrap(),
            header: data.header().unwrap(),
            entry: payload.entry,
            signature: payload.signature,
            digest: bcr_ebill_core::protocol::mint_record::entry_digest(&data.entry),
            disputes,
        }
    }

    #[test]
    fn records_keep_the_signed_entry_and_null_header_fields() {
        for (chain, company) in [("identity", false), ("company", true)] {
            let payload = entry(chain);
            let expected = &vectors()["positive"][chain]["entries"][0];
            let record: MintRecordFfi = view(payload.clone(), vec![]).into();
            // the exact signed text crosses the boundary unchanged
            assert_eq!(record.entry, payload.entry);
            assert_eq!(record.signature, payload.signature);
            assert_eq!(record.digest, expected["digest"].as_str().unwrap());
            assert_eq!(record.block_id, 2);
            assert_eq!(record.timestamp, 1_793_361_601);
            // the parsed header matches the entry JSON, including its nulls
            let json: Value = serde_json::from_str(&record.entry).unwrap();
            let h = &record.header;
            assert_eq!(h.schema, json["schema"]);
            assert_eq!(h.network, json["network"]);
            assert_eq!(h.issuer.signing_key, json["issuer"]["signingKey"]);
            assert_eq!(h.issuer.mint_node_id, json["issuer"]["mintNodeId"]);
            assert_eq!(h.issuer.name, json["issuer"]["name"]);
            assert_eq!(h.subject.chain, json["subject"]["chain"]);
            assert_eq!(h.subject.node_id, json["subject"]["nodeId"]);
            assert_eq!(h.subject.company_node_id.is_some(), company);
            assert_eq!(
                h.subject.company_node_id.as_deref(),
                json["subject"]["companyNodeId"].as_str()
            );
            assert_eq!(h.sequence, json["sequence"].as_u64().unwrap());
            assert_eq!(
                h.previous_entry_digest.as_deref(),
                json["previousEntryDigest"].as_str()
            );
            assert_eq!(h.created_at, json["createdAt"]);
            assert_eq!(h.reason, json["reason"]);
        }
    }

    #[test]
    fn disputes_and_append_results_carry_block_ids() {
        let dispute = MintRecordDisputeView {
            block_id: BlockId::first().add(2),
            block_hash: "dispute".into(),
            timestamp: Timestamp::new(1_793_361_602).unwrap(),
            entry_block_id: BlockId::first().add(1),
            entry_digest: "sha256:digest".into(),
            statement: "Not my bill".into(),
            created_at: Timestamp::new(1_793_361_602).unwrap(),
        };
        let view = view(entry("identity"), vec![dispute]);
        let result: AddMintRecordResultFfi = view.append_result(true).into();
        assert_eq!(
            (result.block_id, result.sequence, result.already_present),
            (2, view.header.sequence, true)
        );
        assert_eq!(result.signing_key, view.header.issuer.signing_key);
        let record: MintRecordFfi = view.into();
        let d = &record.disputes[0];
        assert_eq!((d.block_id, d.entry_block_id), (3, record.block_id));
        assert_eq!((d.timestamp, d.created_at), (1_793_361_602, 1_793_361_602));
        assert_eq!(d.statement, "Not my bill");
    }

    #[test]
    fn snapshot_payload_crosses_unchanged() {
        let v = &vectors()["positive"]["company"]["snapshot"];
        let snapshot = MintRecordSnapshot {
            payload: v["payload"].as_str().unwrap().into(),
            signature: v["signature"].as_str().unwrap().into(),
        };
        let ffi: SignedMintRecordSnapshotFfi = snapshot.clone().into();
        assert_eq!(ffi.payload, snapshot.payload);
        assert_eq!(ffi.signature, snapshot.signature);
    }

    #[test]
    fn inputs_reject_malformed_entries_ids_and_block_zero() {
        assert!(parse_entry(entry("identity")).is_ok());
        let mut bad = entry("identity");
        bad.signature = "zz".into();
        assert!(parse_entry(bad).is_err());
        let mut tampered = entry("identity");
        tampered.entry.push(' ');
        assert!(parse_entry(tampered).unwrap().header().is_err());
        assert!(parse_company_id(None).unwrap().is_none());
        let company = vectors()["publicKeys"]["company"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            parse_company_id(Some(company.clone()))
                .unwrap()
                .unwrap()
                .to_string(),
            company
        );
        assert!(parse_company_id(Some("company".into())).is_err());
        assert!(parse_block_id(0).is_err());
        assert_eq!(parse_block_id(1).unwrap(), BlockId::first());
        assert_eq!(parse_block_id(5).unwrap().inner(), 5);
    }
}
