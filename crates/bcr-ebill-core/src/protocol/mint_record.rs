//! Portable Mint records: exact signed entry bytes, chain validation and disclosure snapshots.
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bcr_common::core::NodeId;
use bitcoin::{
    hashes::{Hash, sha256},
    hex::{DisplayHex, FromHex},
    secp256k1::{Keypair, Message, SECP256K1, XOnlyPublicKey, schnorr},
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::{
    BlockId, Sha256Hash, Timestamp,
    blockchain::{
        Block, Blockchain, Error, Result,
        company::{
            CompanyBlock, CompanyBlockchain, CompanyOpCode, block::CompanyIdentityProofBlockData,
        },
        identity::{IdentityBlock, IdentityBlockchain, IdentityOpCode, IdentityProofBlockData},
    },
    crypto::BcrKeys,
};

/// Entry bytes, before Borsh, ECIES, base58 and the Nostr event envelope.
pub const MAX_MINT_RECORD_ENTRY_BYTES: usize = 32 * 1024;
pub const ENTRY_DOMAIN: &[u8] = b"bitcredit/mint-record-entry/v1\n";
pub const SNAPSHOT_DOMAIN: &[u8] = b"bitcredit/mint-record-snapshot/v1\n";

fn invalid(reason: &str) -> Error {
    Error::MintRecord(reason.into())
}

pub fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    use bitcoin::hashes::HashEngine;
    engine.input(domain);
    engine.input(bytes);
    sha256::Hash::from_engine(engine).to_byte_array()
}

pub fn entry_digest(entry: &[u8]) -> String {
    format!("sha256:{}", sha256::Hash::hash(entry))
}

fn x_only(key: &str) -> Result<XOnlyPublicKey> {
    if key.len() != 64
        || !key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("invalid signing key"));
    }
    XOnlyPublicKey::from_str(key).map_err(|_| invalid("invalid signing key"))
}

mod signature_hex {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        value: &[u8; 64],
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.as_hex().to_string())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<[u8; 64], D::Error> {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        <[u8; 64]>::from_hex(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct MintRecordBlockData {
    pub entry: Vec<u8>,
    #[serde(with = "signature_hex")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct MintRecordDisputeBlockData {
    pub entry_block_id: BlockId,
    pub entry_digest: String,
    pub statement: String,
    pub created_at: Timestamp,
}

// Deliberately parse only the header. The record and unknown extension fields stay opaque.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintRecordHeader {
    pub schema: String,
    pub network: String,
    #[serde(deserialize_with = "header_object")]
    pub issuer: MintRecordIssuer,
    #[serde(deserialize_with = "header_object")]
    pub subject: MintRecordSubject,
    pub sequence: u64,
    #[serde(deserialize_with = "required_option")]
    pub previous_entry_digest: Option<String>,
    pub created_at: String,
    pub reason: String,
}
// Serde structs also accept positional arrays by default. Header objects must match the JSON
// object schema used by receiving Mints; require maps without reserializing any signed bytes.
fn header_object<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> std::result::Result<T, D::Error> {
    struct Object<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Object<T> {
        type Value = T;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a JSON object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            map: A,
        ) -> std::result::Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    d.deserialize_map(Object(std::marker::PhantomData))
}
fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> std::result::Result<Option<T>, D::Error> {
    <Option<T> as serde::Deserialize>::deserialize(d)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintRecordIssuer {
    pub signing_key: String,
    pub mint_node_id: String,
    pub name: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintRecordSubject {
    pub chain: String,
    pub node_id: String,
    #[serde(deserialize_with = "required_option")]
    pub company_node_id: Option<String>,
}

impl MintRecordBlockData {
    pub fn from_text(entry: String, signature: &str) -> Result<Self> {
        if entry.len() > MAX_MINT_RECORD_ENTRY_BYTES {
            return Err(invalid("oversize entry"));
        }
        if signature.len() != 128
            || !signature
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("bad entry signature"));
        }
        Ok(Self {
            entry: entry.into_bytes(),
            signature: <[u8; 64]>::from_hex(signature)
                .map_err(|_| invalid("bad entry signature"))?,
        })
    }

    pub fn header(&self) -> Result<MintRecordHeader> {
        if self.entry.len() > MAX_MINT_RECORD_ENTRY_BYTES {
            return Err(invalid("oversize entry"));
        }
        let text = std::str::from_utf8(&self.entry).map_err(|_| invalid("entry is not UTF-8"))?;
        if !text.trim_start().starts_with('{') {
            return Err(invalid("entry is not a JSON header object"));
        }
        let header: MintRecordHeader =
            serde_json::from_str(text).map_err(|_| invalid("entry is not a JSON header object"))?;
        if header.schema != "mint-record-entry-v1" {
            return Err(invalid("wrong schema"));
        }
        let pubkey = x_only(&header.issuer.signing_key)?;
        let signature = schnorr::Signature::from_slice(&self.signature)
            .map_err(|_| invalid("bad entry signature"))?;
        SECP256K1
            .verify_schnorr(
                &signature,
                &Message::from_digest(domain_hash(ENTRY_DOMAIN, &self.entry)),
                &pubkey,
            )
            .map_err(|_| invalid("bad entry signature"))?;
        Ok(header)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintRecordDisputeView {
    pub block_id: BlockId,
    pub block_hash: String,
    pub timestamp: Timestamp,
    pub entry_block_id: BlockId,
    pub entry_digest: String,
    pub statement: String,
    pub created_at: Timestamp,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintRecordView {
    pub block_id: BlockId,
    pub block_hash: String,
    pub timestamp: Timestamp,
    pub header: MintRecordHeader,
    pub entry: String,
    pub signature: String,
    pub digest: String,
    pub disputes: Vec<MintRecordDisputeView>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddMintRecordResult {
    pub block_id: BlockId,
    pub sequence: u64,
    pub signing_key: String,
    pub already_present: bool,
}
impl MintRecordView {
    pub fn append_result(&self, already_present: bool) -> AddMintRecordResult {
        AddMintRecordResult {
            block_id: self.block_id,
            sequence: self.header.sequence,
            signing_key: self.header.issuer.signing_key.clone(),
            already_present,
        }
    }
}

fn validate_entry(
    data: &MintRecordBlockData,
    subject: &NodeId,
    company: bool,
    signatory: impl Fn(&NodeId) -> Result<bool>,
    records: &[MintRecordView],
) -> Result<MintRecordHeader> {
    let header = data.header()?;
    if header.network != subject.network().to_string() {
        return Err(invalid("wrong network"));
    }
    let s = &header.subject;
    if company {
        let node = NodeId::from_str(&s.node_id).map_err(|_| invalid("wrong subject"))?;
        if s.chain != "company"
            || s.company_node_id.as_deref() != Some(subject.to_string().as_str())
            || node.network() != subject.network()
            || !signatory(&node)?
        {
            return Err(invalid("wrong subject"));
        }
    } else if s.chain != "identity"
        || s.node_id != subject.to_string()
        || s.company_node_id.is_some()
    {
        return Err(invalid("wrong subject"));
    }
    let previous = records
        .iter()
        .rev()
        .find(|r| r.header.issuer.signing_key == header.issuer.signing_key);
    let expected = previous.map_or(Some(1), |r| r.header.sequence.checked_add(1));
    if expected != Some(header.sequence) {
        return Err(invalid("sequence gap"));
    }
    if header.previous_entry_digest.as_deref() != previous.map(|r| r.digest.as_str()) {
        return Err(invalid("wrong previousEntryDigest"));
    }
    Ok(header)
}
fn validate_dispute(data: &MintRecordDisputeBlockData, records: &[MintRecordView]) -> Result<()> {
    if !(1..=1000).contains(&data.statement.chars().count()) {
        return Err(invalid(
            "dispute statement must contain 1..=1000 characters",
        ));
    }
    let record = records
        .iter()
        .find(|r| r.block_id == data.entry_block_id)
        .ok_or_else(|| invalid("dispute entry not found"))?;
    if record.digest != data.entry_digest {
        return Err(invalid("dispute with wrong digest"));
    }
    Ok(())
}

fn ingest(
    records: &mut Vec<MintRecordView>,
    id: BlockId,
    hash: &Sha256Hash,
    timestamp: Timestamp,
    op: &str,
    plaintext: &[u8],
    subject: &NodeId,
    company: bool,
    signatory: impl Fn(&NodeId) -> Result<bool>,
) -> Result<()> {
    match op {
        "MintRecord" => {
            let data: MintRecordBlockData = borsh::from_slice(plaintext)?;
            let header = validate_entry(&data, subject, company, signatory, records)?;
            records.push(MintRecordView {
                block_id: id,
                block_hash: hash.to_string(),
                timestamp,
                header,
                entry: String::from_utf8(data.entry.clone())
                    .map_err(|_| invalid("entry is not UTF-8"))?,
                signature: data.signature.as_hex().to_string(),
                digest: entry_digest(&data.entry),
                disputes: vec![],
            });
        }
        "MintRecordDispute" => {
            let data: MintRecordDisputeBlockData = borsh::from_slice(plaintext)?;
            validate_dispute(&data, records)?;
            let record = records
                .iter_mut()
                .find(|r| r.block_id == data.entry_block_id)
                .ok_or_else(|| invalid("dispute entry not found"))?;
            record.disputes.push(MintRecordDisputeView {
                block_id: id,
                block_hash: hash.to_string(),
                timestamp,
                entry_block_id: data.entry_block_id,
                entry_digest: data.entry_digest,
                statement: data.statement,
                created_at: data.created_at,
            });
        }
        _ => {}
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintRecordSnapshotRequest {
    pub receiving_mint_key: String,
    pub application_ref: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintRecordSnapshot {
    pub payload: String,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintRecordSnapshotPayload {
    pub schema: String,
    pub network: String,
    pub chain: String,
    pub subject_node_id: NodeId,
    pub receiving_mint_key: String,
    pub application_ref: String,
    pub created_at: Timestamp,
    pub head: MintRecordSnapshotHead,
    pub blocks: Vec<MintRecordSnapshotBlock>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintRecordSnapshotHead {
    pub id: BlockId,
    pub hash: Sha256Hash,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintRecordSnapshotBlock {
    pub id: BlockId,
    pub hash: Sha256Hash,
    pub previous_hash: Sha256Hash,
    pub public_key: bitcoin::secp256k1::PublicKey,
    pub signature: String,
    pub op_code: String,
    pub timestamp: Timestamp,
    pub plaintext_hash: Sha256Hash,
    pub data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub company_id: Option<NodeId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signatory_node_id: Option<NodeId>,
}
impl MintRecordSnapshotBlock {
    fn new<B: Block>(block: &B, plaintext: Option<&[u8]>) -> Self
    where
        B::OpCode: std::fmt::Display,
    {
        Self {
            id: block.id(),
            hash: block.hash().clone(),
            previous_hash: block.previous_hash().clone(),
            public_key: *block.public_key(),
            signature: block.signature().as_sig().to_string(),
            op_code: block.op_code().to_string(),
            timestamp: block.timestamp(),
            plaintext_hash: block.plaintext_hash().clone(),
            data: STANDARD.encode(block.data()),
            plaintext: plaintext.map(|p| STANDARD.encode(p)),
            company_id: None,
            signatory_node_id: None,
        }
    }
}
impl MintRecordSnapshotPayload {
    fn new(
        subject: NodeId,
        company: bool,
        request: MintRecordSnapshotRequest,
        created_at: Timestamp,
        blocks: Vec<MintRecordSnapshotBlock>,
    ) -> Result<Self> {
        x_only(&request.receiving_mint_key)?;
        if request.application_ref.is_empty()
            || request.application_ref.len() > 256
            || request.application_ref.chars().any(char::is_control)
        {
            return Err(invalid("invalid applicationRef"));
        }
        let head = blocks.last().ok_or_else(|| invalid("empty chain"))?;
        Ok(Self {
            schema: "mint-record-snapshot-v1".into(),
            network: subject.network().to_string(),
            chain: if company { "company" } else { "identity" }.into(),
            subject_node_id: subject,
            receiving_mint_key: request.receiving_mint_key,
            application_ref: request.application_ref,
            created_at,
            head: MintRecordSnapshotHead {
                id: head.id,
                hash: head.hash.clone(),
            },
            blocks,
        })
    }
    pub fn sign(&self, keys: &BcrKeys) -> Result<MintRecordSnapshot> {
        if keys.pub_key() != self.subject_node_id.pub_key() {
            return Err(invalid("snapshot key does not match subject"));
        }
        let payload = serde_json::to_string(self).map_err(|e| Error::JSON(e.to_string()))?;
        let signature = SECP256K1
            .sign_schnorr(
                &Message::from_digest(domain_hash(SNAPSHOT_DOMAIN, payload.as_bytes())),
                &Keypair::from_secret_key(SECP256K1, &keys.get_private_key()),
            )
            .to_string();
        Ok(MintRecordSnapshot { payload, signature })
    }
}

impl IdentityBlockchain {
    fn identity_subject(&self, keys: &BcrKeys) -> Result<NodeId> {
        match self.get_first_block().get_block_data(keys)? {
            super::blockchain::identity::IdentityBlockPayload::Create(data)
                if data.node_id.pub_key() == keys.pub_key() =>
            {
                Ok(data.node_id)
            }
            _ => Err(invalid("invalid identity genesis")),
        }
    }
    pub fn mint_records(&self, keys: &BcrKeys) -> Result<Vec<MintRecordView>> {
        let subject = self.identity_subject(keys)?;
        let mut records = vec![];
        for block in self.blocks() {
            if matches!(
                block.op_code,
                IdentityOpCode::MintRecord | IdentityOpCode::MintRecordDispute
            ) {
                let plaintext = block.get_decrypted_block_bytes(keys)?;
                if Sha256Hash::from_bytes(&plaintext) != block.plaintext_hash {
                    return Err(invalid("plaintextHash mismatch"));
                }
                ingest(
                    &mut records,
                    block.id,
                    &block.hash,
                    block.timestamp,
                    &block.op_code.to_string(),
                    &plaintext,
                    &subject,
                    false,
                    |_| Ok(false),
                )?;
            }
        }
        Ok(records)
    }
    /// Used before persistence on receipt, sync and recovery, and by local creation.
    pub fn validate_mint_record_block(&self, block: &IdentityBlock, keys: &BcrKeys) -> Result<()> {
        if !matches!(
            block.op_code,
            IdentityOpCode::MintRecord | IdentityOpCode::MintRecordDispute
        ) {
            return Ok(());
        }
        let subject = self.identity_subject(keys)?;
        let mut records = self.mint_records(keys)?;
        let plaintext = block.get_decrypted_block_bytes(keys)?;
        if block.plaintext_hash != Sha256Hash::from_bytes(&plaintext) {
            return Err(invalid("plaintextHash mismatch"));
        }
        ingest(
            &mut records,
            block.id,
            &block.hash,
            block.timestamp,
            &block.op_code.to_string(),
            &plaintext,
            &subject,
            false,
            |_| Ok(false),
        )
    }
    pub fn create_mint_record(
        &self,
        data: &MintRecordBlockData,
        keys: &BcrKeys,
        timestamp: Timestamp,
    ) -> Result<IdentityBlock> {
        let records = self.mint_records(keys)?;
        let subject = self.identity_subject(keys)?;
        validate_entry(data, &subject, false, |_| Ok(false), &records)?;
        IdentityBlock::encrypt_data_create_block_and_validate(
            self.get_latest_block(),
            data,
            keys,
            timestamp,
            IdentityOpCode::MintRecord,
        )
    }
    pub fn create_mint_record_dispute(
        &self,
        data: &MintRecordDisputeBlockData,
        keys: &BcrKeys,
        timestamp: Timestamp,
    ) -> Result<IdentityBlock> {
        validate_dispute(data, &self.mint_records(keys)?)?;
        IdentityBlock::encrypt_data_create_block_and_validate(
            self.get_latest_block(),
            data,
            keys,
            timestamp,
            IdentityOpCode::MintRecordDispute,
        )
    }
    pub fn mint_record_snapshot(
        &self,
        keys: &BcrKeys,
        request: MintRecordSnapshotRequest,
        created_at: Timestamp,
    ) -> Result<MintRecordSnapshot> {
        self.mint_records(keys)?;
        let subject = self.identity_subject(keys)?;
        let wrappers = self.get_chain_with_plaintext_block_data(keys)?;
        let mut blocks = Vec::with_capacity(wrappers.len());
        for wrapper in wrappers {
            let record = matches!(
                wrapper.block.op_code,
                IdentityOpCode::MintRecord
                    | IdentityOpCode::MintRecordDispute
                    | IdentityOpCode::IdentityProof
            );
            let block = MintRecordSnapshotBlock::new(
                &wrapper.block,
                record.then_some(wrapper.plaintext_data_bytes.as_slice()),
            );
            blocks.push(block);
        }
        MintRecordSnapshotPayload::new(subject, false, request, created_at, blocks)?.sign(keys)
    }
}

impl CompanyBlockchain {
    pub fn mint_records(&self, company_keys: &BcrKeys) -> Result<Vec<MintRecordView>> {
        let subject = self.get_first_block().company_id.clone();
        let mut records = vec![];
        let mut prefix = CompanyBlockchain::new_from_blocks(vec![self.get_first_block().clone()])?;
        for block in self.blocks() {
            if matches!(
                block.op_code,
                CompanyOpCode::MintRecord | CompanyOpCode::MintRecordDispute
            ) {
                let plaintext = block.get_decrypted_block_bytes(company_keys)?;
                if Sha256Hash::from_bytes(&plaintext) != block.plaintext_hash {
                    return Err(invalid("plaintextHash mismatch"));
                }
                ingest(
                    &mut records,
                    block.id,
                    &block.hash,
                    block.timestamp,
                    &block.op_code.to_string(),
                    &plaintext,
                    &subject,
                    true,
                    |node| prefix.is_authorized_signatory(node, company_keys),
                )?;
            }
            if !block.id.is_first() && !prefix.try_add_block(block.clone()) {
                return Err(invalid("invalid chain"));
            }
        }
        Ok(records)
    }
    /// Used before persistence on receipt, sync and recovery, and by local creation.
    pub fn validate_mint_record_block(
        &self,
        block: &CompanyBlock,
        company_keys: &BcrKeys,
    ) -> Result<()> {
        if !matches!(
            block.op_code,
            CompanyOpCode::MintRecord | CompanyOpCode::MintRecordDispute
        ) {
            return Ok(());
        }
        let subject = self.get_first_block().company_id.clone();
        let mut records = self.mint_records(company_keys)?;
        let plaintext = block.get_decrypted_block_bytes(company_keys)?;
        if block.plaintext_hash != Sha256Hash::from_bytes(&plaintext) {
            return Err(invalid("plaintextHash mismatch"));
        }
        if block.company_id != subject {
            return Err(invalid("wrong subject"));
        }
        ingest(
            &mut records,
            block.id,
            &block.hash,
            block.timestamp,
            &block.op_code.to_string(),
            &plaintext,
            &subject,
            true,
            |node| self.is_authorized_signatory(node, company_keys),
        )
    }
    pub fn create_mint_record(
        &self,
        data: &MintRecordBlockData,
        identity_keys: &BcrKeys,
        company_keys: &BcrKeys,
        timestamp: Timestamp,
    ) -> Result<CompanyBlock> {
        let records = self.mint_records(company_keys)?;
        let subject = self.get_first_block().company_id.clone();
        validate_entry(
            data,
            &subject,
            true,
            |node| self.is_authorized_signatory(node, company_keys),
            &records,
        )?;
        self.authorize_mint_record_signer(identity_keys, company_keys)?;
        CompanyBlock::encrypt_data_create_block_and_validate(
            self.get_first_block().company_id.clone(),
            self.get_latest_block(),
            data,
            identity_keys,
            company_keys,
            None,
            timestamp,
            CompanyOpCode::MintRecord,
        )
    }
    pub fn create_mint_record_dispute(
        &self,
        data: &MintRecordDisputeBlockData,
        identity_keys: &BcrKeys,
        company_keys: &BcrKeys,
        timestamp: Timestamp,
    ) -> Result<CompanyBlock> {
        validate_dispute(data, &self.mint_records(company_keys)?)?;
        self.authorize_mint_record_signer(identity_keys, company_keys)?;
        CompanyBlock::encrypt_data_create_block_and_validate(
            self.get_first_block().company_id.clone(),
            self.get_latest_block(),
            data,
            identity_keys,
            company_keys,
            None,
            timestamp,
            CompanyOpCode::MintRecordDispute,
        )
    }
    pub fn authorize_mint_record_signer(
        &self,
        identity_keys: &BcrKeys,
        company_keys: &BcrKeys,
    ) -> Result<()> {
        let node = NodeId::new(
            identity_keys.pub_key(),
            self.get_first_block().company_id.network(),
        );
        if !self.is_authorized_signatory(&node, company_keys)? {
            return Err(invalid("caller must be authorized company signatory"));
        }
        Ok(())
    }
    pub fn mint_record_snapshot(
        &self,
        company_keys: &BcrKeys,
        request: MintRecordSnapshotRequest,
        created_at: Timestamp,
    ) -> Result<MintRecordSnapshot> {
        self.mint_records(company_keys)?;
        let subject = self.get_first_block().company_id.clone();
        let wrappers = self.get_chain_with_plaintext_block_data(company_keys)?;
        let mut blocks = Vec::with_capacity(wrappers.len());
        for wrapper in wrappers {
            let record = matches!(
                wrapper.block.op_code,
                CompanyOpCode::MintRecord
                    | CompanyOpCode::MintRecordDispute
                    | CompanyOpCode::IdentityProof
            );
            let mut block = MintRecordSnapshotBlock::new(
                &wrapper.block,
                record.then_some(wrapper.plaintext_data_bytes.as_slice()),
            );
            block.company_id = Some(wrapper.block.company_id);
            block.signatory_node_id = Some(wrapper.block.signatory_node_id);
            blocks.push(block);
        }
        MintRecordSnapshotPayload::new(subject, true, request, created_at, blocks)?
            .sign(company_keys)
    }
}
impl MintRecordSnapshot {
    /// Verifies the signed disclosure. The receiving application additionally owns single-use storage.
    /// Record, dispute and identity-proof plaintext is mandatory; any other plaintext is refused.
    /// Historical company membership is attested by the company snapshot signer: the other blocks
    /// deliberately do not disclose signatory operations or their plaintext.
    pub fn verify(
        &self,
        subject: &NodeId,
        receiving_mint_key: &str,
        application_ref: &str,
        now: Timestamp,
    ) -> Result<MintRecordSnapshotPayload> {
        let sig = schnorr::Signature::from_str(&self.signature)
            .map_err(|_| invalid("bad snapshot signature"))?;
        SECP256K1
            .verify_schnorr(
                &sig,
                &Message::from_digest(domain_hash(SNAPSHOT_DOMAIN, self.payload.as_bytes())),
                &subject.pub_key().x_only_public_key().0,
            )
            .map_err(|_| invalid("bad snapshot signature"))?;
        let payload: MintRecordSnapshotPayload =
            serde_json::from_str(&self.payload).map_err(|_| invalid("invalid snapshot payload"))?;
        if payload.schema != "mint-record-snapshot-v1" {
            return Err(invalid("wrong snapshot schema"));
        }
        if &payload.subject_node_id != subject {
            return Err(invalid("wrong subject"));
        }
        if payload.network != subject.network().to_string() {
            return Err(invalid("wrong network"));
        }
        x_only(receiving_mint_key)?;
        if payload.receiving_mint_key != receiving_mint_key {
            return Err(invalid("wrong receivingMintKey"));
        }
        if payload.application_ref != application_ref {
            return Err(invalid("wrong applicationRef"));
        }
        if now.inner().abs_diff(payload.created_at.inner()) > 600 {
            return Err(invalid("snapshot outside freshness window"));
        }
        let company = match payload.chain.as_str() {
            "identity" => false,
            "company" => true,
            _ => return Err(invalid("wrong chain")),
        };
        let mut previous_hash = Sha256Hash::from_bytes(
            if company {
                subject.to_string()
            } else {
                subject.pub_key().to_string()
            }
            .as_bytes(),
        );
        let mut expected_id = BlockId::first();
        let mut previous_timestamp = Timestamp::zero();
        let mut records = vec![];
        let mut proofs = vec![];
        for block in &payload.blocks {
            if block.id != expected_id || block.previous_hash != previous_hash {
                return Err(invalid("broken previous-hash link"));
            }
            let signature = schnorr::Signature::from_str(&block.signature)
                .map_err(|_| invalid("bad block signature"))?;
            SECP256K1
                .verify_schnorr(
                    &signature,
                    &Message::from_digest(block.hash.decode_to_array()),
                    &block.public_key.x_only_public_key().0,
                )
                .map_err(|_| invalid("bad block signature"))?;
            if !company && block.public_key != subject.pub_key() {
                return Err(invalid("wrong block publicKey"));
            }
            if block.timestamp < previous_timestamp {
                return Err(invalid("decreasing block timestamp"));
            }
            previous_timestamp = block.timestamp;
            let op = &block.op_code;
            if block.id.is_first() != (op == "Create") {
                return Err(invalid("invalid create block position"));
            }
            let timestamp = block.timestamp;
            let plaintext_hash = block.plaintext_hash.clone();
            let data = STANDARD
                .decode(&block.data)
                .map_err(|_| invalid("invalid data base64"))?;
            let sig = super::SchnorrSignature::from(signature);
            let valid_hash = if company {
                let company_id = block
                    .company_id
                    .clone()
                    .ok_or_else(|| invalid("missing companyId"))?;
                let signatory_node_id = block
                    .signatory_node_id
                    .clone()
                    .ok_or_else(|| invalid("missing signatoryNodeId"))?;
                if &company_id != subject || signatory_node_id.network() != subject.network() {
                    return Err(invalid("wrong subject"));
                }
                let aggregated = subject
                    .pub_key()
                    .combine(&signatory_node_id.pub_key())
                    .map_err(|_| invalid("invalid company publicKey"))?;
                if aggregated != block.public_key {
                    return Err(invalid("wrong company publicKey"));
                }
                CompanyBlock {
                    company_id,
                    id: block.id,
                    plaintext_hash,
                    hash: block.hash.clone(),
                    timestamp,
                    data,
                    public_key: block.public_key,
                    signatory_node_id,
                    previous_hash: block.previous_hash.clone(),
                    signature: sig,
                    op_code: CompanyOpCode::from_str(op).map_err(|_| invalid("invalid opCode"))?,
                }
                .validate_hash()
            } else {
                if block.company_id.is_some() || block.signatory_node_id.is_some() {
                    return Err(invalid("unexpected company metadata"));
                }
                IdentityBlock {
                    id: block.id,
                    plaintext_hash,
                    hash: block.hash.clone(),
                    timestamp,
                    data,
                    public_key: block.public_key,
                    previous_hash: block.previous_hash.clone(),
                    signature: sig,
                    op_code: IdentityOpCode::from_str(op).map_err(|_| invalid("invalid opCode"))?,
                }
                .validate_hash()
            };
            if !valid_hash {
                return Err(invalid("block hash mismatch"));
            }
            if op == "IdentityProof" {
                let plaintext = STANDARD
                    .decode(
                        block
                            .plaintext
                            .as_ref()
                            .ok_or_else(|| invalid("missing identity proof plaintext"))?,
                    )
                    .map_err(|_| invalid("invalid plaintext base64"))?;
                if block.plaintext_hash != Sha256Hash::from_bytes(&plaintext) {
                    return Err(invalid("plaintextHash mismatch"));
                }
                let (proof, data) = if company {
                    borsh::from_slice::<CompanyIdentityProofBlockData>(&plaintext)
                        .map(|d| (d.proof, d.data))
                } else {
                    borsh::from_slice::<IdentityProofBlockData>(&plaintext)
                        .map(|d| (d.proof, d.data))
                }
                .map_err(|_| invalid("invalid identity proof"))?;
                if !matches!(proof.verify(&data), Ok(true)) {
                    return Err(invalid("invalid identity proof"));
                }
                proofs.push((proof, data));
            } else if op == "MintRecord" || op == "MintRecordDispute" {
                let plaintext = STANDARD
                    .decode(
                        block
                            .plaintext
                            .as_ref()
                            .ok_or_else(|| invalid("missing record plaintext"))?,
                    )
                    .map_err(|_| invalid("invalid plaintext base64"))?;
                if block.plaintext_hash != Sha256Hash::from_bytes(&plaintext) {
                    return Err(invalid("plaintextHash mismatch"));
                }
                ingest(
                    &mut records,
                    block.id,
                    &block.hash,
                    timestamp,
                    op,
                    &plaintext,
                    subject,
                    company,
                    |_| Ok(true),
                )?;
            } else if block.plaintext.is_some() {
                return Err(invalid("unexpected non-record plaintext"));
            }
            previous_hash = block.hash.clone();
            expected_id = expected_id.add(1);
        }
        let head = payload
            .blocks
            .last()
            .ok_or_else(|| invalid("empty snapshot"))?;
        if head.id != payload.head.id || head.hash != payload.head.hash {
            return Err(invalid("head mismatch"));
        }
        for record in &records {
            verify_identity_proof_references(record, &proofs, subject, company)?;
        }
        Ok(payload)
    }
}

/// `issuedAt` is RFC 3339 UTC (`Z`) with whole seconds; `.000` fractions are accepted.
fn issued_at(value: &str) -> Option<u64> {
    use time::format_description::well_known::Rfc3339;
    if !value.ends_with('Z') || value.as_bytes().get(10) != Some(&b'T') {
        return None;
    }
    let at = super::DateTimeUtc::parse(value, &Rfc3339).ok()?;
    (at.nanosecond() == 0)
        .then(|| u64::try_from(at.unix_timestamp()).ok())
        .flatten()
}

/// Rule 8: every `record.identityProofs` reference of every entry (entries are deltas, so a later
/// entry may name the same proof again) names a disclosed `IdentityProof` block with that
/// signature, witnessed by the entry's `issuer.mintNodeId` (public key; the network letter is
/// ignored), for this subject, signed at `issuedAt`. Witness signatures were checked on ingest.
/// The rest of the record stays opaque.
fn verify_identity_proof_references(
    record: &MintRecordView,
    proofs: &[(super::SignedIdentityProof, super::EmailIdentityProofData)],
    subject: &NodeId,
    company: bool,
) -> Result<()> {
    let entry: serde_json::Value =
        serde_json::from_str(&record.entry).map_err(|_| invalid("invalid identityProofs"))?;
    let references = match entry.get("record").and_then(|r| r.get("identityProofs")) {
        None => return Ok(()),
        Some(serde_json::Value::Array(references)) => references,
        Some(_) => return Err(invalid("invalid identityProofs")),
    };
    let mint = NodeId::from_str(&record.header.issuer.mint_node_id).ok();
    for reference in references {
        let (Some(signature), Some(at)) = (
            reference.get("signature").and_then(|v| v.as_str()),
            reference.get("issuedAt").and_then(|v| v.as_str()),
        ) else {
            return Err(invalid("invalid identityProofs reference"));
        };
        let (proof, data) = proofs
            .iter()
            .find(|(proof, _)| proof.signature.as_str() == signature)
            .ok_or_else(|| invalid("identity proof reference not found"))?;
        if mint.as_ref().map(NodeId::pub_key) != Some(proof.witness.pub_key()) {
            return Err(invalid(
                "identity proof reference witnessed by another Mint",
            ));
        }
        let for_subject = if company {
            data.company_node_id.as_ref() == Some(subject)
        } else {
            &data.node_id == subject && data.company_node_id.is_none()
        };
        if !for_subject {
            return Err(invalid("identity proof reference for another subject"));
        }
        if issued_at(at) != Some(data.created_at.inner()) {
            return Err(invalid("identity proof reference with wrong issuedAt"));
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        Email, EmailIdentityProofData, Name,
        blockchain::{
            company::block::{CompanyCreateBlockData, CompanyIdentityProofBlockData},
            identity::IdentityType,
        },
        tests::tests::{empty_identity, valid_address},
    };
    use bitcoin::{Network, secp256k1::SecretKey};
    use serde_json::json;

    fn keys(scalar: u8) -> BcrKeys {
        let mut bytes = [0u8; 32];
        bytes[31] = scalar;
        BcrKeys::from_private_key(&SecretKey::from_slice(&bytes).unwrap())
    }
    fn node(keys: &BcrKeys) -> NodeId {
        NodeId::new(keys.pub_key(), Network::Regtest)
    }
    fn ts(n: u64) -> Timestamp {
        Timestamp::new(1793361600 + n).unwrap()
    }
    fn identity() -> (IdentityBlockchain, BcrKeys) {
        let keys = keys(3);
        let mut data = empty_identity();
        data.node_id = node(&keys);
        data.t = IdentityType::Anon;
        data.email = None;
        (IdentityBlockchain::new(&data, &keys, ts(0)).unwrap(), keys)
    }
    fn company() -> (CompanyBlockchain, BcrKeys, BcrKeys) {
        let personal = keys(3);
        let company = keys(7);
        let id = node(&company);
        let mut chain = CompanyBlockchain::new(
            &CompanyCreateBlockData {
                id: id.clone(),
                name: Name::new("Synthetic farm").unwrap(),
                country_of_registration: None,
                city_of_registration: None,
                postal_address: valid_address(),
                email: Email::new("farm@example.com").unwrap(),
                registration_number: None,
                registration_date: None,
                proof_of_registration_file: None,
                logo_file: None,
                creation_time: ts(0),
                creator: node(&personal),
            },
            &personal,
            &company,
            ts(0),
        )
        .unwrap();
        let data = EmailIdentityProofData {
            node_id: node(&personal),
            company_node_id: Some(id.clone()),
            email: Email::new("farm@example.com").unwrap(),
            created_at: ts(1),
        };
        let proof = data
            .sign(&node(&personal), &personal.get_private_key())
            .unwrap();
        let block = CompanyBlock::create_block_for_identity_proof(
            id,
            chain.get_latest_block(),
            &CompanyIdentityProofBlockData {
                data,
                proof,
                reference_block: Some(BlockId::first()),
            },
            &personal,
            &company,
            ts(1),
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        (chain, personal, company)
    }
    fn entry(
        subject: &NodeId,
        company: Option<&NodeId>,
        issuer: &BcrKeys,
        sequence: u64,
        previous: Option<String>,
    ) -> MintRecordBlockData {
        signed(
            json!({"schema":"mint-record-entry-v1","network":"regtest","issuer":{"signingKey":issuer.pub_key().x_only_public_key().0.to_string(),"mintNodeId":node(issuer).to_string(),"name":"Synthetic Mint"},"subject":{"chain":if company.is_some(){"company"}else{"identity"},"nodeId":subject.to_string(),"companyNodeId":company.map(ToString::to_string)},"sequence":sequence,"previousEntryDigest":previous,"createdAt":"2026-10-30T12:00:00Z","reason":"applicant_request","record":{},"omissions":[]}),
            issuer,
        )
    }
    fn signed(value: serde_json::Value, issuer: &BcrKeys) -> MintRecordBlockData {
        let entry = serde_json::to_vec(&value).unwrap();
        let signature = SECP256K1
            .sign_schnorr_with_aux_rand(
                &Message::from_digest(domain_hash(ENTRY_DOMAIN, &entry)),
                &Keypair::from_secret_key(SECP256K1, &issuer.get_private_key()),
                &[0; 32],
            )
            .serialize();
        MintRecordBlockData { entry, signature }
    }
    fn malformed(
        data: &MintRecordBlockData,
        field: &str,
        value: serde_json::Value,
        issuer: &BcrKeys,
    ) -> MintRecordBlockData {
        let mut json: serde_json::Value = serde_json::from_slice(&data.entry).unwrap();
        let mut cursor = &mut json;
        let parts: Vec<_> = field.split('.').collect();
        for part in &parts[..parts.len() - 1] {
            cursor = &mut cursor[*part];
        }
        cursor[*parts.last().unwrap()] = value;
        signed(json, issuer)
    }
    fn refused_entries(
        data: &MintRecordBlockData,
        issuer: &BcrKeys,
    ) -> Vec<(MintRecordBlockData, &'static str)> {
        let mut badsig = data.clone();
        badsig.signature[0] ^= 1;
        let mut oversize = data.clone();
        oversize.entry = vec![b' '; MAX_MINT_RECORD_ENTRY_BYTES + 1];
        let mut utf8 = data.clone();
        utf8.entry = vec![255];
        let mut array = data.clone();
        array.entry = b"[]".to_vec();
        vec![
            (badsig, "bad entry signature"),
            (oversize, "oversize entry"),
            (utf8, "entry is not UTF-8"),
            (array, "entry is not a JSON header object"),
            (
                malformed(data, "network", json!("signet"), issuer),
                "wrong network",
            ),
            (
                malformed(data, "schema", json!("other"), issuer),
                "wrong schema",
            ),
            (
                malformed(data, "sequence", json!(0), issuer),
                "sequence gap",
            ),
            (
                malformed(data, "sequence", json!(2), issuer),
                "sequence gap",
            ),
            (
                malformed(data, "previousEntryDigest", json!("sha256:00"), issuer),
                "wrong previousEntryDigest",
            ),
            (
                malformed(data, "subject.nodeId", json!(node(&keys(11))), issuer),
                "wrong subject",
            ),
            (
                malformed(data, "subject.chain", json!("bill"), issuer),
                "wrong subject",
            ),
            (
                malformed(data, "issuer.signingKey", json!("not a key"), issuer),
                "invalid signing key",
            ),
        ]
    }
    fn reason<T: std::fmt::Debug>(result: Result<T>, expected: &str) {
        assert!(
            result.unwrap_err().to_string().contains(expected),
            "expected {expected}"
        );
    }

    #[test]
    fn mint_record_identity_creation_and_receipt_rules() {
        let (mut chain, key) = identity();
        let issuer = keys(5);
        let first = entry(&node(&key), None, &issuer, 1, None);
        for (bad, expected) in refused_entries(&first, &issuer) {
            reason(chain.create_mint_record(&bad, &key, ts(1)), expected);
            let block = IdentityBlock::encrypt_data_create_block_and_validate(
                chain.get_latest_block(),
                &bad,
                &key,
                ts(1),
                IdentityOpCode::MintRecord,
            )
            .unwrap();
            reason(chain.validate_mint_record_block(&block, &key), expected);
            let mut corrupt = chain.clone();
            assert!(corrupt.try_add_block(block));
            reason(corrupt.mint_records(&key), expected);
        }
        let wrong = malformed(
            &first,
            "subject.companyNodeId",
            json!(node(&keys(7))),
            &issuer,
        );
        reason(
            chain.create_mint_record(&wrong, &key, ts(1)),
            "wrong subject",
        );
        let block = chain.create_mint_record(&first, &key, ts(1)).unwrap();
        chain.validate_mint_record_block(&block, &key).unwrap();
        assert!(chain.try_add_block(block));
        reason(
            chain.create_mint_record(&first, &key, ts(2)),
            "sequence gap",
        );
        let second = entry(
            &node(&key),
            None,
            &issuer,
            2,
            Some(entry_digest(&first.entry)),
        );
        let wrong = malformed(
            &second,
            "previousEntryDigest",
            json!("sha256:deadbeef"),
            &issuer,
        );
        reason(
            chain.create_mint_record(&wrong, &key, ts(2)),
            "wrong previousEntryDigest",
        );
        let block = IdentityBlock::encrypt_data_create_block_and_validate(
            chain.get_latest_block(),
            &wrong,
            &key,
            ts(2),
            IdentityOpCode::MintRecord,
        )
        .unwrap();
        reason(
            chain.validate_mint_record_block(&block, &key),
            "wrong previousEntryDigest",
        );
        assert!(chain.try_add_block(chain.create_mint_record(&second, &key, ts(2)).unwrap()));
        assert!(
            chain.try_add_block(
                chain
                    .create_mint_record(&entry(&node(&key), None, &keys(11), 1, None), &key, ts(3))
                    .unwrap()
            )
        );
        let records = chain.mint_records(&key).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].entry.as_bytes(), first.entry);
        let mut encoded = first.clone();
        encoded.entry.extend_from_slice(b"\n");
        reason(encoded.header(), "bad entry signature");
        let snapshot = chain
            .mint_record_snapshot(
                &key,
                MintRecordSnapshotRequest {
                    receiving_mint_key: keys(13).pub_key().x_only_public_key().0.to_string(),
                    application_ref: "synthetic-app".into(),
                },
                ts(4),
            )
            .unwrap();
        let payload = snapshot
            .verify(
                &node(&key),
                &keys(13).pub_key().x_only_public_key().0.to_string(),
                "synthetic-app",
                ts(4),
            )
            .unwrap();
        assert_eq!(payload.blocks.len(), 4);
        assert!(payload.blocks[0].op_code == "Create");
        assert!(payload.blocks[0].plaintext.is_none());
    }
    #[test]
    fn mint_record_snapshot_resolves_identity_proof_references() {
        let mint = keys(5);
        let receiving = keys(13).pub_key().x_only_public_key().0.to_string();
        let verify = |proof_subject: NodeId, record: serde_json::Value| {
            let (mut chain, key) = identity();
            let data = EmailIdentityProofData {
                node_id: proof_subject,
                company_node_id: None,
                email: Email::new("applicant@example.com").unwrap(),
                created_at: ts(1),
            };
            let proof = data.sign(&node(&mint), &mint.get_private_key()).unwrap();
            let signature = proof.signature.to_string();
            let block = IdentityBlock::create_block_for_identity_proof(
                chain.get_latest_block(),
                &IdentityProofBlockData { proof, data },
                &key,
                ts(1),
            )
            .unwrap();
            assert!(chain.try_add_block(block));
            let record = serde_json::from_str::<serde_json::Value>(
                &record.to_string().replace("PROOF", &signature),
            )
            .unwrap();
            let entry = malformed(
                &entry(&node(&key), None, &mint, 1, None),
                "record",
                record,
                &mint,
            );
            assert!(chain.try_add_block(chain.create_mint_record(&entry, &key, ts(2)).unwrap()));
            let request = MintRecordSnapshotRequest {
                receiving_mint_key: receiving.clone(),
                application_ref: "synthetic-app".into(),
            };
            chain
                .mint_record_snapshot(&key, request, ts(4))
                .unwrap()
                .verify(&node(&key), &receiving, "synthetic-app", ts(4))
        };
        let reference = |at: &str| json!({"identityProofs":[{"id":"identity-proof:1","signature":"PROOF","issuedAt":at}]});
        let subject = node(&keys(3));
        verify(subject.clone(), reference("2026-10-30T12:00:01Z")).unwrap();
        // AI-Credit renders issuedAt with Date#toISOString: whole seconds with a .000 fraction.
        verify(subject.clone(), reference("2026-10-30T12:00:01.000Z")).unwrap();
        for at in [
            "2026-10-30T12:00:02Z",
            "2026-10-30T12:00:01.500Z",
            "2026-10-30T12:00:01+00:00",
            "2026-10-30 12:00:01Z",
            "1793361601",
        ] {
            reason(
                verify(subject.clone(), reference(at)),
                "identity proof reference with wrong issuedAt",
            );
        }
        reason(
            verify(node(&keys(19)), reference("2026-10-30T12:00:01Z")),
            "identity proof reference for another subject",
        );
        reason(
            verify(subject.clone(), json!({"identityProofs":{}})),
            "invalid identityProofs",
        );
        reason(
            verify(subject, json!({"identityProofs":[{"signature":"PROOF"}]})),
            "invalid identityProofs reference",
        );
    }
    #[test]
    fn mint_record_company_creation_and_receipt_rules() {
        let (mut chain, personal, key) = company();
        let issuer = keys(5);
        let first = entry(&node(&personal), Some(&node(&key)), &issuer, 1, None);
        for (bad, expected) in refused_entries(&first, &issuer) {
            reason(
                chain.create_mint_record(&bad, &personal, &key, ts(2)),
                expected,
            );
            let block = CompanyBlock::encrypt_data_create_block_and_validate(
                node(&key),
                chain.get_latest_block(),
                &bad,
                &personal,
                &key,
                None,
                ts(2),
                CompanyOpCode::MintRecord,
            )
            .unwrap();
            reason(chain.validate_mint_record_block(&block, &key), expected);
            let mut corrupt = chain.clone();
            assert!(corrupt.try_add_block(block));
            reason(corrupt.mint_records(&key), expected);
        }
        for (path, value) in [
            ("subject.companyNodeId", json!(null)),
            ("subject.companyNodeId", json!(node(&keys(11)))),
            ("subject.nodeId", json!(node(&keys(11)))),
        ] {
            let bad = malformed(&first, path, value, &issuer);
            reason(
                chain.create_mint_record(&bad, &personal, &key, ts(2)),
                "wrong subject",
            );
            let block = CompanyBlock::encrypt_data_create_block_and_validate(
                node(&key),
                chain.get_latest_block(),
                &bad,
                &personal,
                &key,
                None,
                ts(2),
                CompanyOpCode::MintRecord,
            )
            .unwrap();
            reason(
                chain.validate_mint_record_block(&block, &key),
                "wrong subject",
            );
        }
        let block = chain
            .create_mint_record(&first, &personal, &key, ts(2))
            .unwrap();
        chain.validate_mint_record_block(&block, &key).unwrap();
        assert!(chain.try_add_block(block));
        let second = entry(
            &node(&personal),
            Some(&node(&key)),
            &issuer,
            2,
            Some(entry_digest(&first.entry)),
        );
        assert!(
            chain.try_add_block(
                chain
                    .create_mint_record(&second, &personal, &key, ts(3))
                    .unwrap()
            )
        );
        reason(
            chain.create_mint_record(
                &entry(&node(&personal), Some(&node(&key)), &keys(11), 1, None),
                &keys(13),
                &key,
                ts(4),
            ),
            "caller must be authorized",
        );
        let snapshot = chain
            .mint_record_snapshot(
                &key,
                MintRecordSnapshotRequest {
                    receiving_mint_key: keys(13).pub_key().x_only_public_key().0.to_string(),
                    application_ref: "synthetic-company-app".into(),
                },
                ts(4),
            )
            .unwrap();
        let payload = snapshot
            .verify(
                &node(&key),
                &keys(13).pub_key().x_only_public_key().0.to_string(),
                "synthetic-company-app",
                ts(4),
            )
            .unwrap();
        assert_eq!(payload.blocks.len(), 4);
        assert!(payload.blocks[0].op_code == "Create");
        assert!(payload.blocks[0].plaintext.is_none());
        assert!(payload.blocks[1].op_code == "IdentityProof");
        let proof: CompanyIdentityProofBlockData = borsh::from_slice(
            &STANDARD
                .decode(payload.blocks[1].plaintext.as_ref().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(proof.data.company_node_id, Some(node(&key)));
        assert!(payload.blocks[2].signatory_node_id.is_some());
    }
    #[test]
    fn mint_record_disputes_creation_and_receipt_rules_both_chains() {
        let (mut identity, key) = identity();
        let (mut company, personal, company_key) = company();
        let issuer = keys(5);
        let ie = entry(&node(&key), None, &issuer, 1, None);
        let ce = entry(
            &node(&personal),
            Some(&node(&company_key)),
            &issuer,
            1,
            None,
        );
        let ib = identity.create_mint_record(&ie, &key, ts(2)).unwrap();
        let cb = company
            .create_mint_record(&ce, &personal, &company_key, ts(2))
            .unwrap();
        let iid = ib.id;
        let cid = cb.id;
        assert!(identity.try_add_block(ib));
        assert!(company.try_add_block(cb));
        for is_company in [false, true] {
            let data = MintRecordDisputeBlockData {
                entry_block_id: if is_company { cid } else { iid },
                entry_digest: entry_digest(if is_company { &ce.entry } else { &ie.entry }),
                statement: "I dispute the recorded date.".into(),
                created_at: ts(3),
            };
            let mut bad_digest = data.clone();
            bad_digest.entry_digest = "sha256:00".into();
            let mut missing = data.clone();
            missing.entry_block_id = BlockId::first();
            let mut empty = data.clone();
            empty.statement = String::new();
            let mut long = data.clone();
            long.statement = "é".repeat(1001);
            for (bad, expected) in [
                (bad_digest, "dispute with wrong digest"),
                (missing, "dispute entry not found"),
                (empty, "1..=1000"),
                (long, "1..=1000"),
            ] {
                if is_company {
                    reason(
                        company.create_mint_record_dispute(&bad, &personal, &company_key, ts(3)),
                        expected,
                    );
                    let block = CompanyBlock::encrypt_data_create_block_and_validate(
                        node(&company_key),
                        company.get_latest_block(),
                        &bad,
                        &personal,
                        &company_key,
                        None,
                        ts(3),
                        CompanyOpCode::MintRecordDispute,
                    )
                    .unwrap();
                    reason(
                        company.validate_mint_record_block(&block, &company_key),
                        expected,
                    );
                } else {
                    reason(
                        identity.create_mint_record_dispute(&bad, &key, ts(3)),
                        expected,
                    );
                    let block = IdentityBlock::encrypt_data_create_block_and_validate(
                        identity.get_latest_block(),
                        &bad,
                        &key,
                        ts(3),
                        IdentityOpCode::MintRecordDispute,
                    )
                    .unwrap();
                    reason(identity.validate_mint_record_block(&block, &key), expected);
                }
            }
            let mut boundary = data;
            boundary.statement = "é".repeat(1000);
            if is_company {
                let b = company
                    .create_mint_record_dispute(&boundary, &personal, &company_key, ts(3))
                    .unwrap();
                company
                    .validate_mint_record_block(&b, &company_key)
                    .unwrap();
                assert!(company.try_add_block(b));
                assert_eq!(
                    company.mint_records(&company_key).unwrap()[0]
                        .disputes
                        .len(),
                    1
                );
            } else {
                let b = identity
                    .create_mint_record_dispute(&boundary, &key, ts(3))
                    .unwrap();
                identity.validate_mint_record_block(&b, &key).unwrap();
                assert!(identity.try_add_block(b));
                assert_eq!(identity.mint_records(&key).unwrap()[0].disputes.len(), 1);
            }
        }
    }
    #[test]
    fn mint_record_pins_all_existing_borsh_indices_and_plaintext_layout() {
        for (index, op) in [
            IdentityOpCode::Create,
            IdentityOpCode::Update,
            IdentityOpCode::SignPersonBill,
            IdentityOpCode::SignCompanyBill,
            IdentityOpCode::CreateCompany,
            IdentityOpCode::InviteSignatory,
            IdentityOpCode::AcceptSignatoryInvite,
            IdentityOpCode::RejectSignatoryInvite,
            IdentityOpCode::RemoveSignatory,
            IdentityOpCode::IdentityProof,
            IdentityOpCode::MintRecord,
            IdentityOpCode::MintRecordDispute,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(borsh::to_vec(&op).unwrap(), vec![index as u8]);
        }
        for (index, op) in [
            CompanyOpCode::Create,
            CompanyOpCode::Update,
            CompanyOpCode::InviteSignatory,
            CompanyOpCode::RemoveSignatory,
            CompanyOpCode::SignatoryAcceptInvite,
            CompanyOpCode::SignatoryRejectInvite,
            CompanyOpCode::SignCompanyBill,
            CompanyOpCode::IdentityProof,
            CompanyOpCode::MintRecord,
            CompanyOpCode::MintRecordDispute,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(borsh::to_vec(&op).unwrap(), vec![index as u8]);
        }
        let data = MintRecordBlockData {
            entry: b"abc".to_vec(),
            signature: [42; 64],
        };
        let bytes = borsh::to_vec(&data).unwrap();
        assert_eq!(&bytes[..7], b"\x03\x00\x00\x00abc");
        assert_eq!(&bytes[7..], &[42; 64]);
    }
    #[test]
    fn mint_record_size_boundary_and_strict_header_object() {
        let issuer = keys(5);
        let data = entry(&node(&keys(3)), None, &issuer, 1, None);
        let mut value: serde_json::Value = serde_json::from_slice(&data.entry).unwrap();
        value["record"]["padding"] = json!("");
        let overhead = serde_json::to_vec(&value).unwrap().len();
        value["record"]["padding"] = json!("x".repeat(MAX_MINT_RECORD_ENTRY_BYTES - overhead));
        let exact = signed(value.clone(), &issuer);
        assert_eq!(exact.entry.len(), MAX_MINT_RECORD_ENTRY_BYTES);
        exact.header().unwrap();
        value["record"]["padding"] = json!("x".repeat(MAX_MINT_RECORD_ENTRY_BYTES - overhead + 1));
        reason(signed(value, &issuer).header(), "oversize entry");
        let header: serde_json::Value = serde_json::from_slice(&data.entry).unwrap();
        let tuple = json!([
            header["schema"],
            header["network"],
            header["issuer"],
            header["subject"],
            header["sequence"],
            header["previousEntryDigest"],
            header["createdAt"],
            header["reason"]
        ]);
        reason(signed(tuple, &issuer).header(), "JSON header object");
        for path in ["issuer", "subject"] {
            let mut value: serde_json::Value = serde_json::from_slice(&data.entry).unwrap();
            value[path] = if path == "issuer" {
                json!([
                    value[path]["signingKey"],
                    value[path]["mintNodeId"],
                    value[path]["name"]
                ])
            } else {
                json!([
                    value[path]["chain"],
                    value[path]["nodeId"],
                    value[path]["companyNodeId"]
                ])
            };
            reason(signed(value, &issuer).header(), "JSON header object");
        }
        for path in ["previousEntryDigest", "companyNodeId"] {
            let mut v: serde_json::Value = serde_json::from_slice(&data.entry).unwrap();
            if path == "previousEntryDigest" {
                v.as_object_mut().unwrap().remove(path);
            } else {
                v["subject"].as_object_mut().unwrap().remove(path);
            }
            reason(signed(v, &issuer).header(), "JSON header object");
        }
        assert!(
            MintRecordBlockData::from_text(
                String::from_utf8(data.entry).unwrap(),
                &"AA".repeat(64)
            )
            .is_err()
        );
    }
}
