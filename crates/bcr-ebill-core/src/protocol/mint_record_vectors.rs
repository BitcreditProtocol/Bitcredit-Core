//! Public synthetic vectors generated only by native unit tests. No test signer is exported.
use crate::protocol::{
    BlockId, Email, EmailIdentityProofData, Name, OptionalPostalAddress, PostalAddress,
    SchnorrSignature, Sha256Hash, Timestamp,
    blockchain::{
        Block, Blockchain,
        company::{
            CompanyBlock, CompanyBlockchain,
            block::{CompanyCreateBlockData, CompanyIdentityProofBlockData},
        },
        identity::{
            IdentityBlock, IdentityBlockchain, IdentityCreateBlockData, IdentityProofBlockData,
            IdentityType,
        },
    },
    crypto::BcrKeys,
    mint_record::*,
};
use aes_gcm::{
    AesGcm,
    aead::{AeadInOut, KeyInit, Nonce},
    aes::{Aes256, cipher::consts::U16},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bcr_common::core::NodeId;
use bitcoin::{
    Network,
    secp256k1::{Keypair, Message, SECP256K1, Scalar, SecretKey},
};
use serde_json::{Value, json};

fn keys(scalar: u8) -> BcrKeys {
    let mut bytes = [0u8; 32];
    bytes[31] = scalar;
    BcrKeys::from_private_key(&SecretKey::from_slice(&bytes).unwrap())
}
fn node(keys: &BcrKeys) -> NodeId {
    NodeId::new(keys.pub_key(), Network::Regtest)
}
fn ts(offset: u64) -> Timestamp {
    Timestamp::new(1793361600 + offset).unwrap()
}
fn xkey(scalar: u8) -> String {
    keys(scalar).pub_key().x_only_public_key().0.to_string()
}
fn sign(hash: [u8; 32], secret: &SecretKey) -> bitcoin::secp256k1::schnorr::Signature {
    SECP256K1.sign_schnorr_with_aux_rand(
        &Message::from_digest(hash),
        &Keypair::from_secret_key(SECP256K1, secret),
        &[0; 32],
    )
}
/// Fixed ephemeral scalar and nonce ONLY for public test fixtures; normal ECIES stays randomized.
fn encrypt(plaintext: &[u8], receiver: &BcrKeys, block_id: BlockId) -> Vec<u8> {
    let ephemeral =
        ecies::SecretKey::parse_slice(&keys(17).get_private_key().secret_bytes()).unwrap();
    let peer = ecies::PublicKey::parse_slice(&receiver.pub_key().serialize(), None).unwrap();
    let key = ecies::utils::encapsulate(&ephemeral, &peer, false).unwrap();
    let cipher = AesGcm::<Aes256, U16>::new_from_slice(&key).unwrap();
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&block_id.inner().to_le_bytes());
    // Identity and company use different receiver keys, hence distinct symmetric keys.
    let nonce = Nonce::<AesGcm<Aes256, U16>>::try_from(iv.as_slice()).unwrap();
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"", ciphertext.as_mut_slice().into())
        .unwrap();
    let mut output = keys(17).pub_key().serialize_uncompressed().to_vec();
    output.extend(iv);
    output.extend_from_slice(&tag);
    output.extend(ciphertext);
    assert_eq!(
        ecies::decrypt(&receiver.get_private_key().secret_bytes(), &output).unwrap(),
        plaintext
    );
    output
}
fn stable_identity(block: &mut IdentityBlock, plaintext: &[u8], key: &BcrKeys) {
    block.data = encrypt(plaintext, key, block.id);
    block.hash = IdentityBlock::calculate_hash(block.get_block_data_to_hash()).unwrap();
    block.signature =
        SchnorrSignature::from(sign(block.hash.decode_to_array(), &key.get_private_key()));
}
fn stable_company(block: &mut CompanyBlock, plaintext: &[u8], personal: &BcrKeys, key: &BcrKeys) {
    block.data = borsh::to_vec(&(encrypt(plaintext, key, block.id), None::<String>)).unwrap();
    block.hash = CompanyBlock::calculate_hash(block.get_block_data_to_hash()).unwrap();
    let aggregate = personal
        .get_private_key()
        .add_tweak(&Scalar::from(key.get_private_key()))
        .unwrap();
    block.signature = SchnorrSignature::from(sign(block.hash.decode_to_array(), &aggregate));
}
/// An entry in the §1.1–§1.3 form: only new or corrected items, each with an id.
#[allow(clippy::too_many_arguments)]
fn entry(
    person: &NodeId,
    company: Option<&NodeId>,
    issuer: u8,
    sequence: u64,
    previous: Option<String>,
    created_at: &str,
    reason: &str,
    record: Value,
) -> MintRecordBlockData {
    signed_entry(
        json!({"schema":"mint-record-entry-v1","network":"regtest","issuer":{"signingKey":xkey(issuer),"mintNodeId":node(&keys(issuer)),"name":format!("Synthetic Mint {issuer}")},"subject":{"chain":if company.is_some(){"company"}else{"identity"},"nodeId":person,"companyNodeId":company},"sequence":sequence,"previousEntryDigest":previous,"createdAt":created_at,"reason":reason,"record":record,"omissions":[{"section":"documents","reason":"File contents are not carried; the hash identifies each file."}]}),
        issuer,
    )
}
fn harvest_claim(claim: &str, evidence_state: &str) -> Value {
    json!({"id":"claim:harvest","claim":claim,"topic":"business","evidenceState":evidence_state})
}
fn signed_entry(mut value: Value, issuer: u8) -> MintRecordBlockData {
    // Issuers serialize with RFC 8785 (JCS). With ASCII keys, integers and compact output,
    // sorted serde_json output is the JCS text; verifiers still use the exact bytes.
    value.sort_all_objects();
    let entry = serde_json::to_vec(&value).unwrap();
    let signature = sign(
        domain_hash(ENTRY_DOMAIN, &entry),
        &keys(issuer).get_private_key(),
    )
    .serialize();
    MintRecordBlockData { entry, signature }
}
fn sign_payload(payload: &MintRecordSnapshotPayload, scalar: u8) -> MintRecordSnapshot {
    let payload = serde_json::to_string(payload).unwrap();
    let signature = sign(
        domain_hash(SNAPSHOT_DOMAIN, payload.as_bytes()),
        &keys(scalar).get_private_key(),
    )
    .to_string();
    MintRecordSnapshot { payload, signature }
}
fn public_entries(records: &[MintRecordView]) -> Vec<Value> {
    records.iter().map(|r|json!({"entry":r.entry,"signature":r.signature,"digest":r.digest,"header":r.header,"blockId":r.block_id})).collect()
}
fn identity_case() -> (MintRecordSnapshotPayload, Vec<Value>) {
    let key = keys(3);
    let subject = node(&key);
    let data = IdentityCreateBlockData {
        t: IdentityType::Anon,
        node_id: subject.clone(),
        name: Name::new("Synthetic Applicant").unwrap(),
        email: None,
        postal_address: OptionalPostalAddress::empty(),
        date_of_birth: None,
        city_of_birth: None,
        country_of_birth: None,
        identification_number: None,
        nostr_relays: vec![],
        profile_picture_file: None,
        identity_document_file: None,
    };
    let mut chain = IdentityBlockchain::new(&data, &key, ts(0)).unwrap();
    stable_identity(
        &mut chain.blocks_mut()[0],
        &borsh::to_vec(&data).unwrap(),
        &key,
    );
    // Mint A's email proof precedes its records; the snapshot discloses its plaintext.
    let proof = EmailIdentityProofData {
        node_id: subject.clone(),
        company_node_id: None,
        email: Email::new("applicant@example.com").unwrap(),
        created_at: ts(1),
    };
    let proof = IdentityProofBlockData {
        proof: crate::protocol::SignedIdentityProof {
            signature: SchnorrSignature::from(sign(
                Sha256Hash::from_bytes(&borsh::to_vec(&proof).unwrap()).decode_to_array(),
                &keys(5).get_private_key(),
            )),
            witness: node(&keys(5)),
        },
        data: proof,
    };
    let mut block = IdentityBlock::create_block_for_identity_proof(
        chain.get_latest_block(),
        &proof,
        &key,
        ts(1),
    )
    .unwrap();
    stable_identity(&mut block, &borsh::to_vec(&proof).unwrap(), &key);
    assert!(chain.try_add_block(block));
    // Mint A references its proof, then corrects one item by id and withdraws another.
    let first = entry(
        &subject,
        None,
        5,
        1,
        None,
        "2026-10-30T12:00:01Z",
        "applicant_request",
        json!({
            "identityProofs":[{"id":"identity-proof:1","signature":proof.proof.signature.as_str(),"issuedAt":"2026-10-30T12:00:01Z"}],
            "claims":[
                harvest_claim("Synthetic harvest estimate", "applicant_statement"),
                {"id":"claim:buyers","claim":"Synthetic buyer cooperative","topic":"buyers","evidenceState":"applicant_statement"}
            ],
            "instruments":[{"id":"instrument:1","billId":"synthetic-bill-1","outcome":"unknown","recordedAt":null}]
        }),
    );
    let second = entry(
        &subject,
        None,
        5,
        2,
        Some(entry_digest(&first.entry)),
        "2026-10-30T12:00:02Z",
        "correction",
        json!({
            "claims":[harvest_claim("Synthetic harvest estimate, corrected", "applicant_confirmed")],
            "instruments":[{"id":"instrument:1","billId":"synthetic-bill-1","outcome":"paid_late","daysLate":3,"recordedAt":"2026-10-30T12:00:02Z"}],
            "withdrawn":["claim:buyers"]
        }),
    );
    let other = entry(
        &subject,
        None,
        11,
        1,
        None,
        "2026-10-30T12:00:03Z",
        "applicant_request",
        json!({"claims":[harvest_claim("Synthetic harvest estimate", "applicant_statement")]}),
    );
    for (offset, data) in [first.clone(), second, other].into_iter().enumerate() {
        let mut block = chain
            .create_mint_record(&data, &key, ts(offset as u64 + 1))
            .unwrap();
        stable_identity(&mut block, &borsh::to_vec(&data).unwrap(), &key);
        chain.validate_mint_record_block(&block, &key).unwrap();
        assert!(chain.try_add_block(block));
    }
    let dispute = MintRecordDisputeBlockData {
        entry_block_id: BlockId::first().add(2),
        entry_digest: entry_digest(&first.entry),
        statement: "I dispute the harvest estimate.".into(),
        created_at: ts(4),
    };
    let mut block = chain
        .create_mint_record_dispute(&dispute, &key, ts(4))
        .unwrap();
    stable_identity(&mut block, &borsh::to_vec(&dispute).unwrap(), &key);
    chain.validate_mint_record_block(&block, &key).unwrap();
    assert!(chain.try_add_block(block));
    let records = chain.mint_records(&key).unwrap();
    let snapshot = chain
        .mint_record_snapshot(
            &key,
            MintRecordSnapshotRequest {
                receiving_mint_key: xkey(13),
                application_ref: "synthetic-identity-application".into(),
            },
            ts(5),
        )
        .unwrap();
    (
        serde_json::from_str(&snapshot.payload).unwrap(),
        public_entries(&records),
    )
}
fn company_case() -> (MintRecordSnapshotPayload, Vec<Value>) {
    let personal = keys(3);
    let key = keys(7);
    let id = node(&key);
    let data = CompanyCreateBlockData {
        id: id.clone(),
        name: Name::new("Synthetic Farm").unwrap(),
        country_of_registration: None,
        city_of_registration: None,
        postal_address: PostalAddress {
            country: crate::protocol::Country::AT,
            city: crate::protocol::City::new("Vienna").unwrap(),
            zip: None,
            address: crate::protocol::Address::new("Synthetic street 1").unwrap(),
        },
        email: Email::new("farm@example.com").unwrap(),
        registration_number: None,
        registration_date: None,
        proof_of_registration_file: None,
        logo_file: None,
        creation_time: ts(0),
        creator: node(&personal),
    };
    let mut chain = CompanyBlockchain::new(&data, &personal, &key, ts(0)).unwrap();
    stable_company(
        &mut chain.blocks_mut()[0],
        &borsh::to_vec(&data).unwrap(),
        &personal,
        &key,
    );
    let data = EmailIdentityProofData {
        node_id: node(&personal),
        company_node_id: Some(id.clone()),
        email: Email::new("farm@example.com").unwrap(),
        created_at: ts(1),
    };
    let proof = SchnorrSignature::from(sign(
        Sha256Hash::from_bytes(&borsh::to_vec(&data).unwrap()).decode_to_array(),
        &personal.get_private_key(),
    ));
    let data = CompanyIdentityProofBlockData {
        proof: crate::protocol::SignedIdentityProof {
            signature: proof,
            witness: node(&personal),
        },
        data,
        reference_block: Some(BlockId::first()),
    };
    let mut block = CompanyBlock::create_block_for_identity_proof(
        id.clone(),
        chain.get_latest_block(),
        &data,
        &personal,
        &key,
        ts(1),
    )
    .unwrap();
    stable_company(&mut block, &borsh::to_vec(&data).unwrap(), &personal, &key);
    assert!(chain.try_add_block(block));
    let data = entry(
        &node(&personal),
        Some(&id),
        5,
        1,
        None,
        "2026-10-30T12:00:02Z",
        "applicant_request",
        json!({"claims":[harvest_claim("Synthetic harvest estimate", "applicant_statement")]}),
    );
    let mut block = chain
        .create_mint_record(&data, &personal, &key, ts(2))
        .unwrap();
    stable_company(&mut block, &borsh::to_vec(&data).unwrap(), &personal, &key);
    chain.validate_mint_record_block(&block, &key).unwrap();
    let entry_block_id = block.id;
    assert!(chain.try_add_block(block));
    let dispute = MintRecordDisputeBlockData {
        entry_block_id,
        entry_digest: entry_digest(&data.entry),
        statement: "The estimate needs correction.".into(),
        created_at: ts(3),
    };
    let mut block = chain
        .create_mint_record_dispute(&dispute, &personal, &key, ts(3))
        .unwrap();
    stable_company(
        &mut block,
        &borsh::to_vec(&dispute).unwrap(),
        &personal,
        &key,
    );
    chain.validate_mint_record_block(&block, &key).unwrap();
    assert!(chain.try_add_block(block));
    let records = chain.mint_records(&key).unwrap();
    let snapshot = chain
        .mint_record_snapshot(
            &key,
            MintRecordSnapshotRequest {
                receiving_mint_key: xkey(13),
                application_ref: "synthetic-company-application".into(),
            },
            ts(5),
        )
        .unwrap();
    (
        serde_json::from_str(&snapshot.payload).unwrap(),
        public_entries(&records),
    )
}
fn rehash(payload: &mut MintRecordSnapshotPayload) {
    let mut previous = payload.blocks[0].hash.clone();
    for block in payload.blocks.iter_mut().skip(1) {
        block.previous_hash = previous;
        if let Some(encoded) = &block.plaintext {
            let op = block.op_code.clone();
            let plain = STANDARD.decode(encoded).unwrap();
            let key = keys(if payload.chain == "company" { 7 } else { 3 });
            block.plaintext_hash = Sha256Hash::from_bytes(&plain);
            if payload.chain == "identity" {
                let mut real = IdentityBlock {
                    id: block.id,
                    plaintext_hash: block.plaintext_hash.clone(),
                    hash: block.hash.clone(),
                    timestamp: block.timestamp,
                    data: vec![],
                    public_key: block.public_key,
                    previous_hash: block.previous_hash.clone(),
                    signature: SchnorrSignature::from(sign([0; 32], &key.get_private_key())),
                    op_code: op.parse().unwrap(),
                };
                stable_identity(&mut real, &plain, &key);
                block.hash = real.hash;
                block.signature = real.signature.as_sig().to_string();
                block.data = STANDARD.encode(real.data);
            } else {
                let mut real = CompanyBlock {
                    company_id: node(&key),
                    id: block.id,
                    plaintext_hash: block.plaintext_hash.clone(),
                    hash: block.hash.clone(),
                    timestamp: block.timestamp,
                    data: vec![],
                    public_key: block.public_key,
                    signatory_node_id: block.signatory_node_id.clone().unwrap(),
                    previous_hash: block.previous_hash.clone(),
                    signature: SchnorrSignature::from(sign([0; 32], &key.get_private_key())),
                    op_code: op.parse().unwrap(),
                };
                stable_company(&mut real, &plain, &keys(3), &key);
                block.hash = real.hash;
                block.signature = real.signature.as_sig().to_string();
                block.data = STANDARD.encode(real.data);
            }
        }
        previous = block.hash.clone();
    }
    let head = payload.blocks.last().unwrap();
    payload.head = MintRecordSnapshotHead {
        id: head.id,
        hash: head.hash.clone(),
    };
}
fn change_entry(
    payload: &mut MintRecordSnapshotPayload,
    index: usize,
    edit: impl FnOnce(&mut Value),
    bad_signature: bool,
) {
    let block = &mut payload.blocks[index];
    let bytes = STANDARD.decode(block.plaintext.as_ref().unwrap()).unwrap();
    let mut data: MintRecordBlockData = borsh::from_slice(&bytes).unwrap();
    let mut value: Value = serde_json::from_slice(&data.entry).unwrap();
    edit(&mut value);
    let issuer = if value["issuer"]["signingKey"] == xkey(5) {
        5
    } else {
        11
    };
    data = signed_entry(value, issuer);
    if bad_signature {
        data.signature[0] ^= 1;
    }
    block.plaintext = Some(STANDARD.encode(borsh::to_vec(&data).unwrap()));
    rehash(payload);
}
fn case(payload: &MintRecordSnapshotPayload, entries: Vec<Value>, scalar: u8) -> Value {
    json!({"snapshot":sign_payload(payload,scalar),"subjectNodeId":payload.subject_node_id,"receivingMintKey":payload.receiving_mint_key,"applicationRef":payload.application_ref,"verifyAt":ts(5),"entries":entries,"expected":"accept"})
}
fn fixture() -> Value {
    let (identity, identity_entries) = identity_case();
    let (company, company_entries) = company_case();
    let mut negative = vec![];
    for (name, reason) in [
        ("bad_entry_signature", "bad entry signature"),
        ("wrong_network", "wrong network"),
        ("wrong_subject", "wrong subject"),
        ("sequence_gap", "sequence gap"),
        ("wrong_previous_entry_digest", "wrong previousEntryDigest"),
        ("oversize_entry", "oversize entry"),
        ("wrong_schema", "wrong schema"),
    ] {
        let mut payload = identity.clone();
        let index = if name == "sequence_gap" || name == "wrong_previous_entry_digest" {
            3
        } else {
            4
        };
        change_entry(
            &mut payload,
            index,
            |v| match name {
                "wrong_network" => v["network"] = json!("signet"),
                "wrong_subject" => v["subject"]["nodeId"] = json!(node(&keys(19))),
                "sequence_gap" => v["sequence"] = json!(3),
                "wrong_previous_entry_digest" => {
                    v["previousEntryDigest"] = json!("sha256:deadbeef")
                }
                "oversize_entry" => {
                    v["record"]["padding"] = json!("x".repeat(MAX_MINT_RECORD_ENTRY_BYTES))
                }
                "wrong_schema" => v["schema"] = json!("mint-record-entry-v2"),
                _ => {}
            },
            name == "bad_entry_signature",
        );
        let mut vector = case(&payload, vec![], 3);
        vector["name"] = json!(name);
        vector["expected"] = json!("reject");
        vector["expectedRejection"] = json!(reason);
        negative.push(vector);
    }
    for (name, reason) in [
        ("dispute_with_wrong_digest", "dispute with wrong digest"),
        ("broken_previous_hash_link", "broken previous-hash link"),
        ("tampered_plaintext", "plaintextHash mismatch"),
        ("bad_block_signature", "bad block signature"),
        ("bad_snapshot_signature", "bad snapshot signature"),
        ("wrong_receiving_mint_key", "wrong receivingMintKey"),
    ] {
        let mut payload = identity.clone();
        match name {
            "dispute_with_wrong_digest" => {
                let last = payload.blocks.last_mut().unwrap();
                let mut data: MintRecordDisputeBlockData =
                    borsh::from_slice(&STANDARD.decode(last.plaintext.as_ref().unwrap()).unwrap())
                        .unwrap();
                data.entry_digest = "sha256:deadbeef".into();
                last.plaintext = Some(STANDARD.encode(borsh::to_vec(&data).unwrap()));
                rehash(&mut payload);
            }
            "broken_previous_hash_link" => {
                payload.blocks[3].previous_hash = Sha256Hash::from_bytes(b"wrong link")
            }
            "tampered_plaintext" => {
                let mut bytes = STANDARD
                    .decode(payload.blocks[2].plaintext.as_ref().unwrap())
                    .unwrap();
                bytes[5] ^= 1;
                payload.blocks[2].plaintext = Some(STANDARD.encode(bytes));
            }
            "bad_block_signature" => {
                payload.blocks[2].signature = sign([0; 32], &keys(3).get_private_key()).to_string()
            }
            "wrong_receiving_mint_key" => payload.receiving_mint_key = xkey(19),
            _ => {}
        }
        let mut vector = case(&payload, vec![], 3);
        vector["name"] = json!(name);
        vector["receivingMintKey"] = json!(xkey(13));
        vector["expected"] = json!("reject");
        vector["expectedRejection"] = json!(reason);
        if name == "bad_snapshot_signature" {
            vector["snapshot"]["signature"] =
                json!(sign([0; 32], &keys(3).get_private_key()).to_string());
        }
        negative.push(vector);
    }
    // A signed record cannot be disguised as a non-record by omitting its disclosure.
    let mut concealed = identity.clone();
    concealed.blocks[4].op_code = "Update".into();
    concealed.blocks[4].plaintext = None;
    let mut vector = case(&concealed, vec![], 3);
    vector["name"] = json!("concealed_record");
    vector["expected"] = json!("reject");
    vector["expectedRejection"] = json!("block hash mismatch");
    negative.push(vector);
    let mut concealed = identity.clone();
    concealed.blocks[4].plaintext = None;
    let mut vector = case(&concealed, vec![], 3);
    vector["name"] = json!("missing_record_plaintext");
    vector["expected"] = json!("reject");
    vector["expectedRejection"] = json!("missing record plaintext");
    negative.push(vector);
    // The email proof a record refers to cannot be withheld or altered either.
    assert_eq!(identity.blocks[1].op_code, "IdentityProof");
    let mut hidden = identity.clone();
    hidden.blocks[1].plaintext = None;
    let mut altered = identity.clone();
    let mut bytes = STANDARD
        .decode(altered.blocks[1].plaintext.as_ref().unwrap())
        .unwrap();
    let at = bytes.len() - 9; // last byte of the email, before the u64 created_at
    bytes[at] ^= 1;
    altered.blocks[1].plaintext = Some(STANDARD.encode(bytes));
    // Any other block's plaintext is refused even when its hash would match.
    let mut extra = identity.clone();
    let create = STANDARD.decode(&extra.blocks[0].data).unwrap();
    let create = ecies::decrypt(&keys(3).get_private_key().secret_bytes(), &create).unwrap();
    assert_eq!(
        extra.blocks[0].plaintext_hash,
        Sha256Hash::from_bytes(&create)
    );
    extra.blocks[0].plaintext = Some(STANDARD.encode(create));
    for (name, payload, reason) in [
        (
            "missing_identity_proof_plaintext",
            hidden,
            "missing identity proof plaintext",
        ),
        (
            "altered_identity_proof_plaintext",
            altered,
            "plaintextHash mismatch",
        ),
        (
            "unexpected_non_record_plaintext",
            extra,
            "unexpected non-record plaintext",
        ),
    ] {
        let mut vector = case(&payload, vec![], 3);
        vector["name"] = json!(name);
        vector["expected"] = json!("reject");
        vector["expectedRejection"] = json!(reason);
        negative.push(vector);
    }
    json!({"schema":"mint-record-vectors-v1","network":"regtest","maxEntryBytes":MAX_MINT_RECORD_ENTRY_BYTES,"publicKeys":{"identity":node(&keys(3)),"company":node(&keys(7)),"mintA":xkey(5),"mintB":xkey(11),"receivingMint":xkey(13)},"positive":{"identity":case(&identity,identity_entries,3),"company":case(&company,company_entries,7)},"negative":negative})
}
#[test]
fn deterministic_mint_record_vectors_match() {
    let fixture = fixture();
    for key in ["identity", "company"] {
        let case = &fixture["positive"][key];
        let snapshot: MintRecordSnapshot =
            serde_json::from_value(case["snapshot"].clone()).unwrap();
        snapshot
            .verify(
                &serde_json::from_value(case["subjectNodeId"].clone()).unwrap(),
                case["receivingMintKey"].as_str().unwrap(),
                case["applicationRef"].as_str().unwrap(),
                ts(5),
            )
            .unwrap();
        for e in case["entries"].as_array().unwrap() {
            assert_eq!(
                entry_digest(e["entry"].as_str().unwrap().as_bytes()),
                e["digest"].as_str().unwrap()
            );
        }
    }
    for case in fixture["negative"].as_array().unwrap() {
        let snapshot: MintRecordSnapshot =
            serde_json::from_value(case["snapshot"].clone()).unwrap();
        let error = snapshot
            .verify(
                &serde_json::from_value(case["subjectNodeId"].clone()).unwrap(),
                case["receivingMintKey"].as_str().unwrap(),
                case["applicationRef"].as_str().unwrap(),
                ts(5),
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains(case["expectedRejection"].as_str().unwrap()),
            "{}: {error}",
            case["name"]
        );
    }
    let valid = &fixture["positive"]["identity"];
    let snapshot: MintRecordSnapshot = serde_json::from_value(valid["snapshot"].clone()).unwrap();
    let subject: NodeId = serde_json::from_value(valid["subjectNodeId"].clone()).unwrap();
    assert!(
        snapshot
            .verify(
                &subject,
                &xkey(13),
                "synthetic-identity-application",
                ts(605)
            )
            .is_ok()
    );
    assert!(
        snapshot
            .verify(
                &subject,
                &xkey(13),
                "synthetic-identity-application",
                ts(606)
            )
            .unwrap_err()
            .to_string()
            .contains("freshness")
    );
    assert!(
        snapshot
            .verify(&subject, &xkey(13), "other-application", ts(5))
            .unwrap_err()
            .to_string()
            .contains("applicationRef")
    );
    assert!(
        snapshot
            .verify(
                &node(&keys(19)),
                &xkey(13),
                "synthetic-identity-application",
                ts(5)
            )
            .unwrap_err()
            .to_string()
            .contains("snapshot signature")
    );
    let rendered = format!("{}\n", serde_json::to_string_pretty(&fixture).unwrap());
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/mint-record-v1.json");
    if std::env::var_os("BITCREDIT_REGENERATE_PUBLIC_VECTORS").is_some() {
        std::fs::write(&path, &rendered).unwrap();
    }
    assert_eq!(std::fs::read_to_string(path).unwrap(), rendered);
}
