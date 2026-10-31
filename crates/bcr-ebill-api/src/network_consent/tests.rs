use super::*;
use bcr_common::core::BillId;
use bitcoin::secp256k1::{SecretKey, schnorr::Signature};

fn keys(value: u8) -> BcrKeys {
    let mut bytes = [0; 32];
    bytes[31] = value;
    BcrKeys::from_private_key(&SecretKey::from_slice(&bytes).unwrap())
}
fn now() -> Timestamp {
    Timestamp::new(1_790_000_000).unwrap()
}
fn signer() -> NodeId {
    NodeId::new(keys(3).pub_key(), Network::Regtest)
}
fn grant_payload() -> CrossMintGrantPayload {
    CrossMintGrantPayload {
        grant_id: Uuid::from_str("33333333-3333-4333-8333-333333333333").unwrap(),
        requesting_mint_pubkey: keys(4).pub_key().x_only_public_key().0.to_string(),
        answering_mint_pubkey: keys(5).pub_key().x_only_public_key().0.to_string(),
        operation: CrossMintOperation::BillStatus,
        bill_id: BillId::new(keys(6).pub_key(), Network::Regtest),
        case_binding: "b".repeat(64),
        lifetime_seconds: None,
    }
}
fn revoke_payload() -> CrossMintRevokePayload {
    let grant = grant_payload();
    CrossMintRevokePayload {
        grant_id: grant.grant_id,
        requesting_mint_pubkey: grant.requesting_mint_pubkey,
        answering_mint_pubkey: grant.answering_mint_pubkey,
    }
}
fn listing_payload() -> DirectoryListingPayload {
    serde_json::from_value(
        json!({"type":"sole_trader", "name":"Synthetic coffee trader",
        "tradingNames":["Café Example"], "country":"GT", "region":"Alta Verapaz",
        "products":[{"label":"Coffee"}], "description":"Synthetic public business statement",
        "actingPersons":[], "contactRelays":["wss://relay.example.test"],
        "validUntil":1790086400u64, "noticeVersion":"yellow-book-notice-v1"}),
    )
    .unwrap()
}
fn verify(text: &str, signature: &str, keys: &BcrKeys) -> bool {
    SECP256K1
        .verify_schnorr(
            &Signature::from_str(signature).unwrap(),
            &message(text),
            &keys.pub_key().x_only_public_key().0,
        )
        .is_ok()
}
fn deterministic(text: &str) -> String {
    SECP256K1
        .sign_schnorr_with_aux_rand(&message(text), &keys(3).get_key_pair(), &[0; 32])
        .to_string()
}

#[test]
fn grant_and_revoke_bind_every_canonical_field() {
    let proof = sign_grant(&grant_payload(), &signer(), &keys(3), now(), "a".repeat(64)).unwrap();
    assert_eq!(proof.grant.issued_at, now().inner());
    assert_eq!(proof.grant.expires_at, now().inner() + 300);
    assert_eq!(proof.grant.subject_node_id, signer().to_string());
    let text = grant_text(&proof.grant);
    assert!(text.ends_with('\n'));
    assert_eq!(text.lines().count(), 12);
    assert!(verify(&text, &proof.signature, &keys(3)));
    assert!(!verify(&text, &proof.signature, &keys(4)));
    // Mutating each serialized scalar must alter its corresponding signed line.
    for field in [
        "schema",
        "grantId",
        "network",
        "subjectNodeId",
        "requestingMintPubkey",
        "answeringMintPubkey",
        "billId",
        "caseBinding",
        "issuedAt",
        "expiresAt",
        "nonce",
    ] {
        let mut changed = serde_json::to_value(&proof.grant).unwrap();
        let value = &changed[field];
        changed[field] = if let Some(v) = value.as_u64() {
            json!(v + 1)
        } else {
            json!(format!("{}x", value.as_str().unwrap()))
        };
        let changed: CrossMintGrant = serde_json::from_value(changed).unwrap();
        assert!(
            !verify(&grant_text(&changed), &proof.signature, &keys(3)),
            "{field}"
        );
    }
    let proof = sign_revoke(
        &revoke_payload(),
        &signer(),
        &keys(3),
        now(),
        "c".repeat(64),
    )
    .unwrap();
    let text = revoke_text(&proof.revoke);
    assert_eq!(text.lines().count(), 8);
    assert!(verify(&text, &proof.signature, &keys(3)));
    for field in [
        "schema",
        "grantId",
        "network",
        "subjectNodeId",
        "requestingMintPubkey",
        "answeringMintPubkey",
        "nonce",
        "issuedAt",
    ] {
        let mut changed = serde_json::to_value(&proof.revoke).unwrap();
        let value = &changed[field];
        changed[field] = if let Some(v) = value.as_u64() {
            json!(v + 1)
        } else {
            json!(format!("{}x", value.as_str().unwrap()))
        };
        let changed: CrossMintRevoke = serde_json::from_value(changed).unwrap();
        assert!(
            !verify(&revoke_text(&changed), &proof.signature, &keys(3)),
            "{field}"
        );
    }
}

#[test]
fn consent_rejects_unbounded_scope_key_network_and_clock() {
    let payload = grant_payload();
    let nonce = "a".repeat(64);
    for network in [Network::Testnet, Network::Bitcoin] {
        let other = NodeId::new(keys(3).pub_key(), network);
        assert!(sign_grant(&payload, &other, &keys(3), now(), nonce.clone()).is_err());
    }
    assert!(sign_grant(&payload, &signer(), &keys(4), now(), nonce.clone()).is_err());
    assert!(sign_revoke(&revoke_payload(), &signer(), &keys(4), now(), nonce.clone()).is_err());
    let mainnet = NodeId::new(keys(3).pub_key(), Network::Bitcoin);
    assert!(sign_revoke(&revoke_payload(), &mainnet, &keys(3), now(), nonce.clone()).is_err());
    for lifetime in [0, 301, u64::MAX] {
        let mut changed = payload.clone();
        changed.lifetime_seconds = Some(lifetime);
        assert!(sign_grant(&changed, &signer(), &keys(3), now(), nonce.clone()).is_err());
    }
    let mut shorter = payload.clone();
    shorter.lifetime_seconds = Some(1);
    assert_eq!(
        sign_grant(&shorter, &signer(), &keys(3), now(), nonce.clone())
            .unwrap()
            .grant
            .expires_at,
        now().inner() + 1
    );
    for bad in [
        "A".repeat(64),
        "a".repeat(63),
        format!("{}\n", "a".repeat(64)),
    ] {
        let mut changed = payload.clone();
        changed.case_binding = bad.clone();
        assert!(sign_grant(&changed, &signer(), &keys(3), now(), nonce.clone()).is_err());
        let mut changed = payload.clone();
        changed.requesting_mint_pubkey = bad.clone();
        assert!(sign_grant(&changed, &signer(), &keys(3), now(), nonce.clone()).is_err());
        assert!(sign_grant(&payload, &signer(), &keys(3), now(), bad).is_err());
    }
    let mut changed = payload.clone();
    changed.grant_id = Uuid::nil();
    assert!(sign_grant(&changed, &signer(), &keys(3), now(), nonce.clone()).is_err());
    let mut changed = payload.clone();
    changed.answering_mint_pubkey = "f".repeat(64);
    assert!(sign_grant(&changed, &signer(), &keys(3), now(), nonce.clone()).is_err());
    let unsafe_time = Timestamp::zero() + std::time::Duration::from_secs(MAX_SAFE_INTEGER);
    assert!(sign_grant(&payload, &signer(), &keys(3), unsafe_time, nonce).is_err());
    let first = fresh_nonce().unwrap();
    let second = fresh_nonce().unwrap();
    hex32(&first).unwrap();
    hex32(&second).unwrap();
    assert_ne!(first, second);
}

#[test]
fn inputs_reject_unknown_fields_and_caller_derived_values() {
    let grant = serde_json::to_value(grant_payload()).unwrap();
    for field in [
        "network",
        "subjectNodeId",
        "issuedAt",
        "expiresAt",
        "nonce",
        "schema",
        "purpose",
    ] {
        let mut changed = grant.clone();
        changed[field] = json!("injected");
        assert!(
            serde_json::from_value::<CrossMintGrantPayload>(changed).is_err(),
            "{field}"
        );
    }
    let mut changed = grant;
    changed["operation"] = json!("history_summary");
    assert!(serde_json::from_value::<CrossMintGrantPayload>(changed).is_err());
    for field in ["nonce", "issuedAt", "subjectNodeId"] {
        let mut changed = serde_json::to_value(revoke_payload()).unwrap();
        changed[field] = json!("injected");
        assert!(serde_json::from_value::<CrossMintRevokePayload>(changed).is_err());
    }
    for field in [
        "privateKey",
        "schema",
        "network",
        "subjectNodeId",
        "status",
        "billId",
        "score",
    ] {
        let mut changed = serde_json::to_value(listing_payload()).unwrap();
        changed[field] = json!("injected");
        assert!(
            serde_json::from_value::<DirectoryListingPayload>(changed).is_err(),
            "{field}"
        );
    }
    for (field, value) in [
        ("products", json!([{"label":"Coffee", "price":5}])),
        (
            "actingPersons",
            json!([{"publicName":"Example", "publicRole":"Director", "nodeId":"secret"}]),
        ),
        (
            "registration",
            json!({"country":"GT", "registry":"public", "number":"synthetic", "nationalId":"secret"}),
        ),
    ] {
        let mut changed = serde_json::to_value(listing_payload()).unwrap();
        changed[field] = value;
        assert!(serde_json::from_value::<DirectoryListingPayload>(changed).is_err());
    }
}

#[test]
fn listing_and_withdrawal_are_valid_nip01_events() {
    for subject_type in [
        DirectorySubjectType::SoleTrader,
        DirectorySubjectType::Company,
    ] {
        let mut payload = listing_payload();
        payload.subject_type = subject_type.clone();
        if subject_type == DirectorySubjectType::Company {
            payload.registration = Some(DirectoryRegistration {
                country: "GT".into(),
                registry: "commercial-register".into(),
                number: "SYNTHETIC-123".into(),
            });
            payload.business_address = Some(DirectoryBusinessAddress {
                country: "GT".into(),
                city: "Cobán".into(),
                zip: None,
                address: "Synthetic public office".into(),
            });
            payload.business_contact = Some(DirectoryBusinessContact {
                email: Some("business@example.test".into()),
                phone: None,
                website: Some("https://example.test".into()),
            });
        }
        let event =
            sign_listing(&payload, &signer(), &keys(3), subject_type.clone(), now()).unwrap();
        assert_eq!(event.kind, 38900);
        assert_eq!(event.tags, listing_tags(&signer()));
        assert_eq!(
            event.id,
            sha256::Hash::hash(event_text(&event).as_bytes()).to_string()
        );
        assert!(verify(&event_text(&event), &event.sig, &keys(3)));
        // Independent Nostr parser checks the NIP-01 hash and BIP340 signature.
        let nostr_event: nostr::event::Event =
            serde_json::from_value(serde_json::to_value(&event).unwrap()).unwrap();
        nostr_event.verify().unwrap();
        let content: serde_json::Value = serde_json::from_str(&event.content).unwrap();
        assert_eq!(content["subjectNodeId"], signer().to_string());
        assert_eq!(content["status"], "listed");
        let withdrawn = sign_withdrawal(
            &DirectoryWithdrawalPayload {
                prior_events: vec![event.clone()],
            },
            &signer(),
            &keys(3),
            now(),
        )
        .unwrap();
        let content: serde_json::Value =
            serde_json::from_str(&withdrawn.withdrawal.content).unwrap();
        assert_eq!(content.as_object().unwrap().len(), 4);
        assert_eq!(content["status"], "withdrawn");
        assert_eq!(withdrawn.deletion.kind, 5);
        assert!(
            withdrawn
                .deletion
                .tags
                .contains(&vec!["e".into(), event.id])
        );
        assert!(
            !withdrawn
                .deletion
                .tags
                .contains(&vec!["e".into(), withdrawn.withdrawal.id.clone()])
        );
        for event in [withdrawn.withdrawal, withdrawn.deletion] {
            let event: nostr::event::Event =
                serde_json::from_value(serde_json::to_value(event).unwrap()).unwrap();
            event.verify().unwrap();
        }
    }
}

#[test]
fn directory_rejects_wrong_authority_expiry_bounds_and_size() {
    let payload = listing_payload();
    let sign = |p: &DirectoryListingPayload| {
        sign_listing(
            p,
            &signer(),
            &keys(3),
            DirectorySubjectType::SoleTrader,
            now(),
        )
    };
    assert!(
        sign_listing(
            &payload,
            &signer(),
            &keys(4),
            DirectorySubjectType::SoleTrader,
            now()
        )
        .is_err()
    );
    assert!(
        sign_listing(
            &payload,
            &signer(),
            &keys(3),
            DirectorySubjectType::Company,
            now()
        )
        .is_err()
    );
    let mainnet = NodeId::new(keys(3).pub_key(), Network::Bitcoin);
    assert!(
        sign_listing(
            &payload,
            &mainnet,
            &keys(3),
            DirectorySubjectType::SoleTrader,
            now()
        )
        .is_err()
    );
    for (field, value) in [
        ("name", json!("a".repeat(201))),
        ("tradingNames", json!(["a".repeat(201)])),
        ("description", json!("a".repeat(2001))),
        ("products", json!(vec![json!({"label":"Coffee"}); 21])),
        (
            "actingPersons",
            json!(vec![
                json!({"publicName":"Example", "publicRole":"Director"});
                11
            ]),
        ),
        ("contactRelays", json!(vec!["wss://example.test"; 5])),
        ("contactRelays", json!(["https://example.test"])),
        ("validUntil", json!(now().inner())),
        ("validUntil", json!(now().inner() + 30 * 86400 + 1)),
    ] {
        let mut changed = serde_json::to_value(&payload).unwrap();
        changed[field] = value;
        let changed: DirectoryListingPayload = serde_json::from_value(changed).unwrap();
        assert!(sign(&changed).is_err(), "{field}");
    }
    let mut boundary = payload.clone();
    boundary.name = "é".repeat(200);
    boundary.description = Some("x".repeat(2000));
    boundary.products = vec![
        DirectoryProduct {
            code: None,
            label: "Coffee".into()
        };
        20
    ];
    boundary.acting_persons = vec![
        DirectoryActingPerson {
            public_name: "Example".into(),
            public_role: "Director".into()
        };
        10
    ];
    boundary.contact_relays = vec!["wss://example.test".into(); 4];
    assert!(sign(&boundary).is_ok());
    // Match the JavaScript verifier's UTF-16 length, including non-BMP characters.
    boundary.name = "🌱".repeat(100);
    assert!(sign(&boundary).is_ok());
    boundary.name.push('🌱');
    assert!(sign(&boundary).is_err());
    let mut huge = payload.clone();
    huge.trading_names = vec!["商".repeat(200); 20];
    huge.products = vec![
        DirectoryProduct {
            code: None,
            label: "商".repeat(200)
        };
        20
    ];
    assert!(sign(&huge).is_err());
    let event = sign(&payload).unwrap();
    for events in [vec![], vec![event; 32]] {
        assert!(
            sign_withdrawal(
                &DirectoryWithdrawalPayload {
                    prior_events: events
                },
                &signer(),
                &keys(3),
                now()
            )
            .is_err()
        );
    }
}

fn vector_document() -> serde_json::Value {
    let mut grant =
        sign_grant(&grant_payload(), &signer(), &keys(3), now(), "a".repeat(64)).unwrap();
    let grant_canonical = grant_text(&grant.grant);
    grant.signature = deterministic(&grant_canonical);
    let mut revoke = sign_revoke(
        &revoke_payload(),
        &signer(),
        &keys(3),
        now(),
        "c".repeat(64),
    )
    .unwrap();
    let revoke_canonical = revoke_text(&revoke.revoke);
    revoke.signature = deterministic(&revoke_canonical);
    let mut listing = sign_listing(
        &listing_payload(),
        &signer(),
        &keys(3),
        DirectorySubjectType::SoleTrader,
        now(),
    )
    .unwrap();
    let listing_canonical = event_text(&listing);
    listing.sig = deterministic(&listing_canonical);
    let mut withdrawal = sign_withdrawal(
        &DirectoryWithdrawalPayload {
            prior_events: vec![listing.clone()],
        },
        &signer(),
        &keys(3),
        now(),
    )
    .unwrap();
    withdrawal.withdrawal.sig = deterministic(&event_text(&withdrawal.withdrawal));
    withdrawal.deletion.sig = deterministic(&event_text(&withdrawal.deletion));
    let mut mainnet = grant.grant.clone();
    mainnet.network = "bitcoin".into();
    mainnet.subject_node_id = NodeId::new(keys(3).pub_key(), Network::Bitcoin).to_string();
    mainnet.bill_id = BillId::new(keys(6).pub_key(), Network::Bitcoin).to_string();
    let mainnet_text = grant_text(&mainnet);
    let mainnet_signature = deterministic(&mainnet_text);
    json!({"profile":"cross-mint-and-directory-v1", "publicKey":signer().npub().to_string(),
    "compressedPublicKey":keys(3).pub_key().to_string(),
    "grant":{"signed":grant,"canonicalText":grant_canonical,"messageSha256":sha256::Hash::hash(grant_canonical.as_bytes()).to_string()},
    "revoke":{"signed":revoke,"canonicalText":revoke_canonical,"messageSha256":sha256::Hash::hash(revoke_canonical.as_bytes()).to_string()},
    "listing":{"event":listing,"canonicalText":listing_canonical,"messageSha256":sha256::Hash::hash(listing_canonical.as_bytes()).to_string()},
    "withdrawal":withdrawal,
    "negative":[
        {"name":"wrong key", "target":"grant", "publicKey":keys(4).pub_key().x_only_public_key().0.to_string(), "expected":"invalid_signature"},
        {"name":"mainnet", "target":"grant", "signed":{"grant":mainnet,"signature":mainnet_signature}, "canonicalText":mainnet_text, "expected":"unsupported_network"},
        {"name":"expired grant", "target":"grant", "verifyAt":1790000300u64, "expected":"expired"},
        {"name":"expired listing", "target":"listing", "verifyAt":1790086400u64, "expected":"expired"}
    ]})
}

#[test]
fn deterministic_cross_language_vectors_match() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/cross-mint-and-directory-v1.json");
    let generated = vector_document();
    // Explicit opt-in, test-only regeneration. Never takes a runtime secret.
    if std::env::var_os("BITCREDIT_REGENERATE_PUBLIC_VECTORS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&generated).unwrap()),
        )
        .unwrap();
    }
    let expected: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(generated, expected);
    let grant: SignedCrossMintGrant =
        serde_json::from_value(expected["grant"]["signed"].clone()).unwrap();
    assert!(verify(
        &grant_text(&grant.grant),
        &grant.signature,
        &keys(3)
    ));
    let revoke: SignedCrossMintRevoke =
        serde_json::from_value(expected["revoke"]["signed"].clone()).unwrap();
    assert!(verify(
        &revoke_text(&revoke.revoke),
        &revoke.signature,
        &keys(3)
    ));
    let event: nostr::event::Event =
        serde_json::from_value(expected["listing"]["event"].clone()).unwrap();
    event.verify().unwrap();
    assert!(!verify(
        &grant_text(&grant.grant),
        &grant.signature,
        &keys(4)
    ));
    assert_eq!(expected["negative"][2]["verifyAt"], grant.grant.expires_at);
    // Expiry is a policy rejection even though the original signature remains valid.
    assert!(expected["negative"][2]["verifyAt"].as_u64().unwrap() >= grant.grant.expires_at);
}

#[test]
fn withdrawal_rejects_non_directory_wrong_author_network_and_tampered_events() {
    let event = sign_listing(
        &listing_payload(),
        &signer(),
        &keys(3),
        DirectorySubjectType::SoleTrader,
        now(),
    )
    .unwrap();
    let foreign = NodeId::new(keys(4).pub_key(), Network::Regtest);
    let wrong_author = sign_event(
        &foreign,
        &keys(4),
        now(),
        38900,
        listing_tags(&foreign),
        event.content.clone(),
    )
    .unwrap();
    let same_author_note = sign_event(
        &signer(),
        &keys(3),
        now(),
        1,
        listing_tags(&signer()),
        "note".into(),
    )
    .unwrap();
    let same_author_wrong_network = sign_event(
        &signer(),
        &keys(3),
        now(),
        38900,
        vec![vec!["d".into(), "yellow-book:v1:testnet".into()]],
        event.content.clone(),
    )
    .unwrap();
    let mut tampered = event.clone();
    tampered.content.push(' ');
    let mut wrong_id = event.clone();
    wrong_id.id = "a".repeat(64);
    let mut uppercase_id = event.clone();
    uppercase_id.id = uppercase_id.id.to_uppercase();
    let mut wrong_sig = event.clone();
    wrong_sig.sig = "a".repeat(128);
    for invalid in [
        wrong_author,
        same_author_note,
        same_author_wrong_network,
        tampered,
        wrong_id,
        uppercase_id,
        wrong_sig,
    ] {
        assert!(
            sign_withdrawal(
                &DirectoryWithdrawalPayload {
                    prior_events: vec![invalid]
                },
                &signer(),
                &keys(3),
                now()
            )
            .is_err()
        );
    }
    let result = sign_withdrawal(
        &DirectoryWithdrawalPayload {
            prior_events: vec![event.clone()],
        },
        &signer(),
        &keys(3),
        now(),
    )
    .unwrap();
    assert!(result.deletion.tags.contains(&vec!["e".into(), event.id]));
    assert!(result.deletion.tags.contains(&vec![
        "a".into(),
        format!("38900:{}:yellow-book:v1:regtest", signer().npub())
    ]));
    assert!(
        serde_json::from_value::<DirectoryWithdrawalPayload>(
            json!({"priorEventIds":["a".repeat(64)]})
        )
        .is_err()
    );
}

fn voice_payload() -> ServiceVoiceAdmissionPayload {
    ServiceVoiceAdmissionPayload {
        service_mint_node_id: NodeId::new(keys(4).pub_key(), Network::Regtest),
        lifetime_seconds: None,
    }
}

#[test]
fn voice_admission_is_purpose_service_identity_network_clock_and_nonce_bound() {
    let payload = voice_payload();
    let sign = |p: &ServiceVoiceAdmissionPayload, id: &NodeId, key: &BcrKeys, time, nonce| {
        sign_service_voice_admission(p, id, key, &payload.service_mint_node_id, time, nonce)
    };
    let signed = sign(&payload, &signer(), &keys(3), now(), "a".repeat(64)).unwrap();
    let text = service_voice_text(&signed.admission);
    assert_eq!(text.lines().count(), 7);
    assert!(text.ends_with('\n'));
    assert_eq!(signed.admission.expires_at, now().inner() + 300);
    assert!(verify(&text, &signed.signature, &keys(3)));
    assert!(!verify(&text, &signed.signature, &keys(4)));
    for field in [
        "schema",
        "network",
        "subjectNodeId",
        "serviceMintNodeId",
        "issuedAt",
        "expiresAt",
        "nonce",
    ] {
        let mut changed = serde_json::to_value(&signed.admission).unwrap();
        changed[field] = if let Some(v) = changed[field].as_u64() {
            json!(v + 1)
        } else {
            json!(format!("{}x", changed[field].as_str().unwrap()))
        };
        let changed: ServiceVoiceAdmission = serde_json::from_value(changed).unwrap();
        assert!(
            !verify(&service_voice_text(&changed), &signed.signature, &keys(3)),
            "{field}"
        );
    }
    assert!(sign(&payload, &signer(), &keys(4), now(), "a".repeat(64)).is_err());
    for network in [Network::Bitcoin, Network::Testnet] {
        assert!(
            sign(
                &payload,
                &NodeId::new(keys(3).pub_key(), network),
                &keys(3),
                now(),
                "a".repeat(64)
            )
            .is_err()
        );
    }
    let mut other_mint = payload.clone();
    other_mint.service_mint_node_id = NodeId::new(keys(5).pub_key(), Network::Regtest);
    assert!(sign(&other_mint, &signer(), &keys(3), now(), "a".repeat(64)).is_err());
    for lifetime in [0, 301, u64::MAX] {
        let mut changed = payload.clone();
        changed.lifetime_seconds = Some(lifetime);
        assert!(sign(&changed, &signer(), &keys(3), now(), "a".repeat(64)).is_err());
    }
    let mut shortest = payload.clone();
    shortest.lifetime_seconds = Some(1);
    assert_eq!(
        sign(&shortest, &signer(), &keys(3), now(), "a".repeat(64))
            .unwrap()
            .admission
            .expires_at,
        now().inner() + 1
    );
    assert!(
        sign(
            &payload,
            &signer(),
            &keys(3),
            Timestamp::zero(),
            "a".repeat(64)
        )
        .is_err()
    );
    for nonce in [
        "A".repeat(64),
        "a".repeat(63),
        format!("{}\n", "a".repeat(64)),
    ] {
        assert!(sign(&payload, &signer(), &keys(3), now(), nonce).is_err());
    }
    let unsafe_time = Timestamp::zero() + std::time::Duration::from_secs(MAX_SAFE_INTEGER);
    assert!(sign(&payload, &signer(), &keys(3), unsafe_time, "a".repeat(64)).is_err());
    for field in [
        "nonce",
        "issuedAt",
        "expiresAt",
        "subjectNodeId",
        "network",
        "privateKey",
    ] {
        let mut input = serde_json::to_value(&payload).unwrap();
        input[field] = json!("injected");
        assert!(serde_json::from_value::<ServiceVoiceAdmissionPayload>(input).is_err());
    }
}

#[test]
fn deterministic_service_voice_vectors_match() {
    let payload = voice_payload();
    let mut signed = sign_service_voice_admission(
        &payload,
        &signer(),
        &keys(3),
        &payload.service_mint_node_id,
        now(),
        "a".repeat(64),
    )
    .unwrap();
    let text = service_voice_text(&signed.admission);
    signed.signature = deterministic(&text);
    let mut wrong_service = signed.clone();
    wrong_service.admission.service_mint_node_id =
        NodeId::new(keys(5).pub_key(), Network::Regtest).to_string();
    wrong_service.signature = deterministic(&service_voice_text(&wrong_service.admission));
    let mut mainnet = signed.clone();
    mainnet.admission.network = "bitcoin".into();
    mainnet.admission.subject_node_id =
        NodeId::new(keys(3).pub_key(), Network::Bitcoin).to_string();
    mainnet.admission.service_mint_node_id =
        NodeId::new(keys(4).pub_key(), Network::Bitcoin).to_string();
    mainnet.signature = deterministic(&service_voice_text(&mainnet.admission));
    let generated = json!({"profile":"service-voice-admission-v1", "publicKey":signer().npub().to_string(), "serviceMintNodeId":payload.service_mint_node_id.to_string(),
    "positive":{"signed":signed,"canonicalText":text,"messageSha256":sha256::Hash::hash(text.as_bytes()).to_string()},
    "negative":[
        {"name":"wrong service Mint", "signed":wrong_service,"expected":"service_mint_mismatch"},
        {"name":"mainnet", "signed":mainnet,"expected":"unsupported_network"},
        {"name":"expired", "signed":signed,"verifyAt":now().inner()+300,"expected":"expired"},
        {"name":"wrong key", "signed":signed,"publicKey":keys(4).pub_key().x_only_public_key().0.to_string(),"expected":"invalid_signature"}
    ]});
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/service-voice-admission-v1.json");
    if std::env::var_os("BITCREDIT_REGENERATE_PUBLIC_VECTORS").is_some() {
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&generated).unwrap()),
        )
        .unwrap();
    }
    let expected: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(generated, expected);
    assert!(verify(&text, &signed.signature, &keys(3)));
}
