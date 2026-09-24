use crate::data::mint::{
    MintApplicationAdmission, MintApplicationAdmissionPayload, SignedMintApplicationAdmission,
};
use bcr_common::core::NodeId;
use bcr_ebill_core::application::bill::{BillAcceptState, BillPaymentState, BillState};
use bcr_ebill_core::protocol::{
    ProtocolValidationError, Timestamp,
    crypto::BcrKeys,
    mint::{MintRequestState, MintRequestStatus},
};
use bitcoin::{
    hashes::{Hash, sha256},
    secp256k1::{Message, SECP256K1},
};

const SCHEMA: &str = "mint-application-admission-v1";
const ACTION: &str = "open_initial_credit_interview";
const LIFETIME_SECONDS: u64 = 300;

pub(super) fn validate_bill_state(state: &BillState) -> Result<(), ProtocolValidationError> {
    if !matches!(state.accept, BillAcceptState::Accepted(_)) {
        return Err(ProtocolValidationError::BillNotAccepted);
    }
    if matches!(state.payment, BillPaymentState::Paid(_)) {
        return Err(ProtocolValidationError::BillAlreadyPaid);
    }
    Ok(())
}

/// This exact ordering and terminal newline are the cross-language signing contract.
/// Schema/action separate the proof from bill, quote and Bitcoin authorization messages.
fn canonical_text(admission: &MintApplicationAdmission) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        admission.schema_version,
        admission.action,
        admission.bill_id,
        admission.mint_node_id,
        admission.mint_quote_id,
        admission.case_id,
        admission.holder_ref,
        admission.application_token_digest,
        admission.issued_at,
        admission.expires_at,
    )
}

fn canonical_message(admission: &MintApplicationAdmission) -> Message {
    Message::from_digest(sha256::Hash::hash(canonical_text(admission).as_bytes()).to_byte_array())
}

pub(super) fn sign_for_pending_request(
    payload: &MintApplicationAdmissionPayload,
    signer: &NodeId,
    keys: &BcrKeys,
    current_holder: &NodeId,
    requests: &[MintRequestState],
    configured_mint: &NodeId,
    now: Timestamp,
) -> Result<SignedMintApplicationAdmission, ProtocolValidationError> {
    if signer != current_holder || keys.pub_key() != signer.pub_key() {
        return Err(ProtocolValidationError::CallerIsNotHolder);
    }
    if &payload.mint_node != configured_mint
        || payload.bill_id.network() != signer.network()
        || payload.mint_node.network() != signer.network()
    {
        return Err(ProtocolValidationError::InvalidNodeId);
    }
    let digest = payload
        .application_token_digest
        .strip_prefix("sha256:")
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
    if digest.is_none() {
        return Err(ProtocolValidationError::InvalidHash);
    }
    if payload.case_id.get_variant() != uuid::Variant::RFC4122
        || !(1..=8).contains(&payload.case_id.get_version_num())
        || payload.mint_quote_id.get_variant() != uuid::Variant::RFC4122
        || !(1..=8).contains(&payload.mint_quote_id.get_version_num())
    {
        return Err(ProtocolValidationError::FieldInvalid(
            bcr_ebill_core::protocol::Field::Id,
        ));
    }
    let matching: Vec<_> = requests
        .iter()
        .filter(|state| {
            let request = &state.request;
            request.bill_id == payload.bill_id
                && request.mint_node_id == payload.mint_node
                && &request.requester_node_id == signer
                && request.mint_request_id == payload.mint_quote_id
        })
        .collect();
    if matching.len() != 1 || !matches!(matching[0].request.status, MintRequestStatus::Pending) {
        return Err(ProtocolValidationError::InvalidMintRequestId);
    }
    let issued_at = now.inner();
    let expires_at = issued_at
        .checked_add(LIFETIME_SECONDS)
        .filter(|value| issued_at > 0 && *value <= 9_007_199_254_740_991)
        .ok_or(ProtocolValidationError::InvalidTimestamp)?;
    let admission = MintApplicationAdmission {
        schema_version: SCHEMA.to_owned(),
        action: ACTION.to_owned(),
        bill_id: payload.bill_id.to_string(),
        mint_node_id: payload.mint_node.to_string(),
        mint_quote_id: payload.mint_quote_id.to_string(),
        case_id: payload.case_id.to_string(),
        holder_ref: signer.to_string(),
        application_token_digest: payload.application_token_digest.clone(),
        issued_at,
        expires_at,
    };
    let signature = SECP256K1.sign_schnorr(&canonical_message(&admission), &keys.get_key_pair());
    Ok(SignedMintApplicationAdmission {
        admission,
        signature: signature.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bcr_common::core::BillId;
    use bcr_ebill_core::protocol::mint::MintRequest;
    use bitcoin::{
        Network,
        secp256k1::{SecretKey, schnorr::Signature},
    };
    use std::str::FromStr;
    use uuid::Uuid;

    fn keys(value: u8) -> BcrKeys {
        let mut bytes = [0; 32];
        bytes[31] = value;
        BcrKeys::from_private_key(&SecretKey::from_slice(&bytes).unwrap())
    }

    fn fixture() -> (
        MintApplicationAdmissionPayload,
        NodeId,
        BcrKeys,
        MintRequestState,
    ) {
        let keys = keys(3);
        let holder = NodeId::new(keys.pub_key(), Network::Regtest);
        let payload = MintApplicationAdmissionPayload {
            bill_id: BillId::new(keys.pub_key(), Network::Regtest),
            mint_node: NodeId::new(super::tests::keys(4).pub_key(), Network::Regtest),
            mint_quote_id: Uuid::from_str("11111111-1111-4111-8111-111111111111").unwrap(),
            case_id: Uuid::from_str("22222222-2222-4222-8222-222222222222").unwrap(),
            application_token_digest: format!("sha256:{}", "a".repeat(64)),
        };
        let request = MintRequestState {
            request: MintRequest {
                requester_node_id: holder.clone(),
                bill_id: payload.bill_id.clone(),
                mint_node_id: payload.mint_node.clone(),
                mint_request_id: payload.mint_quote_id,
                timestamp: Timestamp::new(1_790_000_000).unwrap(),
                status: MintRequestStatus::Pending,
            },
            offer: None,
        };
        (payload, holder, keys, request)
    }

    #[test]
    fn admission_signs_current_holder_pending_request_only() {
        let (payload, holder, keys, request) = fixture();
        let proof = sign_for_pending_request(
            &payload,
            &holder,
            &keys,
            &holder,
            &[request],
            &payload.mint_node,
            Timestamp::new(1_790_000_000).unwrap(),
        )
        .unwrap();
        assert_eq!(proof.admission.issued_at, 1_790_000_000);
        assert_eq!(proof.admission.expires_at, 1_790_000_300);
        assert_eq!(proof.admission.holder_ref, holder.to_string());
        let signature = Signature::from_str(&proof.signature).unwrap();
        SECP256K1
            .verify_schnorr(
                &signature,
                &canonical_message(&proof.admission),
                &holder.pub_key().x_only_public_key().0,
            )
            .unwrap();
        let mut changed = proof.admission.clone();
        changed.case_id = Uuid::new_v4().to_string();
        assert!(
            SECP256K1
                .verify_schnorr(
                    &signature,
                    &canonical_message(&changed),
                    &holder.pub_key().x_only_public_key().0
                )
                .is_err()
        );
    }

    #[test]
    fn admission_matches_cross_language_vector() {
        // Public deterministic test identity (scalar 3), never a runtime key.
        // Zero auxiliary randomness fixes the test vector only; production signs with randomness.
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/mint_application_admission_v1.json"
        ))
        .unwrap();
        let admission: MintApplicationAdmission =
            serde_json::from_value(vector["admission"].clone()).unwrap();
        let message = canonical_message(&admission);
        assert_eq!(canonical_text(&admission), vector["canonicalText"]);
        assert_eq!(
            sha256::Hash::hash(canonical_text(&admission).as_bytes()).to_string(),
            vector["messageSha256"]
        );
        let keys = keys(3);
        assert_eq!(keys.pub_key().to_string(), vector["compressedPublicKey"]);
        let signature =
            SECP256K1.sign_schnorr_with_aux_rand(&message, &keys.get_key_pair(), &[0; 32]);
        assert_eq!(signature.to_string(), vector["signature"]);
        for field in [
            "schemaVersion",
            "action",
            "billId",
            "mintNodeId",
            "mintQuoteId",
            "caseId",
            "holderRef",
            "applicationTokenDigest",
            "issuedAt",
            "expiresAt",
        ] {
            let mut changed = vector["admission"].clone();
            changed[field] = if let Some(value) = changed[field].as_u64() {
                serde_json::json!(value + 1)
            } else {
                serde_json::json!(format!("{}x", changed[field].as_str().unwrap()))
            };
            let changed: MintApplicationAdmission = serde_json::from_value(changed).unwrap();
            assert!(
                SECP256K1
                    .verify_schnorr(
                        &signature,
                        &canonical_message(&changed),
                        &keys.pub_key().x_only_public_key().0,
                    )
                    .is_err(),
                "signature must bind {field}"
            );
        }
    }

    #[test]
    fn admission_requires_accepted_unpaid_bill() {
        use bcr_ebill_core::application::bill::BillMintState;
        let now = Timestamp::new(1_790_000_000).unwrap();
        let mut state = BillState {
            mint: BillMintState::Requested,
            accept: BillAcceptState::Accepted(now),
            payment: BillPaymentState::None,
        };
        assert!(validate_bill_state(&state).is_ok());
        for accept in [
            BillAcceptState::None,
            BillAcceptState::Requested(now),
            BillAcceptState::Expired(now),
            BillAcceptState::Rejected(now),
        ] {
            state.accept = accept;
            assert_eq!(
                validate_bill_state(&state),
                Err(ProtocolValidationError::BillNotAccepted)
            );
        }
        state.accept = BillAcceptState::Accepted(now);
        state.payment = BillPaymentState::Paid(now);
        assert_eq!(
            validate_bill_state(&state),
            Err(ProtocolValidationError::BillAlreadyPaid)
        );
    }

    #[test]
    fn admission_rejects_substituted_holder_key_mint_or_request() {
        let (payload, holder, keys, request) = fixture();
        let other_keys = super::tests::keys(5);
        let other = NodeId::new(other_keys.pub_key(), Network::Regtest);
        let now = Timestamp::new(1_790_000_000).unwrap();
        assert!(
            sign_for_pending_request(
                &payload,
                &holder,
                &keys,
                &other,
                std::slice::from_ref(&request),
                &payload.mint_node,
                now
            )
            .is_err()
        );
        assert!(
            sign_for_pending_request(
                &payload,
                &holder,
                &other_keys,
                &holder,
                std::slice::from_ref(&request),
                &payload.mint_node,
                now
            )
            .is_err()
        );
        assert!(
            sign_for_pending_request(
                &payload,
                &holder,
                &keys,
                &holder,
                std::slice::from_ref(&request),
                &other,
                now
            )
            .is_err()
        );
        assert!(
            sign_for_pending_request(
                &payload,
                &holder,
                &keys,
                &holder,
                &[],
                &payload.mint_node,
                now
            )
            .is_err()
        );
        assert!(
            sign_for_pending_request(
                &payload,
                &holder,
                &keys,
                &holder,
                &[request.clone(), request.clone()],
                &payload.mint_node,
                now
            )
            .is_err()
        );
        for status in [
            MintRequestStatus::Offered,
            MintRequestStatus::Accepted,
            MintRequestStatus::MintingEnabled,
            MintRequestStatus::Denied { timestamp: now },
            MintRequestStatus::Cancelled { timestamp: now },
            MintRequestStatus::Rejected { timestamp: now },
            MintRequestStatus::Expired { timestamp: now },
        ] {
            let mut not_pending = request.clone();
            not_pending.request.status = status;
            assert!(
                sign_for_pending_request(
                    &payload,
                    &holder,
                    &keys,
                    &holder,
                    &[not_pending],
                    &payload.mint_node,
                    now
                )
                .is_err()
            );
        }
    }

    #[test]
    fn admission_rejects_unbounded_input_and_does_not_accept_caller_timestamps() {
        let (payload, holder, keys, request) = fixture();
        let now = Timestamp::new(1_790_000_000).unwrap();
        for value in [
            "a".repeat(64),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}\naction", "a".repeat(64)),
            format!("sha256:{}", "a".repeat(63)),
        ] {
            let mut invalid = payload.clone();
            invalid.application_token_digest = value;
            assert!(
                sign_for_pending_request(
                    &invalid,
                    &holder,
                    &keys,
                    &holder,
                    std::slice::from_ref(&request),
                    &payload.mint_node,
                    now
                )
                .is_err()
            );
        }
        let mut invalid = payload.clone();
        invalid.case_id = Uuid::nil();
        assert!(
            sign_for_pending_request(
                &invalid,
                &holder,
                &keys,
                &holder,
                &[request],
                &payload.mint_node,
                now
            )
            .is_err()
        );
        let input = serde_json::json!({"bill_id":payload.bill_id,"mint_node":payload.mint_node,"mint_quote_id":payload.mint_quote_id,"case_id":payload.case_id,"application_token_digest":payload.application_token_digest,"issuedAt":1});
        assert!(serde_json::from_value::<MintApplicationAdmissionPayload>(input).is_err());
    }

    #[test]
    fn admission_rejects_request_tuple_and_network_substitution() {
        let (payload, holder, keys, request) = fixture();
        let now = Timestamp::new(1_790_000_000).unwrap();
        let other = NodeId::new(super::tests::keys(6).pub_key(), Network::Regtest);
        for field in ["bill", "mint", "requester", "quote"] {
            let mut changed = request.clone();
            match field {
                "bill" => changed.request.bill_id = BillId::new(other.pub_key(), Network::Regtest),
                "mint" => changed.request.mint_node_id = other.clone(),
                "requester" => changed.request.requester_node_id = other.clone(),
                "quote" => changed.request.mint_request_id = Uuid::new_v4(),
                _ => unreachable!(),
            }
            assert!(
                sign_for_pending_request(
                    &payload,
                    &holder,
                    &keys,
                    &holder,
                    &[changed],
                    &payload.mint_node,
                    now,
                )
                .is_err(),
                "request must bind {field}"
            );
        }
        let mut changed = payload.clone();
        changed.bill_id = BillId::new(keys.pub_key(), Network::Testnet);
        assert!(
            sign_for_pending_request(
                &changed,
                &holder,
                &keys,
                &holder,
                std::slice::from_ref(&request),
                &payload.mint_node,
                now,
            )
            .is_err()
        );
        changed = payload.clone();
        changed.mint_node = NodeId::new(payload.mint_node.pub_key(), Network::Testnet);
        assert!(
            sign_for_pending_request(
                &changed,
                &holder,
                &keys,
                &holder,
                &[request],
                &changed.mint_node,
                now,
            )
            .is_err()
        );
    }
}
