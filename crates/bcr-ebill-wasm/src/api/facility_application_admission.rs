use crate::data::mint::{
    FacilityApplicationAdmission, FacilityApplicationAdmissionAction,
    FacilityApplicationAdmissionPayload, SignedFacilityApplicationAdmission,
};
use bcr_common::core::NodeId;
use bcr_ebill_core::protocol::{ProtocolValidationError, Timestamp, crypto::BcrKeys};
use bitcoin::{
    Network,
    hashes::{Hash, sha256},
    secp256k1::{Message, SECP256K1},
};

const SCHEMA: &str = "facility-application-admission-v1";
const LIFETIME_SECONDS: u64 = 300;

fn action_name(action: FacilityApplicationAdmissionAction) -> &'static str {
    match action {
        FacilityApplicationAdmissionAction::OpenFacilityApplication => "open_facility_application",
        FacilityApplicationAdmissionAction::UpgradeFacilityIdentity => "upgrade_facility_identity",
    }
}

/// This exact ordering and terminal newline are the cross-language signing contract.
/// Its own schema/action keep it apart from bill admission, quote and Bitcoin messages.
fn canonical_text(admission: &FacilityApplicationAdmission) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        admission.schema_version,
        admission.action,
        admission.application_id,
        admission.mint_node_id,
        admission.applicant_ref,
        admission.application_token_digest,
        admission.issued_at,
        admission.expires_at,
    )
}

fn canonical_message(admission: &FacilityApplicationAdmission) -> Message {
    Message::from_digest(sha256::Hash::hash(canonical_text(admission).as_bytes()).to_byte_array())
}

/// Proves control of the currently selected identity's key for one facility capability.
/// Authenticity only: never KYC, truth, solvency, consent or financial authorization.
pub(super) fn sign_for_current_identity(
    payload: &FacilityApplicationAdmissionPayload,
    signer: &NodeId,
    keys: &BcrKeys,
    configured_mint: &NodeId,
    now: Timestamp,
) -> Result<SignedFacilityApplicationAdmission, ProtocolValidationError> {
    if keys.pub_key() != signer.pub_key() {
        return Err(ProtocolValidationError::CallerMustBeSignatory);
    }
    if &payload.mint_node != configured_mint
        || payload.mint_node.network() != signer.network()
        || signer.network() == Network::Bitcoin
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
    if payload.application_id.get_variant() != uuid::Variant::RFC4122
        || !(1..=8).contains(&payload.application_id.get_version_num())
    {
        return Err(ProtocolValidationError::FieldInvalid(
            bcr_ebill_core::protocol::Field::Id,
        ));
    }
    let issued_at = now.inner();
    let expires_at = issued_at
        .checked_add(LIFETIME_SECONDS)
        .filter(|value| issued_at > 0 && *value <= 9_007_199_254_740_991)
        .ok_or(ProtocolValidationError::InvalidTimestamp)?;
    let admission = FacilityApplicationAdmission {
        schema_version: SCHEMA.to_owned(),
        action: action_name(payload.action).to_owned(),
        application_id: payload.application_id.to_string(),
        mint_node_id: payload.mint_node.to_string(),
        applicant_ref: signer.to_string(),
        application_token_digest: payload.application_token_digest.clone(),
        issued_at,
        expires_at,
    };
    let signature = SECP256K1.sign_schnorr(&canonical_message(&admission), &keys.get_key_pair());
    Ok(SignedFacilityApplicationAdmission {
        admission,
        signature: signature.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{SecretKey, schnorr::Signature};
    use std::str::FromStr;
    use uuid::Uuid;

    fn keys(value: u8) -> BcrKeys {
        let mut bytes = [0; 32];
        bytes[31] = value;
        BcrKeys::from_private_key(&SecretKey::from_slice(&bytes).unwrap())
    }

    fn fixture() -> (FacilityApplicationAdmissionPayload, NodeId, BcrKeys) {
        let keys = keys(3);
        let signer = NodeId::new(keys.pub_key(), Network::Regtest);
        let payload = FacilityApplicationAdmissionPayload {
            action: FacilityApplicationAdmissionAction::OpenFacilityApplication,
            application_id: Uuid::from_str("33333333-3333-4333-8333-333333333333").unwrap(),
            mint_node: NodeId::new(super::tests::keys(4).pub_key(), Network::Regtest),
            application_token_digest: format!("sha256:{}", "b".repeat(64)),
        };
        (payload, signer, keys)
    }

    fn verifies(
        admission: &FacilityApplicationAdmission,
        signature: &Signature,
        key: &BcrKeys,
    ) -> bool {
        SECP256K1
            .verify_schnorr(
                signature,
                &canonical_message(admission),
                &key.pub_key().x_only_public_key().0,
            )
            .is_ok()
    }

    #[test]
    fn facility_admission_signs_current_identity_with_core_timestamps() {
        let (payload, signer, keys) = fixture();
        let now = Timestamp::new(1_790_000_000).unwrap();
        for (action, name) in [
            (
                FacilityApplicationAdmissionAction::OpenFacilityApplication,
                "open_facility_application",
            ),
            (
                FacilityApplicationAdmissionAction::UpgradeFacilityIdentity,
                "upgrade_facility_identity",
            ),
        ] {
            let mut payload = payload.clone();
            payload.action = action;
            let proof =
                sign_for_current_identity(&payload, &signer, &keys, &payload.mint_node, now)
                    .unwrap();
            assert_eq!(proof.admission.schema_version, SCHEMA);
            assert_eq!(proof.admission.action, name);
            assert_eq!(proof.admission.applicant_ref, signer.to_string());
            assert_eq!(proof.admission.issued_at, 1_790_000_000);
            assert_eq!(proof.admission.expires_at, 1_790_000_300);
            let signature = Signature::from_str(&proof.signature).unwrap();
            assert!(verifies(&proof.admission, &signature, &keys));
        }
    }

    #[test]
    fn facility_admission_matches_cross_language_vector() {
        // Public deterministic test identity (scalar 3), never a runtime key.
        // Zero auxiliary randomness fixes the test vector only; production signs with randomness.
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/facility_application_admission_v1.json"
        ))
        .unwrap();
        let admission: FacilityApplicationAdmission =
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
        assert!(verifies(&admission, &signature, &keys));
        for field in [
            "schemaVersion",
            "action",
            "applicationId",
            "mintNodeId",
            "applicantRef",
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
            let changed: FacilityApplicationAdmission = serde_json::from_value(changed).unwrap();
            assert!(
                !verifies(&changed, &signature, &keys),
                "signature must bind {field}"
            );
        }
        for case in vector["negative"].as_array().unwrap() {
            let mut changed = vector["admission"].clone();
            for (key, value) in case["admission"].as_object().unwrap() {
                changed[key] = value.clone();
            }
            let changed: FacilityApplicationAdmission = serde_json::from_value(changed).unwrap();
            let signature = case["signature"]
                .as_str()
                .map(|value| Signature::from_str(value).unwrap())
                .unwrap_or(signature);
            assert!(
                !verifies(&changed, &signature, &keys),
                "negative vector {} must fail",
                case["name"]
            );
        }
        // A different, valid key cannot reuse the vector signature.
        assert!(!verifies(&admission, &signature, &super::tests::keys(5)));
    }

    #[test]
    fn facility_admission_rejects_substituted_key_mint_or_network() {
        let (payload, signer, keys) = fixture();
        let now = Timestamp::new(1_790_000_000).unwrap();
        let other_keys = super::tests::keys(5);
        let other = NodeId::new(other_keys.pub_key(), Network::Regtest);
        assert!(
            sign_for_current_identity(&payload, &signer, &other_keys, &payload.mint_node, now)
                .is_err()
        );
        assert!(sign_for_current_identity(&payload, &signer, &keys, &other, now).is_err());
        let mut changed = payload.clone();
        changed.mint_node = NodeId::new(payload.mint_node.pub_key(), Network::Testnet);
        assert!(
            sign_for_current_identity(&changed, &signer, &keys, &changed.mint_node, now).is_err()
        );
        let mainnet_signer = NodeId::new(keys.pub_key(), Network::Bitcoin);
        changed.mint_node = NodeId::new(payload.mint_node.pub_key(), Network::Bitcoin);
        assert!(
            sign_for_current_identity(&changed, &mainnet_signer, &keys, &changed.mint_node, now)
                .is_err()
        );
    }

    #[test]
    fn facility_admission_rejects_unbounded_input_and_caller_signer_or_timestamps() {
        let (payload, signer, keys) = fixture();
        let now = Timestamp::new(1_790_000_000).unwrap();
        for value in [
            "b".repeat(64),
            format!("sha256:{}", "B".repeat(64)),
            format!("sha256:{}\naction", "b".repeat(64)),
            format!("sha256:{}", "b".repeat(63)),
        ] {
            let mut invalid = payload.clone();
            invalid.application_token_digest = value;
            assert!(
                sign_for_current_identity(&invalid, &signer, &keys, &payload.mint_node, now)
                    .is_err()
            );
        }
        let mut invalid = payload.clone();
        invalid.application_id = Uuid::nil();
        assert!(
            sign_for_current_identity(&invalid, &signer, &keys, &payload.mint_node, now).is_err()
        );
        let base = serde_json::json!({
            "action": "open_facility_application",
            "application_id": payload.application_id,
            "mint_node": payload.mint_node,
            "application_token_digest": payload.application_token_digest,
        });
        assert!(
            serde_json::from_value::<FacilityApplicationAdmissionPayload>(base.clone()).is_ok()
        );
        for (key, value) in [
            ("issuedAt", serde_json::json!(1)),
            ("expires_at", serde_json::json!(1)),
            ("applicant_ref", serde_json::json!(signer.to_string())),
            ("signer", serde_json::json!(signer.to_string())),
        ] {
            let mut input = base.clone();
            input[key] = value;
            assert!(serde_json::from_value::<FacilityApplicationAdmissionPayload>(input).is_err());
        }
        let mut input = base;
        input["action"] = serde_json::json!("open_initial_credit_interview");
        assert!(serde_json::from_value::<FacilityApplicationAdmissionPayload>(input).is_err());
    }
}
