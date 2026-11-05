use crate::ffi::{
    api::bill::get_signer_public_data_and_keys, error::EbillFfiError, get_active_ctx,
};
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_api::{
    application_admission::{
        MintApplicationAdmissionPayload, SignedMintApplicationAdmission, mint,
    },
    util::{validate_bill_id_network, validate_node_id_network},
};
use bcr_ebill_core::protocol::{ProtocolValidationError, Timestamp};
use bitcoin::Network;
use flutter_rust_bridge::frb;
use std::str::FromStr;
use uuid::Uuid;

/// Opens an application only; it never accepts an offer or authorizes minting.
/// The signer, network and timestamps are never caller-selected; Core adds them.
#[derive(Debug, Clone)]
pub struct MintApplicationAdmissionPayloadFfi {
    pub bill_id: String,
    pub mint_node_id: String,
    pub mint_quote_id: String,
    pub case_id: String,
    /// `sha256:` followed by 64 lowercase hex characters of the application token's digest
    pub application_token_digest: String,
}

#[derive(Debug, Clone)]
pub struct MintApplicationAdmissionFfi {
    pub schema_version: String,
    pub action: String,
    pub bill_id: String,
    pub mint_node_id: String,
    pub mint_quote_id: String,
    pub case_id: String,
    pub holder_ref: String,
    pub application_token_digest: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone)]
pub struct SignedMintApplicationAdmissionFfi {
    pub admission: MintApplicationAdmissionFfi,
    /// BIP340 signature over SHA256 of the canonical admission lines, lowercase hex
    pub signature: String,
}

impl From<SignedMintApplicationAdmission> for SignedMintApplicationAdmissionFfi {
    fn from(value: SignedMintApplicationAdmission) -> Self {
        let admission = value.admission;
        Self {
            admission: MintApplicationAdmissionFfi {
                schema_version: admission.schema_version,
                action: admission.action,
                bill_id: admission.bill_id,
                mint_node_id: admission.mint_node_id,
                mint_quote_id: admission.mint_quote_id,
                case_id: admission.case_id,
                holder_ref: admission.holder_ref,
                application_token_digest: admission.application_token_digest,
                issued_at: admission.issued_at,
                expires_at: admission.expires_at,
            },
            signature: value.signature,
        }
    }
}

fn parse_payload(
    payload: MintApplicationAdmissionPayloadFfi,
    network: Network,
) -> Result<MintApplicationAdmissionPayload, EbillFfiError> {
    let parse_id = |value: &str| {
        Uuid::from_str(value)
            .map_err(|_| ProtocolValidationError::FieldInvalid(bcr_ebill_core::protocol::Field::Id))
    };
    let payload = MintApplicationAdmissionPayload {
        bill_id: BillId::from_str(&payload.bill_id).map_err(ProtocolValidationError::from)?,
        mint_node: NodeId::from_str(&payload.mint_node_id)
            .map_err(ProtocolValidationError::from)?,
        mint_quote_id: parse_id(&payload.mint_quote_id)?,
        case_id: parse_id(&payload.case_id)?,
        application_token_digest: payload.application_token_digest,
    };
    validate_bill_id_network(&payload.bill_id, network)?;
    validate_node_id_network(&payload.mint_node, network)?;
    Ok(payload)
}

/// Proves that the selected identity is the current holder of an accepted, unpaid bill with
/// exactly one matching pending quote request, for one short-lived application admission.
/// Keys stay inside Core; this neither creates a request nor changes any financial state.
/// Authenticity only: never KYC, truth, solvency, consent or financial authorization.
#[frb]
pub async fn sign_mint_application_admission(
    payload: MintApplicationAdmissionPayloadFfi,
) -> Result<SignedMintApplicationAdmissionFfi, EbillFfiError> {
    let ctx = get_active_ctx().await?;
    let network = ctx.cfg.bitcoin_network();
    let payload = parse_payload(payload, network)?;
    let (signer, keys) = get_signer_public_data_and_keys(ctx.clone()).await?;
    let signer_node_id = signer.node_id();
    validate_node_id_network(&signer_node_id, network)?;
    let identity = ctx.identity_service.get_identity().await?;
    let bill = ctx
        .bill_service
        .get_detail(
            &payload.bill_id,
            &identity,
            &signer,
            &keys,
            Timestamp::now(),
        )
        .await?;
    mint::validate_bill_state(&bill.state)?;
    let current_holder = bill
        .participants
        .endorsee
        .as_ref()
        .unwrap_or(&bill.participants.payee)
        .node_id();
    let requests = ctx
        .bill_service
        .get_mint_state(&payload.bill_id, &signer_node_id)
        .await?;
    let signed = mint::sign_for_pending_request(
        &payload,
        &signer_node_id,
        &keys,
        &current_holder,
        &requests,
        &ctx.cfg.mint_config,
        Timestamp::now(),
    )?;
    Ok(signed.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bcr_ebill_api::MintConfig;
    use bcr_ebill_core::protocol::{
        crypto::BcrKeys,
        mint::{MintRequest, MintRequestState, MintRequestStatus},
    };
    use bitcoin::{
        hashes::{Hash, sha256},
        secp256k1::{Message, SECP256K1, SecretKey, schnorr::Signature},
    };

    fn keys(value: u8) -> BcrKeys {
        let mut bytes = [0; 32];
        bytes[31] = value;
        BcrKeys::from_private_key(&SecretKey::from_slice(&bytes).unwrap())
    }

    fn payload_ffi(bill: &BillId, mint: &NodeId) -> MintApplicationAdmissionPayloadFfi {
        MintApplicationAdmissionPayloadFfi {
            bill_id: bill.to_string(),
            mint_node_id: mint.to_string(),
            mint_quote_id: "11111111-1111-4111-8111-111111111111".into(),
            case_id: "22222222-2222-4222-8222-222222222222".into(),
            application_token_digest: format!("sha256:{}", "a".repeat(64)),
        }
    }

    // Independent restatement of the cross-language canonical text, to prove every FFI field
    // reaches Dart unchanged and stays bound by the signature.
    fn canonical_message(a: &MintApplicationAdmissionFfi) -> Message {
        let text = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            a.schema_version,
            a.action,
            a.bill_id,
            a.mint_node_id,
            a.mint_quote_id,
            a.case_id,
            a.holder_ref,
            a.application_token_digest,
            a.issued_at,
            a.expires_at,
        );
        Message::from_digest(sha256::Hash::hash(text.as_bytes()).to_byte_array())
    }

    #[test]
    fn ffi_admission_carries_the_signed_fields_for_a_pending_request_only() {
        let holder_keys = keys(3);
        let holder = NodeId::new(holder_keys.pub_key(), Network::Regtest);
        let bill = BillId::new(holder_keys.pub_key(), Network::Regtest);
        let mint_node = NodeId::new(keys(4).pub_key(), Network::Regtest);
        let config = MintConfig::new("http://localhost:5343".into(), mint_node.clone()).unwrap();
        let payload = parse_payload(payload_ffi(&bill, &mint_node), Network::Regtest).unwrap();
        let mut request = MintRequestState {
            request: MintRequest {
                requester_node_id: holder.clone(),
                bill_id: bill.clone(),
                mint_node_id: mint_node.clone(),
                mint_request_id: payload.mint_quote_id,
                timestamp: Timestamp::new(1_790_000_000).unwrap(),
                status: MintRequestStatus::Pending,
            },
            offer: None,
        };
        let now = Timestamp::new(1_790_000_000).unwrap();
        let sign = |request: &MintRequestState| {
            mint::sign_for_pending_request(
                &payload,
                &holder,
                &holder_keys,
                &holder,
                std::slice::from_ref(request),
                &config,
                now,
            )
        };

        let signed: SignedMintApplicationAdmissionFfi = sign(&request).unwrap().into();
        let a = &signed.admission;
        assert_eq!(a.schema_version, "mint-application-admission-v1");
        assert_eq!(a.action, "open_initial_credit_interview");
        assert_eq!(a.bill_id, bill.to_string());
        assert_eq!(a.mint_node_id, mint_node.to_string());
        assert_eq!(a.mint_quote_id, "11111111-1111-4111-8111-111111111111");
        assert_eq!(a.case_id, "22222222-2222-4222-8222-222222222222");
        assert_eq!(a.holder_ref, holder.to_string());
        assert_eq!(a.application_token_digest, payload.application_token_digest);
        assert_eq!((a.issued_at, a.expires_at), (1_790_000_000, 1_790_000_300));
        let signature = Signature::from_str(&signed.signature).unwrap();
        let x_only = holder.pub_key().x_only_public_key().0;
        SECP256K1
            .verify_schnorr(&signature, &canonical_message(a), &x_only)
            .unwrap();
        let mut changed = a.clone();
        changed.case_id = Uuid::new_v4().to_string();
        assert!(
            SECP256K1
                .verify_schnorr(&signature, &canonical_message(&changed), &x_only)
                .is_err()
        );

        request.request.status = MintRequestStatus::Accepted;
        assert_eq!(
            sign(&request).unwrap_err(),
            ProtocolValidationError::InvalidMintRequestId
        );
    }

    #[test]
    fn ffi_payload_rejects_malformed_ids_and_other_networks() {
        let holder_keys = keys(3);
        let bill = BillId::new(holder_keys.pub_key(), Network::Regtest);
        let mint_node = NodeId::new(keys(4).pub_key(), Network::Regtest);
        assert!(parse_payload(payload_ffi(&bill, &mint_node), Network::Regtest).is_ok());
        assert!(parse_payload(payload_ffi(&bill, &mint_node), Network::Testnet).is_err());
        for field in ["bill", "mint", "quote", "case"] {
            let mut payload = payload_ffi(&bill, &mint_node);
            match field {
                "bill" => payload.bill_id = "bill".into(),
                "mint" => payload.mint_node_id = "mint".into(),
                "quote" => payload.mint_quote_id = "quote".into(),
                "case" => payload.case_id = "case".into(),
                _ => unreachable!(),
            }
            assert!(
                parse_payload(payload, Network::Regtest).is_err(),
                "must reject {field}"
            );
        }
        let other_bill = BillId::new(holder_keys.pub_key(), Network::Testnet);
        assert!(parse_payload(payload_ffi(&other_bill, &mint_node), Network::Regtest).is_err());
        let other_mint = NodeId::new(keys(4).pub_key(), Network::Testnet);
        assert!(parse_payload(payload_ffi(&bill, &other_mint), Network::Regtest).is_err());
    }
}
