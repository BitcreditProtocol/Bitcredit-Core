//! Test-network statements signed with the selected identity's key inside Core: service voice
//! admission, cross-Mint consent and the public business directory. Each authenticates one
//! optional claim or consent only; none is KYC, truth, solvency or financial authorization.
//! Signers, networks, clocks and nonces are never caller-selected. Core does not publish or
//! deliver anything; the app posts each result's `json` unchanged.
use crate::ffi::{error::EbillFfiError, get_active_ctx};
use anyhow::anyhow;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_api::{
    network_consent::{
        self, CrossMintGrantPayload, CrossMintOperation, CrossMintRevokePayload,
        DirectoryListingPayload, DirectoryWithdrawalPayload, ServiceVoiceAdmissionPayload,
        SignedCrossMintGrant, SignedCrossMintRevoke, SignedDirectoryEvent,
        SignedDirectoryWithdrawal, SignedServiceVoiceAdmission,
        signer::{
            LocalSigningIdentity, SigningIdentitySource, get_current_signer_node_id_and_keys,
            get_current_signer_with_type, get_personal_signer,
        },
    },
    util::{validate_bill_id_network, validate_node_id_network},
};
use bcr_ebill_core::protocol::{Field, ProtocolValidationError, Timestamp};
use bitcoin::Network;
use flutter_rust_bridge::frb;
use serde::Serialize;
use std::str::FromStr;
use uuid::Uuid;

/// Admits transcription at the default (service) Mint only.
#[derive(Debug, Clone)]
pub struct ServiceVoiceAdmissionPayloadFfi {
    pub service_mint_node_id: String,
    /// 1..=300 seconds; 300 when unset
    pub lifetime_seconds: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ServiceVoiceAdmissionFfi {
    pub schema: String,
    pub network: String,
    pub subject_node_id: String,
    pub service_mint_node_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

#[derive(Debug, Clone)]
pub struct SignedServiceVoiceAdmissionFfi {
    pub admission: ServiceVoiceAdmissionFfi,
    /// BIP340 signature over SHA256 of the canonical admission lines, lowercase hex
    pub signature: String,
    /// `{"admission":{...},"signature":"..."}` exactly as AI Credit's `signedAdmission` expects
    pub json: String,
}

/// Single-use consent for one named pair of Mints to exchange one bill's status.
/// The operation is always `bill_status`, the only one defined.
#[derive(Debug, Clone)]
pub struct CrossMintGrantPayloadFfi {
    pub grant_id: String,
    /// x-only federation keys, lowercase hex
    pub requesting_mint_pubkey: String,
    pub answering_mint_pubkey: String,
    pub bill_id: String,
    /// 64 lowercase hex characters
    pub case_binding: String,
    /// 1..=300 seconds; 300 when unset
    pub lifetime_seconds: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct CrossMintGrantFfi {
    pub schema: String,
    pub grant_id: String,
    pub network: String,
    pub subject_node_id: String,
    pub requesting_mint_pubkey: String,
    pub answering_mint_pubkey: String,
    pub operation: String,
    pub bill_id: String,
    pub case_binding: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

#[derive(Debug, Clone)]
pub struct SignedCrossMintGrantFfi {
    pub grant: CrossMintGrantFfi,
    pub signature: String,
    /// `{"grant":{...},"signature":"..."}` exactly as AI Credit's `signedGrant` expects
    pub json: String,
}

#[derive(Debug, Clone)]
pub struct CrossMintRevokePayloadFfi {
    pub grant_id: String,
    pub requesting_mint_pubkey: String,
    pub answering_mint_pubkey: String,
}

#[derive(Debug, Clone)]
pub struct CrossMintRevokeFfi {
    pub schema: String,
    pub grant_id: String,
    pub network: String,
    pub subject_node_id: String,
    pub requesting_mint_pubkey: String,
    pub answering_mint_pubkey: String,
    pub nonce: String,
    pub issued_at: u64,
}

#[derive(Debug, Clone)]
pub struct SignedCrossMintRevokeFfi {
    pub revoke: CrossMintRevokeFfi,
    pub signature: String,
    /// `{"revoke":{...},"signature":"..."}` exactly as AI Credit's `signedRevoke` expects
    pub json: String,
}

/// A complete NIP-01 event. `content` is the signed JSON text.
#[derive(Debug, Clone)]
pub struct SignedDirectoryEventFfi {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
    /// The event as NIP-01 JSON; keep it to withdraw the listing later
    pub json: String,
}

#[derive(Debug, Clone)]
pub struct SignedDirectoryWithdrawalFfi {
    /// The replacement listing that marks the subject withdrawn
    pub withdrawal: SignedDirectoryEventFfi,
    /// The NIP-09 deletion request for the prior listings
    pub deletion: SignedDirectoryEventFfi,
}

fn to_json(value: &impl Serialize) -> Result<String, EbillFfiError> {
    serde_json::to_string(value)
        .map_err(|e| anyhow!("cannot serialize signed statement: {e}").into())
}

fn operation(value: &CrossMintOperation) -> String {
    match value {
        CrossMintOperation::BillStatus => "bill_status".into(),
    }
}

impl TryFrom<SignedServiceVoiceAdmission> for SignedServiceVoiceAdmissionFfi {
    type Error = EbillFfiError;
    fn try_from(value: SignedServiceVoiceAdmission) -> Result<Self, Self::Error> {
        let json = to_json(&value)?;
        let a = value.admission;
        Ok(Self {
            admission: ServiceVoiceAdmissionFfi {
                schema: a.schema,
                network: a.network,
                subject_node_id: a.subject_node_id,
                service_mint_node_id: a.service_mint_node_id,
                issued_at: a.issued_at,
                expires_at: a.expires_at,
                nonce: a.nonce,
            },
            signature: value.signature,
            json,
        })
    }
}

impl TryFrom<SignedCrossMintGrant> for SignedCrossMintGrantFfi {
    type Error = EbillFfiError;
    fn try_from(value: SignedCrossMintGrant) -> Result<Self, Self::Error> {
        let json = to_json(&value)?;
        let g = value.grant;
        Ok(Self {
            grant: CrossMintGrantFfi {
                schema: g.schema,
                grant_id: g.grant_id,
                network: g.network,
                subject_node_id: g.subject_node_id,
                requesting_mint_pubkey: g.requesting_mint_pubkey,
                answering_mint_pubkey: g.answering_mint_pubkey,
                operation: operation(&g.operation),
                bill_id: g.bill_id,
                case_binding: g.case_binding,
                issued_at: g.issued_at,
                expires_at: g.expires_at,
                nonce: g.nonce,
            },
            signature: value.signature,
            json,
        })
    }
}

impl TryFrom<SignedCrossMintRevoke> for SignedCrossMintRevokeFfi {
    type Error = EbillFfiError;
    fn try_from(value: SignedCrossMintRevoke) -> Result<Self, Self::Error> {
        let json = to_json(&value)?;
        let r = value.revoke;
        Ok(Self {
            revoke: CrossMintRevokeFfi {
                schema: r.schema,
                grant_id: r.grant_id,
                network: r.network,
                subject_node_id: r.subject_node_id,
                requesting_mint_pubkey: r.requesting_mint_pubkey,
                answering_mint_pubkey: r.answering_mint_pubkey,
                nonce: r.nonce,
                issued_at: r.issued_at,
            },
            signature: value.signature,
            json,
        })
    }
}

impl TryFrom<SignedDirectoryEvent> for SignedDirectoryEventFfi {
    type Error = EbillFfiError;
    fn try_from(value: SignedDirectoryEvent) -> Result<Self, Self::Error> {
        let json = to_json(&value)?;
        Ok(Self {
            id: value.id,
            pubkey: value.pubkey,
            created_at: value.created_at,
            kind: value.kind,
            tags: value.tags,
            content: value.content,
            sig: value.sig,
            json,
        })
    }
}

impl TryFrom<SignedDirectoryWithdrawal> for SignedDirectoryWithdrawalFfi {
    type Error = EbillFfiError;
    fn try_from(value: SignedDirectoryWithdrawal) -> Result<Self, Self::Error> {
        Ok(Self {
            withdrawal: value.withdrawal.try_into()?,
            deletion: value.deletion.try_into()?,
        })
    }
}

fn parse_uuid(value: &str) -> Result<Uuid, EbillFfiError> {
    Ok(Uuid::from_str(value).map_err(|_| ProtocolValidationError::FieldInvalid(Field::Id))?)
}

fn parse_json<T: serde::de::DeserializeOwned>(value: &str, what: &str) -> Result<T, EbillFfiError> {
    serde_json::from_str(value).map_err(|e| anyhow!("invalid {what} JSON: {e}").into())
}

async fn sign_service_voice_admission_with(
    source: &impl SigningIdentitySource,
    network: Network,
    service_mint: &NodeId,
    payload: ServiceVoiceAdmissionPayloadFfi,
    now: Timestamp,
    nonce: String,
) -> Result<SignedServiceVoiceAdmissionFfi, EbillFfiError> {
    let payload = ServiceVoiceAdmissionPayload {
        service_mint_node_id: NodeId::from_str(&payload.service_mint_node_id)
            .map_err(ProtocolValidationError::from)?,
        lifetime_seconds: payload.lifetime_seconds,
    };
    // The device operator's personal key, even while a company is selected.
    let (_, signer, keys) = get_personal_signer(source).await?;
    validate_node_id_network(&signer, network)?;
    network_consent::sign_service_voice_admission(
        &payload,
        &signer,
        &keys,
        service_mint,
        now,
        nonce,
    )?
    .try_into()
}

async fn sign_cross_mint_grant_with(
    source: &impl SigningIdentitySource,
    network: Network,
    payload: CrossMintGrantPayloadFfi,
    now: Timestamp,
    nonce: String,
) -> Result<SignedCrossMintGrantFfi, EbillFfiError> {
    let payload = CrossMintGrantPayload {
        grant_id: parse_uuid(&payload.grant_id)?,
        requesting_mint_pubkey: payload.requesting_mint_pubkey,
        answering_mint_pubkey: payload.answering_mint_pubkey,
        operation: CrossMintOperation::BillStatus,
        bill_id: BillId::from_str(&payload.bill_id).map_err(ProtocolValidationError::from)?,
        case_binding: payload.case_binding,
        lifetime_seconds: payload.lifetime_seconds,
    };
    validate_bill_id_network(&payload.bill_id, network)?;
    let (signer, keys) = get_current_signer_node_id_and_keys(source).await?;
    validate_node_id_network(&signer, network)?;
    network_consent::sign_grant(&payload, &signer, &keys, now, nonce)?.try_into()
}

async fn sign_cross_mint_revoke_with(
    source: &impl SigningIdentitySource,
    network: Network,
    payload: CrossMintRevokePayloadFfi,
    now: Timestamp,
    nonce: String,
) -> Result<SignedCrossMintRevokeFfi, EbillFfiError> {
    let payload = CrossMintRevokePayload {
        grant_id: parse_uuid(&payload.grant_id)?,
        requesting_mint_pubkey: payload.requesting_mint_pubkey,
        answering_mint_pubkey: payload.answering_mint_pubkey,
    };
    let (signer, keys) = get_current_signer_node_id_and_keys(source).await?;
    validate_node_id_network(&signer, network)?;
    network_consent::sign_revoke(&payload, &signer, &keys, now, nonce)?.try_into()
}

async fn sign_directory_listing_with(
    source: &impl SigningIdentitySource,
    network: Network,
    payload_json: &str,
    now: Timestamp,
) -> Result<SignedDirectoryEventFfi, EbillFfiError> {
    let payload: DirectoryListingPayload = parse_json(payload_json, "directory listing")?;
    let (signer, keys, subject_type) = get_current_signer_with_type(source).await?;
    validate_node_id_network(&signer, network)?;
    network_consent::sign_listing(&payload, &signer, &keys, subject_type, now)?.try_into()
}

async fn sign_directory_withdrawal_with(
    source: &impl SigningIdentitySource,
    network: Network,
    prior_events_json: &[String],
    now: Timestamp,
) -> Result<SignedDirectoryWithdrawalFfi, EbillFfiError> {
    let payload = DirectoryWithdrawalPayload {
        prior_events: prior_events_json
            .iter()
            .map(|event| parse_json(event, "directory event"))
            .collect::<Result<_, _>>()?,
    };
    let (signer, keys, _) = get_current_signer_with_type(source).await?;
    validate_node_id_network(&signer, network)?;
    network_consent::sign_withdrawal(&payload, &signer, &keys, now)?.try_into()
}

/// Admits voice transcription at the default (service) Mint, signed with the device
/// operator's personal key even while a company is selected. Never a case admission.
#[frb]
pub async fn sign_service_voice_admission(
    payload: ServiceVoiceAdmissionPayloadFfi,
) -> Result<SignedServiceVoiceAdmissionFfi, EbillFfiError> {
    let ctx = get_active_ctx().await?;
    let source = LocalSigningIdentity {
        identity_service: ctx.identity_service.as_ref(),
        company_service: ctx.company_service.as_ref(),
    };
    sign_service_voice_admission_with(
        &source,
        ctx.cfg.bitcoin_network(),
        &ctx.cfg.mint_config.default_mint_node_id,
        payload,
        Timestamp::now(),
        network_consent::fresh_nonce()?,
    )
    .await
}

/// Consents, as the selected person or company, to one Mint asking another about one bill.
#[frb]
pub async fn sign_cross_mint_grant(
    payload: CrossMintGrantPayloadFfi,
) -> Result<SignedCrossMintGrantFfi, EbillFfiError> {
    let ctx = get_active_ctx().await?;
    let source = LocalSigningIdentity {
        identity_service: ctx.identity_service.as_ref(),
        company_service: ctx.company_service.as_ref(),
    };
    sign_cross_mint_grant_with(
        &source,
        ctx.cfg.bitcoin_network(),
        payload,
        Timestamp::now(),
        network_consent::fresh_nonce()?,
    )
    .await
}

/// Revokes future disclosure under a grant; the app delivers it to both named Mints.
#[frb]
pub async fn sign_cross_mint_revoke(
    payload: CrossMintRevokePayloadFfi,
) -> Result<SignedCrossMintRevokeFfi, EbillFfiError> {
    let ctx = get_active_ctx().await?;
    let source = LocalSigningIdentity {
        identity_service: ctx.identity_service.as_ref(),
        company_service: ctx.company_service.as_ref(),
    };
    sign_cross_mint_revoke_with(
        &source,
        ctx.cfg.bitcoin_network(),
        payload,
        Timestamp::now(),
        network_consent::fresh_nonce()?,
    )
    .await
}

/// Signs reviewed opt-in public listing fields with the selected subject's key.
/// `payload_json` is the camelCase `DirectoryListingPayload` the web app sends; unknown
/// fields are rejected, and `type` must match the selected subject (`sole_trader` for the
/// person, `company` for a company). Core does not publish the event.
#[frb]
pub async fn sign_directory_listing(
    payload_json: String,
) -> Result<SignedDirectoryEventFfi, EbillFfiError> {
    let ctx = get_active_ctx().await?;
    let source = LocalSigningIdentity {
        identity_service: ctx.identity_service.as_ref(),
        company_service: ctx.company_service.as_ref(),
    };
    sign_directory_listing_with(
        &source,
        ctx.cfg.bitcoin_network(),
        &payload_json,
        Timestamp::now(),
    )
    .await
}

/// Signs a withdrawn replacement and a NIP-09 deletion for the subject's prior listings,
/// given as their `json`. Public copies already fetched cannot be recalled.
#[frb]
pub async fn sign_directory_withdrawal(
    prior_events_json: Vec<String>,
) -> Result<SignedDirectoryWithdrawalFfi, EbillFfiError> {
    let ctx = get_active_ctx().await?;
    let source = LocalSigningIdentity {
        identity_service: ctx.identity_service.as_ref(),
        company_service: ctx.company_service.as_ref(),
    };
    sign_directory_withdrawal_with(
        &source,
        ctx.cfg.bitcoin_network(),
        &prior_events_json,
        Timestamp::now(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bcr_ebill_api::{network_consent::ServiceVoiceAdmission, service::Error};
    use bcr_ebill_core::{
        application::{
            company::{Company, CompanySignatoryStatus},
            identity::ActiveIdentityState,
        },
        protocol::{
            Address, City, Country, Email, EmailIdentityProofData, Name, PostalAddress,
            blockchain::company::block::CompanyCreateBlockData, crypto::BcrKeys,
        },
    };
    use bitcoin::{
        hashes::{Hash, sha256},
        secp256k1::{Message, SECP256K1, SecretKey, schnorr::Signature},
    };
    use serde_json::{Value, json};

    fn keys(n: u8) -> BcrKeys {
        BcrKeys::from_private_key(&SecretKey::from_slice(&[n; 32]).unwrap())
    }
    fn node(n: u8) -> NodeId {
        NodeId::new(keys(n).pub_key(), Network::Regtest)
    }
    fn now() -> Timestamp {
        Timestamp::new(1_790_000_000).unwrap()
    }
    fn nonce() -> String {
        "c".repeat(64)
    }
    fn xonly(n: u8) -> String {
        keys(n).pub_key().x_only_public_key().0.to_string()
    }

    /// Person 1, optionally selecting company 2 where person 1 is an identity-proven signer.
    struct Source {
        selected: Option<ActiveIdentityState>,
        company: Option<Company>,
    }

    impl Source {
        fn person() -> Self {
            Self {
                selected: Some(ActiveIdentityState {
                    personal: node(1),
                    company: None,
                }),
                company: None,
            }
        }
        fn company() -> Self {
            Self {
                selected: Some(ActiveIdentityState {
                    personal: node(1),
                    company: Some(node(2)),
                }),
                company: Some(company()),
            }
        }
        fn missing_company() -> Self {
            Self {
                company: None,
                ..Self::company()
            }
        }
        fn missing_identity() -> Self {
            Self {
                selected: None,
                company: None,
            }
        }
    }

    #[async_trait]
    impl SigningIdentitySource for Source {
        async fn selected(&self) -> bcr_ebill_api::service::Result<ActiveIdentityState> {
            self.selected.clone().ok_or(Error::NotFound)
        }
        async fn personal(&self) -> bcr_ebill_api::service::Result<(NodeId, BcrKeys)> {
            self.selected
                .as_ref()
                .map(|_| (node(1), keys(1)))
                .ok_or(Error::NotFound)
        }
        async fn company(&self, id: &NodeId) -> bcr_ebill_api::service::Result<(Company, BcrKeys)> {
            match &self.company {
                Some(company) if &company.id == id => Ok((company.clone(), keys(2))),
                _ => Err(Error::NotFound),
            }
        }
    }

    fn company() -> Company {
        let ts = now();
        let mut company = Company::from_block_data(
            CompanyCreateBlockData {
                id: node(2),
                name: Name::new("Synthetic company").unwrap(),
                country_of_registration: None,
                city_of_registration: None,
                postal_address: PostalAddress {
                    country: Country::parse("AT").unwrap(),
                    city: City::new("Vienna").unwrap(),
                    zip: None,
                    address: Address::new("Synthetic street 1").unwrap(),
                },
                email: Email::new("synthetic@example.test").unwrap(),
                registration_number: None,
                registration_date: None,
                proof_of_registration_file: None,
                logo_file: None,
                creation_time: ts,
                creator: node(1),
            },
            &node(1),
        );
        let data = EmailIdentityProofData {
            node_id: node(1),
            company_node_id: Some(node(2)),
            email: Email::new("synthetic@example.test").unwrap(),
            created_at: ts,
        };
        let proof = data.sign(&node(3), &keys(3).get_private_key()).unwrap();
        company.signatories[0].status =
            CompanySignatoryStatus::InviteAcceptedIdentityProven { ts, data, proof };
        company
    }

    fn verifies(text: &str, signature: &str, signer: &NodeId) -> bool {
        let message = Message::from_digest(sha256::Hash::hash(text.as_bytes()).to_byte_array());
        SECP256K1
            .verify_schnorr(
                &Signature::from_str(signature).unwrap(),
                &message,
                &signer.pub_key().x_only_public_key().0,
            )
            .is_ok()
    }

    // Independent restatements of AI Credit's canonical texts.
    fn voice_text(a: &ServiceVoiceAdmissionFfi) -> String {
        [
            a.schema.clone(),
            a.network.clone(),
            a.subject_node_id.clone(),
            a.service_mint_node_id.clone(),
            a.issued_at.to_string(),
            a.expires_at.to_string(),
            a.nonce.clone(),
            String::new(),
        ]
        .join("\n")
    }
    fn grant_text(g: &CrossMintGrantFfi) -> String {
        [
            g.schema.clone(),
            g.grant_id.clone(),
            g.network.clone(),
            g.subject_node_id.clone(),
            g.requesting_mint_pubkey.clone(),
            g.answering_mint_pubkey.clone(),
            g.operation.clone(),
            g.bill_id.clone(),
            g.case_binding.clone(),
            g.issued_at.to_string(),
            g.expires_at.to_string(),
            g.nonce.clone(),
            String::new(),
        ]
        .join("\n")
    }
    fn revoke_text(r: &CrossMintRevokeFfi) -> String {
        [
            r.schema.clone(),
            r.grant_id.clone(),
            r.network.clone(),
            r.subject_node_id.clone(),
            r.requesting_mint_pubkey.clone(),
            r.answering_mint_pubkey.clone(),
            r.nonce.clone(),
            r.issued_at.to_string(),
            String::new(),
        ]
        .join("\n")
    }

    fn voice_payload() -> ServiceVoiceAdmissionPayloadFfi {
        ServiceVoiceAdmissionPayloadFfi {
            service_mint_node_id: node(9).to_string(),
            lifetime_seconds: Some(120),
        }
    }
    fn grant_payload() -> CrossMintGrantPayloadFfi {
        CrossMintGrantPayloadFfi {
            grant_id: "33333333-3333-4333-8333-333333333333".into(),
            requesting_mint_pubkey: xonly(4),
            answering_mint_pubkey: xonly(5),
            bill_id: BillId::new(keys(6).pub_key(), Network::Regtest).to_string(),
            case_binding: "b".repeat(64),
            lifetime_seconds: None,
        }
    }
    fn revoke_payload() -> CrossMintRevokePayloadFfi {
        CrossMintRevokePayloadFfi {
            grant_id: "33333333-3333-4333-8333-333333333333".into(),
            requesting_mint_pubkey: xonly(4),
            answering_mint_pubkey: xonly(5),
        }
    }
    fn listing(subject_type: &str) -> String {
        let mut listing = json!({"type": subject_type, "name": "Synthetic coffee trader",
            "tradingNames": ["Café Example"], "country": "GT", "region": "Alta Verapaz",
            "products": [{"label": "Coffee"}], "description": "Synthetic public statement",
            "actingPersons": [], "contactRelays": ["wss://relay.example.test"],
            "validUntil": 1_790_086_400u64, "noticeVersion": "yellow-book-notice-v1"});
        if subject_type == "company" {
            listing["name"] = json!("Synthetic company");
        }
        listing.to_string()
    }

    async fn voice(source: &Source) -> Result<SignedServiceVoiceAdmissionFfi, EbillFfiError> {
        sign_service_voice_admission_with(
            source,
            Network::Regtest,
            &node(9),
            voice_payload(),
            now(),
            nonce(),
        )
        .await
    }
    async fn grant(source: &Source) -> Result<SignedCrossMintGrantFfi, EbillFfiError> {
        sign_cross_mint_grant_with(source, Network::Regtest, grant_payload(), now(), nonce()).await
    }
    async fn revoke(source: &Source) -> Result<SignedCrossMintRevokeFfi, EbillFfiError> {
        sign_cross_mint_revoke_with(source, Network::Regtest, revoke_payload(), now(), nonce())
            .await
    }
    async fn list(source: &Source, kind: &str) -> Result<SignedDirectoryEventFfi, EbillFfiError> {
        sign_directory_listing_with(source, Network::Regtest, &listing(kind), now()).await
    }

    #[tokio::test]
    async fn voice_admission_binds_the_personal_key_even_for_a_company() {
        for source in [Source::person(), Source::company()] {
            let signed = voice(&source).await.unwrap();
            let a = &signed.admission;
            assert_eq!(a.schema, "service-voice-admission-v1");
            assert_eq!(a.network, "regtest");
            assert_eq!(a.subject_node_id, node(1).to_string());
            assert_eq!(a.service_mint_node_id, node(9).to_string());
            assert_eq!((a.issued_at, a.expires_at), (1_790_000_000, 1_790_000_120));
            assert!(verifies(&voice_text(a), &signed.signature, &node(1)));
            let mut changed = a.clone();
            changed.expires_at += 1;
            assert!(!verifies(
                &voice_text(&changed),
                &signed.signature,
                &node(1)
            ));
            // the JSON is AI Credit's strict signedAdmission object, carrying the same fields
            let parsed: Value = serde_json::from_str(&signed.json).unwrap();
            assert_eq!(parsed["signature"], json!(signed.signature));
            assert_eq!(
                parsed["admission"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .collect::<Vec<_>>(),
                [
                    "expiresAt",
                    "issuedAt",
                    "network",
                    "nonce",
                    "schema",
                    "serviceMintNodeId",
                    "subjectNodeId"
                ]
            );
            let back: ServiceVoiceAdmission =
                serde_json::from_value(parsed["admission"].clone()).unwrap();
            assert_eq!(back.subject_node_id, a.subject_node_id);
            assert_eq!(back.nonce, a.nonce);
        }
    }

    #[tokio::test]
    async fn voice_admission_needs_an_identity_and_the_service_mint() {
        assert!(voice(&Source::missing_identity()).await.is_err());
        let other = sign_service_voice_admission_with(
            &Source::person(),
            Network::Regtest,
            &node(8),
            voice_payload(),
            now(),
            nonce(),
        )
        .await;
        assert!(other.is_err());
        let wrong_network = sign_service_voice_admission_with(
            &Source::person(),
            Network::Testnet,
            &node(9),
            voice_payload(),
            now(),
            nonce(),
        )
        .await;
        assert!(wrong_network.is_err());
    }

    #[tokio::test]
    async fn grant_and_revoke_bind_the_selected_subject() {
        for (source, subject) in [(Source::person(), node(1)), (Source::company(), node(2))] {
            let signed = grant(&source).await.unwrap();
            let g = &signed.grant;
            assert_eq!(g.schema, "cross-mint-grant-v1");
            assert_eq!(g.subject_node_id, subject.to_string());
            assert_eq!(g.operation, "bill_status");
            assert_eq!(g.expires_at - g.issued_at, 300);
            assert!(verifies(&grant_text(g), &signed.signature, &subject));
            let parsed: Value = serde_json::from_str(&signed.json).unwrap();
            assert_eq!(parsed["grant"]["subjectNodeId"], json!(g.subject_node_id));
            assert_eq!(parsed["grant"]["operation"], json!("bill_status"));
            assert_eq!(parsed["grant"]["caseBinding"], json!(g.case_binding));
            let back: SignedCrossMintGrant = serde_json::from_str(&signed.json).unwrap();
            assert_eq!(back.signature, signed.signature);
            assert_eq!(back.grant.bill_id, g.bill_id);

            let signed = revoke(&source).await.unwrap();
            let r = &signed.revoke;
            assert_eq!(r.schema, "cross-mint-revoke-v1");
            assert_eq!(r.subject_node_id, subject.to_string());
            assert!(verifies(&revoke_text(r), &signed.signature, &subject));
            let back: SignedCrossMintRevoke = serde_json::from_str(&signed.json).unwrap();
            assert_eq!(back.revoke.grant_id, r.grant_id);
            assert_eq!(back.signature, signed.signature);
        }
    }

    #[tokio::test]
    async fn consent_needs_an_identity_a_signable_company_and_valid_ids() {
        for source in [Source::missing_identity(), Source::missing_company()] {
            assert!(grant(&source).await.is_err());
            assert!(revoke(&source).await.is_err());
        }
        let mut payload = grant_payload();
        payload.grant_id = "grant".into();
        assert!(
            sign_cross_mint_grant_with(
                &Source::person(),
                Network::Regtest,
                payload,
                now(),
                nonce()
            )
            .await
            .is_err()
        );
        let mut payload = grant_payload();
        payload.bill_id = BillId::new(keys(6).pub_key(), Network::Testnet).to_string();
        assert!(
            sign_cross_mint_grant_with(
                &Source::person(),
                Network::Regtest,
                payload,
                now(),
                nonce()
            )
            .await
            .is_err()
        );
        let mut payload = revoke_payload();
        payload.answering_mint_pubkey = payload.requesting_mint_pubkey.clone();
        assert!(
            sign_cross_mint_revoke_with(
                &Source::person(),
                Network::Regtest,
                payload,
                now(),
                nonce()
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn listing_and_withdrawal_are_verifiable_events_of_the_selected_subject() {
        for (source, kind, subject) in [
            (Source::person(), "sole_trader", node(1)),
            (Source::company(), "company", node(2)),
        ] {
            let event = list(&source, kind).await.unwrap();
            assert_eq!(event.kind, 38900);
            assert_eq!(event.pubkey, subject.npub().to_string());
            let content: Value = serde_json::from_str(&event.content).unwrap();
            assert_eq!(content["subjectNodeId"], json!(subject.to_string()));
            assert_eq!(content["type"], json!(kind));
            assert_eq!(content["status"], json!("listed"));
            // the JSON is a NIP-01 event whose id and signature verify
            let parsed: nostr::event::Event = serde_json::from_str(&event.json).unwrap();
            parsed.verify().unwrap();
            assert_eq!(parsed.id.to_hex(), event.id);

            let later = Timestamp::new(now().inner() + 60).unwrap();
            let pair = sign_directory_withdrawal_with(
                &source,
                Network::Regtest,
                std::slice::from_ref(&event.json),
                later,
            )
            .await
            .unwrap();
            for signed in [&pair.withdrawal, &pair.deletion] {
                let parsed: nostr::event::Event = serde_json::from_str(&signed.json).unwrap();
                parsed.verify().unwrap();
                assert_eq!(signed.pubkey, event.pubkey);
            }
            let content: Value = serde_json::from_str(&pair.withdrawal.content).unwrap();
            assert_eq!(content["status"], json!("withdrawn"));
            assert_eq!(pair.deletion.kind, 5);
            assert!(
                pair.deletion
                    .tags
                    .contains(&vec!["e".to_string(), event.id.clone()])
            );
        }
    }

    #[tokio::test]
    async fn listing_rejects_another_subject_type_unknown_fields_and_no_signer() {
        assert!(list(&Source::person(), "company").await.is_err());
        assert!(list(&Source::company(), "sole_trader").await.is_err());
        assert!(
            list(&Source::missing_identity(), "sole_trader")
                .await
                .is_err()
        );
        assert!(list(&Source::missing_company(), "company").await.is_err());
        let mut extra: Value = serde_json::from_str(&listing("sole_trader")).unwrap();
        extra["email"] = json!("private@example.test");
        assert!(
            sign_directory_listing_with(
                &Source::person(),
                Network::Regtest,
                &extra.to_string(),
                now()
            )
            .await
            .is_err()
        );
        // another subject cannot withdraw this listing
        let event = list(&Source::person(), "sole_trader").await.unwrap();
        let later = Timestamp::new(now().inner() + 60).unwrap();
        assert!(
            sign_directory_withdrawal_with(
                &Source::company(),
                Network::Regtest,
                std::slice::from_ref(&event.json),
                later
            )
            .await
            .is_err()
        );
        assert!(
            sign_directory_withdrawal_with(&Source::person(), Network::Regtest, &[], later)
                .await
                .is_err()
        );
    }
}
