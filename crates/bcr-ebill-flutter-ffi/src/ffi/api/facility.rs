use crate::ffi::{
    api::identity::get_current_identity, context::Context, error::EbillFfiError, get_active_ctx,
};
use bcr_common::core::NodeId;
use bcr_ebill_api::{
    application_admission::{
        FacilityApplicationAdmissionAction, FacilityApplicationAdmissionPayload,
        SignedFacilityApplicationAdmission, facility,
    },
    util::validate_node_id_network,
};
use bcr_ebill_core::protocol::{ProtocolValidationError, Timestamp, crypto::BcrKeys};
use flutter_rust_bridge::frb;
use std::{str::FromStr, sync::Arc};
use uuid::Uuid;

/// Which facility capability the proof admits. Neither accepts terms nor authorizes minting.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FacilityApplicationAdmissionActionFfi {
    OpenFacilityApplication = 0,
    UpgradeFacilityIdentity = 1,
}

impl From<FacilityApplicationAdmissionActionFfi> for FacilityApplicationAdmissionAction {
    fn from(value: FacilityApplicationAdmissionActionFfi) -> Self {
        match value {
            FacilityApplicationAdmissionActionFfi::OpenFacilityApplication => {
                Self::OpenFacilityApplication
            }
            FacilityApplicationAdmissionActionFfi::UpgradeFacilityIdentity => {
                Self::UpgradeFacilityIdentity
            }
        }
    }
}

/// The signer, network and timestamps are never caller-selected; Core adds them.
#[derive(Debug, Clone)]
pub struct FacilityApplicationAdmissionPayloadFfi {
    pub action: FacilityApplicationAdmissionActionFfi,
    pub application_id: String,
    pub mint_node_id: String,
    /// `sha256:` followed by 64 lowercase hex characters of the application token's digest
    pub application_token_digest: String,
}

#[derive(Debug, Clone)]
pub struct FacilityApplicationAdmissionFfi {
    pub schema_version: String,
    pub action: String,
    pub application_id: String,
    pub mint_node_id: String,
    pub applicant_ref: String,
    pub application_token_digest: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone)]
pub struct SignedFacilityApplicationAdmissionFfi {
    pub admission: FacilityApplicationAdmissionFfi,
    /// BIP340 signature over SHA256 of the canonical admission lines, lowercase hex
    pub signature: String,
}

impl From<SignedFacilityApplicationAdmission> for SignedFacilityApplicationAdmissionFfi {
    fn from(value: SignedFacilityApplicationAdmission) -> Self {
        let admission = value.admission;
        Self {
            admission: FacilityApplicationAdmissionFfi {
                schema_version: admission.schema_version,
                action: admission.action,
                application_id: admission.application_id,
                mint_node_id: admission.mint_node_id,
                applicant_ref: admission.applicant_ref,
                application_token_digest: admission.application_token_digest,
                issued_at: admission.issued_at,
                expires_at: admission.expires_at,
            },
            signature: value.signature,
        }
    }
}

/// Proves control of the selected identity's key for one facility application capability.
/// Authenticity only: never KYC, truth, solvency, consent or financial authorization.
#[frb]
pub async fn sign_facility_application_admission(
    payload: FacilityApplicationAdmissionPayloadFfi,
) -> Result<SignedFacilityApplicationAdmissionFfi, EbillFfiError> {
    let ctx = get_active_ctx().await?;
    let network = ctx.cfg.bitcoin_network();
    let payload = FacilityApplicationAdmissionPayload {
        action: payload.action.into(),
        application_id: Uuid::from_str(&payload.application_id).map_err(|_| {
            ProtocolValidationError::FieldInvalid(bcr_ebill_core::protocol::Field::Id)
        })?,
        mint_node: NodeId::from_str(&payload.mint_node_id)
            .map_err(ProtocolValidationError::from)?,
        application_token_digest: payload.application_token_digest,
    };
    validate_node_id_network(&payload.mint_node, network)?;
    let (signer, keys) = current_signer(ctx.clone()).await?;
    validate_node_id_network(&signer, network)?;
    let signed = facility::sign_for_current_identity(
        &payload,
        &signer,
        &keys,
        &ctx.cfg.mint_config,
        Timestamp::now(),
    )?;
    Ok(signed.into())
}

/// The selected identity signs: the person, or the selected company when the person is one of
/// its authorized signers.
async fn current_signer(ctx: Arc<Context>) -> Result<(NodeId, BcrKeys), EbillFfiError> {
    let selected = get_current_identity(ctx.clone()).await?;
    let personal = ctx.identity_service.get_full_identity().await?;
    if personal.identity.node_id != selected.personal
        || personal.key_pair.pub_key() != selected.personal.pub_key()
    {
        return Err(ProtocolValidationError::CallerMustBeSignatory.into());
    }
    match selected.company {
        None => Ok((selected.personal, personal.key_pair)),
        Some(company_id) => {
            let (company, keys) = ctx
                .company_service
                .get_company_and_keys_by_id(&company_id)
                .await?;
            if company.id != company_id
                || keys.pub_key() != company.id.pub_key()
                || !company.is_authorized_signer(&selected.personal)
            {
                return Err(
                    ProtocolValidationError::NotASignatory(selected.personal.to_string()).into(),
                );
            }
            Ok((company.id, keys))
        }
    }
}
