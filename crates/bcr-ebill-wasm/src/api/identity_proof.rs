use std::str::FromStr;

use crate::{
    api::{bill::get_signer_public_data_and_keys, identity::get_current_identity_node_id},
    context::get_ctx,
    data::identity_proof::IdentityProofWeb,
};
use bcr_ebill_api::{
    data::identity_proof::IdentityProofStamp, service::Error, util::ValidationError,
};

use super::Result;
use url::Url;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct IdentityProof;

#[wasm_bindgen]
impl IdentityProof {
    #[wasm_bindgen]
    pub fn new() -> Self {
        IdentityProof
    }

    #[wasm_bindgen]
    /// Get identity stamp to post on social media for the currently selected identity
    pub async fn get_identity_stamp(&self) -> Result<String> {
        let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;
        let stamp = IdentityProofStamp::new(
            &signer_public_data.node_id(),
            &signer_keys.get_private_key(),
        )?;
        Ok(stamp.to_string())
    }

    /// Fetch identity proofs for the currently selected identity
    #[wasm_bindgen(unchecked_return_type = "IdentityProofWeb[]")]
    pub async fn list(&self) -> Result<JsValue> {
        let current_identity_node_id = get_current_identity_node_id().await?;
        let identity_proofs: Vec<IdentityProofWeb> = get_ctx()
            .identity_proof_service
            .list(&current_identity_node_id)
            .await?
            .into_iter()
            .map(|ip| ip.into())
            .collect();
        let res = serde_wasm_bindgen::to_value(&identity_proofs)?;
        Ok(res)
    }

    /// Add identity proof for the currently selected identity
    #[wasm_bindgen(unchecked_return_type = "IdentityProofWeb")]
    pub async fn add(&self, url: &str, stamp: &str) -> Result<JsValue> {
        let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;
        let parsed_url =
            Url::parse(url).map_err(|_| Error::Validation(ValidationError::InvalidUrl))?;
        let parsed_stamp = IdentityProofStamp::from_str(stamp)?;
        let identity_proof: IdentityProofWeb = get_ctx()
            .identity_proof_service
            .add(
                &signer_public_data,
                &signer_keys,
                &parsed_url,
                &parsed_stamp,
            )
            .await?
            .into();
        let res = serde_wasm_bindgen::to_value(&identity_proof)?;
        Ok(res)
    }

    /// Archive the identity proof with the given id for the currently selected identity
    #[wasm_bindgen]
    pub async fn archive(&self, id: &str) -> Result<()> {
        let current_identity_node_id = get_current_identity_node_id().await?;
        get_ctx()
            .identity_proof_service
            .archive(&current_identity_node_id, id)
            .await?;
        Ok(())
    }

    /// Re-check the identity proof by its URL with the given id for the currently selected identity
    /// returning the new result
    #[wasm_bindgen(unchecked_return_type = "IdentityProofWeb")]
    pub async fn re_check(&self, id: &str) -> Result<JsValue> {
        let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;
        let identity_proof: IdentityProofWeb = get_ctx()
            .identity_proof_service
            .re_check(&signer_public_data, &signer_keys, id)
            .await?
            .into();
        let res = serde_wasm_bindgen::to_value(&identity_proof)?;
        Ok(res)
    }
}

impl Default for IdentityProof {
    fn default() -> Self {
        IdentityProof
    }
}
