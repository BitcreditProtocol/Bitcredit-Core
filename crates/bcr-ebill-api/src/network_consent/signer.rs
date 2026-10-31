//! Selects the key for directory and consent statements: the personal key, or a company key
//! only for an identity-proven, authorized signatory of the selected company. Keys stay in Core.
use super::DirectorySubjectType;
use crate::service::{
    Error, Result, company_service::CompanyServiceApi, identity_service::IdentityServiceApi,
};
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    application::{company::Company, identity::ActiveIdentityState},
    protocol::{ProtocolValidationError, crypto::BcrKeys},
};

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait SigningIdentitySource: Send + Sync {
    async fn selected(&self) -> Result<ActiveIdentityState>;
    async fn personal(&self) -> Result<(NodeId, BcrKeys)>;
    async fn company(&self, id: &NodeId) -> Result<(Company, BcrKeys)>;
}

/// The selected identity and its keys from the local identity and company services.
pub struct LocalSigningIdentity<'a> {
    pub identity_service: &'a dyn IdentityServiceApi,
    pub company_service: &'a dyn CompanyServiceApi,
}

#[async_trait]
impl SigningIdentitySource for LocalSigningIdentity<'_> {
    async fn selected(&self) -> Result<ActiveIdentityState> {
        self.identity_service.get_current_identity().await
    }
    async fn personal(&self) -> Result<(NodeId, BcrKeys)> {
        let identity = self.identity_service.get_full_identity().await?;
        Ok((identity.identity.node_id, identity.key_pair))
    }
    async fn company(&self, id: &NodeId) -> Result<(Company, BcrKeys)> {
        self.company_service.get_company_and_keys_by_id(id).await
    }
}

/// The device operator's personal key, which must be the selected personal identity.
pub async fn get_personal_signer(
    source: &impl SigningIdentitySource,
) -> Result<(ActiveIdentityState, NodeId, BcrKeys)> {
    let selected = source.selected().await?;
    let (personal, keys) = source.personal().await?;
    if personal != selected.personal || keys.pub_key() != personal.pub_key() {
        return Err(Error::Validation(
            ProtocolValidationError::CallerMustBeSignatory.into(),
        ));
    }
    Ok((selected, personal, keys))
}

/// The selected identity's own key: the personal key, or a company key only for a signatory.
pub async fn get_current_signer_with_type(
    source: &impl SigningIdentitySource,
) -> Result<(NodeId, BcrKeys, DirectorySubjectType)> {
    let (selected, personal, keys) = get_personal_signer(source).await?;
    match selected.company {
        None => Ok((personal, keys, DirectorySubjectType::SoleTrader)),
        Some(company_id) => {
            let (company, keys) = source.company(&company_id).await?;
            if company.id != company_id
                || keys.pub_key() != company.id.pub_key()
                || !company.is_authorized_signer(&personal)
            {
                return Err(Error::Validation(
                    ProtocolValidationError::NotASignatory(personal.to_string()).into(),
                ));
            }
            Ok((company.id, keys, DirectorySubjectType::Company))
        }
    }
}

/// The selected identity's own key without its directory subject type.
pub async fn get_current_signer_node_id_and_keys(
    source: &impl SigningIdentitySource,
) -> Result<(NodeId, BcrKeys)> {
    let (signer, keys, _) = get_current_signer_with_type(source).await?;
    Ok((signer, keys))
}

#[cfg(test)]
#[path = "signer_tests.rs"]
mod tests;
