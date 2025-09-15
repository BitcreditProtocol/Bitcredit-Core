use crate::{external::identity_proof::IdentityProofApi, util};

use super::{Error, Result};
use std::sync::Arc;

use async_trait::async_trait;
use bcr_ebill_core::{
    NodeId, ServiceTraitBounds, ValidationError,
    identity_proof::{IdentityProof, IdentityProofStamp, IdentityProofStatus},
};
use bcr_ebill_persistence::identity_proof::IdentityProofStoreApi;
use url::Url;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait IdentityProofServiceApi: ServiceTraitBounds {
    /// Lists all identity proofs for the given node_id
    async fn list(&self, node_id: &NodeId) -> Result<Vec<IdentityProof>>;
    /// Adds a new identity proof for the given node id and Url
    async fn add(
        &self,
        node_id: &NodeId,
        url: &Url,
        stamp: &IdentityProofStamp,
    ) -> Result<IdentityProof>;
    /// Archives the identity proof for the given id
    async fn archive(&self, node_id: &NodeId, id: &str) -> Result<()>;
    /// Re-checks (via the URL) the identity proof for the given ID, persisting and returning the result
    async fn re_check(&self, node_id: &NodeId, id: &str) -> Result<IdentityProof>;
}

/// The identity proof service is responsible for managing identity proofs for local identities
#[derive(Clone)]
pub struct IdentityProofService {
    store: Arc<dyn IdentityProofStoreApi>,
    identity_proof_client: Arc<dyn IdentityProofApi>,
}

impl IdentityProofService {
    pub fn new(
        store: Arc<dyn IdentityProofStoreApi>,
        identity_proof_client: Arc<dyn IdentityProofApi>,
    ) -> Self {
        Self {
            store,
            identity_proof_client,
        }
    }
}

impl ServiceTraitBounds for IdentityProofService {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl IdentityProofServiceApi for IdentityProofService {
    async fn list(&self, node_id: &NodeId) -> Result<Vec<IdentityProof>> {
        let identity_proofs = self.store.list_by_node_id(node_id).await?;
        Ok(identity_proofs)
    }

    async fn add(
        &self,
        node_id: &NodeId,
        url: &Url,
        stamp: &IdentityProofStamp,
    ) -> Result<IdentityProof> {
        let now = util::date::now().timestamp() as u64;
        if !stamp.verify_against_node_id(node_id) {
            return Err(Error::Validation(ValidationError::InvalidSignature));
        }
        let status = self.identity_proof_client.check_url(stamp, url).await;
        let checked = util::date::now().timestamp() as u64;

        // only add, if the check was successful
        if !matches!(status, IdentityProofStatus::Success) {
            return Err(Error::Validation(
                ValidationError::InvalidIdentityProofStatus(status.to_string()),
            ));
        }

        let identity_proof = IdentityProof {
            node_id: node_id.to_owned(),
            stamp: stamp.to_owned(),
            url: url.to_owned(),
            timestamp: now,
            status,
            status_last_checked_timestamp: checked,
        };

        self.store.add(&identity_proof).await?;
        Ok(identity_proof)
    }

    async fn archive(&self, node_id: &NodeId, id: &str) -> Result<()> {
        match self.store.get_by_id(id).await? {
            Some(identity_proof) => {
                if &identity_proof.node_id != node_id {
                    // does not belong to the caller - can't archive
                    return Err(Error::NotFound);
                }
                self.store.archive(id).await?;
                Ok(())
            }
            None => {
                return Err(Error::NotFound);
            }
        }
    }

    async fn re_check(&self, node_id: &NodeId, id: &str) -> Result<IdentityProof> {
        match self.store.get_by_id(id).await? {
            Some(mut identity_proof) => {
                if &identity_proof.node_id != node_id {
                    // does not belong to the caller - can't re-check
                    return Err(Error::NotFound);
                }
                // re-check the status
                let status = self
                    .identity_proof_client
                    .check_url(&identity_proof.stamp, &identity_proof.url)
                    .await;
                let checked = util::date::now().timestamp() as u64;

                // update the status in the DB
                self.store.update_status_by_id(id, &status, checked).await?;

                // return the updated status
                identity_proof.status = status;
                identity_proof.status_last_checked_timestamp = checked;
                Ok(identity_proof)
            }
            None => {
                return Err(Error::NotFound);
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{
        external::identity_proof::MockIdentityProofApi,
        tests::tests::{
            MockIdentityProofStore, node_id_test, node_id_test_other, private_key_test,
        },
    };

    use super::*;

    #[tokio::test]
    async fn test_add() {
        let mut ctx = get_ctx();
        ctx.store.expect_add().returning(|_| Ok(()));
        ctx.store
            .expect_update_status_by_id()
            .returning(|_, _, _| Ok(()));
        ctx.identity_proof_client
            .expect_check_url()
            .returning(|_, _| IdentityProofStatus::Success);
        let service = get_service(ctx);

        let res = service
            .add(
                &node_id_test(),
                &Url::parse("https://bit.cr/").expect("valid url"),
                &IdentityProofStamp::new(&node_id_test(), &private_key_test()).unwrap(),
            )
            .await;
        assert!(res.is_ok());
        assert!(matches!(
            res.as_ref().unwrap().status,
            IdentityProofStatus::Success
        ));
    }

    #[tokio::test]
    async fn test_add_not_success() {
        let mut ctx = get_ctx();
        ctx.store.expect_add().returning(|_| Ok(())).never();
        ctx.store
            .expect_update_status_by_id()
            .returning(|_, _, _| Ok(()));
        ctx.identity_proof_client
            .expect_check_url()
            .returning(|_, _| IdentityProofStatus::NotFound);
        let service = get_service(ctx);

        let res = service
            .add(
                &node_id_test(),
                &Url::parse("https://bit.cr/").expect("valid url"),
                &IdentityProofStamp::new(&node_id_test(), &private_key_test()).unwrap(),
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_list() {
        let mut ctx = get_ctx();
        ctx.store.expect_list_by_node_id().returning(|_| Ok(vec![]));
        let service = get_service(ctx);

        let res = service.list(&node_id_test()).await.expect("can do list");
        assert_eq!(res.len(), 0);
    }

    #[tokio::test]
    async fn test_archive() {
        let mut ctx = get_ctx();
        ctx.store.expect_archive().returning(|_| Ok(()));
        ctx.store.expect_get_by_id().returning(|_| {
            Ok(Some(IdentityProof {
                node_id: node_id_test(),
                stamp: IdentityProofStamp::new(&node_id_test(), &private_key_test()).unwrap(),
                url: Url::parse("https://bit.cr/").expect("valid url"),
                timestamp: 1731593928,
                status: IdentityProofStatus::Success,
                status_last_checked_timestamp: 1731593929,
            }))
        });
        let service = get_service(ctx);

        let res = service.archive(&node_id_test(), "some_id").await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_archive_wrong_node_id() {
        let mut ctx = get_ctx();
        ctx.store.expect_get_by_id().returning(|_| {
            Ok(Some(IdentityProof {
                node_id: node_id_test_other(),
                stamp: IdentityProofStamp::new(&node_id_test(), &private_key_test()).unwrap(),
                url: Url::parse("https://bit.cr/").expect("valid url"),
                timestamp: 1731593928,
                status: IdentityProofStatus::Success,
                status_last_checked_timestamp: 1731593929,
            }))
        });
        let service = get_service(ctx);

        let res = service.archive(&node_id_test(), "some_id").await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_archive_no_entity() {
        let mut ctx = get_ctx();
        ctx.store.expect_get_by_id().returning(|_| Ok(None));
        let service = get_service(ctx);

        let res = service.archive(&node_id_test(), "some_id").await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_re_check() {
        let mut ctx = get_ctx();
        ctx.store.expect_get_by_id().returning(|_| {
            Ok(Some(IdentityProof {
                node_id: node_id_test(),
                stamp: IdentityProofStamp::new(&node_id_test(), &private_key_test()).unwrap(),
                url: Url::parse("https://bit.cr/").expect("valid url"),
                timestamp: 1731593928,
                status: IdentityProofStatus::Success,
                status_last_checked_timestamp: 1731593929,
            }))
        });
        ctx.store
            .expect_update_status_by_id()
            .returning(|_, _, _| Ok(()));
        ctx.identity_proof_client
            .expect_check_url()
            .returning(|_, _| IdentityProofStatus::NotFound);
        let service = get_service(ctx);

        let res = service.re_check(&node_id_test(), "some_id").await;
        assert!(res.is_ok());
        assert!(matches!(
            res.as_ref().unwrap().status,
            IdentityProofStatus::NotFound
        ));
    }

    #[tokio::test]
    async fn test_re_check_wrong_node_id() {
        let mut ctx = get_ctx();
        ctx.store.expect_get_by_id().returning(|_| {
            Ok(Some(IdentityProof {
                node_id: node_id_test_other(),
                stamp: IdentityProofStamp::new(&node_id_test(), &private_key_test()).unwrap(),
                url: Url::parse("https://bit.cr/").expect("valid url"),
                timestamp: 1731593928,
                status: IdentityProofStatus::Success,
                status_last_checked_timestamp: 1731593929,
            }))
        });
        let service = get_service(ctx);

        let res = service.re_check(&node_id_test(), "some_id").await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_re_check_no_entity() {
        let mut ctx = get_ctx();
        ctx.store.expect_get_by_id().returning(|_| Ok(None));
        let service = get_service(ctx);

        let res = service.re_check(&node_id_test(), "some_id").await;
        assert!(res.is_err());
    }

    struct MockIdentityProofContext {
        pub store: MockIdentityProofStore,
        pub identity_proof_client: MockIdentityProofApi,
    }

    fn get_ctx() -> MockIdentityProofContext {
        MockIdentityProofContext {
            store: MockIdentityProofStore::new(),
            identity_proof_client: MockIdentityProofApi::new(),
        }
    }

    fn get_service(ctx: MockIdentityProofContext) -> IdentityProofService {
        IdentityProofService {
            store: Arc::new(ctx.store),
            identity_proof_client: Arc::new(ctx.identity_proof_client),
        }
    }
}
