use crate::{
    external::identity_proof::IdentityProofApi,
    service::notification_service::NotificationServiceApi,
};

use super::{Error, Result};
use std::sync::Arc;

use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    ServiceTraitBounds, ValidationError,
    blockchain::{
        Block,
        company::{CompanyBlock, CompanyIdentityProofBlockData},
        identity::{IdentityBlock, IdentityProofBlockData},
    },
    company::CompanyKeys,
    contact::{BillParticipant, ContactType},
    identity_proof::{IdentityProof, IdentityProofStamp, IdentityProofStatus},
    protocol::{CompanyChainEvent, IdentityChainEvent},
    timestamp::Timestamp,
    util::BcrKeys,
};
use bcr_ebill_persistence::{
    company::{CompanyChainStoreApi, CompanyStoreApi},
    identity::{IdentityChainStoreApi, IdentityStoreApi},
    identity_proof::IdentityProofStoreApi,
};
use chrono::Days;
use log::{debug, error, info, warn};
use url::Url;

const IDENTITY_PROOFS_CHECK_AFTER_DAYS: u64 = 14; // check every two weeks

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait IdentityProofServiceApi: ServiceTraitBounds {
    /// Lists all identity proofs for the given node_id
    async fn list(&self, node_id: &NodeId) -> Result<Vec<IdentityProof>>;
    /// Adds a new identity proof for the given node id and Url
    async fn add(
        &self,
        signer_public_data: &BillParticipant,
        signer_keys: &BcrKeys,
        url: &Url,
        stamp: &IdentityProofStamp,
    ) -> Result<IdentityProof>;
    /// Archives the identity proof for the given id
    async fn archive(&self, node_id: &NodeId, id: &str) -> Result<()>;
    /// Re-checks (via the URL) the identity proof for the given ID, persisting and returning the result
    async fn re_check(
        &self,
        signer_public_data: &BillParticipant,
        signer_keys: &BcrKeys,
        id: &str,
    ) -> Result<IdentityProof>;
    /// Job to re-check identity proofs which haven't been checked for a while
    async fn re_check_outdated_identity_proofs(&self) -> Result<()>;
}

/// The identity proof service is responsible for managing identity proofs for local identities
#[derive(Clone)]
pub struct IdentityProofService {
    store: Arc<dyn IdentityProofStoreApi>,
    identity_proof_client: Arc<dyn IdentityProofApi>,
    identity_blockchain_store: Arc<dyn IdentityChainStoreApi>,
    company_blockchain_store: Arc<dyn CompanyChainStoreApi>,
    notification_service: Arc<dyn NotificationServiceApi>,
    identity_store: Arc<dyn IdentityStoreApi>,
    company_store: Arc<dyn CompanyStoreApi>,
}

impl IdentityProofService {
    pub fn new(
        store: Arc<dyn IdentityProofStoreApi>,
        identity_proof_client: Arc<dyn IdentityProofApi>,
        identity_blockchain_store: Arc<dyn IdentityChainStoreApi>,
        company_blockchain_store: Arc<dyn CompanyChainStoreApi>,
        notification_service: Arc<dyn NotificationServiceApi>,
        identity_store: Arc<dyn IdentityStoreApi>,
        company_store: Arc<dyn CompanyStoreApi>,
    ) -> Self {
        Self {
            store,
            identity_proof_client,
            identity_blockchain_store,
            company_blockchain_store,
            notification_service,
            identity_store,
            company_store,
        }
    }

    async fn populate_company_block(
        &self,
        id: &NodeId,
        keys: &CompanyKeys,
        new_signatory: Option<NodeId>,
    ) -> Result<()> {
        let company = self.company_store.get(id).await?;
        let chain = self.company_blockchain_store.get_chain(id).await?;
        self.notification_service
            .send_company_chain_events(CompanyChainEvent::new(
                &company,
                &chain,
                keys,
                new_signatory,
                true,
            ))
            .await?;
        Ok(())
    }

    async fn populate_identity_block(&self, block: &IdentityBlock, keys: &BcrKeys) -> Result<()> {
        let identity = self.identity_store.get().await?;
        self.notification_service
            .send_identity_chain_events(IdentityChainEvent::new(&identity, block, keys))
            .await?;
        Ok(())
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
        signer_public_data: &BillParticipant,
        signer_keys: &BcrKeys,
        url: &Url,
        stamp: &IdentityProofStamp,
    ) -> Result<IdentityProof> {
        debug!("Adding identity proof for {}", signer_public_data.node_id());
        let now = Timestamp::now();
        let node_id = signer_public_data.node_id();
        if !stamp.verify_against_node_id(&node_id) {
            return Err(Error::Validation(ValidationError::InvalidSignature));
        }

        let signer_is_company = match signer_public_data {
            BillParticipant::Anon(_) => false, // Anon can only be personal identity
            BillParticipant::Ident(data) => matches!(data.t, ContactType::Company),
        };

        // TODO(multi-relay): don't default to first, but to default relay of receiver with this capability
        let nostr_relay = match signer_public_data.nostr_relays().first() {
            Some(r) => r.to_owned(),
            None => {
                return Err(Error::Validation(ValidationError::InvalidRelayUrl));
            }
        };
        let status = self
            .identity_proof_client
            .check_url(
                &nostr_relay,
                stamp,
                signer_keys.get_nostr_keys().secret_key(),
                url,
            )
            .await;
        let checked = Timestamp::now();

        // only add, if the check was successful
        if !matches!(status, IdentityProofStatus::Success) {
            return Err(Error::Validation(
                ValidationError::InvalidIdentityProofStatus(status.to_string()),
            ));
        }

        let block_id = if signer_is_company {
            // Add to company chain
            let identity_keys = self.identity_store.get_key_pair().await?;
            let previous_block = self
                .company_blockchain_store
                .get_latest_block(&node_id)
                .await?;
            let company_keys = CompanyKeys {
                private_key: signer_keys.get_private_key(),
                public_key: signer_keys.pub_key(),
            };
            let new_block = CompanyBlock::create_block_for_identity_proof(
                node_id.clone(),
                &previous_block,
                &CompanyIdentityProofBlockData {
                    stamp: stamp.to_owned(),
                    url: url.to_owned(),
                },
                &identity_keys,
                &company_keys,
                now,
            )?;
            self.company_blockchain_store
                .add_block(&node_id, &new_block)
                .await?;
            self.populate_company_block(&node_id, &company_keys, None)
                .await?;
            new_block.id()
        } else {
            // Add to identity chain
            let previous_block = self.identity_blockchain_store.get_latest_block().await?;
            let new_block = IdentityBlock::create_block_for_identity_proof(
                &previous_block,
                &IdentityProofBlockData {
                    stamp: stamp.to_owned(),
                    url: url.to_owned(),
                },
                signer_keys,
                now,
            )?;
            self.identity_blockchain_store.add_block(&new_block).await?;
            self.populate_identity_block(&new_block, signer_keys)
                .await?;
            new_block.id()
        };

        // Store in DB
        let identity_proof = IdentityProof {
            node_id,
            stamp: stamp.to_owned(),
            url: url.to_owned(),
            timestamp: now,
            status,
            status_last_checked_timestamp: checked,
            block_id,
        };
        debug!("Added identity proof for {}", signer_public_data.node_id());

        self.store.add(&identity_proof).await?;
        Ok(identity_proof)
    }

    async fn archive(&self, node_id: &NodeId, id: &str) -> Result<()> {
        debug!("Archiving identity proof {id}");
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

    async fn re_check(
        &self,
        signer_public_data: &BillParticipant,
        signer_keys: &BcrKeys,
        id: &str,
    ) -> Result<IdentityProof> {
        debug!("Re-checking identity proof {id}");
        match self.store.get_by_id(id).await? {
            Some(mut identity_proof) => {
                if identity_proof.node_id != signer_public_data.node_id() {
                    // does not belong to the caller - can't re-check
                    return Err(Error::NotFound);
                }

                // TODO(multi-relay): don't default to first, but to default relay of receiver with this capability
                let nostr_relay = match signer_public_data.nostr_relays().first() {
                    Some(r) => r.to_owned(),
                    None => {
                        return Err(Error::Validation(ValidationError::InvalidRelayUrl));
                    }
                };

                // re-check the status
                let status = self
                    .identity_proof_client
                    .check_url(
                        &nostr_relay,
                        &identity_proof.stamp,
                        signer_keys.get_nostr_keys().secret_key(),
                        &identity_proof.url,
                    )
                    .await;
                let checked = Timestamp::now();

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

    async fn re_check_outdated_identity_proofs(&self) -> Result<()> {
        let two_weeks_ago: Timestamp = Timestamp::now()
            .to_datetime()
            .checked_sub_days(Days::new(IDENTITY_PROOFS_CHECK_AFTER_DAYS))
            .expect("is a valid date")
            .into();
        let identity_proofs = self
            .store
            .get_with_status_last_checked_timestamp_before(two_weeks_ago)
            .await?;

        if identity_proofs.is_empty() {
            return Ok(());
        }

        let full_identity = self.identity_store.get_full().await?;
        let companies = self.company_store.get_all().await?;

        // TODO(multi-relay): don't default to first, but to default relay of receiver with this capability
        let nostr_relay = match full_identity.identity.nostr_relays.first() {
            Some(r) => r.to_owned(),
            None => {
                return Err(Error::Validation(ValidationError::InvalidRelayUrl));
            }
        };

        for identity_proof in identity_proofs.iter() {
            let node_id = &identity_proof.node_id;
            // get private key for identity proof node id
            let private_key = if &full_identity.identity.node_id == node_id {
                full_identity
                    .key_pair
                    .get_nostr_keys()
                    .secret_key()
                    .to_owned()
            } else if let Some((_company, company_keys)) = companies.get(node_id) {
                nostr::Keys::new(company_keys.private_key.into())
                    .secret_key()
                    .to_owned()
            } else {
                warn!(
                    "No local identity available for node id {} and identity proof {}",
                    &node_id,
                    &identity_proof.id()
                );
                continue;
            };
            info!("Re-checking identity proof {}", &identity_proof.id());
            // re-check the status
            let status = self
                .identity_proof_client
                .check_url(
                    &nostr_relay,
                    &identity_proof.stamp,
                    &private_key,
                    &identity_proof.url,
                )
                .await;
            let checked = Timestamp::now();

            // update the status in the DB
            if let Err(e) = self
                .store
                .update_status_by_id(&identity_proof.id(), &status, checked)
                .await
            {
                error!(
                    "Could not persist new status for identity proof {}: {e}",
                    &identity_proof.id()
                );
            }
            info!(
                "Re-checked identity proof {} - result: {}",
                &identity_proof.id(),
                status
            );
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use bcr_ebill_core::{
        block_id::BlockId,
        blockchain::{Blockchain, identity::IdentityBlockchain},
    };

    use crate::{
        external::identity_proof::MockIdentityProofApi,
        service::{
            company_service::tests::{
                get_baseline_company, get_valid_company_block, get_valid_company_chain,
            },
            notification_service::MockNotificationServiceApi,
        },
        tests::tests::{
            MockCompanyChainStoreApiMock, MockCompanyStoreApiMock, MockIdentityChainStoreApiMock,
            MockIdentityProofStore, MockIdentityStoreApiMock,
            bill_identified_participant_only_node_id, empty_identity, node_id_test,
            node_id_test_other, private_key_test,
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
            .returning(|_, _, _, _| IdentityProofStatus::Success);
        ctx.identity_blockchain_store
            .expect_add_block()
            .returning(|_| Ok(()));
        ctx.identity_blockchain_store
            .expect_get_latest_block()
            .returning(|| {
                let identity = empty_identity();
                Ok(IdentityBlockchain::new(
                    &identity.into(),
                    &BcrKeys::new(),
                    Timestamp::new(1731593928).unwrap(),
                )
                .unwrap()
                .get_latest_block()
                .clone())
            });
        ctx.identity_store
            .expect_get()
            .returning(|| Ok(empty_identity()));
        ctx.notification_service
            .expect_send_identity_chain_events()
            .returning(|_| Ok(()))
            .times(1);
        let service = get_service(ctx);

        let mut signer = bill_identified_participant_only_node_id(node_id_test());
        signer.nostr_relays = vec![url::Url::parse("ws://localhost:8080").unwrap()];

        let res = service
            .add(
                &BillParticipant::Ident(signer),
                &BcrKeys::from_private_key(&private_key_test()).unwrap(),
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
    async fn test_add_company() {
        let mut ctx = get_ctx();
        ctx.store.expect_add().returning(|_| Ok(()));
        ctx.store
            .expect_update_status_by_id()
            .returning(|_, _, _| Ok(()));
        ctx.identity_proof_client
            .expect_check_url()
            .returning(|_, _, _, _| IdentityProofStatus::Success);
        ctx.company_blockchain_store
            .expect_add_block()
            .returning(|_, _| Ok(()));
        ctx.company_blockchain_store
            .expect_get_chain()
            .returning(|_| Ok(get_valid_company_chain()))
            .once();
        ctx.company_blockchain_store
            .expect_get_latest_block()
            .returning(|_| Ok(get_valid_company_block()));
        ctx.identity_store
            .expect_get()
            .returning(|| Ok(empty_identity()));
        ctx.notification_service
            .expect_send_company_chain_events()
            .returning(|_| Ok(()))
            .times(1);
        ctx.company_store
            .expect_get()
            .returning(|_| Ok(get_baseline_company()));
        ctx.identity_store
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::from_private_key(&private_key_test()).unwrap()));
        let service = get_service(ctx);

        let mut signer = bill_identified_participant_only_node_id(node_id_test());
        signer.nostr_relays = vec![url::Url::parse("ws://localhost:8080").unwrap()];
        signer.t = ContactType::Company;

        let res = service
            .add(
                &BillParticipant::Ident(signer),
                &BcrKeys::from_private_key(&private_key_test()).unwrap(),
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
            .returning(|_, _, _, _| IdentityProofStatus::NotFound);
        let service = get_service(ctx);
        let mut signer = bill_identified_participant_only_node_id(node_id_test());
        signer.nostr_relays = vec![url::Url::parse("ws://localhost:8080").unwrap()];

        let res = service
            .add(
                &BillParticipant::Ident(signer),
                &BcrKeys::from_private_key(&private_key_test()).unwrap(),
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
                timestamp: Timestamp::new(1731593928).unwrap(),
                status: IdentityProofStatus::Success,
                status_last_checked_timestamp: Timestamp::new(1731593929).unwrap(),
                block_id: BlockId::next_from_previous_block_id(&BlockId::first()),
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
                timestamp: Timestamp::new(1731593928).unwrap(),
                status: IdentityProofStatus::Success,
                status_last_checked_timestamp: Timestamp::new(1731593929).unwrap(),
                block_id: BlockId::next_from_previous_block_id(&BlockId::first()),
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
                timestamp: Timestamp::new(1731593928).unwrap(),
                status: IdentityProofStatus::Success,
                status_last_checked_timestamp: Timestamp::new(1731593929).unwrap(),
                block_id: BlockId::next_from_previous_block_id(&BlockId::first()),
            }))
        });
        ctx.store
            .expect_update_status_by_id()
            .returning(|_, _, _| Ok(()));
        ctx.identity_proof_client
            .expect_check_url()
            .returning(|_, _, _, _| IdentityProofStatus::NotFound);
        let service = get_service(ctx);
        let mut signer = bill_identified_participant_only_node_id(node_id_test());
        signer.nostr_relays = vec![url::Url::parse("ws://localhost:8080").unwrap()];

        let res = service
            .re_check(
                &BillParticipant::Ident(signer),
                &BcrKeys::from_private_key(&private_key_test()).unwrap(),
                "some_id",
            )
            .await;
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
                timestamp: Timestamp::new(1731593928).unwrap(),
                status: IdentityProofStatus::Success,
                status_last_checked_timestamp: Timestamp::new(1731593929).unwrap(),
                block_id: BlockId::next_from_previous_block_id(&BlockId::first()),
            }))
        });
        let service = get_service(ctx);
        let mut signer = bill_identified_participant_only_node_id(node_id_test());
        signer.nostr_relays = vec![url::Url::parse("ws://localhost:8080").unwrap()];

        let res = service
            .re_check(
                &BillParticipant::Ident(signer),
                &BcrKeys::from_private_key(&private_key_test()).unwrap(),
                "some_id",
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_re_check_no_entity() {
        let mut ctx = get_ctx();
        ctx.store.expect_get_by_id().returning(|_| Ok(None));
        let service = get_service(ctx);
        let mut signer = bill_identified_participant_only_node_id(node_id_test());
        signer.nostr_relays = vec![url::Url::parse("ws://localhost:8080").unwrap()];

        let res = service
            .re_check(
                &BillParticipant::Ident(signer),
                &BcrKeys::from_private_key(&private_key_test()).unwrap(),
                "some_id",
            )
            .await;
        assert!(res.is_err());
    }

    struct MockIdentityProofContext {
        pub store: MockIdentityProofStore,
        pub identity_proof_client: MockIdentityProofApi,
        pub identity_blockchain_store: MockIdentityChainStoreApiMock,
        pub company_blockchain_store: MockCompanyChainStoreApiMock,
        pub notification_service: MockNotificationServiceApi,
        pub identity_store: MockIdentityStoreApiMock,
        pub company_store: MockCompanyStoreApiMock,
    }

    fn get_ctx() -> MockIdentityProofContext {
        MockIdentityProofContext {
            store: MockIdentityProofStore::new(),
            identity_proof_client: MockIdentityProofApi::new(),
            identity_blockchain_store: MockIdentityChainStoreApiMock::new(),
            company_blockchain_store: MockCompanyChainStoreApiMock::new(),
            notification_service: MockNotificationServiceApi::new(),
            identity_store: MockIdentityStoreApiMock::new(),
            company_store: MockCompanyStoreApiMock::new(),
        }
    }

    fn get_service(ctx: MockIdentityProofContext) -> IdentityProofService {
        IdentityProofService {
            store: Arc::new(ctx.store),
            identity_proof_client: Arc::new(ctx.identity_proof_client),
            identity_blockchain_store: Arc::new(ctx.identity_blockchain_store),
            company_blockchain_store: Arc::new(ctx.company_blockchain_store),
            notification_service: Arc::new(ctx.notification_service),
            identity_store: Arc::new(ctx.identity_store),
            company_store: Arc::new(ctx.company_store),
        }
    }
}
