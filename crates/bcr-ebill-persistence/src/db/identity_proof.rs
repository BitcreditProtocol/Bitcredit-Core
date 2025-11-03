use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    ServiceTraitBounds,
    block_id::BlockId,
    identity_proof::{IdentityProof, IdentityProofStamp, IdentityProofStatus},
    timestamp::Timestamp,
};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;
use url::Url;

use crate::{
    Result,
    constants::{DB_ID, DB_NODE_ID, DB_STATUS, DB_STATUS_LAST_CHECKED_TIMESTAMP, DB_TABLE},
    db::surreal::{Bindings, SurrealWrapper},
    identity_proof::IdentityProofStoreApi,
};

#[derive(Clone)]
pub struct SurrealIdentityProofStore {
    db: SurrealWrapper,
}

impl SurrealIdentityProofStore {
    const IDENTITY_PROOF_TABLE: &'static str = "identity_proof";

    pub fn new(db: SurrealWrapper) -> Self {
        Self { db }
    }
}

impl ServiceTraitBounds for SurrealIdentityProofStore {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl IdentityProofStoreApi for SurrealIdentityProofStore {
    async fn list_by_node_id(&self, node_id: &NodeId) -> Result<Vec<IdentityProof>> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::IDENTITY_PROOF_TABLE)?;
        bindings.add(DB_NODE_ID, node_id.to_owned())?;

        let identity_proofs: Vec<IdentityProofDb> = self
            .db
            .query(
                "SELECT * from type::table($table) WHERE archived = false AND node_id = $node_id",
                bindings,
            )
            .await?;
        Ok(identity_proofs.into_iter().map(|ip| ip.into()).collect())
    }

    async fn add(&self, identity_proof: &IdentityProof) -> Result<()> {
        let entity: IdentityProofDb = identity_proof.into();
        let _: Option<IdentityProofDb> = self
            .db
            .create(Self::IDENTITY_PROOF_TABLE, None, entity)
            .await?;
        Ok(())
    }

    async fn archive(&self, id: &str) -> Result<()> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::IDENTITY_PROOF_TABLE)?;
        let db_id: Thing = (Self::IDENTITY_PROOF_TABLE.to_owned(), id.to_owned()).into();
        bindings.add(DB_ID, db_id)?;

        self.db
            .query_check(
                "UPDATE type::table($table) SET archived = true WHERE id = $id",
                bindings,
            )
            .await?;
        Ok(())
    }

    async fn archive_by_node_id(&self, node_id: &NodeId) -> Result<()> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::IDENTITY_PROOF_TABLE)?;
        bindings.add(DB_NODE_ID, node_id.to_owned())?;

        self.db
            .query_check(
                "UPDATE type::table($table) SET archived = true WHERE node_id = $node_id",
                bindings,
            )
            .await?;
        Ok(())
    }

    async fn get_by_id(&self, id: &str) -> Result<Option<IdentityProof>> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::IDENTITY_PROOF_TABLE)?;
        let db_id: Thing = (Self::IDENTITY_PROOF_TABLE.to_owned(), id.to_owned()).into();
        bindings.add(DB_ID, db_id)?;

        let result: Vec<IdentityProofDb> = self
            .db
            .query(
                "SELECT * from type::table($table) WHERE archived = false AND id = $id",
                bindings,
            )
            .await?;
        Ok(result.first().map(|r| r.to_owned().into()))
    }

    async fn update_status_by_id(
        &self,
        id: &str,
        status: &IdentityProofStatus,
        status_last_checked_timestamp: Timestamp,
    ) -> Result<()> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::IDENTITY_PROOF_TABLE)?;
        let db_id: Thing = (Self::IDENTITY_PROOF_TABLE.to_owned(), id.to_owned()).into();
        bindings.add(DB_ID, db_id)?;
        let db_status: IdentityProofStatusDb = status.to_owned().into();
        bindings.add(DB_STATUS, db_status)?;
        bindings.add(
            DB_STATUS_LAST_CHECKED_TIMESTAMP,
            status_last_checked_timestamp.inner(),
        )?;

        self.db
            .query_check(
                "UPDATE type::table($table) SET status = $status, status_last_checked_timestamp = $status_last_checked_timestamp WHERE id = $id AND archived = false",
                bindings,
            )
            .await?;
        Ok(())
    }

    async fn get_with_status_last_checked_timestamp_before(
        &self,
        before_timestamp: Timestamp,
    ) -> Result<Vec<IdentityProof>> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::IDENTITY_PROOF_TABLE)?;
        bindings.add(DB_STATUS_LAST_CHECKED_TIMESTAMP, before_timestamp.inner())?;

        let result: Vec<IdentityProofDb> = self
            .db
            .query(
                "SELECT * from type::table($table) WHERE status_last_checked_timestamp < $status_last_checked_timestamp AND archived = false",
                bindings,
            )
            .await?;
        Ok(result.iter().map(|r| r.to_owned().into()).collect())
    }
}

/// An identity proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProofDb {
    pub id: Thing,
    pub node_id: NodeId,
    pub stamp: IdentityProofStamp,
    pub url: Url,
    pub timestamp: Timestamp,
    pub status: IdentityProofStatusDb,
    pub status_last_checked_timestamp: Timestamp,
    pub block_id: BlockId,
    pub archived: bool,
}

impl From<&IdentityProof> for IdentityProofDb {
    fn from(value: &IdentityProof) -> Self {
        Self {
            id: (
                SurrealIdentityProofStore::IDENTITY_PROOF_TABLE.to_owned(),
                value.id(),
            )
                .into(),
            node_id: value.node_id.to_owned(),
            stamp: value.stamp.to_owned(),
            url: value.url.to_owned(),
            timestamp: value.timestamp,
            status: value.status.clone().into(),
            status_last_checked_timestamp: value.status_last_checked_timestamp,
            block_id: value.block_id,
            archived: false,
        }
    }
}

impl From<IdentityProofDb> for IdentityProof {
    fn from(value: IdentityProofDb) -> Self {
        Self {
            node_id: value.node_id,
            stamp: value.stamp,
            url: value.url,
            timestamp: value.timestamp,
            status: value.status.into(),
            status_last_checked_timestamp: value.status_last_checked_timestamp,
            block_id: value.block_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IdentityProofStatusDb {
    Success,
    NotFound,
    FailureConnect,
    FailureClient,
    FailureServer,
}

impl From<IdentityProofStatus> for IdentityProofStatusDb {
    fn from(value: IdentityProofStatus) -> Self {
        match value {
            IdentityProofStatus::Success => IdentityProofStatusDb::Success,
            IdentityProofStatus::NotFound => IdentityProofStatusDb::NotFound,
            IdentityProofStatus::FailureConnect => IdentityProofStatusDb::FailureConnect,
            IdentityProofStatus::FailureClient => IdentityProofStatusDb::FailureClient,
            IdentityProofStatus::FailureServer => IdentityProofStatusDb::FailureServer,
        }
    }
}

impl From<IdentityProofStatusDb> for IdentityProofStatus {
    fn from(value: IdentityProofStatusDb) -> Self {
        match value {
            IdentityProofStatusDb::Success => IdentityProofStatus::Success,
            IdentityProofStatusDb::NotFound => IdentityProofStatus::NotFound,
            IdentityProofStatusDb::FailureConnect => IdentityProofStatus::FailureConnect,
            IdentityProofStatusDb::FailureClient => IdentityProofStatus::FailureClient,
            IdentityProofStatusDb::FailureServer => IdentityProofStatus::FailureServer,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        db::get_memory_db,
        tests::tests::{node_id_test, private_key_test},
    };

    use super::*;

    #[tokio::test]
    async fn test_add_archive_get_list() {
        let store = get_store().await;
        let identity_proof = IdentityProof {
            node_id: node_id_test(),
            stamp: IdentityProofStamp::new(&node_id_test(), &private_key_test())
                .expect("valid stamp"),
            url: Url::parse("https://bit.cr/").expect("valid url"),
            timestamp: Timestamp::new(1731593928).unwrap(),
            status: IdentityProofStatus::Success,
            status_last_checked_timestamp: Timestamp::new(1731593929).unwrap(),
            block_id: BlockId::next_from_previous_block_id(&BlockId::first()),
        };

        // add it
        store.add(&identity_proof).await.expect("adding works");
        let id = identity_proof.id();
        // get it
        let gotten = store.get_by_id(&id).await.expect("can execute get");
        assert!(gotten.is_some());
        assert_eq!(gotten.as_ref().unwrap().id(), id);
        assert_eq!(gotten.as_ref().unwrap().node_id, identity_proof.node_id);
        assert!(matches!(
            gotten.as_ref().unwrap().status,
            IdentityProofStatus::Success
        ));

        // update status
        store
            .update_status_by_id(
                &id,
                &IdentityProofStatus::NotFound,
                Timestamp::new(1731593930).unwrap(),
            )
            .await
            .expect("updating works");
        let gotten_edited = store.get_by_id(&id).await.expect("can execute get");
        assert!(gotten_edited.is_some());
        assert!(matches!(
            gotten_edited.as_ref().unwrap().status,
            IdentityProofStatus::NotFound
        ));
        assert_eq!(
            gotten_edited
                .as_ref()
                .unwrap()
                .status_last_checked_timestamp,
            Timestamp::new(1731593930).unwrap()
        );

        // get list
        let identity_proofs = store
            .list_by_node_id(&node_id_test())
            .await
            .expect("list works");
        assert_eq!(identity_proofs.len(), 1);

        // archive it
        store.archive(&id).await.expect("can archive");

        // get list again, should be empty
        let identity_proofs_archive = store
            .list_by_node_id(&node_id_test())
            .await
            .expect("list works");
        assert_eq!(identity_proofs_archive.len(), 0);

        // get it again - it's not there
        let gotten_archived = store.get_by_id(&id).await.expect("can execute get");
        assert!(gotten_archived.is_none());
    }

    async fn get_store() -> SurrealIdentityProofStore {
        let mem_db = get_memory_db("test", "identity_proof")
            .await
            .expect("could not create memory db");
        SurrealIdentityProofStore::new(SurrealWrapper {
            db: mem_db,
            files: false,
        })
    }
}
