use super::{Result, surreal::Bindings};
use async_trait::async_trait;
use bcr_ebill_core::{
    ServiceTraitBounds,
    mint::{MintRequest, MintRequestStatus},
};
use serde::{Deserialize, Serialize};

use crate::{
    constants::{DB_BILL_ID, DB_MINT_NODE_ID, DB_MINT_REQUESTER_NODE_ID, DB_TABLE},
    mint::MintStoreApi,
};

use super::surreal::SurrealWrapper;

#[derive(Clone)]
pub struct SurrealMintStore {
    db: SurrealWrapper,
}

impl SurrealMintStore {
    const REQUESTS_TABLE: &'static str = "requests";

    pub fn new(db: SurrealWrapper) -> Self {
        Self { db }
    }
}

impl ServiceTraitBounds for SurrealMintStore {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl MintStoreApi for SurrealMintStore {
    async fn get_requests(
        &self,
        requester_node_id: &str,
        bill_id: &str,
        mint_node_id: &str,
    ) -> Result<Vec<MintRequest>> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::REQUESTS_TABLE)?;
        bindings.add(DB_BILL_ID, bill_id.to_owned())?;
        bindings.add(DB_MINT_NODE_ID, mint_node_id.to_owned())?;
        bindings.add(DB_MINT_REQUESTER_NODE_ID, requester_node_id.to_owned())?;
        let results: Vec<MintRequestDb> = self.db
            .query("SELECT * from type::table($table) WHERE bill_id = $bill_id AND mint_node_id = $mint_node_id AND requester_node_id = $requester_node_id", bindings).await?;
        Ok(results.into_iter().map(|c| c.into()).collect())
    }

    async fn add_request(
        &self,
        requester_node_id: &str,
        bill_id: &str,
        mint_node_id: &str,
        mint_request_id: &str,
        timestamp: u64,
    ) -> Result<()> {
        let entity = MintRequestDb {
            requester_node_id: requester_node_id.to_owned(),
            bill_id: bill_id.to_owned(),
            mint_node_id: mint_node_id.to_owned(),
            mint_request_id: mint_request_id.to_owned(),
            timestamp,
            status: MintRequestStatusDb::Pending,
        };
        let _: Option<MintRequestDb> = self.db.create(Self::REQUESTS_TABLE, None, entity).await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintRequestDb {
    pub requester_node_id: String,
    pub bill_id: String,
    pub mint_node_id: String,
    pub mint_request_id: String,
    pub timestamp: u64,
    pub status: MintRequestStatusDb,
}

impl From<MintRequestDb> for MintRequest {
    fn from(value: MintRequestDb) -> Self {
        Self {
            requester_node_id: value.requester_node_id,
            bill_id: value.bill_id,
            mint_node_id: value.mint_node_id,
            mint_request_id: value.mint_request_id,
            timestamp: value.timestamp,
            status: value.status.into(),
        }
    }
}

impl From<MintRequest> for MintRequestDb {
    fn from(value: MintRequest) -> Self {
        Self {
            requester_node_id: value.requester_node_id,
            bill_id: value.bill_id,
            mint_node_id: value.mint_node_id,
            mint_request_id: value.mint_request_id,
            timestamp: value.timestamp,
            status: value.status.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MintRequestStatusDb {
    Pending,
    Denied,
    Offered {
        keyset_id: String,
        expiration_timestamp: u64,
        discounted: u64,
    },
    Accepted {
        keyset_id: String,
    },
    Rejected {
        timestamp: u64,
    },
}

impl From<MintRequestStatusDb> for MintRequestStatus {
    fn from(value: MintRequestStatusDb) -> Self {
        match value {
            MintRequestStatusDb::Pending => MintRequestStatus::Pending,
            MintRequestStatusDb::Denied => MintRequestStatus::Denied,
            MintRequestStatusDb::Offered {
                keyset_id,
                expiration_timestamp,
                discounted,
            } => MintRequestStatus::Offered {
                keyset_id,
                expiration_timestamp,
                discounted,
            },
            MintRequestStatusDb::Accepted { keyset_id } => {
                MintRequestStatus::Accepted { keyset_id }
            }
            MintRequestStatusDb::Rejected { timestamp } => {
                MintRequestStatus::Rejected { timestamp }
            }
        }
    }
}

impl From<MintRequestStatus> for MintRequestStatusDb {
    fn from(value: MintRequestStatus) -> Self {
        match value {
            MintRequestStatus::Pending => MintRequestStatusDb::Pending,
            MintRequestStatus::Denied => MintRequestStatusDb::Denied,
            MintRequestStatus::Offered {
                keyset_id,
                expiration_timestamp,
                discounted,
            } => MintRequestStatusDb::Offered {
                keyset_id,
                expiration_timestamp,
                discounted,
            },
            MintRequestStatus::Accepted { keyset_id } => {
                MintRequestStatusDb::Accepted { keyset_id }
            }
            MintRequestStatus::Rejected { timestamp } => {
                MintRequestStatusDb::Rejected { timestamp }
            }
        }
    }
}
