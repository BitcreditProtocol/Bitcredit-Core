use super::{BillIdDb, Result, surreal::Bindings};
use async_trait::async_trait;
use bcr_ebill_core::{
    ServiceTraitBounds,
    mint::{MintOffer, MintRequest, MintRequestStatus},
};
use serde::{Deserialize, Serialize};

use crate::{
    Error,
    constants::{
        DB_BILL_ID, DB_MINT_NODE_ID, DB_MINT_REQUEST_ID, DB_MINT_REQUESTER_NODE_ID, DB_PROOFS,
        DB_STATUS, DB_STATUS_ACCEPTED, DB_STATUS_OFFERED, DB_STATUS_PENDING, DB_TABLE,
    },
    mint::MintStoreApi,
};

use super::surreal::SurrealWrapper;

#[derive(Clone)]
pub struct SurrealMintStore {
    db: SurrealWrapper,
}

impl SurrealMintStore {
    const REQUESTS_TABLE: &'static str = "requests";
    const OFFERS_TABLE: &'static str = "offers";

    pub fn new(db: SurrealWrapper) -> Self {
        Self { db }
    }
}

impl ServiceTraitBounds for SurrealMintStore {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl MintStoreApi for SurrealMintStore {
    async fn exists_for_bill(&self, requester_node_id: &str, bill_id: &str) -> Result<bool> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::REQUESTS_TABLE)?;
        bindings.add(DB_BILL_ID, bill_id.to_owned())?;
        bindings.add(DB_MINT_REQUESTER_NODE_ID, requester_node_id.to_owned())?;
        match self
            .db
            .query::<Option<BillIdDb>>(
                "SELECT bill_id FROM type::table($table) WHERE bill_id = $bill_id GROUP BY bill_id",
                bindings,
            )
            .await
        {
            Ok(res) => {
                if res.is_empty() {
                    // not found
                    Ok(false)
                } else {
                    // found - check keys
                    Ok(true)
                }
            }
            Err(e) => {
                log::error!(
                    "Error checking if there are mint requests for bill {bill_id} exists: {e}"
                );
                Ok(false)
            }
        }
    }

    async fn get_all_active_requests(&self) -> Result<Vec<MintRequest>> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::REQUESTS_TABLE)?;
        bindings.add(DB_STATUS_OFFERED, MintRequestStatusDb::Offered)?;
        bindings.add(DB_STATUS_PENDING, MintRequestStatusDb::Pending)?;
        bindings.add(DB_STATUS_ACCEPTED, MintRequestStatusDb::Accepted)?;
        let results: Vec<MintRequestDb> = self.db
            .query("SELECT * from type::table($table) WHERE status = $status_offered OR status = $status_pending OR status = $status_accepted", bindings).await?;
        Ok(results.into_iter().map(|c| c.into()).collect())
    }

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

    async fn get_requests_for_bill(
        &self,
        requester_node_id: &str,
        bill_id: &str,
    ) -> Result<Vec<MintRequest>> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::REQUESTS_TABLE)?;
        bindings.add(DB_BILL_ID, bill_id.to_owned())?;
        bindings.add(DB_MINT_REQUESTER_NODE_ID, requester_node_id.to_owned())?;
        let results: Vec<MintRequestDb> = self.db
            .query("SELECT * from type::table($table) WHERE bill_id = $bill_id AND requester_node_id = $requester_node_id", bindings).await?;
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

    async fn get_request(&self, mint_request_id: &str) -> Result<Option<MintRequest>> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::REQUESTS_TABLE)?;
        bindings.add(DB_MINT_REQUEST_ID, mint_request_id.to_owned())?;
        let results: Vec<MintRequestDb> = self
            .db
            .query(
                "SELECT * from type::table($table) WHERE mint_request_id = $mint_request_id",
                bindings,
            )
            .await?;
        Ok(results.first().map(|r| r.clone().into()))
    }

    async fn update_request(
        &self,
        mint_request_id: &str,
        new_status: &MintRequestStatus,
    ) -> Result<()> {
        let mut bindings = Bindings::default();
        let status: MintRequestStatusDb = new_status.clone().into();
        bindings.add(DB_TABLE, Self::REQUESTS_TABLE)?;
        bindings.add(DB_MINT_REQUEST_ID, mint_request_id.to_owned())?;
        bindings.add(DB_STATUS, status)?;
        self.db
            .query_check("UPDATE type::table($table) SET status = $status WHERE mint_request_id = $mint_request_id", bindings)
            .await?;
        Ok(())
    }

    async fn add_proofs_to_offer(&self, mint_request_id: &str, proofs: &str) -> Result<()> {
        // we only add proofs, if there is an offer and it has no proofs yet
        if let Ok(Some(offer)) = self.get_offer(mint_request_id).await {
            if offer.proofs.is_some() {
                return Err(Error::MintOfferAlreadyExists);
            }
        } else {
            return Err(Error::MintOfferDoesNotExist);
        }
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::OFFERS_TABLE)?;
        bindings.add(DB_MINT_REQUEST_ID, mint_request_id.to_owned())?;
        bindings.add(DB_PROOFS, Some(proofs.to_owned()))?;
        self.db
            .query_check("UPDATE type::table($table) SET proofs = $proofs WHERE mint_request_id = $mint_request_id", bindings)
            .await?;
        Ok(())
    }

    async fn add_offer(
        &self,
        mint_request_id: &str,
        keyset_id: &str,
        expiration_timestamp: u64,
        discounted_sum: u64,
    ) -> Result<()> {
        // we only add an offer, if there isn't already an offer for this request
        if let Ok(Some(_)) = self.get_offer(mint_request_id).await {
            return Err(Error::MintOfferAlreadyExists);
        }
        let entity = MintOfferDb {
            mint_request_id: mint_request_id.to_owned(),
            keyset_id: keyset_id.to_owned(),
            expiration_timestamp,
            discounted_sum,
            proofs: None,
        };
        let _: Option<MintOfferDb> = self.db.create(Self::OFFERS_TABLE, None, entity).await?;
        Ok(())
    }

    async fn get_offer(&self, mint_request_id: &str) -> Result<Option<MintOffer>> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::OFFERS_TABLE)?;
        bindings.add(DB_MINT_REQUEST_ID, mint_request_id.to_owned())?;
        let results: Vec<MintOfferDb> = self
            .db
            .query(
                "SELECT * from type::table($table) WHERE mint_request_id = $mint_request_id",
                bindings,
            )
            .await?;
        Ok(results.first().map(|r| r.clone().into()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintOfferDb {
    pub mint_request_id: String,
    pub keyset_id: String,
    pub expiration_timestamp: u64,
    pub discounted_sum: u64,
    pub proofs: Option<String>,
}

impl From<MintOfferDb> for MintOffer {
    fn from(value: MintOfferDb) -> Self {
        Self {
            mint_request_id: value.mint_request_id,
            keyset_id: value.keyset_id,
            expiration_timestamp: value.expiration_timestamp,
            discounted_sum: value.discounted_sum,
            proofs: value.proofs,
        }
    }
}

impl From<MintOffer> for MintOfferDb {
    fn from(value: MintOffer) -> Self {
        Self {
            mint_request_id: value.mint_request_id,
            keyset_id: value.keyset_id,
            expiration_timestamp: value.expiration_timestamp,
            discounted_sum: value.discounted_sum,
            proofs: value.proofs,
        }
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
    Denied { timestamp: u64 },
    Offered,
    Accepted,
    Rejected { timestamp: u64 },
    Cancelled { timestamp: u64 },
    Expired { timestamp: u64 },
}

impl From<MintRequestStatusDb> for MintRequestStatus {
    fn from(value: MintRequestStatusDb) -> Self {
        match value {
            MintRequestStatusDb::Pending => MintRequestStatus::Pending,
            MintRequestStatusDb::Denied { timestamp } => MintRequestStatus::Denied { timestamp },
            MintRequestStatusDb::Offered => MintRequestStatus::Offered,
            MintRequestStatusDb::Accepted => MintRequestStatus::Accepted,
            MintRequestStatusDb::Rejected { timestamp } => {
                MintRequestStatus::Rejected { timestamp }
            }
            MintRequestStatusDb::Cancelled { timestamp } => {
                MintRequestStatus::Cancelled { timestamp }
            }
            MintRequestStatusDb::Expired { timestamp } => MintRequestStatus::Expired { timestamp },
        }
    }
}

impl From<MintRequestStatus> for MintRequestStatusDb {
    fn from(value: MintRequestStatus) -> Self {
        match value {
            MintRequestStatus::Pending => MintRequestStatusDb::Pending,
            MintRequestStatus::Denied { timestamp } => MintRequestStatusDb::Denied { timestamp },
            MintRequestStatus::Offered => MintRequestStatusDb::Offered,
            MintRequestStatus::Accepted => MintRequestStatusDb::Accepted,
            MintRequestStatus::Rejected { timestamp } => {
                MintRequestStatusDb::Rejected { timestamp }
            }
            MintRequestStatus::Cancelled { timestamp } => {
                MintRequestStatusDb::Cancelled { timestamp }
            }
            MintRequestStatus::Expired { timestamp } => MintRequestStatusDb::Expired { timestamp },
        }
    }
}
