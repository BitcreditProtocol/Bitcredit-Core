use super::{
    Result,
    surreal::{Bindings, SurrealWrapper},
};
use crate::{
    constants::{DB_NODE_ID, DB_TABLE},
    util::date::{self, DateTimeUtc},
};
use async_trait::async_trait;
use bcr_ebill_core::ServiceTraitBounds;
use serde::{Deserialize, Serialize};

use crate::{NostrEventOffset, NostrEventOffsetStoreApi};

#[derive(Clone)]
pub struct SurrealNostrEventOffsetStore {
    db: SurrealWrapper,
}

impl SurrealNostrEventOffsetStore {
    const TABLE: &'static str = "nostr_event_offset";

    pub fn new(db: SurrealWrapper) -> Self {
        Self { db }
    }
}

impl ServiceTraitBounds for SurrealNostrEventOffsetStore {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NostrEventOffsetStoreApi for SurrealNostrEventOffsetStore {
    async fn current_offset(&self, node_id: &str) -> Result<u64> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TABLE)?;
        bindings.add(DB_NODE_ID, node_id.to_owned())?;
        let result: Vec<NostrEventOffsetDb> = self
            .db
            .query(&format!("SELECT * FROM type::table($table) where {DB_NODE_ID} = $node_id ORDER BY time DESC LIMIT 1"), bindings)
            .await?;
        let value = result
            .first()
            .map(|c| c.time.timestamp())
            .unwrap_or(0)
            .try_into()?;
        Ok(value)
    }

    async fn is_processed(&self, event_id: &str) -> Result<bool> {
        let result: Option<NostrEventOffsetDb> =
            self.db.select_one(Self::TABLE, event_id.to_owned()).await?;
        Ok(result.is_some())
    }

    async fn add_event(&self, data: NostrEventOffset) -> Result<()> {
        let db: NostrEventOffsetDb = data.into();
        let _: Option<NostrEventOffsetDb> = self
            .db
            .create(Self::TABLE, Some(db.event_id.to_owned()), db)
            .await?;
        Ok(())
    }
}

/// A nostr event offset.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct NostrEventOffsetDb {
    pub event_id: String,
    pub time: DateTimeUtc,
    pub success: bool,
    pub node_id: String,
}

impl From<NostrEventOffsetDb> for NostrEventOffset {
    fn from(db: NostrEventOffsetDb) -> Self {
        Self {
            event_id: db.event_id,
            time: db.time.timestamp() as u64,
            success: db.success,
            node_id: db.node_id,
        }
    }
}

impl From<NostrEventOffset> for NostrEventOffsetDb {
    fn from(offset: NostrEventOffset) -> Self {
        Self {
            event_id: offset.event_id,
            time: date::seconds(offset.time),
            success: offset.success,
            node_id: offset.node_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::get_memory_db;

    #[tokio::test]
    async fn test_get_offset_from_empty_table() {
        let store = get_store().await;
        let offset = store
            .current_offset("node_id")
            .await
            .expect("could not get offset");
        assert_eq!(offset, 0);
    }

    #[tokio::test]
    async fn test_add_event() {
        let store = get_store().await;
        let data = NostrEventOffset {
            event_id: "test_event".to_string(),
            time: 1000,
            success: true,
            node_id: "node_id".to_string(),
        };
        store
            .add_event(data)
            .await
            .expect("Could not add event offset");

        let offset = store
            .current_offset("node_id")
            .await
            .expect("could not get offset");
        assert_eq!(offset, 1000);
    }

    #[tokio::test]
    async fn test_is_processed() {
        let store = get_store().await;
        let data = NostrEventOffset {
            event_id: "test_event".to_string(),
            time: 1000,
            success: false,
            node_id: "node_id".to_string(),
        };
        let is_known = store
            .is_processed(&data.event_id)
            .await
            .expect("could not check if processed");
        assert!(!is_known, "new event should not be known");

        store
            .add_event(data.clone())
            .await
            .expect("could not add event offset");
        let is_processed = store
            .is_processed(&data.event_id)
            .await
            .expect("could not check if processed");
        assert!(is_processed, "existing event should be known");
    }

    async fn get_store() -> SurrealNostrEventOffsetStore {
        let mem_db = get_memory_db("test", "nostr_event_offset")
            .await
            .expect("could not create memory db");
        SurrealNostrEventOffsetStore::new(SurrealWrapper {
            db: mem_db,
            files: false,
        })
    }
}
