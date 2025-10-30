use super::{
    Result,
    surreal::{Bindings, SurrealWrapper},
};
use crate::{
    constants::DB_TABLE,
    nostr::{NostrChainEvent, NostrChainEventStoreApi},
};
use async_trait::async_trait;
use bcr_ebill_core::{
    ServiceTraitBounds, blockchain::BlockchainType, hash::Sha256Hash, timestamp::Timestamp,
};
use nostr::event::Event;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct SurrealNostrChainEventStore {
    #[allow(dead_code)]
    db: SurrealWrapper,
}
//
// columns
const CHAIN_ID: &str = "chain_id";
const CHAIN_TYPE: &str = "chain_type";
const BLOCK_HASH: &str = "block_hash";
const BLOCK_HEIGHT: &str = "block_height";
const ROOT_ID: &str = "root_id";
const EVENT_ID: &str = "event_id";
const VALID: &str = "valid";

impl SurrealNostrChainEventStore {
    const TABLE: &'static str = "nostr_chain_event";

    #[allow(dead_code)]
    pub fn new(db: SurrealWrapper) -> Self {
        Self { db }
    }

    async fn find_all_valid_chain_events(
        &self,
        chain_id: String,
        chain_type: BlockchainType,
    ) -> Result<Vec<NostrChainEventDb>> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TABLE)?;
        bindings.add(CHAIN_ID, chain_id.to_owned())?;
        bindings.add(CHAIN_TYPE, chain_type)?;

        let result: Vec<NostrChainEventDb> = self.db
                .query(format!(
                    "SELECT * FROM type::table(${DB_TABLE}) WHERE {CHAIN_ID} = ${CHAIN_ID} AND {CHAIN_TYPE} = ${CHAIN_TYPE} AND {VALID} = true ORDER BY {BLOCK_HEIGHT} DESC"
                ).as_str(), bindings)
                .await?;
        Ok(result)
    }
}

impl ServiceTraitBounds for SurrealNostrChainEventStore {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NostrChainEventStoreApi for SurrealNostrChainEventStore {
    /// Finds all chain events for the given chain id and type. This will return all valid
    /// events we ever received for a chain id.
    async fn find_chain_events(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> Result<Vec<NostrChainEvent>> {
        let result: Vec<NostrChainEventDb> = self
            .find_all_valid_chain_events(chain_id.to_owned(), chain_type)
            .await?;
        Ok(result.into_iter().map(Into::into).collect())
    }

    /// Finds the latest chain events for the given chain id and type. This can be considered the
    /// tip of the current chain state on Nostr. Latest means the blocks with the highest block
    /// height. In split chain scenarios this can return more than one event.
    async fn find_latest_block_events(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> Result<Vec<NostrChainEvent>> {
        let result: Vec<NostrChainEventDb> = self
            .find_all_valid_chain_events(chain_id.to_owned(), chain_type)
            .await?;
        // Find the highest block_height
        let max_height = result.first().map(|e| e.block_height);
        let latest: Vec<NostrChainEventDb> = match max_height {
            Some(height) => result
                .into_iter()
                .filter(|e| e.block_height == height)
                .collect(),
            None => vec![],
        };
        Ok(latest.into_iter().map(Into::into).collect())
    }

    /// Finds a message with a specific block hash as extracted from the chain payload.
    async fn find_by_block_hash(&self, hash: &Sha256Hash) -> Result<Option<NostrChainEvent>> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TABLE)?;
        bindings.add(BLOCK_HASH, hash.to_owned())?;

        let result: Vec<NostrChainEventDb> = self
            .db
            .query(
                format!(
                    "SELECT * FROM type::table(${DB_TABLE}) WHERE {BLOCK_HASH} = ${BLOCK_HASH}"
                )
                .as_str(),
                bindings,
            )
            .await?;

        let value = result.first().map(|v| v.to_owned().into());
        Ok(value)
    }

    /// Adds a new chain event to the store.
    async fn add_chain_event(&self, event: NostrChainEvent) -> Result<()> {
        let db_data: NostrChainEventDb = event.clone().into();
        let _: Option<NostrChainEventDb> = self
            .db
            .upsert(Self::TABLE, event.event_id.to_owned(), db_data)
            .await?;
        Ok(())
    }

    /// Finds an event by a specific Nostr event_id
    async fn by_event_id(&self, event_id: &str) -> Result<Option<NostrChainEvent>> {
        let event_id = event_id.to_owned();
        let result: Option<NostrChainEventDb> = self.db.select_one(Self::TABLE, event_id).await?;
        Ok(result.map(|r| r.into()))
    }

    /// Finds the root (genesis) event for a given chain
    async fn find_root_event(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
    ) -> Result<Option<NostrChainEvent>> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TABLE)?;
        bindings.add(CHAIN_ID, chain_id.to_owned())?;
        bindings.add(CHAIN_TYPE, chain_type)?;

        let result: Vec<NostrChainEventDb> = self.db
                .query(format!(
                    "SELECT * FROM type::table(${DB_TABLE}) WHERE {CHAIN_ID} = ${CHAIN_ID} AND {CHAIN_TYPE} = ${CHAIN_TYPE} AND {EVENT_ID} = {ROOT_ID} AND {VALID} = true"
                ).as_str(), bindings)
                .await?;
        Ok(result.first().map(|r| r.to_owned().into()))
    }
}

/// Data we need to communicate with a Nostr contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrChainEventDb {
    /// The nostr event id of this event.
    pub event_id: String,
    /// The event id that started the thread.
    pub root_id: String,
    /// The event id this event was appended to.
    pub reply_id: Option<String>,
    /// The npub of the sender of this event.
    pub author: String,
    /// The BCR id of the blockchain.
    pub chain_id: String,
    /// The type of the blockchain.
    pub chain_type: BlockchainType,
    /// The block height of the block contained in this event.
    pub block_height: usize,
    /// The hash of the block contained in this event.
    pub block_hash: Sha256Hash,
    /// The timestamp when we received the event.
    pub received: Timestamp,
    /// The timestamp of the event.
    pub time: Timestamp,
    /// The event as we received it via nostr.
    pub payload: Event,
    /// We consider this event as part of the valid chain
    pub valid: bool,
}

impl From<NostrChainEvent> for NostrChainEventDb {
    fn from(event: NostrChainEvent) -> Self {
        Self {
            event_id: event.event_id,
            root_id: event.root_id,
            reply_id: event.reply_id,
            author: event.author,
            chain_id: event.chain_id,
            chain_type: event.chain_type,
            block_height: event.block_height,
            block_hash: event.block_hash,
            received: event.received,
            time: event.time,
            payload: event.payload,
            valid: event.valid,
        }
    }
}

impl From<NostrChainEventDb> for NostrChainEvent {
    fn from(db: NostrChainEventDb) -> Self {
        Self {
            event_id: db.event_id,
            root_id: db.root_id,
            reply_id: db.reply_id,
            author: db.author,
            chain_id: db.chain_id,
            chain_type: db.chain_type,
            block_height: db.block_height,
            block_hash: db.block_hash,
            received: db.received,
            time: db.time,
            payload: db.payload,
            valid: db.valid,
        }
    }
}

#[cfg(test)]
mod tests {
    use bcr_ebill_core::{timestamp::Timestamp, util::BcrKeys};
    use nostr::event::EventBuilder;

    use super::*;
    use crate::db::get_memory_db;

    #[tokio::test]
    async fn test_add_event() {
        let store = get_store("add_event").await;
        let event = get_root_event();
        let res = store.add_chain_event(event.clone()).await;
        assert!(res.is_ok());

        let stored = store
            .by_event_id(&event.event_id)
            .await
            .expect("could not query event by id");
        assert!(stored.is_some());
    }

    #[tokio::test]
    async fn test_event_by_hash() {
        let store = get_store("event_by_hash").await;
        let root = get_root_event();
        let child = get_child_event("child_id", 2, &Sha256Hash::new("child_hash"), &root, None);
        store
            .add_chain_event(root)
            .await
            .expect("root event creation failed");
        store
            .add_chain_event(child)
            .await
            .expect("child event creation failed");
        let by_hash = store
            .find_by_block_hash(&Sha256Hash::new("child_hash"))
            .await
            .expect("could not find by hash");
        assert!(
            by_hash.is_some(),
            "Expected item by hash to return something"
        );
        assert_eq!(by_hash.unwrap().event_id, "child_id");
    }

    #[tokio::test]
    async fn test_find_root_event() {
        let store = get_store("find_root_event").await;
        let root = get_root_event();
        let child = get_child_event("child_id", 2, &Sha256Hash::new("child_hash"), &root, None);
        store
            .add_chain_event(root)
            .await
            .expect("root event creation failed");
        store
            .add_chain_event(child)
            .await
            .expect("child event creation failed");

        let root_result = store
            .find_root_event("chain_id", BlockchainType::Bill)
            .await
            .expect("could not find root event");

        assert!(
            root_result.is_some(),
            "Expected find root event to return something"
        );
        assert_eq!(root_result.unwrap().event_id, "root_event_id");
    }

    #[tokio::test]
    async fn test_find_latest_block_events() {
        let store = get_store("find_latest_block_events").await;
        let root = get_root_event();
        let child = get_child_event(
            "child_event",
            2,
            &Sha256Hash::new("child_hash"),
            &root,
            None,
        );
        let target1 = get_child_event(
            "child_event_a",
            3,
            &Sha256Hash::new("child_hash_a"),
            &root,
            Some(&child),
        );
        let target2 = get_child_event(
            "child_event_b",
            3,
            &Sha256Hash::new("child_hash_b"),
            &root,
            Some(&child),
        );
        store
            .add_chain_event(root)
            .await
            .expect("root event creation failed");
        store
            .add_chain_event(child)
            .await
            .expect("child event creation failed");
        store
            .add_chain_event(target1)
            .await
            .expect("target event creation failed");

        let latest = store
            .find_latest_block_events("chain_id", BlockchainType::Bill)
            .await
            .expect("could not find latest block events");
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].event_id, "child_event_a");

        store
            .add_chain_event(target2)
            .await
            .expect("target event creation failed");

        let latest = store
            .find_latest_block_events("chain_id", BlockchainType::Bill)
            .await
            .expect("could not find latest block events");
        assert_eq!(latest.len(), 2);
    }

    #[tokio::test]
    async fn test_find_all_events() {
        let store = get_store("find_all_events").await;
        let root = get_root_event();
        let child = get_child_event(
            "child_event",
            2,
            &Sha256Hash::new("child_hash"),
            &root,
            None,
        );
        let target1 = get_child_event(
            "child_event_a",
            3,
            &Sha256Hash::new("child_hash_a"),
            &root,
            Some(&child),
        );
        let target2 = get_child_event(
            "child_event_b",
            3,
            &Sha256Hash::new("child_hash_b"),
            &root,
            Some(&child),
        );
        let mut invalid = get_child_event(
            "child_event_c",
            3,
            &Sha256Hash::new("child_hash_c"),
            &root,
            Some(&child),
        );
        invalid.valid = false;

        store
            .add_chain_event(root)
            .await
            .expect("root event creation failed");
        store
            .add_chain_event(child)
            .await
            .expect("child event creation failed");
        store
            .add_chain_event(target1)
            .await
            .expect("target event creation failed");
        store
            .add_chain_event(target2)
            .await
            .expect("target event creation failed");

        store
            .add_chain_event(invalid)
            .await
            .expect("failed to add invalid event");

        let all = store
            .find_chain_events("chain_id", BlockchainType::Bill)
            .await
            .expect("could not find all events");

        // result should not include invalid event
        assert_eq!(all.len(), 4);
    }
    async fn get_store(db: &str) -> SurrealNostrChainEventStore {
        let mem_db = get_memory_db("test", db)
            .await
            .expect("could not create memory db");
        SurrealNostrChainEventStore::new(SurrealWrapper {
            db: mem_db,
            files: false,
        })
    }

    fn get_root_event() -> NostrChainEvent {
        get_test_chain_event(
            "root_event_id",
            "root_event_id",
            None,
            1,
            &Sha256Hash::new("root_hash"),
        )
    }

    fn get_child_event(
        id: &str,
        height: usize,
        hash: &Sha256Hash,
        root: &NostrChainEvent,
        parent: Option<&NostrChainEvent>,
    ) -> NostrChainEvent {
        get_test_chain_event(
            id,
            &root.event_id,
            parent.map(|p| p.event_id.to_owned()),
            height,
            hash,
        )
    }

    fn get_test_chain_event(
        event_id: &str,
        root_id: &str,
        reply_id: Option<String>,
        block_height: usize,
        block_hash: &Sha256Hash,
    ) -> NostrChainEvent {
        NostrChainEvent {
            event_id: event_id.to_string(),
            root_id: root_id.to_string(),
            reply_id,
            author: "author".to_string(),
            chain_id: "chain_id".to_string(),
            chain_type: BlockchainType::Bill,
            block_height,
            block_hash: block_hash.to_owned(),
            received: Timestamp::now(),
            time: Timestamp::now(),
            payload: get_test_event(),
            valid: true,
        }
    }

    fn get_test_event() -> Event {
        let keys = BcrKeys::new().get_nostr_keys();
        EventBuilder::text_note("content")
            .build(keys.public_key)
            .sign_with_keys(&keys)
            .expect("could not create nostr test event")
    }
}
