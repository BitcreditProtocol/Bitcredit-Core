use super::{
    Result,
    surreal::{Bindings, SurrealWrapper},
};
use crate::{
    constants::{DB_HANDSHAKE_STATUS, DB_ID, DB_TABLE, DB_TRUST_LEVEL},
    nostr::NostrContactStoreApi,
};
use async_trait::async_trait;
use bcr_ebill_core::{
    ServiceTraitBounds,
    nostr_contact::{HandshakeStatus, NostrContact, TrustLevel},
    util::crypto::get_nostr_npub_as_hex_from_node_id,
};
use nostr::key::PublicKey;
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Clone)]
pub struct SurrealNostrContactStore {
    db: SurrealWrapper,
}

impl SurrealNostrContactStore {
    const TABLE: &'static str = "nostr_contact";

    pub fn new(db: SurrealWrapper) -> Self {
        Self { db }
    }

    fn thing_id(id: &str) -> Thing {
        Thing::from((Self::TABLE.to_owned(), id.to_owned()))
    }
}

impl ServiceTraitBounds for SurrealNostrContactStore {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NostrContactStoreApi for SurrealNostrContactStore {
    /// Find a Nostr contact by the node id. This is the primary key for the contact.
    async fn by_node_id(&self, node_id: &str) -> Result<Option<NostrContact>> {
        let result: Option<NostrContactDb> =
            self.db.select_one(Self::TABLE, node_id.to_owned()).await?;
        let value = result.map(|v| v.to_owned().into());
        Ok(value)
    }
    /// Find a Nostr contact by the npub. This is the public Nostr key of the contact.
    async fn by_npub(&self, npub: &PublicKey) -> Result<Option<NostrContact>> {
        self.by_node_id(npub.to_hex().as_str()).await
    }
    /// Creates a new or updates an existing Nostr contact.
    async fn upsert(&self, data: &NostrContact) -> Result<()> {
        let db_data: NostrContactDb = data.clone().into();
        let _: Option<NostrContactDb> = self
            .db
            .upsert(Self::TABLE, data.node_id.to_owned(), db_data)
            .await?;
        Ok(())
    }
    /// Delete an Nostr contact. This will remove the contact from the store.
    async fn delete(&self, node_id: &str) -> Result<()> {
        let _: Option<NostrContactDb> = self.db.delete(Self::TABLE, node_id.to_owned()).await?;
        Ok(())
    }
    /// Sets a new handshake status for the contact. This is used to track the handshake process.
    async fn set_handshake_status(&self, node_id: &str, status: HandshakeStatus) -> Result<()> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TABLE)?;
        bindings.add(DB_HANDSHAKE_STATUS, status)?;
        bindings.add(DB_ID, Self::thing_id(node_id))?;
        self.db
            .query_check(&update_field_query(DB_HANDSHAKE_STATUS), bindings)
            .await?;
        Ok(())
    }
    /// Sets a new trust level for the contact. This is used to track the trust level of the
    /// contact.
    async fn set_trust_level(&self, node_id: &str, trust_level: TrustLevel) -> Result<()> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TABLE)?;
        bindings.add(DB_TRUST_LEVEL, trust_level)?;
        bindings.add(DB_ID, Self::thing_id(node_id))?;
        self.db
            .query_check(&update_field_query(DB_TRUST_LEVEL), bindings)
            .await?;
        Ok(())
    }

    // returns all npubs that have a trust level higher than or equal to the given level.
    async fn get_npubs(&self, levels: Vec<TrustLevel>) -> Result<Vec<PublicKey>> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TABLE)?;
        bindings.add(DB_TRUST_LEVEL, levels)?;
        let query = format!(
            "SELECT * from type::table(${DB_TABLE}) where {DB_TRUST_LEVEL} IN ${DB_TRUST_LEVEL}"
        );
        let result: Vec<NostrContactDb> = self.db.query(&query, bindings).await?;
        let keys = result
            .into_iter()
            .filter_map(|c| get_nostr_npub_as_hex_from_node_id(c.id.id.to_raw().as_str()).ok())
            .filter_map(|npub| PublicKey::from_hex(&npub).ok())
            .collect::<Vec<PublicKey>>();
        Ok(keys)
    }
}

fn update_field_query(field_name: &str) -> String {
    format!(
        "UPDATE type::table(${DB_TABLE}) SET {field_name} = ${field_name} WHERE {DB_ID} = ${DB_ID}"
    )
}

/// Data we need to communicate with a Nostr contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrContactDb {
    /// Our node id. This is the node id and acts as the primary key.
    pub id: Thing,
    /// The Nostr name of the contact as retreived via Nostr metadata.
    pub name: Option<String>,
    /// The relays we found for this contact either from a message or the result of a relay list
    /// query.
    pub relays: Vec<String>,
    /// The trust level we assign to this contact.
    pub trust_level: TrustLevel,
    /// The handshake status with this contact.
    pub handshake_status: HandshakeStatus,
}

impl From<NostrContact> for NostrContactDb {
    fn from(contact: NostrContact) -> Self {
        Self {
            id: Thing::from((
                SurrealNostrContactStore::TABLE.to_owned(),
                contact.node_id.to_owned(),
            )),
            name: contact.name,
            relays: contact.relays,
            trust_level: contact.trust_level,
            handshake_status: contact.handshake_status,
        }
    }
}

impl From<NostrContactDb> for NostrContact {
    fn from(db: NostrContactDb) -> Self {
        Self {
            node_id: db.id.id.to_raw(),
            name: db.name,
            relays: db.relays,
            trust_level: db.trust_level,
            handshake_status: db.handshake_status,
        }
    }
}

#[cfg(test)]
mod tests {
    use bcr_ebill_core::util::BcrKeys;

    use super::*;
    use crate::db::get_memory_db;

    #[tokio::test]
    async fn test_upsert_and_retrieve_by_node_id() {
        let store = get_store().await;
        let contact = get_test_message("test_node_id");

        // Upsert the contact
        store
            .upsert(&contact)
            .await
            .expect("Failed to upsert contact");

        // Retrieve the contact by node_id
        let retrieved = store
            .by_node_id("test_node_id")
            .await
            .expect("Failed to retrieve contact")
            .expect("Contact not found");

        assert_eq!(retrieved.node_id, contact.node_id);
        assert_eq!(retrieved.name, contact.name);
        assert_eq!(retrieved.relays, contact.relays);
        assert_eq!(retrieved.trust_level, contact.trust_level);
        assert_eq!(retrieved.handshake_status, contact.handshake_status);
    }

    #[tokio::test]
    async fn test_upsert_and_retrieve_by_npub() {
        let npub = BcrKeys::new().get_nostr_keys().public_key();
        let store = get_store().await;
        let contact = get_test_message(npub.to_hex().as_str());

        // Upsert the contact
        store
            .upsert(&contact)
            .await
            .expect("Failed to upsert contact");

        // Retrieve the contact by node_id
        let retrieved = store
            .by_npub(&npub)
            .await
            .expect("Failed to retrieve contact by npub")
            .expect("Contact by npub not found");

        assert_eq!(retrieved.node_id, contact.node_id);
    }

    #[tokio::test]
    async fn test_delete_contact() {
        let store = get_store().await;
        let contact = get_test_message("test_node_id");

        // Upsert the contact
        store
            .upsert(&contact)
            .await
            .expect("Failed to upsert contact");

        // Delete the contact
        store
            .delete("test_node_id")
            .await
            .expect("Failed to delete contact");

        // Try to retrieve the contact
        let retrieved = store
            .by_node_id("test_node_id")
            .await
            .expect("Failed to retrieve contact");
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_set_handshake_status() {
        let store = get_store().await;
        let contact = get_test_message("test_node_id");

        // Upsert the contact
        store
            .upsert(&contact)
            .await
            .expect("Failed to upsert contact");

        // Update handshake status
        store
            .set_handshake_status("test_node_id", HandshakeStatus::InProgress)
            .await
            .expect("Failed to set handshake status");

        // Retrieve the contact and verify the handshake status
        let retrieved = store
            .by_node_id("test_node_id")
            .await
            .expect("Failed to retrieve contact")
            .expect("Contact not found");

        assert_eq!(retrieved.handshake_status, HandshakeStatus::InProgress);
    }

    #[tokio::test]
    async fn test_set_trust_level() {
        let store = get_store().await;
        let contact = get_test_message("test_node_id");

        // Upsert the contact
        store
            .upsert(&contact)
            .await
            .expect("Failed to upsert contact");

        // Update trust level
        store
            .set_trust_level("test_node_id", TrustLevel::Participant)
            .await
            .expect("Failed to set trust level");

        // Retrieve the contact and verify the trust level
        let retrieved = store
            .by_node_id("test_node_id")
            .await
            .expect("Failed to retrieve contact")
            .expect("Contact not found");

        assert_eq!(retrieved.trust_level, TrustLevel::Participant);
    }

    #[tokio::test]
    async fn test_get_npubs() {
        let keys = BcrKeys::new();
        let store = get_store().await;
        let npub = keys.get_public_key();
        let contact = get_test_message(&npub);

        // Upsert the contact
        store
            .upsert(&contact)
            .await
            .expect("Failed to upsert contact");

        // Update trust level
        store
            .set_trust_level(&npub, TrustLevel::Participant)
            .await
            .expect("Failed to set trust level");

        // Retrieve the contact and verify the trust level
        let retrieved = store
            .get_npubs(vec![TrustLevel::Participant])
            .await
            .expect("Failed to retrieve contact");

        assert!(!retrieved.is_empty());
    }

    async fn get_store() -> SurrealNostrContactStore {
        let mem_db = get_memory_db("test", "nostr_contact")
            .await
            .expect("could not create memory db");
        SurrealNostrContactStore::new(SurrealWrapper {
            db: mem_db,
            files: false,
        })
    }

    fn get_test_message(node_id: &str) -> NostrContact {
        NostrContact {
            node_id: node_id.to_string(),
            name: Some("contact_name".to_string()),
            relays: vec!["test_relay".to_string()],
            trust_level: TrustLevel::None,
            handshake_status: HandshakeStatus::None,
        }
    }
}
