use std::collections::HashMap;

use super::{
    FileDb, PostalAddressDb, Result,
    surreal::{Bindings, SurrealWrapper},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{
    ContactStoreApi,
    constants::{DB_SEARCH_TERM, DB_TABLE},
};
use bcr_ebill_core::{
    NodeId, ServiceTraitBounds,
    contact::{Contact, ContactType},
};

#[derive(Clone)]
pub struct SurrealContactStore {
    db: SurrealWrapper,
}

impl SurrealContactStore {
    const TABLE: &'static str = "contacts";

    pub fn new(db: SurrealWrapper) -> Self {
        Self { db }
    }
}

impl ServiceTraitBounds for SurrealContactStore {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ContactStoreApi for SurrealContactStore {
    async fn search(&self, search_term: &str) -> Result<Vec<Contact>> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TABLE)?;
        bindings.add(DB_SEARCH_TERM, search_term.to_owned())?;

        let results: Vec<ContactDb> = self.db
            .query("SELECT * from type::table($table) WHERE string::lowercase(name) CONTAINS $search_term", bindings).await?;
        Ok(results.into_iter().map(|c| c.into()).collect())
    }

    async fn get_map(&self) -> Result<HashMap<NodeId, Contact>> {
        let all: Vec<ContactDb> = self.db.select_all(Self::TABLE).await?;
        let mut map = HashMap::new();
        for contact in all.into_iter() {
            map.insert(contact.node_id.clone(), contact.into());
        }
        Ok(map)
    }

    async fn get(&self, node_id: &NodeId) -> Result<Option<Contact>> {
        let result: Option<ContactDb> =
            self.db.select_one(Self::TABLE, node_id.to_string()).await?;
        Ok(result.map(|c| c.to_owned().into()))
    }

    async fn insert(&self, node_id: &NodeId, data: Contact) -> Result<()> {
        let entity: ContactDb = data.into();
        let _: Option<ContactDb> = self
            .db
            .create(Self::TABLE, Some(node_id.to_string()), entity)
            .await?;
        Ok(())
    }

    async fn delete(&self, node_id: &NodeId) -> Result<()> {
        let _: Option<ContactDb> = self.db.delete(Self::TABLE, node_id.to_string()).await?;
        Ok(())
    }

    async fn update(&self, node_id: &NodeId, data: Contact) -> Result<()> {
        let entity: ContactDb = data.into();
        let _: Option<ContactDb> = self
            .db
            .update(Self::TABLE, node_id.to_string(), entity)
            .await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactDb {
    #[serde(rename = "type")]
    pub t: ContactType,
    pub node_id: NodeId,
    pub name: String,
    pub email: Option<String>,                   // only optional for anon,
    pub postal_address: Option<PostalAddressDb>, // only optional for anon
    pub date_of_birth_or_registration: Option<String>,
    pub country_of_birth_or_registration: Option<String>,
    pub city_of_birth_or_registration: Option<String>,
    pub identification_number: Option<String>,
    pub avatar_file: Option<FileDb>,
    pub proof_document_file: Option<FileDb>,
    pub nostr_relays: Vec<String>,
}

impl From<ContactDb> for Contact {
    fn from(contact: ContactDb) -> Self {
        Self {
            t: contact.t,
            node_id: contact.node_id,
            name: contact.name,
            email: contact.email,
            postal_address: contact.postal_address.map(|pa| pa.into()),
            date_of_birth_or_registration: contact.date_of_birth_or_registration,
            country_of_birth_or_registration: contact.country_of_birth_or_registration,
            city_of_birth_or_registration: contact.city_of_birth_or_registration,
            identification_number: contact.identification_number,
            avatar_file: contact.avatar_file.map(|f| f.into()),
            proof_document_file: contact.proof_document_file.map(|f| f.into()),
            nostr_relays: contact.nostr_relays,
        }
    }
}

impl From<Contact> for ContactDb {
    fn from(contact: Contact) -> Self {
        Self {
            t: contact.t,
            node_id: contact.node_id,
            name: contact.name,
            email: contact.email,
            postal_address: contact.postal_address.map(|pa| pa.into()),
            date_of_birth_or_registration: contact.date_of_birth_or_registration,
            country_of_birth_or_registration: contact.country_of_birth_or_registration,
            city_of_birth_or_registration: contact.city_of_birth_or_registration,
            identification_number: contact.identification_number,
            avatar_file: contact.avatar_file.map(|f| f.into()),
            proof_document_file: contact.proof_document_file.map(|f| f.into()),
            nostr_relays: contact.nostr_relays,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        db::get_memory_db,
        tests::tests::{empty_address, node_id_test, node_id_test_other},
    };

    pub fn get_baseline_contact() -> Contact {
        Contact {
            t: ContactType::Person,
            node_id: node_id_test(),
            name: "some_name".to_string(),
            email: Some("some_mail@example.com".to_string()),
            postal_address: Some(empty_address()),
            date_of_birth_or_registration: None,
            country_of_birth_or_registration: None,
            city_of_birth_or_registration: None,
            identification_number: None,
            avatar_file: None,
            proof_document_file: None,
            nostr_relays: vec![],
        }
    }

    #[tokio::test]
    async fn test_insert_contact() {
        let store = get_store().await;
        let contact = get_baseline_contact();
        store
            .insert(&node_id_test(), contact.clone())
            .await
            .expect("could not create contact");

        let stored = store
            .get(&node_id_test())
            .await
            .expect("could not query contact")
            .expect("could not find created contact");

        assert_eq!(&stored.name, "some_name");
        assert_eq!(&stored.node_id, &node_id_test());
    }

    #[tokio::test]
    async fn test_delete_contact() {
        let store = get_store().await;
        let contact = get_baseline_contact();
        store
            .insert(&node_id_test(), contact.clone())
            .await
            .expect("could not create contact");

        let stored = store
            .get(&node_id_test())
            .await
            .expect("could not query contact")
            .expect("could not find created contact");

        assert_eq!(&stored.name, "some_name");

        store
            .delete(&node_id_test())
            .await
            .expect("could not delete contact");

        let empty = store
            .get(&node_id_test())
            .await
            .expect("could not query deleted contact");
        assert!(empty.is_none());
    }

    #[tokio::test]
    async fn test_update_contact() {
        let store = get_store().await;
        let contact = get_baseline_contact();
        store
            .insert(&node_id_test(), contact.clone())
            .await
            .expect("could not create contact");

        let mut data = contact.clone();
        data.name = "other_name".to_string();
        store
            .update(&node_id_test(), data)
            .await
            .expect("could not update contact");

        let updated = store
            .get(&node_id_test())
            .await
            .expect("could not query contact")
            .expect("could not find created contact");

        assert_eq!(&updated.name, "other_name");
    }

    #[tokio::test]
    async fn test_get_map() {
        let store = get_store().await;
        let contact = get_baseline_contact();
        let mut contact2 = get_baseline_contact();
        contact2.node_id = node_id_test_other();
        contact2.name = "other_name".to_string();
        store
            .insert(&node_id_test(), contact.clone())
            .await
            .expect("could not create contact");
        store
            .insert(&contact2.node_id, contact2.clone())
            .await
            .expect("could not create contact");

        let all = store.get_map().await.expect("all query failed");
        assert_eq!(all.len(), 2);
        assert!(all.contains_key(&node_id_test()));
        assert!(all.contains_key(&contact2.node_id));
        assert_eq!(all.get(&contact2.node_id).unwrap().name, "other_name");
    }

    async fn get_store() -> SurrealContactStore {
        let mem_db = get_memory_db("test", "contact")
            .await
            .expect("could not create get_memory_db");
        SurrealContactStore::new(SurrealWrapper {
            db: mem_db,
            files: false,
        })
    }
}
