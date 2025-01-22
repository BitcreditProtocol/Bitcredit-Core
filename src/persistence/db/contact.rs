use std::collections::HashMap;

use super::{FileDb, PostalAddressDb, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use surrealdb::{engine::any::Any, Surreal};

use crate::{
    persistence::ContactStoreApi,
    service::contact_service::{Contact, ContactType},
};

#[derive(Clone)]
pub struct SurrealContactStore {
    db: Surreal<Any>,
}

impl SurrealContactStore {
    const TABLE: &'static str = "contacts";

    pub fn new(db: Surreal<Any>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl ContactStoreApi for SurrealContactStore {
    async fn get_map(&self) -> Result<HashMap<String, Contact>> {
        let all: Vec<ContactDb> = self.db.select(Self::TABLE).await?;
        let mut map = HashMap::new();
        for contact in all.into_iter() {
            map.insert(contact.node_id.clone(), contact.into());
        }
        Ok(map)
    }

    async fn get(&self, node_id: &str) -> Result<Option<Contact>> {
        let result: Option<ContactDb> = self.db.select((Self::TABLE, node_id.to_owned())).await?;
        Ok(result.map(|c| c.to_owned().into()))
    }

    async fn insert(&self, node_id: &str, data: Contact) -> Result<()> {
        let entity: ContactDb = data.into();
        let _: Option<ContactDb> = self
            .db
            .create((Self::TABLE, node_id.to_owned()))
            .content(entity)
            .await?;
        Ok(())
    }

    async fn delete(&self, node_id: &str) -> Result<()> {
        let _: Option<ContactDb> = self.db.delete((Self::TABLE, node_id.to_owned())).await?;
        Ok(())
    }

    async fn update(&self, node_id: &str, data: Contact) -> Result<()> {
        let entity: ContactDb = data.into();
        let _: Option<ContactDb> = self
            .db
            .update((Self::TABLE, node_id.to_owned()))
            .content(entity)
            .await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactDb {
    #[serde(rename = "type")]
    pub t: ContactType,
    pub node_id: String,
    pub name: String,
    pub email: String,
    pub postal_address: PostalAddressDb,
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
            postal_address: contact.postal_address.into(),
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
            postal_address: contact.postal_address.into(),
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
        persistence::db::get_memory_db, tests::tests::TEST_NODE_ID_SECP, web::data::PostalAddress,
    };

    pub fn get_baseline_contact() -> Contact {
        Contact {
            t: ContactType::Person,
            node_id: TEST_NODE_ID_SECP.to_owned(),
            name: "some_name".to_string(),
            email: "some_mail@example.com".to_string(),
            postal_address: PostalAddress::new_empty(),
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
            .insert(TEST_NODE_ID_SECP, contact.clone())
            .await
            .expect("could not create contact");

        let stored = store
            .get(TEST_NODE_ID_SECP)
            .await
            .expect("could not query contact")
            .expect("could not find created contact");

        assert_eq!(&stored.name, "some_name");
        assert_eq!(&stored.node_id, TEST_NODE_ID_SECP);
    }

    #[tokio::test]
    async fn test_delete_contact() {
        let store = get_store().await;
        let contact = get_baseline_contact();
        store
            .insert(TEST_NODE_ID_SECP, contact.clone())
            .await
            .expect("could not create contact");

        let stored = store
            .get(TEST_NODE_ID_SECP)
            .await
            .expect("could not query contact")
            .expect("could not find created contact");

        assert_eq!(&stored.name, "some_name");

        store
            .delete(TEST_NODE_ID_SECP)
            .await
            .expect("could not delete contact");

        let empty = store
            .get(TEST_NODE_ID_SECP)
            .await
            .expect("could not query deleted contact");
        assert!(empty.is_none());
    }

    #[tokio::test]
    async fn test_update_contact() {
        let store = get_store().await;
        let contact = get_baseline_contact();
        store
            .insert(TEST_NODE_ID_SECP, contact.clone())
            .await
            .expect("could not create contact");

        let mut data = contact.clone();
        data.name = "other_name".to_string();
        store
            .update(TEST_NODE_ID_SECP, data)
            .await
            .expect("could not update contact");

        let updated = store
            .get(TEST_NODE_ID_SECP)
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
        contact2.node_id = "1234123124123124123412".to_string();
        contact2.name = "other_name".to_string();
        store
            .insert(TEST_NODE_ID_SECP, contact.clone())
            .await
            .expect("could not create contact");
        store
            .insert("1234123124123124123412", contact2.clone())
            .await
            .expect("could not create contact");

        let all = store.get_map().await.expect("all query failed");
        assert_eq!(all.len(), 2);
        assert!(all.contains_key(TEST_NODE_ID_SECP));
        assert!(all.contains_key("1234123124123124123412"));
        assert_eq!(
            all.get("1234123124123124123412").unwrap().name,
            "other_name"
        );
    }

    async fn get_store() -> SurrealContactStore {
        let mem_db = get_memory_db("test", "contact")
            .await
            .expect("could not create get_memory_db");
        SurrealContactStore::new(mem_db)
    }
}
