use super::{
    FileDb, PostalAddressDb, Result,
    surreal::{Bindings, SurrealWrapper},
};
use crate::constants::{DB_SEARCH_TERM, DB_TABLE};
use async_trait::async_trait;
use bcr_ebill_core::{
    application::ServiceTraitBounds, application::company::Company, protocol::City,
    protocol::Country, protocol::Date, protocol::Email, protocol::Identification, protocol::Name,
    protocol::SecretKey, protocol::crypto::BcrKeys,
};

use crate::{Error, company::CompanyStoreApi};
use bcr_common::core::NodeId;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, str::FromStr};
use surrealdb::sql::Thing;

#[derive(Clone)]
pub struct SurrealCompanyStore {
    db: SurrealWrapper,
}

impl SurrealCompanyStore {
    const DATA_TABLE: &'static str = "company";
    const KEYS_TABLE: &'static str = "company_keys";

    pub fn new(db: SurrealWrapper) -> Self {
        Self { db }
    }
}

impl ServiceTraitBounds for SurrealCompanyStore {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl CompanyStoreApi for SurrealCompanyStore {
    async fn search(&self, search_term: &str) -> Result<Vec<Company>> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::DATA_TABLE)?;
        bindings.add(DB_SEARCH_TERM, search_term.to_owned())?;
        let results: Vec<CompanyDb> = self.db
            .query("SELECT * from type::table($table) WHERE string::lowercase(name) CONTAINS $search_term AND active != false", bindings).await?;
        results.into_iter().map(|c| c.try_into()).collect()
    }

    async fn exists(&self, id: &NodeId) -> bool {
        self.get(id).await.map(|_| true).unwrap_or(false)
            && self.get_key_pair(id).await.map(|_| true).unwrap_or(false)
    }

    async fn get(&self, id: &NodeId) -> Result<Company> {
        let result: Option<CompanyDb> =
            self.db.select_one(Self::DATA_TABLE, id.to_string()).await?;
        match result {
            None => Err(Error::NoSuchEntity("company".to_string(), id.to_string())),
            Some(c) => Ok(c.try_into()?),
        }
    }

    async fn get_all(&self) -> Result<HashMap<NodeId, (Company, BcrKeys)>> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::DATA_TABLE)?;
        let companies: Vec<CompanyDb> = self
            .db
            .query(
                "SELECT * from type::table($table) WHERE active != false",
                bindings,
            )
            .await?;
        let company_keys: Vec<KeyDb> = self.db.select_all(Self::KEYS_TABLE).await?;
        let companies_map: HashMap<NodeId, CompanyDb> = companies
            .into_iter()
            .map(|company| {
                let id =
                    NodeId::from_str(&company.id.id.to_raw()).map_err(|_| Error::EncodingError)?;
                Ok((id, company))
            })
            .collect::<Result<_>>()?;
        let companies_keys_map: HashMap<NodeId, KeyDb> = company_keys
            .into_iter()
            .filter_map(|keys| {
                keys.id.clone().map(|id| {
                    let id = NodeId::from_str(&id.id.to_raw()).map_err(|_| Error::EncodingError)?;
                    Ok((id, keys))
                })
            })
            .collect::<Result<_>>()?;
        let combined: Result<HashMap<NodeId, (Company, BcrKeys)>> = companies_map
            .into_iter()
            .filter_map(|(id, company)| {
                companies_keys_map.get(&id).map(|keys| {
                    company
                        .try_into()
                        .map(|mapped_company| (id, (mapped_company, keys.clone().into())))
                })
            })
            .collect();
        combined
    }

    async fn insert(&self, data: &Company) -> Result<()> {
        let id = data.id.to_owned();
        let entity: CompanyDb = data.into();
        let _: Option<CompanyDb> = self
            .db
            .create(Self::DATA_TABLE, Some(id.to_string()), entity)
            .await?;
        Ok(())
    }

    async fn update(&self, id: &NodeId, data: &Company) -> Result<()> {
        let entity: CompanyDb = data.into();
        let _: Option<CompanyDb> = self
            .db
            .update(Self::DATA_TABLE, id.to_string(), entity)
            .await?;
        Ok(())
    }

    async fn remove(&self, id: &NodeId) -> Result<()> {
        let _: Option<CompanyDb> = self.db.delete(Self::DATA_TABLE, id.to_string()).await?;
        let _: Option<KeyDb> = self.db.delete(Self::KEYS_TABLE, id.to_string()).await?;
        Ok(())
    }

    async fn save_key_pair(&self, id: &NodeId, key_pair: &BcrKeys) -> Result<()> {
        let entity: KeyDb = key_pair.into();
        let _: Option<KeyDb> = self
            .db
            .create(Self::KEYS_TABLE, Some(id.to_string()), entity)
            .await?;
        Ok(())
    }

    async fn get_key_pair(&self, id: &NodeId) -> Result<BcrKeys> {
        let result: Option<KeyDb> = self.db.select_one(Self::KEYS_TABLE, id.to_string()).await?;
        match result {
            None => Err(Error::NoSuchEntity("company".to_string(), id.to_string())),
            Some(c) => Ok(c.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyDb {
    pub id: Thing,
    pub name: Name,
    pub country_of_registration: Option<Country>,
    pub city_of_registration: Option<City>,
    pub postal_address: PostalAddressDb,
    pub email: Email,
    pub registration_number: Option<Identification>,
    pub registration_date: Option<Date>,
    pub proof_of_registration_file: Option<FileDb>,
    pub logo_file: Option<FileDb>,
    pub signatories: Vec<NodeId>,
    #[serde(default = "active_default")]
    pub active: bool,
}

// needed to default existing companies to active
fn active_default() -> bool {
    true
}

impl TryFrom<CompanyDb> for Company {
    type Error = Error;
    fn try_from(value: CompanyDb) -> Result<Company> {
        Ok(Self {
            id: NodeId::from_str(&value.id.id.to_raw()).map_err(|_| Error::EncodingError)?,
            name: value.name,
            country_of_registration: value.country_of_registration,
            city_of_registration: value.city_of_registration,
            postal_address: value.postal_address.into(),
            email: value.email,
            registration_number: value.registration_number,
            registration_date: value.registration_date,
            proof_of_registration_file: value.proof_of_registration_file.map(|f| f.into()),
            logo_file: value.logo_file.map(|f| f.into()),
            signatories: value.signatories,
            active: value.active,
        })
    }
}

impl From<&Company> for CompanyDb {
    fn from(value: &Company) -> Self {
        Self {
            id: (
                SurrealCompanyStore::DATA_TABLE.to_owned(),
                value.id.to_string(),
            )
                .into(),
            name: value.name.clone(),
            country_of_registration: value.country_of_registration.clone(),
            city_of_registration: value.city_of_registration.clone(),
            postal_address: PostalAddressDb::from(&value.postal_address),
            email: value.email.clone(),
            registration_number: value.registration_number.clone(),
            registration_date: value.registration_date.clone(),
            proof_of_registration_file: value
                .proof_of_registration_file
                .clone()
                .map(|f| (&f).into()),
            logo_file: value.logo_file.clone().map(|f| (&f).into()),
            signatories: value.signatories.clone(),
            active: value.active,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDb {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Thing>,
    pub private_key: SecretKey,
}
impl From<KeyDb> for BcrKeys {
    fn from(value: KeyDb) -> Self {
        BcrKeys::from_private_key(&value.private_key)
    }
}
impl From<&BcrKeys> for KeyDb {
    fn from(value: &BcrKeys) -> Self {
        Self {
            id: None,
            private_key: value.get_private_key(),
        }
    }
}

#[cfg(test)]
mod tests {
    use bcr_ebill_core::protocol::Country;

    use super::*;
    use crate::{
        db::get_memory_db,
        tests::tests::{empty_address, node_id_test, node_id_test_other, private_key_test},
    };

    async fn get_store() -> SurrealCompanyStore {
        let mem_db = get_memory_db("test", "company")
            .await
            .expect("could not create memory db");
        SurrealCompanyStore::new(SurrealWrapper {
            db: mem_db,
            files: false,
        })
    }

    fn get_baseline_company() -> Company {
        Company {
            id: node_id_test(),
            name: Name::new("some_name").unwrap(),
            country_of_registration: Some(Country::AT),
            city_of_registration: Some(City::new("Vienna").unwrap()),
            postal_address: empty_address(),
            email: Email::new("company@example.com").unwrap(),
            registration_number: Some(Identification::new("some_number").unwrap()),
            registration_date: Some(Date::new("2012-01-01").unwrap()),
            proof_of_registration_file: None,
            logo_file: None,
            signatories: vec![node_id_test()],
            active: true,
        }
    }

    #[tokio::test]
    async fn test_exists() {
        let store = get_store().await;
        assert!(!store.exists(&node_id_test()).await);
        store.insert(&get_baseline_company()).await.unwrap();
        assert!(!store.exists(&node_id_test()).await);
        store
            .save_key_pair(
                &node_id_test(),
                &BcrKeys::from_private_key(&private_key_test()),
            )
            .await
            .unwrap();
        assert!(store.exists(&node_id_test()).await)
    }

    #[tokio::test]
    async fn test_get() {
        let store = get_store().await;
        store.insert(&get_baseline_company()).await.unwrap();
        let company = store.get(&node_id_test()).await.unwrap();
        assert_eq!(company.name, Name::new("some_name").unwrap());
    }

    #[tokio::test]
    async fn test_remove() {
        let store = get_store().await;
        store.insert(&get_baseline_company()).await.unwrap();
        store
            .save_key_pair(
                &node_id_test(),
                &BcrKeys::from_private_key(&private_key_test()),
            )
            .await
            .unwrap();
        assert!(store.exists(&node_id_test()).await);
        store.remove(&node_id_test()).await.unwrap();
        assert!(!store.exists(&node_id_test()).await);
    }

    #[tokio::test]
    async fn test_get_key_pair() {
        let store = get_store().await;
        store
            .save_key_pair(
                &node_id_test(),
                &BcrKeys::from_private_key(&private_key_test()),
            )
            .await
            .unwrap();
        let company_keys = store.get_key_pair(&node_id_test()).await.unwrap();
        assert_eq!(company_keys.pub_key(), node_id_test().pub_key());
    }

    #[tokio::test]
    async fn test_update() {
        let store = get_store().await;
        store.insert(&get_baseline_company()).await.unwrap();
        let mut company = store.get(&node_id_test()).await.unwrap();
        company.name = Name::new("some other company").unwrap();
        store.update(&node_id_test(), &company).await.unwrap();
        let changed_company = store.get(&node_id_test()).await.unwrap();
        assert_eq!(
            changed_company.name,
            Name::new("some other company").unwrap()
        );
    }

    #[tokio::test]
    async fn test_get_all() {
        let store = get_store().await;
        let mut company = get_baseline_company();
        company.name = Name::new("first").unwrap();
        store.insert(&company).await.unwrap();
        store
            .save_key_pair(
                &node_id_test(),
                &BcrKeys::from_private_key(&private_key_test()),
            )
            .await
            .unwrap();
        let mut company2 = get_baseline_company();
        company2.id = node_id_test_other();
        store.insert(&company2).await.unwrap();
        store
            .save_key_pair(
                &company2.id,
                &BcrKeys::from_private_key(&private_key_test()),
            )
            .await
            .unwrap();
        let companies = store.get_all().await.unwrap();
        assert_eq!(companies.len(), 2);
        assert_eq!(
            companies.get(&node_id_test()).as_ref().unwrap().0.name,
            Name::new("first").unwrap()
        );
        assert_eq!(
            companies.get(&node_id_test()).as_ref().unwrap().1.pub_key(),
            node_id_test().pub_key()
        );
        assert_eq!(
            companies.get(&company2.id).as_ref().unwrap().0.name,
            Name::new("some_name").unwrap()
        );
        assert_eq!(
            companies.get(&company2.id).as_ref().unwrap().1.pub_key(),
            node_id_test().pub_key()
        );
    }

    #[tokio::test]
    async fn test_get_all_and_search_only_return_active_companies() {
        let store = get_store().await;
        let mut company = get_baseline_company();
        company.name = Name::new("first company").unwrap();
        store.insert(&company).await.unwrap();
        store
            .save_key_pair(
                &node_id_test(),
                &BcrKeys::from_private_key(&private_key_test()),
            )
            .await
            .unwrap();
        let mut company2 = get_baseline_company();
        company2.id = node_id_test_other();
        company2.name = Name::new("second company").unwrap();
        company2.active = false;

        store.insert(&company2).await.unwrap();
        store
            .save_key_pair(
                &company2.id,
                &BcrKeys::from_private_key(&private_key_test()),
            )
            .await
            .unwrap();
        let companies = store.get_all().await.unwrap();
        assert_eq!(companies.len(), 1);
        assert_eq!(
            companies.get(&node_id_test()).as_ref().unwrap().0.name,
            Name::new("first company").unwrap()
        );
        let search_results = store.search("company").await.unwrap();
        assert_eq!(search_results.len(), 1);
        assert_eq!(
            search_results.first().unwrap().name,
            Name::new("first company").unwrap()
        );
    }
}
