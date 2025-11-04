use std::str::FromStr;

use super::{FileDb, OptionalPostalAddressDb, Result, surreal::SurrealWrapper};
use crate::{Error, identity::IdentityStoreApi, util::BcrKeys};
use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    SecretKey, ServiceTraitBounds,
    city::City,
    country::Country,
    date::Date,
    email::Email,
    identification::Identification,
    identity::{ActiveIdentityState, Identity, IdentityType, IdentityWithAll},
    name::Name,
};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct SurrealIdentityStore {
    db: SurrealWrapper,
}

impl SurrealIdentityStore {
    const IDENTITY_TABLE: &'static str = "identity";
    const ACTIVE_IDENTITY_TABLE: &'static str = "active_identity";
    const KEY_TABLE: &'static str = "identity_key";
    const NETWORK_TABLE: &'static str = "identity_network";
    const UNIQUE_ID: &'static str = "unique_record";

    pub fn new(db: SurrealWrapper) -> Self {
        Self { db }
    }
}

impl SurrealIdentityStore {
    async fn get_db_keys(&self) -> Result<Option<KeyDb>> {
        self.db
            .select_one(Self::KEY_TABLE, Self::UNIQUE_ID.to_owned())
            .await
    }

    async fn get_db_network(&self) -> Result<Option<bitcoin::Network>> {
        let result: Option<NetworkDb> = self
            .db
            .select_one(Self::NETWORK_TABLE, Self::UNIQUE_ID.to_owned())
            .await?;
        Ok(result.map(|nw| nw.network))
    }
}

impl ServiceTraitBounds for SurrealIdentityStore {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl IdentityStoreApi for SurrealIdentityStore {
    async fn exists(&self) -> bool {
        self.get().await.map(|_| true).unwrap_or(false)
    }

    async fn save(&self, identity: &Identity) -> Result<()> {
        let entity: IdentityDb = identity.into();
        let _: Option<IdentityDb> = self
            .db
            .upsert(Self::IDENTITY_TABLE, Self::UNIQUE_ID.to_owned(), entity)
            .await?;
        Ok(())
    }

    async fn get(&self) -> Result<Identity> {
        let result: Option<IdentityDb> = self
            .db
            .select_one(Self::IDENTITY_TABLE, Self::UNIQUE_ID.to_owned())
            .await?;
        match result {
            None => Err(Error::NoSuchEntity("identity".to_string(), "".to_string())),
            Some(i) => Ok(i.into()),
        }
    }

    async fn get_full(&self) -> Result<IdentityWithAll> {
        Ok(IdentityWithAll {
            identity: self.get().await?,
            key_pair: self.get_key_pair().await?,
        })
    }

    async fn save_key_pair(&self, key_pair: &BcrKeys, seed: &str) -> Result<()> {
        let entity: KeyDb = KeyDb::from_generated_keys(key_pair, seed);
        let _: Option<KeyDb> = self
            .db
            .upsert(Self::KEY_TABLE, Self::UNIQUE_ID.to_owned(), entity)
            .await?;
        Ok(())
    }

    async fn get_key_pair(&self) -> Result<BcrKeys> {
        let result: Option<KeyDb> = self.get_db_keys().await?;
        match result {
            None => Err(Error::NoSuchEntity(
                "identity key pair".to_string(),
                "".to_string(),
            )),
            Some(value) => value.try_into(),
        }
    }

    async fn set_or_check_network(&self, configured_network: bitcoin::Network) -> Result<()> {
        let network = self.get_db_network().await?;
        match network {
            None => {
                let _: Option<NetworkDb> = self
                    .db
                    .create(
                        Self::NETWORK_TABLE,
                        Some(Self::UNIQUE_ID.to_owned()),
                        NetworkDb {
                            network: configured_network,
                        },
                    )
                    .await?;
                Ok(())
            }
            Some(nw) => {
                if configured_network != nw {
                    return Err(Error::NetworkDoesNotMatch);
                }
                Ok(())
            }
        }
    }

    async fn get_or_create_key_pair(&self) -> Result<BcrKeys> {
        let keys = match self.get_key_pair().await {
            Ok(keys) => keys,
            _ => {
                let (new_keys, seed) = BcrKeys::new_with_seed_phrase()?;
                self.save_key_pair(&new_keys, &seed).await?;
                new_keys
            }
        };
        Ok(keys)
    }

    async fn get_seedphrase(&self) -> Result<String> {
        let result = self.get_db_keys().await?;
        match result {
            Some(key_db) => Ok(key_db.seed_phrase),
            None => Err(Error::NoSuchEntity(
                "seedphrase".to_string(),
                "".to_string(),
            )),
        }
    }

    async fn get_current_identity(&self) -> Result<ActiveIdentityState> {
        let result: Option<ActiveIdentityDb> = self
            .db
            .select_one(Self::ACTIVE_IDENTITY_TABLE, Self::UNIQUE_ID.to_owned())
            .await?;
        match result {
            None => {
                let identity = self.get().await?;
                Ok(ActiveIdentityState {
                    personal: identity.node_id,
                    company: None,
                })
            }
            Some(i) => Ok(i.into()),
        }
    }

    async fn set_current_identity(&self, identity_state: &ActiveIdentityState) -> Result<()> {
        let entity: ActiveIdentityDb = identity_state.into();
        let _: Option<ActiveIdentityDb> = self
            .db
            .upsert(
                Self::ACTIVE_IDENTITY_TABLE,
                Self::UNIQUE_ID.to_owned(),
                entity,
            )
            .await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDb {
    pub network: bitcoin::Network,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveIdentityDb {
    pub personal: NodeId,
    pub company: Option<NodeId>,
}

impl From<ActiveIdentityDb> for ActiveIdentityState {
    fn from(active_identity: ActiveIdentityDb) -> Self {
        Self {
            personal: active_identity.personal,
            company: active_identity.company,
        }
    }
}

impl From<&ActiveIdentityState> for ActiveIdentityDb {
    fn from(active_identity: &ActiveIdentityState) -> Self {
        Self {
            personal: active_identity.personal.clone(),
            company: active_identity.company.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityDb {
    #[serde(rename = "type")]
    pub t: IdentityType,
    pub node_id: NodeId,
    pub name: Name,
    pub email: Option<Email>,
    pub postal_address: OptionalPostalAddressDb,
    pub date_of_birth: Option<Date>,
    pub country_of_birth: Option<Country>,
    pub city_of_birth: Option<City>,
    pub identification_number: Option<Identification>,
    pub nostr_relays: Vec<url::Url>,
    pub profile_picture_file: Option<FileDb>,
    pub identity_document_file: Option<FileDb>,
}

impl From<IdentityDb> for Identity {
    fn from(identity: IdentityDb) -> Self {
        Self {
            t: identity.t,
            node_id: identity.node_id,
            name: identity.name,
            email: identity.email,
            postal_address: identity.postal_address.into(),
            date_of_birth: identity.date_of_birth,
            country_of_birth: identity.country_of_birth,
            city_of_birth: identity.city_of_birth,
            identification_number: identity.identification_number,
            nostr_relays: identity.nostr_relays,
            profile_picture_file: identity.profile_picture_file.map(|f| f.into()),
            identity_document_file: identity.identity_document_file.map(|f| f.into()),
        }
    }
}

impl From<&Identity> for IdentityDb {
    fn from(identity: &Identity) -> Self {
        Self {
            t: identity.t.clone(),
            node_id: identity.node_id.clone(),
            name: identity.name.clone(),
            email: identity.email.clone(),
            postal_address: OptionalPostalAddressDb::from(&identity.postal_address),
            date_of_birth: identity.date_of_birth.clone(),
            country_of_birth: identity.country_of_birth.clone(),
            city_of_birth: identity.city_of_birth.clone(),
            identification_number: identity.identification_number.clone(),
            nostr_relays: identity.nostr_relays.clone(),
            profile_picture_file: identity.profile_picture_file.clone().map(|f| (&f).into()),
            identity_document_file: identity.identity_document_file.clone().map(|f| (&f).into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDb {
    pub key: String,
    pub seed_phrase: String,
}

impl KeyDb {
    fn from_generated_keys(key_pair: &BcrKeys, seed: &str) -> Self {
        Self {
            key: key_pair.get_private_key_string(),
            seed_phrase: seed.to_string(),
        }
    }
}

impl TryFrom<KeyDb> for BcrKeys {
    type Error = crate::Error;
    fn try_from(value: KeyDb) -> Result<Self> {
        let key_pair = BcrKeys::from_private_key(
            &SecretKey::from_str(&value.key).map_err(|e| Error::CryptoUtil(e.into()))?,
        )?;
        Ok(key_pair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{db::get_memory_db, tests::tests::empty_identity};

    async fn get_store() -> SurrealIdentityStore {
        let mem_db = get_memory_db("test", "identity")
            .await
            .expect("could not create memory db");
        SurrealIdentityStore::new(SurrealWrapper {
            db: mem_db,
            files: false,
        })
    }

    #[tokio::test]
    async fn test_exists() {
        let store = get_store().await;
        assert!(!store.exists().await);
        store.save(&empty_identity()).await.unwrap();
        assert!(store.exists().await)
    }

    #[tokio::test]
    async fn test_identity() {
        let store = get_store().await;
        let mut identity = empty_identity();
        identity.name = Name::new("Minka").unwrap();
        store.save(&identity).await.unwrap();
        let fetched_identity = store.get().await.unwrap();
        assert_eq!(identity, fetched_identity);
    }

    #[tokio::test]
    async fn test_full_identity() {
        let store = get_store().await;
        let mut identity = empty_identity();
        identity.name = Name::new("Minka").unwrap();
        let (keys, seed) = BcrKeys::new_with_seed_phrase().expect("key could not be generated");
        store.save(&identity).await.unwrap();
        store.save_key_pair(&keys, &seed).await.unwrap();
        let fetched_full_identity = store.get_full().await.unwrap();
        assert_eq!(identity.name, fetched_full_identity.identity.name);
        assert_eq!(
            keys.get_public_key(),
            fetched_full_identity.key_pair.get_public_key()
        );
    }

    #[tokio::test]
    async fn test_key_pair() {
        let store = get_store().await;
        let (keys, seed) = BcrKeys::new_with_seed_phrase().expect("key could not be generated");
        store.save_key_pair(&keys, &seed).await.unwrap();
        let fetched_key_pair = store.get_key_pair().await.unwrap();
        assert_eq!(keys.get_public_key(), fetched_key_pair.get_public_key());
    }
}
