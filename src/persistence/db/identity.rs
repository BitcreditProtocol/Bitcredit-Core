use super::Result;
use crate::{
    persistence::{identity::IdentityStoreApi, Error},
    service::identity_service::{Identity, IdentityWithAll},
    util::BcrKeys,
};
use async_trait::async_trait;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use surrealdb::{engine::any::Any, Surreal};

#[derive(Clone)]
pub struct SurrealIdentityStore {
    db: Surreal<Any>,
}

impl SurrealIdentityStore {
    const IDENTITY_TABLE: &'static str = "identity";
    const NODE_ID_TABLE: &'static str = "identity_node_id";
    const KEY_TABLE: &'static str = "identity_key";
    const UNIQUE_ID: &'static str = "unique_record";

    pub fn new(db: Surreal<Any>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl IdentityStoreApi for SurrealIdentityStore {
    async fn exists(&self) -> bool {
        self.get().await.map(|_| true).unwrap_or(false)
    }

    async fn libp2p_credentials_exist(&self) -> bool {
        self.get_node_id().await.map(|_| true).unwrap_or(false)
            && self.get_key_pair().await.map(|_| true).unwrap_or(false)
    }

    async fn save(&self, identity: &Identity) -> Result<()> {
        let entity: IdentityDb = identity.into();
        let _: Option<IdentityDb> = self
            .db
            .upsert((Self::IDENTITY_TABLE, Self::UNIQUE_ID))
            .content(entity)
            .await?;
        Ok(())
    }

    async fn get(&self) -> Result<Identity> {
        let result: Option<IdentityDb> = self
            .db
            .select((Self::IDENTITY_TABLE, Self::UNIQUE_ID))
            .await?;
        match result {
            None => Err(Error::NoIdentity),
            Some(i) => Ok(i.into()),
        }
    }

    async fn get_full(&self) -> Result<IdentityWithAll> {
        let results = tokio::join!(self.get(), self.get_node_id(), self.get_key_pair());
        match results {
            (Ok(identity), Ok(node_id), Ok(key_pair)) => Ok(IdentityWithAll {
                identity,
                node_id,
                key_pair,
            }),
            _ => {
                if let Err(e) = results.0 {
                    Err(e)
                } else if let Err(e) = results.1 {
                    Err(e)
                } else if let Err(e) = results.2 {
                    Err(e)
                } else {
                    unreachable!("one of the tasks has to have failed");
                }
            }
        }
    }

    async fn save_node_id(&self, node_id: &PeerId) -> Result<()> {
        let entity: NodeIdDb = node_id.into();
        let _: Option<NodeIdDb> = self
            .db
            .upsert((Self::NODE_ID_TABLE, Self::UNIQUE_ID))
            .content(entity)
            .await?;
        Ok(())
    }

    async fn get_node_id(&self) -> Result<PeerId> {
        let result: Option<NodeIdDb> = self
            .db
            .select((Self::NODE_ID_TABLE, Self::UNIQUE_ID))
            .await?;
        match result {
            None => Err(Error::NoNodeId),
            Some(value) => value.try_into(),
        }
    }

    async fn save_key_pair(&self, key_pair: &BcrKeys) -> Result<()> {
        let entity: KeyDb = key_pair.try_into()?;
        let _: Option<KeyDb> = self
            .db
            .upsert((Self::KEY_TABLE, Self::UNIQUE_ID))
            .content(entity)
            .await?;
        Ok(())
    }

    async fn get_key_pair(&self) -> Result<BcrKeys> {
        let result: Option<KeyDb> = self.db.select((Self::KEY_TABLE, Self::UNIQUE_ID)).await?;
        match result {
            None => Err(Error::NoIdentityKey),
            Some(value) => value.try_into(),
        }
    }

    async fn get_or_create_key_pair(&self) -> Result<BcrKeys> {
        let keys = match self.get_key_pair().await {
            Ok(keys) => keys,
            _ => {
                let new_keys = BcrKeys::new();
                let p2p_keys = new_keys.get_libp2p_keys()?;
                let node_id = p2p_keys.public().to_peer_id();
                self.save_node_id(&node_id).await?;
                self.save_key_pair(&new_keys).await?;
                new_keys
            }
        };
        Ok(keys)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityDb {
    pub name: String,
    pub company: String,
    pub date_of_birth: String,
    pub city_of_birth: String,
    pub country_of_birth: String,
    pub email: String,
    pub postal_address: String,
    pub public_key_pem: String,
    pub private_key_pem: String,
    pub bitcoin_public_key: String,
    pub bitcoin_private_key: String,
    pub nostr_npub: Option<String>,
    pub nostr_relay: Option<String>,
}

impl From<IdentityDb> for Identity {
    fn from(identity: IdentityDb) -> Self {
        Self {
            name: identity.name,
            company: identity.company,
            date_of_birth: identity.date_of_birth,
            city_of_birth: identity.city_of_birth,
            country_of_birth: identity.country_of_birth,
            email: identity.email,
            postal_address: identity.postal_address,
            public_key_pem: identity.public_key_pem,
            private_key_pem: identity.private_key_pem,
            bitcoin_public_key: identity.bitcoin_public_key,
            bitcoin_private_key: identity.bitcoin_private_key,
            nostr_npub: identity.nostr_npub,
            nostr_relay: identity.nostr_relay,
        }
    }
}

impl From<&Identity> for IdentityDb {
    fn from(identity: &Identity) -> Self {
        Self {
            name: identity.name.clone(),
            company: identity.company.clone(),
            date_of_birth: identity.date_of_birth.clone(),
            city_of_birth: identity.city_of_birth.clone(),
            country_of_birth: identity.country_of_birth.clone(),
            email: identity.email.clone(),
            postal_address: identity.postal_address.clone(),
            public_key_pem: identity.public_key_pem.clone(),
            private_key_pem: identity.private_key_pem.clone(),
            bitcoin_public_key: identity.bitcoin_public_key.clone(),
            bitcoin_private_key: identity.bitcoin_private_key.clone(),
            nostr_npub: identity.nostr_npub.clone(),
            nostr_relay: identity.nostr_relay.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdDb {
    pub node_id: Vec<u8>,
}

impl TryFrom<NodeIdDb> for PeerId {
    type Error = crate::persistence::Error;
    fn try_from(value: NodeIdDb) -> Result<Self> {
        let node_id = PeerId::from_bytes(&value.node_id)?;
        Ok(node_id)
    }
}

impl From<&PeerId> for NodeIdDb {
    fn from(value: &PeerId) -> Self {
        NodeIdDb {
            node_id: value.to_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDb {
    pub key: String,
}

impl TryFrom<&BcrKeys> for KeyDb {
    type Error = crate::persistence::Error;
    fn try_from(value: &BcrKeys) -> Result<Self> {
        let data = value.get_private_key_string();
        Ok(KeyDb { key: data })
    }
}

impl TryFrom<KeyDb> for BcrKeys {
    type Error = crate::persistence::Error;
    fn try_from(value: KeyDb) -> Result<Self> {
        let key_pair = BcrKeys::from_private_key(&value.key)?;
        Ok(key_pair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::db::get_memory_db;

    async fn get_store() -> SurrealIdentityStore {
        let mem_db = get_memory_db("test", "identity")
            .await
            .expect("could not create memory db");
        SurrealIdentityStore::new(mem_db)
    }

    #[tokio::test]
    async fn test_exists() {
        let store = get_store().await;
        assert!(!store.exists().await);
        store.save(&Identity::new_empty()).await.unwrap();
        assert!(store.exists().await)
    }

    #[tokio::test]
    async fn test_libp2p_credentials_exist() {
        let store = get_store().await;
        assert!(!store.libp2p_credentials_exist().await);
        store.save_node_id(&PeerId::random()).await.unwrap();
        assert!(!store.libp2p_credentials_exist().await);
        store.save_key_pair(&BcrKeys::new()).await.unwrap();
        assert!(store.libp2p_credentials_exist().await)
    }

    #[tokio::test]
    async fn test_identity() {
        let store = get_store().await;
        let mut identity = Identity::new_empty();
        identity.name = "Minka".to_string();
        store.save(&identity).await.unwrap();
        let fetched_identity = store.get().await.unwrap();
        assert_eq!(identity, fetched_identity);
    }

    #[tokio::test]
    async fn test_full_identity() {
        let store = get_store().await;
        let mut identity = Identity::new_empty();
        identity.name = "Minka".to_string();
        let node_id = PeerId::random();
        let key_pair = BcrKeys::new();
        store.save(&identity).await.unwrap();
        store.save_node_id(&node_id).await.unwrap();
        store.save_key_pair(&key_pair).await.unwrap();
        let fetched_full_identity = store.get_full().await.unwrap();
        assert_eq!(identity.name, fetched_full_identity.identity.name);
        assert_eq!(
            node_id.to_string(),
            fetched_full_identity.node_id.to_string()
        );
        assert_eq!(
            key_pair.get_public_key(),
            fetched_full_identity.key_pair.get_public_key()
        );
    }

    #[tokio::test]
    async fn test_node_id() {
        let store = get_store().await;
        let node_id = PeerId::random();
        store.save_node_id(&node_id).await.unwrap();
        let fetched_node_id = store.get_node_id().await.unwrap();
        assert_eq!(node_id.to_string(), fetched_node_id.to_string());
    }

    #[tokio::test]
    async fn test_key_pair() {
        let key_pair = BcrKeys::new();
        let store = get_store().await;
        store.save_key_pair(&key_pair).await.unwrap();
        let fetched_key_pair = store.get_key_pair().await.unwrap();
        assert_eq!(key_pair.get_public_key(), fetched_key_pair.get_public_key());
    }
}
