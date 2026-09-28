use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use surrealdb::sql::{Value, to_value};
use surrealdb::{Surreal, engine::any::Any};

use super::Result;
use crate::Error;

#[derive(Default, Clone, Debug)]
pub struct Bindings {
    pub inner: BTreeMap<String, Value>,
}

impl Bindings {
    pub fn add<T>(&mut self, key: &str, val: T) -> Result<()>
    where
        T: Serialize + 'static,
    {
        self.inner.insert(
            key.to_owned(),
            to_value(val).map_err(|e| {
                Error::SurrealConnection(format!("invalid binding for: {key}: {e}"))
            })?,
        );
        Ok(())
    }
}
/// API wrapper for SurrealDB, since we ran into a memory leak when using surrealdb with the Rust SDK
/// on WASM.
/// Because of that, we abstracted out the API we need and behind, use different versions of the API
/// for WASM and non-WASM. non-WASM simply continues to use the Rust SDK, whereas WASM uses the mechanism
/// showcased in the official surreal.wasm repository https://github.com/surrealdb/surrealdb.wasm
/// which goes around the API and uses the RPC API directly.
/// The hope is, that this will be fixed at some point and we'll be easily able to transition back to
/// just using the Rust SDK.
#[derive(Clone, Debug)]
pub struct SurrealWrapper {
    pub db: Surreal<Any>,
    pub files: bool,
}

impl SurrealWrapper {
    pub async fn query<T>(&self, query: &str, bindings: Bindings) -> Result<Vec<T>>
    where
        T: DeserializeOwned,
    {
        let db = self.db().await?;
        let mut db_query = db.query(query);

        for (k, v) in bindings.inner.into_iter() {
            db_query = db_query.bind((k, v));
        }

        let res: Vec<T> = db_query.await?.take(0)?;
        Ok(res)
    }

    pub async fn query_check(&self, query: &str, bindings: Bindings) -> Result<()> {
        let db = self.db().await?;
        let mut db_query = db.query(query);

        for (k, v) in bindings.inner.into_iter() {
            db_query = db_query.bind((k, v));
        }

        let _ = db_query.await?.check()?;
        Ok(())
    }

    pub async fn upsert<T, D>(&self, table: &str, id: String, data: D) -> Result<Option<T>>
    where
        T: DeserializeOwned,
        D: Serialize + 'static,
    {
        let data: Option<T> = self.db().await?.upsert((table, id)).content(data).await?;
        Ok(data)
    }

    pub async fn update<T, D>(&self, table: &str, id: String, data: D) -> Result<Option<T>>
    where
        T: DeserializeOwned,
        D: Serialize + 'static,
    {
        let data: Option<T> = self.db().await?.update((table, id)).content(data).await?;
        Ok(data)
    }

    pub async fn create<T, D>(&self, table: &str, id: Option<String>, data: D) -> Result<Option<T>>
    where
        T: DeserializeOwned,
        D: Serialize + 'static,
    {
        let data: Option<T> = if let Some(id_set) = id {
            self.db()
                .await?
                .create((table, id_set.to_owned()))
                .content(data)
                .await?
        } else {
            self.db().await?.create(table).content(data).await?
        };
        Ok(data)
    }

    pub async fn delete<T>(&self, table: &str, id: String) -> Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        let data: Option<T> = self.db().await?.delete((table, id)).await?;
        Ok(data)
    }

    pub async fn delete_all<T>(&self, table: &str) -> Result<Vec<T>>
    where
        T: DeserializeOwned,
    {
        let data: Vec<T> = self.db().await?.delete(table).await?;
        Ok(data)
    }

    pub async fn select_one<T>(&self, table: &str, id: String) -> Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        let data: Option<T> = self.db().await?.select((table, id)).await?;
        Ok(data)
    }

    pub async fn select_all<T>(&self, table: &str) -> Result<Vec<T>>
    where
        T: DeserializeOwned,
    {
        let data: Vec<T> = self.db().await?.select(table).await?;
        Ok(data)
    }

    async fn db(&self) -> Result<Surreal<Any>> {
        Ok(self.db.clone())
    }
}
