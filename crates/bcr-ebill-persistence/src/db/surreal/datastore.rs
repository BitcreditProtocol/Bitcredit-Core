use crate::constants::{
    SURREAL_DB_CON_INDXDB_DATA, SURREAL_DB_CON_INDXDB_FILES, SURREAL_DB_INDXDB_DB_DATA,
    SURREAL_DB_INDXDB_DB_FILES, SURREAL_DB_INDXDB_NS_DATA, SURREAL_DB_INDXDB_NS_FILES,
};
use crate::{Error, Result};
use arc_swap::ArcSwap;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use surrealdb::{
    dbs::Session,
    kvs::Datastore,
    rpc::{Data, Method, RpcContext, RpcProtocolV1, RpcProtocolV2},
    sql::{Array, Id, Object, Query, Table, Thing, Value},
};
use tokio::sync::Semaphore;
use tokio_with_wasm as tokio;
use uuid::Uuid;

const VERSION: u8 = 2;

pub struct SurrealWasmEngine(SurrealWasmEngineInner);

pub struct SurrealWasmEngineInner {
    pub kvs: Arc<Datastore>,
    pub lock: Arc<Semaphore>,
    pub session: ArcSwap<Session>,
}

/// Wrapper for IndexedDB connection, settings taken from
/// https://github.com/surrealdb/surrealdb.wasm/blob/main/src/app/mod.rs
impl SurrealWasmEngine {
    pub async fn execute(&self, method: Method, params: Array) -> Result<Data> {
        let res = RpcContext::execute(&self.0, Some(VERSION), method, params)
            .await
            .map_err(|e| Error::SurrealConnection(format!("RPC Execute Error: {e}")))?;
        Ok(res)
    }

    pub async fn new_files() -> Result<SurrealWasmEngine> {
        Self::new_inner(
            SURREAL_DB_CON_INDXDB_FILES,
            SURREAL_DB_INDXDB_NS_FILES,
            SURREAL_DB_INDXDB_DB_FILES,
        )
        .await
    }

    pub async fn new() -> Result<SurrealWasmEngine> {
        Self::new_inner(
            SURREAL_DB_CON_INDXDB_DATA,
            SURREAL_DB_INDXDB_NS_DATA,
            SURREAL_DB_INDXDB_DB_DATA,
        )
        .await
    }

    async fn new_inner(con: &str, ns: &str, db: &str) -> Result<SurrealWasmEngine> {
        let kvs = Datastore::new(con)
            .await
            .map_err(|e| Error::SurrealConnection(format!("IndexedDB data store: {e}")))?;
        let session = Session::default().with_rt(true);

        let inner = SurrealWasmEngineInner {
            #[allow(clippy::arc_with_non_send_sync)]
            kvs: Arc::new(kvs),
            session: ArcSwap::new(Arc::new(session)),
            lock: Arc::new(Semaphore::new(1)),
        };
        RpcContext::execute(&inner, Some(2), Method::Use, Array::from(vec![ns, db]))
            .await
            .map_err(|e| Error::SurrealConnection(format!("Use DB/NS: {e}")))?;

        Ok(SurrealWasmEngine(inner))
    }

    pub async fn select<T>(&self, table: &str, id: Option<String>) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let params = if let Some(id_set) = id {
            Array::from(Value::from(Thing::from((
                table,
                Id::from(id_set.to_owned()),
            ))))
        } else {
            Array::from(vec![table.to_owned()])
        };
        let data = self
            .execute(Method::Select, params)
            .await
            .map_err(|e| Error::SurrealConnection(format!("Error during Select: {e}")))?;
        match data {
            Data::Other(val) => {
                let ret: T = from_surreal(val)?;
                Ok(ret)
            }
            _ => Err(Error::SurrealConnection("Invalid Return Type".into())),
        }
    }

    pub async fn delete<T>(&self, table: &str, id: String) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let params = Array::from(Value::from(Thing::from((table, Id::from(id)))));
        let data = self
            .execute(Method::Delete, params)
            .await
            .map_err(|e| Error::SurrealConnection(format!("Error during Delete: {e}")))?;
        match data {
            Data::Other(val) => {
                let ret: T = from_surreal(val)?;
                Ok(ret)
            }
            _ => Err(Error::SurrealConnection("Invalid Return Type".into())),
        }
    }

    pub async fn delete_all<T>(&self, table: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let params = Array::from(Value::Table(Table::from(table)));
        let data = self
            .execute(Method::Delete, params)
            .await
            .map_err(|e| Error::SurrealConnection(format!("Error during Delete: {e}")))?;
        match data {
            Data::Other(val) => {
                let ret: T = from_surreal(val)?;
                Ok(ret)
            }
            _ => Err(Error::SurrealConnection("Invalid Return Type".into())),
        }
    }

    pub async fn create<T, D>(&self, table: &str, id: Option<String>, data: D) -> Result<T>
    where
        T: DeserializeOwned,
        D: Serialize + 'static,
    {
        let params = if let Some(id_set) = id {
            Array::from(vec![
                Value::from(Thing::from((table, Id::from(id_set.to_owned())))),
                Value::Object(to_surreal(data)?),
            ])
        } else {
            Array::from(vec![Value::from(table), Value::Object(to_surreal(data)?)])
        };

        let data = self
            .execute(Method::Create, params)
            .await
            .map_err(|e| Error::SurrealConnection(format!("Error during Create: {e}")))?;

        match data {
            Data::Other(val) => {
                let ret: T = from_surreal(val)?;
                Ok(ret)
            }
            _ => Err(Error::SurrealConnection("Invalid Return Type".into())),
        }
    }

    pub async fn update<T, D>(&self, table: &str, id: String, data: D) -> Result<T>
    where
        T: DeserializeOwned,
        D: Serialize + 'static,
    {
        let params = Array::from(vec![
            Value::from(Thing::from((table, Id::from(id)))),
            Value::Object(to_surreal(data)?),
        ]);

        let data = self
            .execute(Method::Update, params)
            .await
            .map_err(|e| Error::SurrealConnection(format!("Error during Update: {e}")))?;

        match data {
            Data::Other(val) => {
                let ret: T = from_surreal(val)?;
                Ok(ret)
            }
            _ => Err(Error::SurrealConnection("Invalid Return Type".into())),
        }
    }

    pub async fn upsert<T, D>(&self, table: &str, id: String, data: D) -> Result<T>
    where
        T: DeserializeOwned,
        D: Serialize + 'static,
    {
        let params = Array::from(vec![
            Value::from(Thing::from((table, Id::from(id)))),
            Value::Object(to_surreal(data)?),
        ]);

        let data = self
            .execute(Method::Upsert, params)
            .await
            .map_err(|e| Error::SurrealConnection(format!("Error during Upsert: {e}")))?;

        match data {
            Data::Other(val) => {
                let ret: T = from_surreal(val)?;
                Ok(ret)
            }
            _ => Err(Error::SurrealConnection("Invalid Return Type".into())),
        }
    }

    pub async fn query<T>(&self, query: &str, bindings: super::Bindings) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let data = self.query_base(query, bindings).await?;
        match data {
            Data::Query(responses) => match responses.into_iter().next() {
                None => Err(Error::SurrealConnection("Query - no response".into())),
                Some(first_response) => match first_response.result {
                    Err(e) => Err(Error::SurrealConnection(format!("Error during Query: {e}"))),
                    Ok(val) => {
                        let ret: T = from_surreal(val)?;
                        Ok(ret)
                    }
                },
            },
            _ => Err(Error::SurrealConnection("Invalid Return Type".into())),
        }
    }

    pub async fn query_check(&self, query: &str, bindings: super::Bindings) -> Result<()> {
        let data = self.query_base(query, bindings).await?;
        match data {
            Data::Query(responses) => match responses.into_iter().next() {
                None => Err(Error::SurrealConnection("Query - no response".into())),
                Some(first_response) => match first_response.result {
                    Err(e) => Err(Error::SurrealConnection(format!("Error during Query: {e}"))),
                    Ok(_) => Ok(()), // query was successful
                },
            },
            _ => Err(Error::SurrealConnection("Invalid Return Type".into())),
        }
    }

    async fn query_base(&self, query: &str, bindings: super::Bindings) -> Result<Data> {
        let parsed_query: Query = surrealdb::syn::parse(query)
            .map_err(|e| Error::SurrealConnection(format!("Invalid Query: {query}: {e}")))?;

        let params = Array::from(vec![
            Value::Query(parsed_query),
            Value::Object(Object::from(bindings.inner)),
        ]);

        let data = self
            .execute(Method::Query, params)
            .await
            .map_err(|e| Error::SurrealConnection(format!("Error during Query: {e}")))?;
        Ok(data)
    }
}

fn from_surreal<T>(val: Value) -> Result<T>
where
    T: DeserializeOwned,
{
    let result: T = surrealdb::sql::from_value(val)
        .map_err(|e| Error::SurrealConnection(format!("From Value: {e}")))?;
    Ok(result)
}

pub fn to_surreal<T: Serialize + 'static>(input: T) -> Result<Object> {
    let surreal_val = surrealdb::sql::to_value(input)
        .map_err(|e| Error::SurrealConnection(format!("To Value: {e}")))?;
    match surreal_val {
        Value::Object(obj) => Ok(obj),
        _ => Err(Error::SurrealConnection(
            "To Surreal Value - not an object".into(),
        )),
    }
}

impl RpcContext for SurrealWasmEngineInner {
    fn kvs(&self) -> &Datastore {
        &self.kvs
    }

    fn lock(&self) -> Arc<Semaphore> {
        self.lock.clone()
    }

    fn session(&self) -> Arc<Session> {
        self.session.load_full()
    }

    fn set_session(&self, session: Arc<Session>) {
        self.session.store(session);
    }

    fn version_data(&self) -> Data {
        Value::Strand("surrealdb-2.3.1".to_string().into()).into()
    }

    const LQ_SUPPORT: bool = true;
    #[allow(clippy::manual_async_fn)]
    fn handle_live(&self, _lqid: &Uuid) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }

    #[allow(clippy::manual_async_fn)]
    fn handle_kill(&self, _lqid: &Uuid) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }
}

impl RpcProtocolV1 for SurrealWasmEngineInner {}
impl RpcProtocolV2 for SurrealWasmEngineInner {}
