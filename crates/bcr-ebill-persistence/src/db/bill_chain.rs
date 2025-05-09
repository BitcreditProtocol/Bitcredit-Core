use super::super::{Error, Result};
#[cfg(target_arch = "wasm32")]
use super::get_new_surreal_db;
use crate::{
    bill::BillChainStoreApi,
    constants::{
        DB_BILL_ID, DB_BLOCK_ID, DB_DATA, DB_HASH, DB_OP_CODE, DB_PREVIOUS_HASH, DB_PUBLIC_KEY,
        DB_SIGNATURE, DB_TABLE, DB_TIMESTAMP,
    },
};
use async_trait::async_trait;
use bcr_ebill_core::blockchain::{
    Block,
    bill::{BillBlock, BillBlockchain, BillOpCode},
};
use serde::{Deserialize, Serialize};
use surrealdb::{Surreal, engine::any::Any};

const CREATE_BLOCK_QUERY: &str = r#"CREATE type::table($table) CONTENT {
                                    bill_id: $bill_id,
                                    block_id: $block_id,
                                    hash: $hash,
                                    previous_hash: $previous_hash,
                                    signature: $signature,
                                    timestamp: $timestamp,
                                    public_key: $public_key,
                                    data: $data,
                                    op_code: $op_code
                                };"#;

#[derive(Clone)]
pub struct SurrealBillChainStore {
    #[allow(dead_code)]
    db: Surreal<Any>,
}

impl SurrealBillChainStore {
    const TABLE: &'static str = "bill_chain";

    pub fn new(db: Surreal<Any>) -> Self {
        Self { db }
    }

    async fn create_block(&self, query: &str, entity: BillBlockDb) -> Result<()> {
        let _ = self
            .db()
            .await?
            .query(query)
            .bind((DB_TABLE, Self::TABLE))
            .bind((DB_BILL_ID, entity.bill_id))
            .bind((DB_BLOCK_ID, entity.block_id))
            .bind((DB_HASH, entity.hash))
            .bind((DB_PREVIOUS_HASH, entity.previous_hash))
            .bind((DB_SIGNATURE, entity.signature))
            .bind((DB_TIMESTAMP, entity.timestamp))
            .bind((DB_PUBLIC_KEY, entity.public_key))
            .bind((DB_DATA, entity.data))
            .bind((DB_OP_CODE, entity.op_code))
            .await?
            .check()?;
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    async fn db(&self) -> Result<Surreal<Any>> {
        get_new_surreal_db().await
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn db(&self) -> Result<Surreal<Any>> {
        Ok(self.db.clone())
    }
}

#[async_trait]
impl BillChainStoreApi for SurrealBillChainStore {
    async fn get_latest_block(&self, id: &str) -> Result<BillBlock> {
        let result: Vec<BillBlockDb> = self
            .db().await?
            .query("SELECT * FROM type::table($table) WHERE bill_id = $bill_id ORDER BY block_id DESC LIMIT 1")
            .bind((DB_TABLE, Self::TABLE))
            .bind((DB_BILL_ID, id.to_owned()))
            .await
            .map_err(|e| {
                log::error!("Get Latest Bill Block: {e}");
                e
            })?
            .take(0)?;

        match result.first() {
            None => Err(Error::NoBillBlock),
            Some(block) => Ok(block.to_owned().into()),
        }
    }

    async fn add_block(&self, id: &str, block: &BillBlock) -> Result<()> {
        let entity: BillBlockDb = block.into();
        match self.get_latest_block(id).await {
            Err(Error::NoBillBlock) => {
                // if there is no latest block, ensure it's a valid first block
                if block.id == 1 && block.verify() && block.validate_hash() {
                    // Atomically ensure it's the first block
                    let query = format!(
                        r#"
                        BEGIN TRANSACTION;
                        LET $blocks = (RETURN count(SELECT * FROM type::table($table) WHERE bill_id = $bill_id));
                        IF $blocks = 0 AND $block_id = 1 {{
                            {}
                        }} ELSE {{
                            THROW "invalid block - not the first block";
                        }};
                        COMMIT TRANSACTION;
                    "#,
                        CREATE_BLOCK_QUERY
                    );
                    self.create_block(&query, entity).await.map_err(|e| {
                        log::error!("Create Bill Block: {e}");
                        e
                    })?;
                    Ok(())
                } else {
                    return Err(Error::AddBillBlock(format!(
                        "First Block validation error: block id: {}",
                        block.id
                    )));
                }
            }
            Ok(latest_block) => {
                // if there is a latest block, ensure it's a valid follow-up block
                if !block.validate_with_previous(&latest_block) {
                    return Err(Error::AddBillBlock(format!(
                        "Block validation error: block id: {}, latest block id: {}",
                        block.id, latest_block.id
                    )));
                }
                // Atomically ensure the block is valid
                let query = format!(
                    r#"
                    BEGIN TRANSACTION;
                    LET $latest_block = (SELECT block_id, hash FROM type::table($table) WHERE bill_id = $bill_id ORDER BY block_id DESC LIMIT 1)[0];
                    IF $latest_block.block_id + 1 = $block_id AND $latest_block.hash = $previous_hash {{
                        {}
                    }} ELSE {{
                        THROW "invalid block";
                    }};
                    COMMIT TRANSACTION;
                "#,
                    CREATE_BLOCK_QUERY
                );
                self.create_block(&query, entity).await.map_err(|e| {
                    log::error!("Create Bill Block: {e}");
                    e
                })?;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    async fn get_chain(&self, id: &str) -> Result<BillBlockchain> {
        let result: Vec<BillBlockDb> = self
            .db()
            .await?
            .query(
                "SELECT * FROM type::table($table) WHERE bill_id = $bill_id ORDER BY block_id ASC",
            )
            .bind((DB_TABLE, Self::TABLE))
            .bind((DB_BILL_ID, id.to_owned()))
            .await
            .map_err(|e| {
                log::error!("Get Bill Chain: {e}");
                e
            })?
            .take(0)?;

        let blocks: Vec<BillBlock> = result.into_iter().map(|b| b.into()).collect();
        let chain = BillBlockchain::new_from_blocks(blocks)?;

        Ok(chain)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillBlockDb {
    pub bill_id: String,
    pub block_id: u64,
    pub hash: String,
    pub previous_hash: String,
    pub signature: String,
    pub timestamp: u64,
    pub public_key: String,
    pub data: String,
    pub op_code: BillOpCode,
}

impl From<BillBlockDb> for BillBlock {
    fn from(value: BillBlockDb) -> Self {
        Self {
            bill_id: value.bill_id,
            id: value.block_id,
            hash: value.hash,
            timestamp: value.timestamp,
            data: value.data,
            public_key: value.public_key,
            previous_hash: value.previous_hash,
            signature: value.signature,
            op_code: value.op_code,
        }
    }
}

impl From<&BillBlock> for BillBlockDb {
    fn from(value: &BillBlock) -> Self {
        Self {
            bill_id: value.bill_id.clone(),
            block_id: value.id,
            hash: value.hash.clone(),
            previous_hash: value.previous_hash.clone(),
            signature: value.signature.clone(),
            timestamp: value.timestamp,
            public_key: value.public_key.clone(),
            data: value.data.clone(),
            op_code: value.op_code.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        db::{bill::tests::get_first_block, get_memory_db},
        tests::tests::{empty_address, get_bill_keys},
    };
    use bcr_ebill_core::{
        blockchain::{
            Blockchain,
            bill::block::{BillAcceptBlockData, BillIdentParticipantBlockData},
        },
        contact::ContactType,
        util::BcrKeys,
    };

    async fn get_store() -> SurrealBillChainStore {
        let mem_db = get_memory_db("test", "bill_chain")
            .await
            .expect("could not create get_memory_db");
        SurrealBillChainStore::new(mem_db)
    }

    #[tokio::test]
    async fn test_chain() {
        let store = get_store().await;
        let block = get_first_block("1234");
        store.add_block("1234", &block).await.unwrap();
        let last_block = store.get_latest_block("1234").await;
        assert!(last_block.is_ok());
        assert_eq!(last_block.as_ref().unwrap().id, 1);

        let block2 = BillBlock::create_block_for_accept(
            "1234".to_string(),
            &block,
            &BillAcceptBlockData {
                accepter: BillIdentParticipantBlockData {
                    t: ContactType::Person,
                    node_id: "555555".to_owned(),
                    name: "some dude".to_owned(),
                    postal_address: empty_address(),
                },
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: empty_address(),
            },
            &BcrKeys::new(),
            None,
            &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
            1731593928,
        )
        .unwrap();
        store.add_block("1234", &block2).await.unwrap();
        let last_block = store.get_latest_block("1234").await;
        assert!(last_block.is_ok());
        assert_eq!(last_block.as_ref().unwrap().id, 2);
        let chain = store.get_chain("1234").await.unwrap();
        assert_eq!(chain.blocks().len(), 2);
    }
}
