use super::{
    super::{Error, Result},
    surreal::{Bindings, SurrealWrapper},
};
use crate::{
    bill::BillChainStoreApi,
    constants::{
        DB_BILL_ID, DB_BLOCK_ID, DB_DATA, DB_HASH, DB_OP_CODE, DB_PREVIOUS_HASH, DB_PUBLIC_KEY,
        DB_SIGNATURE, DB_TABLE, DB_TIMESTAMP,
    },
};
use async_trait::async_trait;
use bcr_ebill_core::{
    PublicKey, ServiceTraitBounds,
    bill::BillId,
    blockchain::{
        Block,
        bill::{BillBlock, BillBlockchain, BillOpCode},
    },
};
use serde::{Deserialize, Serialize};

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
    db: SurrealWrapper,
}

impl SurrealBillChainStore {
    const TABLE: &'static str = "bill_chain";

    pub fn new(db: SurrealWrapper) -> Self {
        Self { db }
    }

    async fn create_block(&self, query: &str, entity: BillBlockDb) -> Result<()> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TABLE)?;
        bindings.add(DB_BILL_ID, entity.bill_id)?;
        bindings.add(DB_BLOCK_ID, entity.block_id)?;
        bindings.add(DB_HASH, entity.hash)?;
        bindings.add(DB_PREVIOUS_HASH, entity.previous_hash)?;
        bindings.add(DB_SIGNATURE, entity.signature)?;
        bindings.add(DB_TIMESTAMP, entity.timestamp)?;
        bindings.add(DB_PUBLIC_KEY, entity.public_key)?;
        bindings.add(DB_DATA, entity.data)?;
        bindings.add(DB_OP_CODE, entity.op_code)?;
        self.db.query_check(query, bindings).await?;
        Ok(())
    }
}

impl ServiceTraitBounds for SurrealBillChainStore {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl BillChainStoreApi for SurrealBillChainStore {
    async fn get_latest_block(&self, id: &BillId) -> Result<BillBlock> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TABLE)?;
        bindings.add(DB_BILL_ID, id.to_owned())?;
        let result: Vec<BillBlockDb> = self
            .db
            .query("SELECT * FROM type::table($table) WHERE bill_id = $bill_id ORDER BY block_id DESC LIMIT 1", bindings)
            .await
            .map_err(|e| {
                log::error!("Get Latest Bill Block: {e}");
                e
            })?;

        match result.first() {
            None => Err(Error::NoBillBlock),
            Some(block) => Ok(block.to_owned().into()),
        }
    }

    async fn add_block(&self, id: &BillId, block: &BillBlock) -> Result<()> {
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

    async fn get_chain(&self, id: &BillId) -> Result<BillBlockchain> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TABLE)?;
        bindings.add(DB_BILL_ID, id.to_owned())?;
        let result: Vec<BillBlockDb> = self
            .db
            .query(
                "SELECT * FROM type::table($table) WHERE bill_id = $bill_id ORDER BY block_id ASC",
                bindings,
            )
            .await
            .map_err(|e| {
                log::error!("Get Bill Chain: {e}");
                e
            })?;

        let blocks: Vec<BillBlock> = result.into_iter().map(|b| b.into()).collect();
        let chain = BillBlockchain::new_from_blocks(blocks)?;

        Ok(chain)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillBlockDb {
    pub bill_id: BillId,
    pub block_id: u64,
    pub hash: String,
    pub previous_hash: String,
    pub signature: String,
    pub timestamp: u64,
    pub public_key: PublicKey,
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
            public_key: value.public_key,
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
        tests::tests::{bill_id_test, empty_address, get_bill_keys, node_id_test},
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
        SurrealBillChainStore::new(SurrealWrapper {
            db: mem_db,
            files: false,
        })
    }

    #[tokio::test]
    async fn test_chain() {
        let store = get_store().await;
        let block = get_first_block(&bill_id_test());
        store.add_block(&bill_id_test(), &block).await.unwrap();
        let last_block = store.get_latest_block(&bill_id_test()).await;
        assert!(last_block.is_ok());
        assert_eq!(last_block.as_ref().unwrap().id, 1);

        let block2 = BillBlock::create_block_for_accept(
            bill_id_test(),
            &block,
            &BillAcceptBlockData {
                accepter: BillIdentParticipantBlockData {
                    t: ContactType::Person,
                    node_id: node_id_test(),
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
        store.add_block(&bill_id_test(), &block2).await.unwrap();
        let last_block = store.get_latest_block(&bill_id_test()).await;
        assert!(last_block.is_ok());
        assert_eq!(last_block.as_ref().unwrap().id, 2);
        let chain = store.get_chain(&bill_id_test()).await.unwrap();
        assert_eq!(chain.blocks().len(), 2);
    }
}
