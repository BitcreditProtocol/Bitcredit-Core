use super::{
    super::{Error, Result},
    surreal::{Bindings, SurrealWrapper},
};
use crate::{
    constants::{
        DB_BLOCK_ID, DB_DATA, DB_HASH, DB_OP_CODE, DB_PLAINTEXT_HASH, DB_PREVIOUS_HASH,
        DB_PUBLIC_KEY, DB_SIGNATURE, DB_TABLE, DB_TIMESTAMP,
    },
    identity::IdentityChainStoreApi,
};
use async_trait::async_trait;
use bcr_ebill_core::{
    PublicKey, ServiceTraitBounds,
    blockchain::{
        Block,
        identity::{IdentityBlock, IdentityBlockchain, IdentityOpCode},
    },
};
use serde::{Deserialize, Serialize};

const CREATE_BLOCK_QUERY: &str = r#"CREATE type::table($table) CONTENT {
                                    block_id: $block_id,
                                    plaintext_hash: $plaintext_hash,
                                    hash: $hash,
                                    previous_hash: $previous_hash,
                                    signature: $signature,
                                    timestamp: $timestamp,
                                    public_key: $public_key,
                                    data: $data,
                                    op_code: $op_code
                                };"#;

#[derive(Clone)]
pub struct SurrealIdentityChainStore {
    db: SurrealWrapper,
}

impl SurrealIdentityChainStore {
    const TABLE: &'static str = "identity_chain";

    pub fn new(db: SurrealWrapper) -> Self {
        Self { db }
    }

    async fn create_block(&self, query: &str, entity: IdentityBlockDb) -> Result<()> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TABLE)?;
        bindings.add(DB_BLOCK_ID, entity.block_id)?;
        bindings.add(DB_PLAINTEXT_HASH, entity.plaintext_hash)?;
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

impl ServiceTraitBounds for SurrealIdentityChainStore {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl IdentityChainStoreApi for SurrealIdentityChainStore {
    async fn get_latest_block(&self) -> Result<IdentityBlock> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TABLE)?;

        let result: Vec<IdentityBlockDb> = self
            .db
            .query(
                "SELECT * FROM type::table($table) ORDER BY block_id DESC LIMIT 1",
                bindings,
            )
            .await
            .map_err(|e| {
                log::error!("Get Identity Block: {e}");
                e
            })?;

        match result.first() {
            None => Err(Error::NoIdentityBlock),
            Some(block) => Ok(block.to_owned().into()),
        }
    }

    async fn add_block(&self, block: &IdentityBlock) -> Result<()> {
        let entity: IdentityBlockDb = block.into();
        match self.get_latest_block().await {
            Err(Error::NoIdentityBlock) => {
                // if there is no latest block, ensure it's a valid first block
                if block.id == 1 && block.verify() && block.validate_hash() {
                    // Atomically ensure it's the first block
                    let query = format!(
                        r#"
                        BEGIN TRANSACTION;
                        LET $blocks = (RETURN count(SELECT * FROM type::table($table)));
                        IF $blocks = 0 AND $block_id = 1 {{
                            {CREATE_BLOCK_QUERY}
                        }} ELSE {{
                            THROW "invalid block - not the first block";
                        }};
                        COMMIT TRANSACTION;
                    "#
                    );
                    self.create_block(&query, entity).await.map_err(|e| {
                        log::error!("Create Identity Block: {e}");
                        e
                    })?;
                    Ok(())
                } else {
                    return Err(Error::AddIdentityBlock(format!(
                        "First Block validation error: block id: {}",
                        block.id
                    )));
                }
            }
            Ok(latest_block) => {
                // if there is a latest block, ensure it's a valid follow-up block
                if !block.validate_with_previous(&latest_block) {
                    return Err(Error::AddIdentityBlock(format!(
                        "Block validation error: block id: {}, latest block id: {}",
                        block.id, latest_block.id
                    )));
                }
                // Atomically ensure the block is valid
                let query = format!(
                    r#"
                    BEGIN TRANSACTION;
                    LET $latest_block = (SELECT block_id, hash FROM type::table($table) ORDER BY block_id DESC LIMIT 1)[0];
                    IF $latest_block.block_id + 1 = $block_id AND $latest_block.hash = $previous_hash {{
                        {CREATE_BLOCK_QUERY}
                    }} ELSE {{
                        THROW "invalid block";
                    }};
                    COMMIT TRANSACTION;
                "#
                );
                self.create_block(&query, entity).await.map_err(|e| {
                    log::error!("Create Identity Block: {e}");
                    e
                })?;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    async fn get_chain(&self) -> Result<IdentityBlockchain> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TABLE)?;

        let result: Vec<IdentityBlockDb> = self
            .db
            .query(
                "SELECT * FROM type::table($table) ORDER BY block_id DESC LIMIT 1",
                bindings,
            )
            .await
            .map_err(|e| {
                log::error!("Get Identity Block: {e}");
                e
            })?;
        let blocks = result
            .into_iter()
            .map(|b| b.into())
            .collect::<Vec<IdentityBlock>>();
        Ok(IdentityBlockchain::new_from_blocks(blocks)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityBlockDb {
    pub block_id: u64,
    pub plaintext_hash: String,
    pub hash: String,
    pub previous_hash: String,
    pub signature: String,
    pub timestamp: u64,
    pub public_key: PublicKey,
    pub data: String,
    pub op_code: IdentityOpCode,
}

impl From<IdentityBlockDb> for IdentityBlock {
    fn from(value: IdentityBlockDb) -> Self {
        Self {
            id: value.block_id,
            plaintext_hash: value.plaintext_hash,
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

impl From<&IdentityBlock> for IdentityBlockDb {
    fn from(value: &IdentityBlock) -> Self {
        Self {
            block_id: value.id,
            plaintext_hash: value.plaintext_hash.clone(),
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
        db::get_memory_db,
        tests::tests::{empty_identity, empty_optional_address},
        util::BcrKeys,
    };
    use bcr_ebill_core::blockchain::identity::IdentityUpdateBlockData;

    async fn get_store() -> SurrealIdentityChainStore {
        let mem_db = get_memory_db("test", "identity_chain")
            .await
            .expect("could not create get_memory_db");
        SurrealIdentityChainStore::new(SurrealWrapper {
            db: mem_db,
            files: false,
        })
    }

    #[tokio::test]
    async fn test_add_block() {
        let store = get_store().await;
        let block = IdentityBlock::create_block_for_create(
            "genesis hash".to_string(),
            &empty_identity().into(),
            &BcrKeys::new(),
            1731593928,
        )
        .unwrap();
        store.add_block(&block).await.unwrap();
        let last_block = store.get_latest_block().await;
        assert!(last_block.is_ok());
        assert_eq!(last_block.as_ref().unwrap().id, 1);

        let block2 = IdentityBlock::create_block_for_update(
            &block,
            &IdentityUpdateBlockData {
                name: None,
                email: None,
                postal_address: empty_optional_address(),
                date_of_birth: None,
                country_of_birth: None,
                city_of_birth: None,
                identification_number: None,
                profile_picture_file: None,
                identity_document_file: None,
            },
            &BcrKeys::new(),
            1731593928,
        )
        .unwrap();
        store.add_block(&block2).await.unwrap();
        let last_block = store.get_latest_block().await;
        assert!(last_block.is_ok());
        assert_eq!(last_block.as_ref().unwrap().id, 2);
    }
}
