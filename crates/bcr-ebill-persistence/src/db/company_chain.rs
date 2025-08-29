use super::{
    super::{Error, Result},
    surreal::{Bindings, SurrealWrapper},
};
use crate::{
    company::CompanyChainStoreApi,
    constants::{
        DB_BLOCK_ID, DB_COMPANY_ID, DB_DATA, DB_HASH, DB_OP_CODE, DB_PLAINTEXT_HASH,
        DB_PREVIOUS_HASH, DB_PUBLIC_KEY, DB_SIGNATORY_NODE_ID, DB_SIGNATURE, DB_TABLE,
        DB_TIMESTAMP,
    },
};
use async_trait::async_trait;
use bcr_ebill_core::{
    NodeId, PublicKey, ServiceTraitBounds,
    blockchain::{
        Block,
        company::{CompanyBlock, CompanyBlockchain, CompanyOpCode},
    },
};
use serde::{Deserialize, Serialize};

const CREATE_BLOCK_QUERY: &str = r#"CREATE type::table($table) CONTENT {
                                    company_id: $company_id,
                                    block_id: $block_id,
                                    plaintext_hash: $plaintext_hash,
                                    hash: $hash,
                                    previous_hash: $previous_hash,
                                    signature: $signature,
                                    timestamp: $timestamp,
                                    public_key: $public_key,
                                    signatory_node_id: $signatory_node_id,
                                    data: $data,
                                    op_code: $op_code
                                };"#;

#[derive(Clone)]
pub struct SurrealCompanyChainStore {
    db: SurrealWrapper,
}

impl SurrealCompanyChainStore {
    const TABLE: &'static str = "company_chain";

    pub fn new(db: SurrealWrapper) -> Self {
        Self { db }
    }

    async fn create_block(&self, query: &str, entity: CompanyBlockDb) -> Result<()> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TABLE)?;
        bindings.add(DB_COMPANY_ID, entity.company_id)?;
        bindings.add(DB_BLOCK_ID, entity.block_id)?;
        bindings.add(DB_PLAINTEXT_HASH, entity.plaintext_hash)?;
        bindings.add(DB_HASH, entity.hash)?;
        bindings.add(DB_PREVIOUS_HASH, entity.previous_hash)?;
        bindings.add(DB_SIGNATURE, entity.signature)?;
        bindings.add(DB_TIMESTAMP, entity.timestamp)?;
        bindings.add(DB_PUBLIC_KEY, entity.public_key)?;
        bindings.add(DB_SIGNATORY_NODE_ID, entity.signatory_node_id)?;
        bindings.add(DB_DATA, entity.data)?;
        bindings.add(DB_OP_CODE, entity.op_code)?;
        self.db.query_check(query, bindings).await?;
        Ok(())
    }
}

impl ServiceTraitBounds for SurrealCompanyChainStore {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl CompanyChainStoreApi for SurrealCompanyChainStore {
    async fn get_latest_block(&self, id: &NodeId) -> Result<CompanyBlock> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TABLE)?;
        bindings.add(DB_COMPANY_ID, id.to_owned())?;
        let result: Vec<CompanyBlockDb> = self
            .db
            .query("SELECT * FROM type::table($table) WHERE company_id = $company_id ORDER BY block_id DESC LIMIT 1", bindings)
            .await
            .map_err(|e| {
                log::error!("Get Latest Company Block: {e}");
                e
            })?;

        match result.first() {
            None => Err(Error::NoCompanyBlock),
            Some(block) => Ok(block.to_owned().into()),
        }
    }

    async fn add_block(&self, id: &NodeId, block: &CompanyBlock) -> Result<()> {
        let entity: CompanyBlockDb = block.into();
        match self.get_latest_block(id).await {
            Err(Error::NoCompanyBlock) => {
                // if there is no latest block, ensure it's a valid first block
                if block.id == 1 && block.verify() && block.validate_hash() {
                    // Atomically ensure it's the first block
                    let query = format!(
                        r#"
                        BEGIN TRANSACTION;
                        LET $blocks = (RETURN count(SELECT * FROM type::table($table) WHERE company_id = $company_id));
                        IF $blocks = 0 AND $block_id = 1 {{
                            {CREATE_BLOCK_QUERY}
                        }} ELSE {{
                            THROW "invalid block - not the first block";
                        }};
                        COMMIT TRANSACTION;
                    "#
                    );
                    self.create_block(&query, entity).await.map_err(|e| {
                        log::error!("Create Company Block: {e}");
                        e
                    })?;
                    Ok(())
                } else {
                    return Err(Error::AddCompanyBlock(format!(
                        "First Block validation error: block id: {}",
                        block.id
                    )));
                }
            }
            Ok(latest_block) => {
                // if there is a latest block, ensure it's a valid follow-up block
                if !block.validate_with_previous(&latest_block) {
                    return Err(Error::AddCompanyBlock(format!(
                        "Block validation error: block id: {}, latest block id: {}",
                        block.id, latest_block.id
                    )));
                }
                // Atomically ensure the block is valid
                let query = format!(
                    r#"
                    BEGIN TRANSACTION;
                    LET $latest_block = (SELECT block_id, hash FROM type::table($table) WHERE company_id = $company_id ORDER BY block_id DESC LIMIT 1)[0];
                    IF $latest_block.block_id + 1 = $block_id AND $latest_block.hash = $previous_hash {{
                        {CREATE_BLOCK_QUERY}
                    }} ELSE {{
                        THROW "invalid block";
                    }};
                    COMMIT TRANSACTION;
                "#
                );
                self.create_block(&query, entity).await.map_err(|e| {
                    log::error!("Create Company Block: {e}");
                    e
                })?;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    async fn remove(&self, id: &NodeId) -> Result<()> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TABLE)?;
        bindings.add(DB_COMPANY_ID, id.to_owned())?;
        self.db
            .query_check(
                "DELETE FROM type::table($table) WHERE company_id = $company_id",
                bindings,
            )
            .await?;
        Ok(())
    }

    async fn get_chain(&self, id: &NodeId) -> Result<CompanyBlockchain> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TABLE)?;
        bindings.add(DB_COMPANY_ID, id.to_owned())?;
        let result: Vec<CompanyBlockDb> = self
            .db
            .query("SELECT * FROM type::table($table) WHERE company_id = $company_id ORDER BY block_id ASC", bindings)
            .await
            .map_err(|e| {
                log::error!("Get Company Chain: {e}");
                e
            })?;

        let blocks: Vec<CompanyBlock> = result.into_iter().map(|b| b.into()).collect();
        let chain = CompanyBlockchain::new_from_blocks(blocks)?;

        Ok(chain)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyBlockDb {
    pub company_id: NodeId,
    pub block_id: u64,
    pub plaintext_hash: String,
    pub hash: String,
    pub previous_hash: String,
    pub signature: String,
    pub timestamp: u64,
    pub public_key: PublicKey,
    pub signatory_node_id: NodeId,
    pub data: String,
    pub op_code: CompanyOpCode,
}

impl From<CompanyBlockDb> for CompanyBlock {
    fn from(value: CompanyBlockDb) -> Self {
        Self {
            company_id: value.company_id,
            id: value.block_id,
            plaintext_hash: value.plaintext_hash,
            hash: value.hash,
            timestamp: value.timestamp,
            data: value.data,
            public_key: value.public_key,
            signatory_node_id: value.signatory_node_id,
            previous_hash: value.previous_hash,
            signature: value.signature,
            op_code: value.op_code,
        }
    }
}

impl From<&CompanyBlock> for CompanyBlockDb {
    fn from(value: &CompanyBlock) -> Self {
        Self {
            company_id: value.company_id.clone(),
            block_id: value.id,
            plaintext_hash: value.plaintext_hash.clone(),
            hash: value.hash.clone(),
            previous_hash: value.previous_hash.clone(),
            signature: value.signature.clone(),
            timestamp: value.timestamp,
            public_key: value.public_key,
            signatory_node_id: value.signatory_node_id.clone(),
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
        tests::tests::{empty_address, empty_optional_address, node_id_test, private_key_test},
        util::BcrKeys,
    };
    use bcr_ebill_core::{
        blockchain::company::CompanyUpdateBlockData,
        company::{Company, CompanyKeys},
    };

    async fn get_store() -> SurrealCompanyChainStore {
        let mem_db = get_memory_db("test", "company_chain")
            .await
            .expect("could not create get_memory_db");
        SurrealCompanyChainStore::new(SurrealWrapper {
            db: mem_db,
            files: false,
        })
    }

    fn get_company_keys() -> CompanyKeys {
        CompanyKeys {
            private_key: private_key_test(),
            public_key: node_id_test().pub_key(),
        }
    }

    #[tokio::test]
    async fn test_add_block() {
        let store = get_store().await;
        let block = CompanyBlock::create_block_for_create(
            node_id_test(),
            "genesis hash".to_string(),
            &Company {
                id: node_id_test(),
                name: "Hayek Ltd".to_string(),
                country_of_registration: Some("AT".to_string()),
                city_of_registration: Some("Vienna".to_string()),
                postal_address: empty_address(),
                email: "hayekltd@example.com".to_string(),
                registration_number: Some("123124123".to_string()),
                registration_date: Some("2024-01-01".to_string()),
                proof_of_registration_file: None,
                logo_file: None,
                signatories: vec![node_id_test()],
                active: true,
            }
            .into(),
            &BcrKeys::new(),
            &get_company_keys(),
            1731593928,
        )
        .unwrap();
        store.add_block(&node_id_test(), &block).await.unwrap();
        let last_block = store.get_latest_block(&node_id_test()).await;
        assert!(last_block.is_ok());
        assert_eq!(last_block.as_ref().unwrap().id, 1);

        let block2 = CompanyBlock::create_block_for_update(
            node_id_test(),
            &block,
            &CompanyUpdateBlockData {
                name: None,
                email: None,
                postal_address: empty_optional_address(),
                country_of_registration: None,
                city_of_registration: None,
                registration_number: None,
                registration_date: None,
                logo_file: None,
                proof_of_registration_file: None,
            },
            &BcrKeys::new(),
            &get_company_keys(),
            1731593928,
        )
        .unwrap();
        store.add_block(&node_id_test(), &block2).await.unwrap();
        let last_block = store.get_latest_block(&node_id_test()).await;
        assert!(last_block.is_ok());
        assert_eq!(last_block.as_ref().unwrap().id, 2);
    }

    #[tokio::test]
    async fn test_remove_blockchain() {
        let store = get_store().await;
        let block = CompanyBlock::create_block_for_create(
            node_id_test(),
            "genesis hash".to_string(),
            &Company {
                id: node_id_test(),
                name: "Hayek Ltd".to_string(),
                country_of_registration: Some("AT".to_string()),
                city_of_registration: Some("Vienna".to_string()),
                postal_address: empty_address(),
                email: "hayekltd@example.com".to_string(),
                registration_number: Some("123124123".to_string()),
                registration_date: Some("2024-01-01".to_string()),
                proof_of_registration_file: None,
                logo_file: None,
                signatories: vec![node_id_test()],
                active: true,
            }
            .into(),
            &BcrKeys::new(),
            &get_company_keys(),
            1731593928,
        )
        .unwrap();
        store.add_block(&node_id_test(), &block).await.unwrap();
        let result = store.remove(&node_id_test()).await;
        assert!(result.is_ok());
    }
}
