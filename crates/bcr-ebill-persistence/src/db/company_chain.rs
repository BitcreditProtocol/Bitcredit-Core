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
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    application::ServiceTraitBounds,
    protocol::{
        BlockId, PublicKey, SchnorrSignature, Sha256Hash, Timestamp,
        blockchain::{
            Block,
            company::{CompanyBlock, CompanyBlockchain, CompanyOpCode},
        },
    },
};
use bitcoin::base58;
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
            None => Err(Error::NoSuchEntity(
                "company block".to_string(),
                id.to_string(),
            )),
            Some(block) => block.to_owned().try_into(),
        }
    }

    async fn add_block(&self, id: &NodeId, block: &CompanyBlock) -> Result<()> {
        let entity: CompanyBlockDb = block.into();
        match self.get_latest_block(id).await {
            Err(Error::NoSuchEntity(_, _)) => {
                // if there is no latest block, ensure it's a valid first block
                if block.id.is_first() && block.verify() && block.validate_hash() {
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
                    return Err(Error::InsertFailed(format!(
                        "First Company Block validation error: block id: {}",
                        block.id
                    )));
                }
            }
            Ok(latest_block) => {
                // if there is a latest block, ensure it's a valid follow-up block
                if !block.validate_with_previous(&latest_block) {
                    return Err(Error::InsertFailed(format!(
                        "Company Block validation error: block id: {}, latest block id: {}",
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

        let blocks: Result<Vec<CompanyBlock>> = result.into_iter().map(|b| b.try_into()).collect();
        let chain =
            CompanyBlockchain::new_from_blocks(blocks?).map_err(|e| Error::Protocol(e.into()))?;

        Ok(chain)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyBlockDb {
    pub company_id: NodeId,
    pub block_id: BlockId,
    pub plaintext_hash: Sha256Hash,
    pub hash: Sha256Hash,
    pub previous_hash: Sha256Hash,
    pub signature: SchnorrSignature,
    pub timestamp: Timestamp,
    pub public_key: PublicKey,
    pub signatory_node_id: NodeId,
    pub data: String,
    pub op_code: CompanyOpCode,
}

impl TryFrom<CompanyBlockDb> for CompanyBlock {
    type Error = Error;

    fn try_from(value: CompanyBlockDb) -> Result<Self> {
        Ok(Self {
            company_id: value.company_id,
            id: value.block_id,
            plaintext_hash: value.plaintext_hash,
            hash: value.hash,
            timestamp: value.timestamp,
            data: base58::decode(&value.data).map_err(|_| Error::EncodingError)?,
            public_key: value.public_key,
            signatory_node_id: value.signatory_node_id,
            previous_hash: value.previous_hash,
            signature: value.signature,
            op_code: value.op_code,
        })
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
            data: base58::encode(&value.data.clone()),
            op_code: value.op_code.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        db::get_memory_db,
        protocol::crypto::BcrKeys,
        tests::tests::{empty_address, empty_optional_address, node_id_test, private_key_test},
    };
    use bcr_ebill_core::{
        application::company::{Company, CompanySignatory},
        protocol::{
            City, Country, Date, Email, Identification, Name,
            blockchain::company::CompanyUpdateBlockData,
        },
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

    fn get_company_keys() -> BcrKeys {
        BcrKeys::from_private_key(&private_key_test())
    }

    #[tokio::test]
    async fn test_add_block() {
        let store = get_store().await;
        let block = CompanyBlock::create_block_for_create(
            node_id_test(),
            Sha256Hash::new("genesis hash"),
            &Company {
                id: node_id_test(),
                name: Name::new("Hayek Ltd").unwrap(),
                country_of_registration: Some(Country::AT),
                city_of_registration: Some(City::new("Vienna").unwrap()),
                postal_address: empty_address(),
                email: Email::new("hayekltd@example.com").unwrap(),
                registration_number: Some(Identification::new("123124123").unwrap()),
                registration_date: Some(Date::new("2024-01-01").unwrap()),
                proof_of_registration_file: None,
                logo_file: None,
                signatories: vec![CompanySignatory {
                    node_id: node_id_test(),
                    email: Email::new("test@example.com").unwrap(),
                }],
                active: true,
            }
            .into(),
            &BcrKeys::new(),
            &get_company_keys(),
            Timestamp::new(1731593928).unwrap(),
        )
        .unwrap();
        store.add_block(&node_id_test(), &block).await.unwrap();
        let last_block = store.get_latest_block(&node_id_test()).await;
        assert!(last_block.is_ok());
        assert_eq!(last_block.as_ref().unwrap().id.inner(), 1);

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
            Timestamp::new(1731593928).unwrap(),
        )
        .unwrap();
        store.add_block(&node_id_test(), &block2).await.unwrap();
        let last_block = store.get_latest_block(&node_id_test()).await;
        assert!(last_block.is_ok());
        assert_eq!(last_block.as_ref().unwrap().id.inner(), 2);
    }

    #[tokio::test]
    async fn test_remove_blockchain() {
        let store = get_store().await;
        let block = CompanyBlock::create_block_for_create(
            node_id_test(),
            Sha256Hash::new("genesis hash"),
            &Company {
                id: node_id_test(),
                name: Name::new("Hayek Ltd").unwrap(),
                country_of_registration: Some(Country::AT),
                city_of_registration: Some(City::new("Vienna").unwrap()),
                postal_address: empty_address(),
                email: Email::new("hayekltd@example.com").unwrap(),
                registration_number: Some(Identification::new("123124123").unwrap()),
                registration_date: Some(Date::new("2024-01-01").unwrap()),
                proof_of_registration_file: None,
                logo_file: None,
                signatories: vec![CompanySignatory {
                    node_id: node_id_test(),
                    email: Email::new("test@example.com").unwrap(),
                }],
                active: true,
            }
            .into(),
            &BcrKeys::new(),
            &get_company_keys(),
            Timestamp::new(1731593928).unwrap(),
        )
        .unwrap();
        store.add_block(&node_id_test(), &block).await.unwrap();
        let result = store.remove(&node_id_test()).await;
        assert!(result.is_ok());
    }
}
