use super::Result;
use super::bill::BillOpCode;
use super::{Block, Blockchain, FIRST_BLOCK_ID};
use crate::util::{self, BcrKeys, crypto};
use crate::{File, OptionalPostalAddress, identity::Identity};
use borsh::to_vec;
use borsh_derive::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum IdentityOpCode {
    Create,
    Update,
    SignPersonBill,
    SignCompanyBill,
    CreateCompany,
    AddSignatory,
    RemoveSignatory,
}

#[derive(BorshSerialize)]
pub struct IdentityBlockDataToHash {
    id: u64,
    previous_hash: String,
    data: String,
    timestamp: u64,
    public_key: String,
    op_code: IdentityOpCode,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IdentityBlock {
    pub id: u64,
    pub hash: String,
    pub timestamp: u64,
    pub data: String,
    pub public_key: String,
    pub previous_hash: String,
    pub signature: String,
    pub op_code: IdentityOpCode,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct IdentityCreateBlockData {
    pub node_id: String,
    pub name: String,
    pub email: Option<String>,
    pub postal_address: OptionalPostalAddress,
    pub date_of_birth: Option<String>,
    pub city_of_birth: Option<String>,
    pub country_of_birth: Option<String>,
    pub identification_number: Option<String>,
    pub nostr_relay: Option<String>,
    pub profile_picture_file: Option<File>,
    pub identity_document_file: Option<File>,
}

impl From<Identity> for IdentityCreateBlockData {
    fn from(value: Identity) -> Self {
        Self {
            node_id: value.node_id,
            name: value.name,
            email: value.email,
            date_of_birth: value.date_of_birth,
            country_of_birth: value.country_of_birth,
            city_of_birth: value.city_of_birth,
            postal_address: value.postal_address,
            identification_number: value.identification_number,
            nostr_relay: value.nostr_relay,
            profile_picture_file: value.profile_picture_file,
            identity_document_file: value.identity_document_file,
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct IdentityUpdateBlockData {
    pub name: Option<String>,
    pub email: Option<String>,
    pub postal_address: OptionalPostalAddress,
    pub date_of_birth: Option<String>,
    pub country_of_birth: Option<String>,
    pub city_of_birth: Option<String>,
    pub identification_number: Option<String>,
    pub profile_picture_file: Option<File>,
    pub identity_document_file: Option<File>,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct IdentitySignPersonBillBlockData {
    pub bill_id: String,
    pub block_id: u64,
    pub block_hash: String,
    pub operation: BillOpCode,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct IdentitySignCompanyBillBlockData {
    pub bill_id: String,
    pub block_id: u64,
    pub block_hash: String,
    pub company_id: String,
    pub operation: BillOpCode,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct IdentityCreateCompanyBlockData {
    pub company_id: String,
    pub block_hash: String,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct IdentityAddSignatoryBlockData {
    pub company_id: String,
    pub block_id: u64,
    pub block_hash: String,
    pub signatory: String,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct IdentityRemoveSignatoryBlockData {
    pub company_id: String,
    pub block_id: u64,
    pub block_hash: String,
    pub signatory: String,
}

impl Block for IdentityBlock {
    type OpCode = IdentityOpCode;
    type BlockDataToHash = IdentityBlockDataToHash;

    fn id(&self) -> u64 {
        self.id
    }

    fn timestamp(&self) -> u64 {
        self.timestamp
    }

    fn op_code(&self) -> &Self::OpCode {
        &self.op_code
    }

    fn hash(&self) -> &str {
        &self.hash
    }

    fn previous_hash(&self) -> &str {
        &self.previous_hash
    }

    fn data(&self) -> &str {
        &self.data
    }

    fn signature(&self) -> &str {
        &self.signature
    }

    fn public_key(&self) -> &str {
        &self.public_key
    }

    fn validate(&self) -> bool {
        true
    }

    fn get_block_data_to_hash(&self) -> Self::BlockDataToHash {
        IdentityBlockDataToHash {
            id: self.id(),
            previous_hash: self.previous_hash().to_owned(),
            data: self.data().to_owned(),
            timestamp: self.timestamp(),
            public_key: self.public_key().to_owned(),
            op_code: self.op_code().to_owned(),
        }
    }
}

impl IdentityBlock {
    fn new(
        id: u64,
        previous_hash: String,
        data: String,
        op_code: IdentityOpCode,
        keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let hash = Self::calculate_hash(IdentityBlockDataToHash {
            id,
            previous_hash: previous_hash.clone(),
            data: data.clone(),
            timestamp,
            public_key: keys.get_public_key(),
            op_code: op_code.clone(),
        })?;
        let signature = crypto::signature(&hash, &keys.get_private_key_string())?;

        Ok(Self {
            id,
            hash,
            timestamp,
            previous_hash,
            signature,
            public_key: keys.get_public_key(),
            data,
            op_code,
        })
    }

    pub fn create_block_for_create(
        genesis_hash: String,
        identity: &IdentityCreateBlockData,
        keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let identity_bytes = to_vec(identity)?;

        let encrypted_data = util::base58_encode(&util::crypto::encrypt_ecies(
            &identity_bytes,
            &keys.get_public_key(),
        )?);

        Self::new(
            FIRST_BLOCK_ID,
            genesis_hash,
            encrypted_data,
            IdentityOpCode::Create,
            keys,
            timestamp,
        )
    }

    pub fn create_block_for_update(
        previous_block: &Self,
        data: &IdentityUpdateBlockData,
        keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            previous_block,
            data,
            keys,
            timestamp,
            IdentityOpCode::Update,
        )?;
        Ok(block)
    }

    pub fn create_block_for_sign_person_bill(
        previous_block: &Self,
        data: &IdentitySignPersonBillBlockData,
        keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            previous_block,
            data,
            keys,
            timestamp,
            IdentityOpCode::SignPersonBill,
        )?;
        Ok(block)
    }

    pub fn create_block_for_sign_company_bill(
        previous_block: &Self,
        data: &IdentitySignCompanyBillBlockData,
        keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            previous_block,
            data,
            keys,
            timestamp,
            IdentityOpCode::SignCompanyBill,
        )?;
        Ok(block)
    }

    pub fn create_block_for_create_company(
        previous_block: &Self,
        data: &IdentityCreateCompanyBlockData,
        keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            previous_block,
            data,
            keys,
            timestamp,
            IdentityOpCode::CreateCompany,
        )?;
        Ok(block)
    }

    pub fn create_block_for_add_signatory(
        previous_block: &Self,
        data: &IdentityAddSignatoryBlockData,
        keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            previous_block,
            data,
            keys,
            timestamp,
            IdentityOpCode::AddSignatory,
        )?;
        Ok(block)
    }

    pub fn create_block_for_remove_signatory(
        previous_block: &Self,
        data: &IdentityRemoveSignatoryBlockData,
        keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            previous_block,
            data,
            keys,
            timestamp,
            IdentityOpCode::RemoveSignatory,
        )?;
        Ok(block)
    }

    fn encrypt_data_create_block_and_validate<T: borsh::BorshSerialize>(
        previous_block: &Self,
        data: &T,
        keys: &BcrKeys,
        timestamp: u64,
        op_code: IdentityOpCode,
    ) -> Result<Self> {
        let bytes = to_vec(&data)?;

        let encrypted_data = util::base58_encode(&util::crypto::encrypt_ecies(
            &bytes,
            &keys.get_public_key(),
        )?);

        let new_block = Self::new(
            previous_block.id + 1,
            previous_block.hash.clone(),
            encrypted_data,
            op_code,
            keys,
            timestamp,
        )?;

        if !new_block.validate_with_previous(previous_block) {
            return Err(super::Error::BlockInvalid);
        }
        Ok(new_block)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IdentityBlockchain {
    blocks: Vec<IdentityBlock>,
}

impl Blockchain for IdentityBlockchain {
    type Block = IdentityBlock;

    fn blocks(&self) -> &Vec<Self::Block> {
        &self.blocks
    }

    fn blocks_mut(&mut self) -> &mut Vec<Self::Block> {
        &mut self.blocks
    }
}

impl IdentityBlockchain {
    /// Creates a new identity chain
    pub fn new(identity: &IdentityCreateBlockData, keys: &BcrKeys, timestamp: u64) -> Result<Self> {
        let genesis_hash = util::base58_encode(keys.get_public_key().as_bytes());

        let first_block =
            IdentityBlock::create_block_for_create(genesis_hash, identity, keys, timestamp)?;

        Ok(Self {
            blocks: vec![first_block],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::tests::{empty_identity, valid_optional_address};

    #[test]
    fn create_and_check_validity() {
        let identity = empty_identity();

        let chain = IdentityBlockchain::new(&identity.into(), &BcrKeys::new(), 1731593928);
        assert!(chain.is_ok());
        assert!(chain.as_ref().unwrap().is_chain_valid());
    }

    #[test]
    fn multi_block() {
        let identity = empty_identity();
        let keys = BcrKeys::new();

        let chain = IdentityBlockchain::new(&identity.into(), &keys, 1731593928);
        assert!(chain.is_ok());
        assert!(chain.as_ref().unwrap().is_chain_valid());
        let mut chain = chain.unwrap();

        let update_block = IdentityBlock::create_block_for_update(
            chain.get_latest_block(),
            &IdentityUpdateBlockData {
                name: Some("newname".to_string()),
                email: None,
                postal_address: valid_optional_address(),
                date_of_birth: None,
                country_of_birth: None,
                city_of_birth: None,
                identification_number: None,
                profile_picture_file: None,
                identity_document_file: None,
            },
            &keys,
            1731593928,
        );
        assert!(update_block.is_ok());
        chain.try_add_block(update_block.unwrap());

        let sign_person_bill_block = IdentityBlock::create_block_for_sign_person_bill(
            chain.get_latest_block(),
            &IdentitySignPersonBillBlockData {
                bill_id: "some_bill".to_string(),
                block_id: 1,
                block_hash: "some hash".to_string(),
                operation: BillOpCode::Issue,
            },
            &keys,
            1731593928,
        );
        assert!(sign_person_bill_block.is_ok());
        chain.try_add_block(sign_person_bill_block.unwrap());

        let sign_company_bill_block = IdentityBlock::create_block_for_sign_company_bill(
            chain.get_latest_block(),
            &IdentitySignCompanyBillBlockData {
                bill_id: "some_bill".to_string(),
                block_id: 1,
                block_hash: "some hash".to_string(),
                company_id: "some_id".to_string(),
                operation: BillOpCode::Issue,
            },
            &keys,
            1731593928,
        );
        assert!(sign_company_bill_block.is_ok());
        chain.try_add_block(sign_company_bill_block.unwrap());

        let create_company_block = IdentityBlock::create_block_for_create_company(
            chain.get_latest_block(),
            &IdentityCreateCompanyBlockData {
                company_id: "some id".to_string(),
                block_hash: "some hash".to_string(),
            },
            &keys,
            1731593928,
        );
        assert!(create_company_block.is_ok());
        chain.try_add_block(create_company_block.unwrap());

        let add_signatory_block = IdentityBlock::create_block_for_add_signatory(
            chain.get_latest_block(),
            &IdentityAddSignatoryBlockData {
                company_id: "some_id".to_string(),
                block_id: 2,
                block_hash: "some_hash".to_string(),
                signatory: "some_signatory".to_string(),
            },
            &keys,
            1731593928,
        );
        assert!(add_signatory_block.is_ok());
        chain.try_add_block(add_signatory_block.unwrap());

        let remove_signatory_block = IdentityBlock::create_block_for_remove_signatory(
            chain.get_latest_block(),
            &IdentityRemoveSignatoryBlockData {
                company_id: "some_id".to_string(),
                block_id: 2,
                block_hash: "some_hash".to_string(),
                signatory: "some_signatory".to_string(),
            },
            &keys,
            1731593928,
        );
        assert!(remove_signatory_block.is_ok());
        chain.try_add_block(remove_signatory_block.unwrap());

        assert_eq!(chain.blocks().len(), 7);
        assert!(chain.is_chain_valid());
    }
}
