use super::Result;
use super::bill::BillOpCode;
use super::{Block, Blockchain, FIRST_BLOCK_ID};
use crate::NodeId;
use crate::bill::BillId;
use crate::util::{self, BcrKeys, crypto};
use crate::{
    File, OptionalPostalAddress, PostalAddress,
    company::{Company, CompanyKeys},
};
use borsh::{from_slice, to_vec};
use borsh_derive::{BorshDeserialize, BorshSerialize};
use log::error;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum CompanyOpCode {
    Create,
    Update,
    AddSignatory,
    RemoveSignatory,
    SignCompanyBill,
}

#[derive(BorshSerialize)]
pub struct CompanyBlockDataToHash {
    company_id: NodeId,
    id: u64,
    plaintext_hash: String,
    previous_hash: String,
    data: String,
    timestamp: u64,
    public_key: String,
    signatory_node_id: NodeId,
    op_code: CompanyOpCode,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum SignatoryType {
    Solo,
}

/// Structure for the block data of a company block
///
/// - `data` contains the actual data of the block, encrypted using the company's pub key
/// - `key` is optional and if set, contains the company private keys encrypted by an identity
///   pub key (e.g. for CreateCompany the creator's and AddSignatory the signatory's)
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct CompanyBlockData {
    data: String,
    key: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CompanyBlock {
    pub company_id: NodeId,
    pub id: u64,
    pub plaintext_hash: String,
    pub hash: String,
    pub timestamp: u64,
    pub data: String,
    pub public_key: PublicKey,
    pub signatory_node_id: NodeId,
    pub previous_hash: String,
    pub signature: String,
    pub op_code: CompanyOpCode,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct CompanyCreateBlockData {
    pub id: NodeId,
    pub name: String,
    pub country_of_registration: Option<String>,
    pub city_of_registration: Option<String>,
    pub postal_address: PostalAddress,
    pub email: String,
    pub registration_number: Option<String>,
    pub registration_date: Option<String>,
    pub proof_of_registration_file: Option<File>,
    pub logo_file: Option<File>,
    pub signatories: Vec<NodeId>,
}

impl From<Company> for CompanyCreateBlockData {
    fn from(value: Company) -> Self {
        Self {
            id: value.id,
            name: value.name,
            country_of_registration: value.country_of_registration,
            city_of_registration: value.city_of_registration,
            postal_address: value.postal_address,
            email: value.email,
            registration_number: value.registration_number,
            registration_date: value.registration_date,
            proof_of_registration_file: value.proof_of_registration_file,
            logo_file: value.logo_file,
            signatories: value.signatories,
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Default, PartialEq)]
pub struct CompanyUpdateBlockData {
    pub name: Option<String>,
    pub email: Option<String>,
    pub postal_address: OptionalPostalAddress,
    pub country_of_registration: Option<String>,
    pub city_of_registration: Option<String>,
    pub registration_number: Option<String>,
    pub registration_date: Option<String>,
    pub logo_file: Option<File>,
    pub proof_of_registration_file: Option<File>,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct CompanySignCompanyBillBlockData {
    pub bill_id: BillId,
    pub block_id: u64,
    pub block_hash: String,
    pub operation: BillOpCode,
    pub bill_key: Option<String>,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct CompanyAddSignatoryBlockData {
    pub signatory: NodeId,
    pub t: SignatoryType,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct CompanyRemoveSignatoryBlockData {
    pub signatory: NodeId,
}

#[derive(Debug)]
pub enum CompanyBlockPayload {
    Create(CompanyCreateBlockData),
    Update(CompanyUpdateBlockData),
    SignBill(CompanySignCompanyBillBlockData),
    AddSignatory(CompanyAddSignatoryBlockData),
    RemoveSignatory(CompanyRemoveSignatoryBlockData),
}

impl Block for CompanyBlock {
    type OpCode = CompanyOpCode;
    type BlockDataToHash = CompanyBlockDataToHash;

    fn id(&self) -> u64 {
        self.id
    }

    fn timestamp(&self) -> u64 {
        self.timestamp
    }

    fn op_code(&self) -> &Self::OpCode {
        &self.op_code
    }

    fn plaintext_hash(&self) -> &str {
        &self.plaintext_hash
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

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn validate(&self) -> bool {
        true
    }

    /// We validate the plaintext hash against the plaintext data from the CompanyBlockData wrapper
    fn validate_plaintext_hash(&self, private_key: &secp256k1::SecretKey) -> bool {
        match util::base58_decode(&self.data) {
            Ok(decoded_wrapper) => match from_slice::<CompanyBlockData>(&decoded_wrapper) {
                Ok(data_wrapper) => match util::base58_decode(&data_wrapper.data) {
                    Ok(decoded) => match util::crypto::decrypt_ecies(&decoded, private_key) {
                        Ok(decrypted) => self.plaintext_hash() == util::sha256_hash(&decrypted),
                        Err(e) => {
                            error!(
                                "Decrypt Error while validating plaintext hash for id {}: {e}",
                                self.id()
                            );
                            false
                        }
                    },
                    Err(e) => {
                        error!(
                            "Decode Error while validating plaintext hash for id {}: {e}",
                            self.id()
                        );
                        false
                    }
                },
                Err(e) => {
                    error!(
                        "Wrapper Deserialize Error while validating plaintext hash for id {}: {e}",
                        self.id()
                    );
                    false
                }
            },
            Err(e) => {
                error!(
                    "Wrapper Decode Error while validating plaintext hash for id {}: {e}",
                    self.id()
                );
                false
            }
        }
    }

    fn get_block_data_to_hash(&self) -> Self::BlockDataToHash {
        CompanyBlockDataToHash {
            company_id: self.company_id.clone(),
            id: self.id(),
            plaintext_hash: self.plaintext_hash().to_owned(),
            previous_hash: self.previous_hash().to_owned(),
            data: self.data().to_owned(),
            timestamp: self.timestamp(),
            public_key: self.public_key().to_string(),
            signatory_node_id: self.signatory_node_id.clone(),
            op_code: self.op_code().to_owned(),
        }
    }
}

impl CompanyBlock {
    /// Create a new block and sign it with an aggregated key, combining the identity key of the
    /// signer and the company key
    fn new(
        company_id: NodeId,
        id: u64,
        previous_hash: String,
        data: String,
        op_code: CompanyOpCode,
        identity_keys: &BcrKeys,
        company_keys: &CompanyKeys,
        timestamp: u64,
        plaintext_hash: String,
    ) -> Result<Self> {
        // The order here is important: identity -> company
        let keys: Vec<secp256k1::SecretKey> = vec![
            identity_keys.get_private_key(),
            company_keys.private_key.to_owned(),
        ];
        let signatory_node_id = NodeId::new(identity_keys.pub_key(), company_id.network());
        let aggregated_public_key = crypto::get_aggregated_public_key(&keys)?;
        let hash = Self::calculate_hash(CompanyBlockDataToHash {
            company_id: company_id.clone(),
            id,
            plaintext_hash: plaintext_hash.clone(),
            previous_hash: previous_hash.clone(),
            data: data.clone(),
            timestamp,
            public_key: aggregated_public_key.to_string(),
            signatory_node_id: signatory_node_id.clone(),
            op_code: op_code.clone(),
        })?;
        let signature = crypto::aggregated_signature(&hash, &keys)?;

        Ok(Self {
            company_id,
            id,
            plaintext_hash,
            hash,
            timestamp,
            previous_hash,
            signature,
            public_key: aggregated_public_key,
            signatory_node_id,
            data,
            op_code,
        })
    }

    pub fn create_block_for_create(
        company_id: NodeId,
        genesis_hash: String,
        company: &CompanyCreateBlockData,
        identity_keys: &BcrKeys,
        company_keys: &CompanyKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let company_bytes = to_vec(company)?;
        let plaintext_hash = Self::calculate_plaintext_hash(company)?;
        // encrypt data using company pub key
        let encrypted_data = util::base58_encode(&util::crypto::encrypt_ecies(
            &company_bytes,
            &BcrKeys::try_from(company_keys)?.pub_key(),
        )?);

        let key_bytes = to_vec(&company_keys.get_private_key_string())?;
        // encrypt company keys using creator's identity pub key
        let encrypted_key = util::base58_encode(&util::crypto::encrypt_ecies(
            &key_bytes,
            &identity_keys.pub_key(),
        )?);

        let data = CompanyBlockData {
            data: encrypted_data,
            key: Some(encrypted_key),
        };
        let serialized_and_hashed_data = util::base58_encode(&to_vec(&data)?);

        Self::new(
            company_id.to_owned(),
            FIRST_BLOCK_ID,
            genesis_hash,
            serialized_and_hashed_data,
            CompanyOpCode::Create,
            identity_keys,
            company_keys,
            timestamp,
            plaintext_hash,
        )
    }

    pub fn create_block_for_update(
        company_id: NodeId,
        previous_block: &Self,
        data: &CompanyUpdateBlockData,
        identity_keys: &BcrKeys,
        company_keys: &CompanyKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            company_id,
            previous_block,
            data,
            identity_keys,
            company_keys,
            None,
            timestamp,
            CompanyOpCode::Update,
        )?;
        Ok(block)
    }

    pub fn create_block_for_sign_company_bill(
        company_id: NodeId,
        previous_block: &Self,
        data: &CompanySignCompanyBillBlockData,
        identity_keys: &BcrKeys,
        company_keys: &CompanyKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            company_id,
            previous_block,
            data,
            identity_keys,
            company_keys,
            None,
            timestamp,
            CompanyOpCode::SignCompanyBill,
        )?;
        Ok(block)
    }

    pub fn create_block_for_add_signatory(
        company_id: NodeId,
        previous_block: &Self,
        data: &CompanyAddSignatoryBlockData,
        identity_keys: &BcrKeys,
        company_keys: &CompanyKeys,
        signatory_public_key: &PublicKey, // the signatory's public key
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            company_id,
            previous_block,
            data,
            identity_keys,
            company_keys,
            Some(signatory_public_key),
            timestamp,
            CompanyOpCode::AddSignatory,
        )?;
        Ok(block)
    }

    pub fn create_block_for_remove_signatory(
        company_id: NodeId,
        previous_block: &Self,
        data: &CompanyRemoveSignatoryBlockData,
        identity_keys: &BcrKeys,
        company_keys: &CompanyKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            company_id,
            previous_block,
            data,
            identity_keys,
            company_keys,
            None,
            timestamp,
            CompanyOpCode::RemoveSignatory,
        )?;
        Ok(block)
    }

    pub fn get_block_data(&self, company_keys: &CompanyKeys) -> Result<CompanyBlockPayload> {
        let data = self.get_decrypted_block(company_keys)?;
        let result: CompanyBlockPayload = match self.op_code {
            CompanyOpCode::Create => CompanyBlockPayload::Create(from_slice(&data)?),
            CompanyOpCode::Update => CompanyBlockPayload::Update(from_slice(&data)?),
            CompanyOpCode::AddSignatory => CompanyBlockPayload::AddSignatory(from_slice(&data)?),
            CompanyOpCode::RemoveSignatory => {
                CompanyBlockPayload::RemoveSignatory(from_slice(&data)?)
            }
            CompanyOpCode::SignCompanyBill => CompanyBlockPayload::SignBill(from_slice(&data)?),
        };
        Ok(result)
    }

    fn get_decrypted_block(&self, company_keys: &CompanyKeys) -> Result<Vec<u8>> {
        let bytes = util::base58_decode(&self.data)?;
        let block_data: CompanyBlockData = from_slice(&bytes)?;
        let decoded_data_bytes = util::base58_decode(&block_data.data)?;
        let decrypted_bytes =
            util::crypto::decrypt_ecies(&decoded_data_bytes, &company_keys.private_key)?;
        Ok(decrypted_bytes)
    }

    fn encrypt_data_create_block_and_validate<T: borsh::BorshSerialize>(
        company_id: NodeId,
        previous_block: &Self,
        data: &T,
        identity_keys: &BcrKeys,
        company_keys: &CompanyKeys,
        public_key_for_keys: Option<&PublicKey>,
        timestamp: u64,
        op_code: CompanyOpCode,
    ) -> Result<Self> {
        let bytes = to_vec(&data)?;
        let plaintext_hash = Self::calculate_plaintext_hash(data)?;
        // encrypt data using the company pub key
        let encrypted_data = util::base58_encode(&util::crypto::encrypt_ecies(
            &bytes,
            &BcrKeys::try_from(company_keys)?.pub_key(),
        )?);

        let mut key = None;

        // in case there are keys to encrypt, encrypt them using the receiver's identity pub key
        if op_code == CompanyOpCode::AddSignatory
            && let Some(signatory_public_key) = public_key_for_keys
        {
            let key_bytes = to_vec(&company_keys.get_private_key_string())?;
            let encrypted_key = util::base58_encode(&util::crypto::encrypt_ecies(
                &key_bytes,
                signatory_public_key,
            )?);
            key = Some(encrypted_key);
        }

        let data = CompanyBlockData {
            data: encrypted_data,
            key,
        };
        let serialized_and_hashed_data = util::base58_encode(&to_vec(&data)?);

        let new_block = Self::new(
            company_id,
            previous_block.id + 1,
            previous_block.hash.clone(),
            serialized_and_hashed_data,
            op_code,
            identity_keys,
            company_keys,
            timestamp,
            plaintext_hash,
        )?;

        if !new_block.validate_with_previous(previous_block) {
            return Err(super::Error::BlockInvalid);
        }
        Ok(new_block)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CompanyBlockchain {
    blocks: Vec<CompanyBlock>,
}

impl Blockchain for CompanyBlockchain {
    type Block = CompanyBlock;

    fn blocks(&self) -> &Vec<Self::Block> {
        &self.blocks
    }

    fn blocks_mut(&mut self) -> &mut Vec<Self::Block> {
        &mut self.blocks
    }
}

impl CompanyBlockchain {
    /// Creates a new company chain
    pub fn new(
        company: &CompanyCreateBlockData,
        identity_keys: &BcrKeys,
        company_keys: &CompanyKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let genesis_hash = util::base58_encode(company.id.to_string().as_bytes());

        let first_block = CompanyBlock::create_block_for_create(
            company.id.clone(),
            genesis_hash,
            company,
            identity_keys,
            company_keys,
            timestamp,
        )?;

        Ok(Self {
            blocks: vec![first_block],
        })
    }

    /// Creates a company chain from a vec of blocks
    pub fn new_from_blocks(blocks_to_add: Vec<CompanyBlock>) -> Result<Self> {
        match blocks_to_add.first() {
            None => Err(super::Error::BlockchainInvalid),
            Some(first) => {
                if !first.verify() || !first.validate_hash() {
                    return Err(super::Error::BlockchainInvalid);
                }

                let chain = Self {
                    blocks: blocks_to_add,
                };

                if !chain.is_chain_valid() {
                    return Err(super::Error::BlockchainInvalid);
                }

                Ok(chain)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::tests::{
        bill_id_test, node_id_test, private_key_test, valid_address, valid_optional_address,
    };

    fn get_baseline_company_data() -> (NodeId, (Company, CompanyKeys)) {
        (
            node_id_test(),
            (
                Company {
                    id: node_id_test(),
                    name: "some_name".to_string(),
                    country_of_registration: Some("AT".to_string()),
                    city_of_registration: Some("Vienna".to_string()),
                    postal_address: valid_address(),
                    email: "company@example.com".to_string(),
                    registration_number: Some("some_number".to_string()),
                    registration_date: Some("2012-01-01".to_string()),
                    proof_of_registration_file: None,
                    logo_file: None,
                    signatories: vec![node_id_test()],
                },
                CompanyKeys {
                    private_key: private_key_test(),
                    public_key: node_id_test().pub_key(),
                },
            ),
        )
    }

    #[test]
    fn test_plaintext_hash() {
        let (_id, (company, company_keys)) = get_baseline_company_data();

        let chain = CompanyBlockchain::new(
            &CompanyCreateBlockData::from(company),
            &BcrKeys::new(),
            &company_keys,
            1731593928,
        );
        assert!(chain.is_ok());
        assert!(chain.as_ref().unwrap().is_chain_valid());
        assert!(
            chain.as_ref().unwrap().blocks()[0].validate_plaintext_hash(&company_keys.private_key)
        );
    }

    #[test]
    fn create_and_check_validity() {
        let (_id, (company, company_keys)) = get_baseline_company_data();

        let chain = CompanyBlockchain::new(
            &CompanyCreateBlockData::from(company),
            &BcrKeys::new(),
            &company_keys,
            1731593928,
        );
        assert!(chain.is_ok());
        assert!(chain.as_ref().unwrap().is_chain_valid());
    }

    #[test]
    fn multi_block() {
        let (id, (company, company_keys)) = get_baseline_company_data();
        let identity_keys = BcrKeys::new();

        let chain = CompanyBlockchain::new(
            &CompanyCreateBlockData::from(company),
            &identity_keys,
            &company_keys,
            1731593928,
        );
        assert!(chain.is_ok());
        assert!(chain.as_ref().unwrap().is_chain_valid());

        let mut chain = chain.unwrap();
        let update_block = CompanyBlock::create_block_for_update(
            id.clone(),
            chain.get_latest_block(),
            &CompanyUpdateBlockData {
                name: Some("new_name".to_string()),
                email: None,
                postal_address: valid_optional_address(),
                country_of_registration: None,
                city_of_registration: None,
                registration_number: None,
                registration_date: None,
                logo_file: None,
                proof_of_registration_file: None,
            },
            &identity_keys,
            &company_keys,
            1731593929,
        );
        assert!(update_block.is_ok());
        chain.try_add_block(update_block.unwrap());

        let bill_block = CompanyBlock::create_block_for_sign_company_bill(
            id.clone(),
            chain.get_latest_block(),
            &CompanySignCompanyBillBlockData {
                bill_id: bill_id_test(),
                block_id: 1,
                block_hash: "some hash".to_string(),
                operation: BillOpCode::Issue,
                bill_key: Some(private_key_test().display_secret().to_string()),
            },
            &identity_keys,
            &company_keys,
            1731593930,
        );
        assert!(bill_block.is_ok());
        chain.try_add_block(bill_block.unwrap());

        let add_signatory_block = CompanyBlock::create_block_for_add_signatory(
            id.clone(),
            chain.get_latest_block(),
            &CompanyAddSignatoryBlockData {
                signatory: node_id_test(),
                t: SignatoryType::Solo,
            },
            &identity_keys,
            &company_keys,
            &node_id_test().pub_key(),
            1731593931,
        );
        assert!(add_signatory_block.is_ok());
        chain.try_add_block(add_signatory_block.unwrap());

        let remove_signatory_block = CompanyBlock::create_block_for_remove_signatory(
            id.clone(),
            chain.get_latest_block(),
            &CompanyRemoveSignatoryBlockData {
                signatory: node_id_test(),
            },
            &identity_keys,
            &company_keys,
            1731593932,
        );
        assert!(remove_signatory_block.is_ok());
        chain.try_add_block(remove_signatory_block.unwrap());

        assert_eq!(chain.blocks().len(), 5);
        assert!(chain.is_chain_valid());

        let new_chain_from_empty_blocks = CompanyBlockchain::new_from_blocks(vec![]);
        assert!(new_chain_from_empty_blocks.is_err());

        let blocks = chain.blocks();

        for block in blocks {
            assert!(block.validate_plaintext_hash(&company_keys.private_key));
        }

        let new_chain_from_blocks = CompanyBlockchain::new_from_blocks(blocks.to_owned());
        assert!(new_chain_from_blocks.is_ok());
        assert!(new_chain_from_blocks.as_ref().unwrap().is_chain_valid());

        let mut_blocks = chain.blocks_mut();
        mut_blocks[2].hash = "invalidhash".to_string();
        let new_chain_from_invalid_blocks =
            CompanyBlockchain::new_from_blocks(mut_blocks.to_owned());
        assert!(new_chain_from_invalid_blocks.is_err());
    }
}
