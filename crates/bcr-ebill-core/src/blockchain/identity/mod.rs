use super::Result;
use super::bill::BillOpCode;
use super::{Block, Blockchain};
use crate::block_id::BlockId;
use crate::blockchain::{Error, borsh_to_json_value};
use crate::city::City;
use crate::country::Country;
use crate::date::Date;
use crate::email::Email;
use crate::hash::Sha256Hash;
use crate::identification::Identification;
use crate::identity::IdentityType;
use crate::identity_proof::IdentityProofStamp;
use crate::name::Name;
use crate::signature::SchnorrSignature;
use crate::timestamp::Timestamp;
use crate::util::{self, BcrKeys, crypto};
use crate::{Field, Validate, ValidationError};
use crate::{File, OptionalPostalAddress, identity::Identity};
use bcr_common::core::{BillId, NodeId};
use borsh::{from_slice, to_vec};
use borsh_derive::{BorshDeserialize, BorshSerialize};
use log::error;
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum IdentityOpCode {
    Create,
    Update,
    SignPersonBill,
    SignCompanyBill,
    CreateCompany,
    AddSignatory,
    RemoveSignatory,
    IdentityProof,
}

#[derive(BorshSerialize)]
pub struct IdentityBlockDataToHash {
    id: BlockId,
    plaintext_hash: Sha256Hash,
    previous_hash: Sha256Hash,
    data: Vec<u8>,
    timestamp: Timestamp,
    #[borsh(
        serialize_with = "crate::util::borsh::serialize_pubkey",
        deserialize_with = "crate::util::borsh::deserialize_pubkey"
    )]
    public_key: PublicKey,
    op_code: IdentityOpCode,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IdentityBlock {
    pub id: BlockId,
    pub plaintext_hash: Sha256Hash,
    pub hash: Sha256Hash,
    pub timestamp: Timestamp,
    pub data: Vec<u8>,
    #[borsh(
        serialize_with = "crate::util::borsh::serialize_pubkey",
        deserialize_with = "crate::util::borsh::deserialize_pubkey"
    )]
    pub public_key: PublicKey,
    pub previous_hash: Sha256Hash,
    pub signature: SchnorrSignature,
    pub op_code: IdentityOpCode,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct IdentityBlockPlaintextWrapper {
    pub block: IdentityBlock,
    pub plaintext_data_bytes: Vec<u8>,
}

impl IdentityBlockPlaintextWrapper {
    /// This is only used for dev mode
    pub fn to_json_text(&self) -> Result<String> {
        let mut serialized =
            serde_json::to_value(&self.block).map_err(|e| Error::JSON(e.to_string()))?;

        let block_data: serde_json::Value = match self.block.op_code() {
            IdentityOpCode::Create => {
                borsh_to_json_value::<IdentityCreateBlockData>(&self.plaintext_data_bytes)?
            }
            IdentityOpCode::Update => {
                borsh_to_json_value::<IdentityUpdateBlockData>(&self.plaintext_data_bytes)?
            }
            IdentityOpCode::AddSignatory => {
                borsh_to_json_value::<IdentityAddSignatoryBlockData>(&self.plaintext_data_bytes)?
            }
            IdentityOpCode::RemoveSignatory => {
                borsh_to_json_value::<IdentityRemoveSignatoryBlockData>(&self.plaintext_data_bytes)?
            }
            IdentityOpCode::SignPersonBill => {
                borsh_to_json_value::<IdentitySignPersonBillBlockData>(&self.plaintext_data_bytes)?
            }
            IdentityOpCode::SignCompanyBill => {
                borsh_to_json_value::<IdentitySignCompanyBillBlockData>(&self.plaintext_data_bytes)?
            }
            IdentityOpCode::CreateCompany => {
                borsh_to_json_value::<IdentityCreateCompanyBlockData>(&self.plaintext_data_bytes)?
            }
            IdentityOpCode::IdentityProof => {
                borsh_to_json_value::<IdentityProofBlockData>(&self.plaintext_data_bytes)?
            }
        };

        if let Some(obj) = serialized.as_object_mut() {
            obj.insert("data".to_string(), block_data);
        } else {
            return Err(Error::JSON(
                "Block didn't serialize to JSON object".to_string(),
            ));
        }

        serde_json::to_string(&serialized).map_err(|e| Error::JSON(e.to_string()))
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IdentityCreateBlockData {
    pub t: IdentityType,
    pub node_id: NodeId,
    pub name: Name,
    pub email: Option<Email>,
    pub postal_address: OptionalPostalAddress,
    pub date_of_birth: Option<Date>,
    pub city_of_birth: Option<City>,
    pub country_of_birth: Option<Country>,
    pub identification_number: Option<Identification>,
    #[borsh(
        serialize_with = "crate::util::borsh::serialize_vec_url",
        deserialize_with = "crate::util::borsh::deserialize_vec_url"
    )]
    pub nostr_relays: Vec<url::Url>,
    pub profile_picture_file: Option<File>,
    pub identity_document_file: Option<File>,
}

impl Validate for IdentityCreateBlockData {
    fn validate(&self) -> std::result::Result<(), crate::ValidationError> {
        if let IdentityType::Ident = self.t {
            // email needs to be set and not blank
            if self.email.is_none() {
                return Err(ValidationError::FieldEmpty(Field::Email));
            }
            // For Ident, the postal address needs to be fully set
            self.postal_address.validate_to_be_non_optional()?;
        }
        Ok(())
    }
}

impl From<Identity> for IdentityCreateBlockData {
    fn from(value: Identity) -> Self {
        Self {
            t: value.t,
            node_id: value.node_id,
            name: value.name,
            email: value.email,
            date_of_birth: value.date_of_birth,
            country_of_birth: value.country_of_birth,
            city_of_birth: value.city_of_birth,
            postal_address: value.postal_address,
            identification_number: value.identification_number,
            nostr_relays: value.nostr_relays,
            profile_picture_file: value.profile_picture_file,
            identity_document_file: value.identity_document_file,
        }
    }
}

#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Default, Debug, Clone, PartialEq,
)]
pub struct IdentityUpdateBlockData {
    pub t: Option<IdentityType>, // for deanonymization
    pub name: Option<Name>,
    pub email: Option<Email>,
    pub postal_address: OptionalPostalAddress,
    pub date_of_birth: Option<Date>,
    pub country_of_birth: Option<Country>,
    pub city_of_birth: Option<City>,
    pub identification_number: Option<Identification>,
    pub profile_picture_file: Option<File>,
    pub identity_document_file: Option<File>,
}

impl Validate for IdentityUpdateBlockData {
    fn validate(&self) -> std::result::Result<(), crate::ValidationError> {
        // deanonymization
        if let Some(IdentityType::Ident) = self.t {
            // email needs to be set and not blank
            if self.email.is_none() {
                return Err(ValidationError::FieldEmpty(Field::Email));
            }
            // For Ident, the postal address needs to be fully set
            self.postal_address.validate_to_be_non_optional()?;
        }
        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IdentitySignPersonBillBlockData {
    pub bill_id: BillId,
    pub block_id: BlockId,
    pub block_hash: Sha256Hash,
    pub operation: BillOpCode,
    #[borsh(
        serialize_with = "crate::util::borsh::serialize_optional_privkey",
        deserialize_with = "crate::util::borsh::deserialize_optional_privkey"
    )]
    pub bill_key: Option<SecretKey>,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IdentitySignCompanyBillBlockData {
    pub bill_id: BillId,
    pub block_id: BlockId,
    pub block_hash: Sha256Hash,
    pub company_id: NodeId,
    pub operation: BillOpCode,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IdentityCreateCompanyBlockData {
    pub company_id: NodeId,
    #[borsh(
        serialize_with = "crate::util::borsh::serialize_privkey",
        deserialize_with = "crate::util::borsh::deserialize_privkey"
    )]
    pub company_key: SecretKey,
    pub block_hash: Sha256Hash,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IdentityAddSignatoryBlockData {
    pub company_id: NodeId,
    pub block_id: BlockId,
    pub block_hash: Sha256Hash,
    pub signatory: NodeId,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IdentityRemoveSignatoryBlockData {
    pub company_id: NodeId,
    pub block_id: BlockId,
    pub block_hash: Sha256Hash,
    pub signatory: NodeId,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IdentityProofBlockData {
    pub stamp: IdentityProofStamp,
    #[borsh(
        serialize_with = "crate::util::borsh::serialize_url",
        deserialize_with = "crate::util::borsh::deserialize_url"
    )]
    pub url: url::Url,
}

#[derive(Debug)]
pub enum IdentityBlockPayload {
    Create(IdentityCreateBlockData),
    Update(IdentityUpdateBlockData),
    SignPersonalBill(IdentitySignPersonBillBlockData),
    SignCompanyBill(IdentitySignCompanyBillBlockData),
    CreateCompany(IdentityCreateCompanyBlockData),
    AddSignatory(IdentityAddSignatoryBlockData),
    RemoveSignatory(IdentityRemoveSignatoryBlockData),
    IdentityProof(IdentityProofBlockData),
}

impl Block for IdentityBlock {
    type OpCode = IdentityOpCode;
    type BlockDataToHash = IdentityBlockDataToHash;

    fn id(&self) -> BlockId {
        self.id
    }

    fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    fn op_code(&self) -> &Self::OpCode {
        &self.op_code
    }

    fn plaintext_hash(&self) -> &Sha256Hash {
        &self.plaintext_hash
    }

    fn hash(&self) -> &Sha256Hash {
        &self.hash
    }

    fn previous_hash(&self) -> &Sha256Hash {
        &self.previous_hash
    }

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn signature(&self) -> &SchnorrSignature {
        &self.signature
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn validate(&self) -> bool {
        true
    }

    fn validate_plaintext_hash(&self, private_key: &secp256k1::SecretKey) -> bool {
        match util::crypto::decrypt_ecies(self.data(), private_key) {
            Ok(decrypted) => self.plaintext_hash() == &Sha256Hash::from_bytes(&decrypted),
            Err(e) => {
                error!(
                    "Decrypt Error while validating plaintext hash for id {}: {e}",
                    self.id()
                );
                false
            }
        }
    }

    fn get_block_data_to_hash(&self) -> Self::BlockDataToHash {
        IdentityBlockDataToHash {
            id: self.id(),
            plaintext_hash: self.plaintext_hash().to_owned(),
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
        id: BlockId,
        previous_hash: Sha256Hash,
        data: Vec<u8>,
        op_code: IdentityOpCode,
        keys: &BcrKeys,
        timestamp: Timestamp,
        plaintext_hash: Sha256Hash,
    ) -> Result<Self> {
        let hash = Self::calculate_hash(IdentityBlockDataToHash {
            id,
            plaintext_hash: plaintext_hash.clone(),
            previous_hash: previous_hash.clone(),
            data: data.clone(),
            timestamp,
            public_key: keys.pub_key(),
            op_code: op_code.clone(),
        })?;
        let signature = crypto::signature(&hash, &keys.get_private_key())?;

        Ok(Self {
            id,
            plaintext_hash,
            hash,
            timestamp,
            previous_hash,
            signature,
            public_key: keys.pub_key(),
            data,
            op_code,
        })
    }

    pub fn create_block_for_create(
        genesis_hash: Sha256Hash,
        identity: &IdentityCreateBlockData,
        keys: &BcrKeys,
        timestamp: Timestamp,
    ) -> Result<Self> {
        let identity_bytes = to_vec(identity)?;
        let plaintext_hash = Self::calculate_plaintext_hash(identity)?;

        let encrypted_data = util::crypto::encrypt_ecies(&identity_bytes, &keys.pub_key())?;

        Self::new(
            BlockId::first(),
            genesis_hash,
            encrypted_data,
            IdentityOpCode::Create,
            keys,
            timestamp,
            plaintext_hash,
        )
    }

    pub fn create_block_for_update(
        previous_block: &Self,
        data: &IdentityUpdateBlockData,
        keys: &BcrKeys,
        timestamp: Timestamp,
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
        timestamp: Timestamp,
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
        timestamp: Timestamp,
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
        timestamp: Timestamp,
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
        timestamp: Timestamp,
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
        timestamp: Timestamp,
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

    pub fn create_block_for_identity_proof(
        previous_block: &Self,
        data: &IdentityProofBlockData,
        keys: &BcrKeys,
        timestamp: Timestamp,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            previous_block,
            data,
            keys,
            timestamp,
            IdentityOpCode::IdentityProof,
        )?;
        Ok(block)
    }

    fn encrypt_data_create_block_and_validate<T: borsh::BorshSerialize>(
        previous_block: &Self,
        data: &T,
        keys: &BcrKeys,
        timestamp: Timestamp,
        op_code: IdentityOpCode,
    ) -> Result<Self> {
        let bytes = to_vec(&data)?;
        let plaintext_hash = Self::calculate_plaintext_hash(data)?;

        let encrypted_data = util::crypto::encrypt_ecies(&bytes, &keys.pub_key())?;

        let new_block = Self::new(
            BlockId::next_from_previous_block_id(&previous_block.id()),
            previous_block.hash.clone(),
            encrypted_data,
            op_code,
            keys,
            timestamp,
            plaintext_hash,
        )?;

        if !new_block.validate_with_previous(previous_block) {
            return Err(super::Error::BlockInvalid);
        }
        Ok(new_block)
    }

    pub fn get_block_data(&self, keys: &BcrKeys) -> Result<IdentityBlockPayload> {
        let data = self.get_decrypted_block_bytes(keys)?;
        let result: IdentityBlockPayload = match self.op_code {
            IdentityOpCode::Create => IdentityBlockPayload::Create(from_slice(&data)?),
            IdentityOpCode::Update => IdentityBlockPayload::Update(from_slice(&data)?),
            IdentityOpCode::SignPersonBill => {
                IdentityBlockPayload::SignPersonalBill(from_slice(&data)?)
            }
            IdentityOpCode::SignCompanyBill => {
                IdentityBlockPayload::SignCompanyBill(from_slice(&data)?)
            }
            IdentityOpCode::CreateCompany => {
                IdentityBlockPayload::CreateCompany(from_slice(&data)?)
            }
            IdentityOpCode::AddSignatory => IdentityBlockPayload::AddSignatory(from_slice(&data)?),
            IdentityOpCode::RemoveSignatory => {
                IdentityBlockPayload::RemoveSignatory(from_slice(&data)?)
            }
            IdentityOpCode::IdentityProof => {
                IdentityBlockPayload::IdentityProof(from_slice(&data)?)
            }
        };
        Ok(result)
    }

    fn get_decrypted_block_bytes(&self, keys: &BcrKeys) -> Result<Vec<u8>> {
        let decrypted_bytes = util::crypto::decrypt_ecies(&self.data, &keys.get_private_key())?;
        Ok(decrypted_bytes)
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
    pub fn new(
        identity: &IdentityCreateBlockData,
        keys: &BcrKeys,
        timestamp: Timestamp,
    ) -> Result<Self> {
        let genesis_hash = Sha256Hash::from_bytes(keys.get_public_key().as_bytes());

        let first_block =
            IdentityBlock::create_block_for_create(genesis_hash, identity, keys, timestamp)?;

        Ok(Self {
            blocks: vec![first_block],
        })
    }

    /// Creates an identity chain from a list of blocks
    pub fn new_from_blocks(blocks_to_add: Vec<IdentityBlock>) -> Result<Self> {
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

    pub fn get_chain_with_plaintext_block_data(
        &self,
        keys: &BcrKeys,
    ) -> Result<Vec<IdentityBlockPlaintextWrapper>> {
        let mut result = Vec::with_capacity(self.blocks().len());
        for block in self.blocks.iter() {
            let plaintext_data_bytes = match block.op_code() {
                IdentityOpCode::Create => block.get_decrypted_block_bytes(keys)?,
                IdentityOpCode::Update => block.get_decrypted_block_bytes(keys)?,
                IdentityOpCode::AddSignatory => block.get_decrypted_block_bytes(keys)?,
                IdentityOpCode::RemoveSignatory => block.get_decrypted_block_bytes(keys)?,
                IdentityOpCode::SignCompanyBill => block.get_decrypted_block_bytes(keys)?,
                IdentityOpCode::IdentityProof => block.get_decrypted_block_bytes(keys)?,
                IdentityOpCode::SignPersonBill => block.get_decrypted_block_bytes(keys)?,
                IdentityOpCode::CreateCompany => block.get_decrypted_block_bytes(keys)?,
            };

            if block.plaintext_hash != Sha256Hash::from_bytes(&plaintext_data_bytes) {
                return Err(Error::BlockInvalid);
            }

            result.push(IdentityBlockPlaintextWrapper {
                block: block.clone(),
                plaintext_data_bytes,
            });
        }

        // Validate the chain from the wrapper
        IdentityBlockchain::new_from_blocks(
            result
                .iter()
                .map(|wrapper| wrapper.block.to_owned())
                .collect::<Vec<IdentityBlock>>(),
        )?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::tests::{
        bill_id_test, empty_identity, node_id_test, private_key_test, valid_optional_address,
    };

    #[test]
    fn test_plaintext_hash() {
        let identity = empty_identity();
        let keys = BcrKeys::new();

        let chain =
            IdentityBlockchain::new(&identity.into(), &keys, Timestamp::new(1731593928).unwrap());
        assert!(chain.is_ok());
        assert!(chain.as_ref().unwrap().is_chain_valid());
        assert!(
            chain.as_ref().unwrap().blocks()[0].validate_plaintext_hash(&keys.get_private_key())
        );
    }

    #[test]
    fn create_and_check_validity() {
        let identity = empty_identity();

        let chain = IdentityBlockchain::new(
            &identity.into(),
            &BcrKeys::new(),
            Timestamp::new(1731593928).unwrap(),
        );
        assert!(chain.is_ok());
        assert!(chain.as_ref().unwrap().is_chain_valid());
    }

    #[test]
    fn multi_block() {
        let identity = empty_identity();
        let keys = BcrKeys::new();

        let chain =
            IdentityBlockchain::new(&identity.into(), &keys, Timestamp::new(1731593928).unwrap());
        assert!(chain.is_ok());
        assert!(chain.as_ref().unwrap().is_chain_valid());
        let mut chain = chain.unwrap();

        let update_block = IdentityBlock::create_block_for_update(
            chain.get_latest_block(),
            &IdentityUpdateBlockData {
                t: None,
                name: Some(Name::new("newname").unwrap()),
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
            Timestamp::new(1731593928).unwrap(),
        );
        assert!(update_block.is_ok());
        chain.try_add_block(update_block.unwrap());

        let sign_person_bill_block = IdentityBlock::create_block_for_sign_person_bill(
            chain.get_latest_block(),
            &IdentitySignPersonBillBlockData {
                bill_id: bill_id_test(),
                block_id: BlockId::first(),
                block_hash: Sha256Hash::new("some hash"),
                operation: BillOpCode::Issue,
                bill_key: Some(private_key_test()),
            },
            &keys,
            Timestamp::new(1731593928).unwrap(),
        );
        assert!(sign_person_bill_block.is_ok());
        chain.try_add_block(sign_person_bill_block.unwrap());

        let sign_company_bill_block = IdentityBlock::create_block_for_sign_company_bill(
            chain.get_latest_block(),
            &IdentitySignCompanyBillBlockData {
                bill_id: bill_id_test(),
                block_id: BlockId::first(),
                block_hash: Sha256Hash::new("some hash"),
                company_id: node_id_test(),
                operation: BillOpCode::Issue,
            },
            &keys,
            Timestamp::new(1731593928).unwrap(),
        );
        assert!(sign_company_bill_block.is_ok());
        chain.try_add_block(sign_company_bill_block.unwrap());

        let create_company_block = IdentityBlock::create_block_for_create_company(
            chain.get_latest_block(),
            &IdentityCreateCompanyBlockData {
                company_id: node_id_test(),
                company_key: private_key_test(),
                block_hash: Sha256Hash::new("some hash"),
            },
            &keys,
            Timestamp::new(1731593928).unwrap(),
        );
        assert!(create_company_block.is_ok());
        chain.try_add_block(create_company_block.unwrap());

        let add_signatory_block = IdentityBlock::create_block_for_add_signatory(
            chain.get_latest_block(),
            &IdentityAddSignatoryBlockData {
                company_id: node_id_test(),
                block_id: BlockId::next_from_previous_block_id(&BlockId::first()),
                block_hash: Sha256Hash::new("some hash"),
                signatory: node_id_test(),
            },
            &keys,
            Timestamp::new(1731593928).unwrap(),
        );
        assert!(add_signatory_block.is_ok());
        chain.try_add_block(add_signatory_block.unwrap());

        let remove_signatory_block = IdentityBlock::create_block_for_remove_signatory(
            chain.get_latest_block(),
            &IdentityRemoveSignatoryBlockData {
                company_id: node_id_test(),
                block_id: BlockId::next_from_previous_block_id(&BlockId::first()),
                block_hash: Sha256Hash::new("some hash"),
                signatory: node_id_test(),
            },
            &keys,
            Timestamp::new(1731593928).unwrap(),
        );
        assert!(remove_signatory_block.is_ok());
        chain.try_add_block(remove_signatory_block.unwrap());

        let identity_proof_block = IdentityBlock::create_block_for_identity_proof(
            chain.get_latest_block(),
            &IdentityProofBlockData {
                stamp: IdentityProofStamp::new(&node_id_test(), &private_key_test()).unwrap(),
                url: url::Url::parse("https://bit.cr").unwrap(),
            },
            &keys,
            Timestamp::new(1731593929).unwrap(),
        );
        assert!(identity_proof_block.is_ok());
        chain.try_add_block(identity_proof_block.unwrap());

        assert_eq!(chain.blocks().len(), 8);
        assert!(chain.is_chain_valid());
        for block in chain.blocks() {
            assert!(block.validate_plaintext_hash(&keys.get_private_key()));
        }
    }
}
